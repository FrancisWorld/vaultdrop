import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import migrate
from .config import Settings, get_settings
from .container import build_container
from .errors import DomainError
from .routers import audit, auth, files, shares, uploads

log = logging.getLogger(__name__)
STATIC_DIR = Path(__file__).resolve().parent / "static"
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def content_security_policy(storage_origin: str) -> str:
    """Strict CSP: scripts and styles only from this origin, network only to it and storage."""
    return "; ".join(
        [
            "default-src 'none'",
            "script-src 'self'",
            "style-src 'self'",
            f"connect-src 'self' {storage_origin}",
            "img-src 'self'",
            "form-action 'self'",
            "base-uri 'none'",
            "frame-ancestors 'none'",
        ]
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    container = build_container(settings)
    csp = content_security_policy(container.s3.browser_origin)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        if settings.auto_migrate:
            await asyncio.to_thread(migrate.upgrade, settings.database_url)
        if settings.s3_bootstrap:
            await asyncio.to_thread(container.s3.bootstrap)
        sweeper: asyncio.Task[None] | None = None
        if settings.sweep_interval_seconds > 0:
            sweeper = asyncio.create_task(
                container.maintenance.run_forever(settings.sweep_interval_seconds)
            )
        try:
            yield
        finally:
            if sweeper:
                sweeper.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await sweeper
            container.database.dispose()
            log.info("shutdown complete")

    app = FastAPI(title="VaultDrop", version="0.2.0", lifespan=lifespan)
    app.state.container = container

    @app.exception_handler(DomainError)
    async def domain_error(_request: Request, error: DomainError) -> JSONResponse:
        return JSONResponse(
            {"detail": error.detail}, status_code=error.status_code, headers=error.headers
        )

    @app.middleware("http")
    async def harden(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        origin = request.headers.get("origin")
        if request.method in UNSAFE_METHODS and origin:
            own = f"{request.url.scheme}://{request.headers.get('host', '')}"
            if origin.rstrip("/") != own and origin.rstrip("/") not in settings.origins:
                return JSONResponse({"detail": "Cross-origin request rejected"}, status_code=403)
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = csp
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if settings.cookie_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        if request.url.path.startswith(("/v1/", "/s/")):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/s/{token}", include_in_schema=False)
    def share_page(token: str) -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html", media_type="text/html")

    for module in (auth, uploads, files, shares, audit):
        app.include_router(module.router)
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
    return app
