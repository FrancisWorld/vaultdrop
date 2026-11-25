from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .config import get_settings
from .database import create_all
from .routers.audit import router as audit_router
from .routers.auth import router as auth_router
from .routers.files import router as files_router
from .routers.uploads import router as uploads_router
from .routers.uploads import s3

app = FastAPI(title="VaultDrop", version="0.1.0")
settings = get_settings()
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins.split(","), allow_methods=["GET", "POST", "DELETE"], allow_headers=["Content-Type"], allow_credentials=True)


@app.middleware("http")
async def security_headers(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob:; connect-src 'self' http://localhost:* https:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


@app.on_event("startup")
def startup() -> None:
    create_all()
    s3.ensure_bucket()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


app.include_router(auth_router)
app.include_router(uploads_router)
app.include_router(files_router)
app.include_router(audit_router)
app.mount("/", StaticFiles(directory="static", html=True), name="static")
