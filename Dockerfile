FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS build
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY vaultdrop ./vaultdrop
RUN uv sync --locked --no-dev --no-cache

FROM python:3.12-slim-bookworm
RUN groupadd --gid 10001 vaultdrop && useradd --uid 10001 --gid 10001 --create-home vaultdrop
WORKDIR /app
COPY --from=build /app/.venv /app/.venv
COPY vaultdrop /app/vaultdrop
COPY scripts /app/scripts
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=5 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"]
CMD ["uvicorn", "--factory", "vaultdrop.api:create_app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--timeout-graceful-shutdown", "15"]
