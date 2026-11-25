FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS build
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY vaultdrop ./vaultdrop
COPY static ./static
RUN uv sync --locked --no-dev --no-cache

FROM python:3.12-slim-bookworm
RUN groupadd --gid 10001 vaultdrop && useradd --uid 10001 --gid 10001 --create-home vaultdrop
WORKDIR /app
COPY --from=build /app/.venv /app/.venv
COPY --from=build /app/static /app/static
COPY vaultdrop /app/vaultdrop
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "vaultdrop.api:app", "--host", "0.0.0.0", "--port", "8000"]
