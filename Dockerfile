# syntax=docker/dockerfile:1

# ---- builder: resolve and install locked dependencies into a venv ----
FROM python:3.12-slim-bookworm AS builder

COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app
# Dependencies first: this layer is cached until pyproject.toml / uv.lock change.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

# ---- runtime: no uv, no build tools, non-root ----
FROM python:3.12-slim-bookworm AS runtime

# Fixed uid/gid so volume permissions and compose `user:` stay predictable.
RUN groupadd --system --gid 10001 mirage \
    && useradd --system --uid 10001 --gid mirage --no-create-home --shell /usr/sbin/nologin mirage

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY --from=builder --chown=mirage:mirage /app/.venv /app/.venv
COPY --chown=mirage:mirage alembic.ini ./
COPY --chown=mirage:mirage app ./app
COPY --chown=mirage:mirage domain ./domain
COPY --chown=mirage:mirage workers ./workers
COPY --chown=mirage:mirage migrations ./migrations

USER mirage:mirage
EXPOSE 8080

# Default process: the public honeypot. Workers override CMD, e.g.
# `python -m workers.persister`.
# - uvicorn's own Server header and access log are off: the persona sets Server,
#   and attacker-controlled paths must not end up in application logs.
# - proxy headers are handled by the app (trusted proxies from Settings), not uvicorn.
CMD ["uvicorn", "app.main:create_app", "--factory", \
     "--host", "0.0.0.0", "--port", "8080", \
     "--loop", "uvloop", "--http", "httptools", \
     "--no-server-header", "--no-access-log", "--no-proxy-headers"]
