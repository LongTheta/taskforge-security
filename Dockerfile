# TaskForge Security - Production Dockerfile
# Python 3.11 slim, non-root user, uv for reproducible installs

FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_NO_DEV=1

WORKDIR /app

# Install uv for reproducible installs from lockfile
COPY --from=ghcr.io/astral-sh/uv:0.10 /uv /uvx /bin/

# Non-root user
RUN groupadd --gid 1000 app && \
    useradd --uid 1000 --gid app --shell /bin/sh --create-home app

# Dependencies from lockfile (reproducible)
COPY pyproject.toml uv.lock ./
COPY app ./app
RUN uv sync --locked --no-install-project && uv sync --locked --no-editable

USER app

EXPOSE 8081

ENV PATH="/app/.venv/bin:$PATH"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8081"]
