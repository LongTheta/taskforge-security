# TaskForge Security - Production Dockerfile
# Python 3.11 slim, non-root user, minimal layers

FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Non-root user
RUN groupadd --gid 1000 app && \
    useradd --uid 1000 --gid app --shell /bin/sh --create-home app

# Dependencies and application (needed for pip install)
COPY pyproject.toml ./
COPY app ./app
RUN pip install --no-cache-dir .

USER app

EXPOSE 8081

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8081"]
