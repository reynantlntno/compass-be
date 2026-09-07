# Project: COMPASS
# File: Containerfile
# Purpose: Django web service container image
# Base: Python 3.12 slim (Debian bookworm)
# Notes: Podman-compatible. Use "podman compose build" to build.

FROM python:3.12-slim-bookworm

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install system dependencies for psycopg, Pillow, and the PostgreSQL 16
# client tools used exclusively by the supervised backup worker.  Debian
# bookworm's built-in client is PostgreSQL 15, which cannot safely create a
# dump from the PostgreSQL 16 service used by COMPASS.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
    && curl --fail --silent --show-error --location \
        https://www.postgresql.org/media/keys/ACCC4CF8.asc \
        | gpg --dearmor --yes --output /usr/share/keyrings/postgresql-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/postgresql-archive-keyring.gpg] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" \
        > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    postgresql-client-16 \
    libjpeg62-turbo-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && python -m playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . .

# The staging deployment uses this wrapper to turn root-owned Podman
# secret mounts into process environment variables without placing secret
# values in Compose files, Terraform, or image layers.
COPY deploy/compass-secret-env.sh /usr/local/bin/compass-secret-env
RUN chmod 0550 /usr/local/bin/compass-secret-env

# Expose port
EXPOSE 8000

# The image defaults to the synchronous Django WSGI server used by staging and
# production.  Local development explicitly overrides this with runserver in
# compose.override.yaml, so an image started outside the local overlay does
# not silently become a development deployment.
CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3", "--timeout", "60", "--graceful-timeout", "30", "--access-logfile", "-", "--access-logformat", "%(U)s %(m)s %(s)s", "--error-logfile", "-"]
