"""Shared, fail-closed validation for deployment environment settings."""

from __future__ import annotations

import os
from urllib.parse import urlparse

from django.core.exceptions import ImproperlyConfigured


_PLACEHOLDER_MARKERS = (
    "change-me",
    "placeholder",
    "replace-me",
    "your-secret",
)


def _configured_value(name: str, *, reject_placeholders: bool = False) -> str:
    value = os.environ.get(name)
    if value is None or not value.strip():
        raise ImproperlyConfigured(f"{name} must be configured for this environment.")
    if value != value.strip() or any(ord(character) < 32 for character in value):
        raise ImproperlyConfigured(f"{name} contains invalid whitespace or control characters.")
    if reject_placeholders:
        normalized = value.lower()
        if (
            any(marker in normalized for marker in _PLACEHOLDER_MARKERS)
            or "<" in value
            or ">" in value
        ):
            raise ImproperlyConfigured(f"{name} must not use a placeholder value.")
    return value


def require_value(name: str, *, reject_placeholders: bool = False) -> str:
    """Require one non-empty deployment value without exposing its contents."""

    return _configured_value(name, reject_placeholders=reject_placeholders)


def require_secret(
    name: str,
    *,
    distinct_from: tuple[str, ...] = (),
    minimum_length: int = 1,
) -> str:
    """Require a non-placeholder secret and optionally enforce key separation."""

    value = _configured_value(name, reject_placeholders=True)
    if len(value) < minimum_length:
        raise ImproperlyConfigured(
            f"{name} must contain at least {minimum_length} characters."
        )
    if any(value == other for other in distinct_from):
        raise ImproperlyConfigured(f"{name} must be distinct from another deployment secret.")
    return value


def require_database_url(name: str = "DATABASE_URL") -> str:
    """Require the canonical PostgreSQL URL scheme; never silently use SQLite."""

    value = _configured_value(name, reject_placeholders=True)
    parsed = urlparse(value)
    if parsed.scheme != "postgresql" or not parsed.hostname:
        raise ImproperlyConfigured(f"{name} must be a valid PostgreSQL URL.")
    return value


def require_redis_url(name: str = "CACHE_URL") -> str:
    """Require a Redis-compatible cache URL for distributed abuse controls."""

    value = _configured_value(name, reject_placeholders=True)
    parsed = urlparse(value)
    if parsed.scheme not in {"redis", "rediss"} or not parsed.hostname:
        raise ImproperlyConfigured(f"{name} must be a valid Redis URL.")
    return value


def require_https_url(name: str) -> str:
    """Require a public HTTPS URL without embedded credentials or fragments."""

    value = _configured_value(name, reject_placeholders=True)
    parsed = urlparse(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ImproperlyConfigured(f"{name} must be a canonical HTTPS URL.")
    return value


def validate_origins(
    origins: list[str],
    *,
    name: str,
    require_https: bool = False,
) -> list[str]:
    """Validate a possibly empty, comma-separated origin allowlist."""

    normalized_origins = []
    seen_origins = set()
    for raw_origin in origins:
        origin = str(raw_origin).strip()
        if not origin:
            continue
        if any(character.isspace() for character in origin):
            raise ImproperlyConfigured(f"{name} must contain only canonical origins.")
        parsed = urlparse(origin)
        scheme = parsed.scheme.lower()
        try:
            port = parsed.port
        except ValueError:
            raise ImproperlyConfigured(f"{name} must contain only canonical origins.") from None
        if (
            origin in {"*", "null", "file://"}
            or scheme not in {"http", "https"}
            or (require_https and scheme != "https")
            or not parsed.hostname
            or "*" in parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            scheme_message = "HTTPS" if require_https else "HTTP(S)"
            raise ImproperlyConfigured(
                f"{name} must contain only canonical {scheme_message} origins."
            )
        hostname = parsed.hostname.lower()
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        if port is None or port == (443 if scheme == "https" else 80):
            host = hostname
        else:
            host = f"{hostname}:{port}"
        normalized_origin = f"{scheme}://{host}"
        if normalized_origin in seen_origins:
            raise ImproperlyConfigured(f"{name} must not contain duplicate origins.")
        seen_origins.add(normalized_origin)
        normalized_origins.append(normalized_origin)
    return normalized_origins


def require_https_origins(name: str = "CSRF_TRUSTED_ORIGINS") -> list[str]:
    """Require an explicit comma-separated HTTPS origin allowlist."""

    raw_value = _configured_value(name, reject_placeholders=True)
    origins = validate_origins(
        raw_value.split(","),
        name=name,
        require_https=True,
    )
    if not origins:
        raise ImproperlyConfigured(f"{name} must contain at least one HTTPS origin.")
    return origins


def validate_allowed_hosts(hosts: list[str], name: str = "ALLOWED_HOSTS") -> list[str]:
    """Reject empty, wildcard, or URL-shaped deployment host allowlists."""

    normalized_hosts = []
    seen_hosts = set()
    for raw_host in hosts:
        host = str(raw_host).strip().lower()
        if not host:
            continue
        if any(character.isspace() for character in host) or "*" in host:
            raise ImproperlyConfigured(f"{name} must contain specific hosts only.")
        if "/" in host or "://" in host:
            raise ImproperlyConfigured(f"{name} must contain hostnames, not URLs.")
        if host in seen_hosts:
            raise ImproperlyConfigured(f"{name} must not contain duplicate hosts.")
        seen_hosts.add(host)
        normalized_hosts.append(host)
    if not normalized_hosts:
        raise ImproperlyConfigured(f"{name} must contain specific hosts only.")
    return normalized_hosts
