"""Explicit cookie transport for the browser-facing authentication boundary.

The API remains bearer-first.  Cookie authentication is enabled only when a
client opts into the COMPASS session media type and transport marker.  Cookie
names and attributes live here so the issuer, verifier, and logout boundary
cannot drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import ceil

from django.conf import settings
from django.http import JsonResponse
from django.utils.cache import patch_vary_headers


SESSION_MEDIA_TYPE = "application/vnd.compass.session+json"
SESSION_TRANSPORT_HEADER = "X-COMPASS-Auth-Transport"
SESSION_TRANSPORT_VALUE = "cookie"

_ACCESS_COOKIE_BASE = "compass-access"
_REFRESH_COOKIE_BASE = "compass-refresh"
_MAX_COOKIE_VALUE_LENGTH = 512
_EXPIRED_COOKIE_DATE = "Thu, 01 Jan 1970 00:00:00 GMT"


@dataclass(frozen=True, slots=True)
class SessionCookieNames:
    access: str
    refresh: str


def _uses_secure_prefixes() -> bool:
    environment = str(getattr(settings, "COMPASS_ENVIRONMENT", "development") or "").strip().lower()
    return environment in {"staging", "production"}


def session_cookie_names() -> SessionCookieNames:
    if _uses_secure_prefixes():
        return SessionCookieNames(
            access=f"__Host-{_ACCESS_COOKIE_BASE}",
            refresh=f"__Secure-{_REFRESH_COOKIE_BASE}",
        )
    return SessionCookieNames(
        access=_ACCESS_COOKIE_BASE,
        refresh=_REFRESH_COOKIE_BASE,
    )


def session_transport_requested(request) -> bool:
    """Return true only for the complete, explicit cookie profile."""

    headers = getattr(request, "headers", {})
    transport = str(headers.get(SESSION_TRANSPORT_HEADER, "") or "").strip().lower()
    if transport != SESSION_TRANSPORT_VALUE:
        return False
    accept = str(headers.get("Accept", "") or "")
    media_types = {
        part.split(";", 1)[0].strip().lower()
        for part in accept.split(",")
        if part.strip()
    }
    return SESSION_MEDIA_TYPE in media_types


def authorization_header(request) -> str:
    return str((getattr(request, "META", {}) or {}).get("HTTP_AUTHORIZATION", "") or "").strip()


def _safe_cookie_value(value) -> str | None:
    if not isinstance(value, str) or not value or len(value) > _MAX_COOKIE_VALUE_LENGTH:
        return None
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        return None
    if ";" in value or "," in value:
        return None
    return value


def request_cookie_value(request, name: str) -> str | None:
    cookies = getattr(request, "COOKIES", {}) or {}
    return _safe_cookie_value(cookies.get(name))


def session_access_cookie(request) -> str | None:
    return request_cookie_value(request, session_cookie_names().access)


def session_refresh_cookie(request) -> str | None:
    return request_cookie_value(request, session_cookie_names().refresh)


def session_response(data, *, status: int = 200) -> JsonResponse:
    response = JsonResponse(data, status=status)
    response["Cache-Control"] = "no-store"
    patch_vary_headers(response, ["Accept", SESSION_TRANSPORT_HEADER])
    return response


def set_session_cookies(response, token_pair) -> None:
    """Set opaque auth cookies with fixed paths and no Domain attribute."""

    secure = _uses_secure_prefixes()
    names = session_cookie_names()
    access_max_age = max(1, ceil((token_pair.access_expires_at - _now()).total_seconds()))
    refresh_max_age = max(1, ceil((token_pair.refresh_expires_at - _now()).total_seconds()))
    response.set_cookie(
        names.access,
        token_pair.access_token,
        max_age=access_max_age,
        path="/",
        secure=secure,
        httponly=True,
        samesite="Lax",
    )
    response.set_cookie(
        names.refresh,
        token_pair.refresh_token,
        max_age=refresh_max_age,
        path="/api/v1/auth/",
        secure=secure,
        httponly=True,
        samesite="Lax",
    )


def clear_session_cookies(response) -> None:
    """Expire both cookie paths without copying arbitrary upstream attributes."""

    secure = _uses_secure_prefixes()
    names = session_cookie_names()
    for name, path in (
        (names.access, "/"),
        (names.refresh, "/api/v1/auth/"),
    ):
        response.set_cookie(
            name,
            "",
            max_age=0,
            expires=_EXPIRED_COOKIE_DATE,
            path=path,
            secure=secure,
            httponly=True,
            samesite="Lax",
        )


def _now():
    from django.utils import timezone

    return timezone.now()
