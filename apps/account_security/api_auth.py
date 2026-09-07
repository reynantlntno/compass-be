"""Django Ninja authentication boundary for opaque COMPASS bearer tokens."""

from __future__ import annotations

from ninja.security import HttpBearer

from apps.account_security.api_tokens import (
    ApiTokenPrincipal,
    resolve_access_token,
)
from apps.account_security.session_cookies import (
    authorization_header,
    session_access_cookie,
    session_transport_requested,
)


def extract_bearer_token(request) -> str | None:
    """Parse one canonical Authorization header without accepting query tokens."""

    header = str(request.META.get("HTTP_AUTHORIZATION", "") or "").strip()
    parts = header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    return token if token and len(token) <= 512 else None


def authenticate_bearer_request(request) -> ApiTokenPrincipal | None:
    if session_transport_requested(request):
        # A request must choose one credential transport.  Returning no
        # principal keeps the framework response generic and prevents a
        # valid bearer from silently winning over a conflicting cookie.
        if authorization_header(request):
            return None
        return resolve_access_token(session_access_cookie(request))
    return resolve_access_token(extract_bearer_token(request))


class CompassBearerAuthentication(HttpBearer):
    """Resolve only active, current, assurance-valid opaque access tokens."""

    def __call__(self, request):
        if session_transport_requested(request):
            if authorization_header(request):
                return None
            return resolve_access_token(session_access_cookie(request))
        return super().__call__(request)

    def authenticate(self, request, token):
        return resolve_access_token(token)
