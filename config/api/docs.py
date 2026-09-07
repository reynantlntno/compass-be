"""Environment-aware access control for generated API documentation."""

from __future__ import annotations

from functools import wraps

from django.http import JsonResponse

from apps.access_control.rules import is_it_admin
from apps.account_security.api_auth import authenticate_bearer_request
from apps.common.api.headers import apply_noindex_header


def bearer_it_admin_docs(view):
    """Protect the deployed OpenAPI schema with a bearer IT Admin token."""

    @wraps(view)
    def wrapped(request, *args, **kwargs):
        principal = authenticate_bearer_request(request)
        if principal is None or not is_it_admin(principal.user):
            response = JsonResponse({"detail": "Not found."}, status=404)
            response["Cache-Control"] = "no-store"
            return apply_noindex_header(response)
        return view(request, *args, **kwargs)

    return wrapped
