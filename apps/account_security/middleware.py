from django.contrib.auth import logout
from django.http import JsonResponse

from apps.account_security.assurance import (
    ASSURANCE_SESSION_KEY,
    clear_internal_assurance,
    validate_internal_assurance_marker,
)
from apps.account_security.audit import log_security_event
from apps.account_security.policies import is_internal_assurance_required
from apps.account_security.session_metadata import record_authenticated_session
from apps.account_security.network import get_client_ip_from_headers
from apps.common.contracts import RequestMetadata


class InternalAssuranceMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = request.user
        if not user.is_authenticated:
            return self.get_response(request)

        required = is_internal_assurance_required(user)
        marker = request.session.get(ASSURANCE_SESSION_KEY)
        valid, reason = validate_internal_assurance_marker(user, marker)

        if not required:
            if marker is not None:
                clear_internal_assurance(request)
            record_authenticated_session(request.session, _request_context(request))
            return self.get_response(request)

        if valid:
            record_authenticated_session(request.session, _request_context(request))
            return self.get_response(request)

        log_security_event(
            action_type="internal_assurance_rejected",
            target_model="accounts.User",
            target_object_id=str(user.pk),
            severity="WARNING",
            actor_user=user,
            metadata={"reason": reason, "route_class": "api"},
        )
        logout(request)

        status = 403 if request.method not in {"GET", "HEAD"} else 401
        response = JsonResponse(
            {"detail": "Additional internal assurance is required."},
            status=status,
        )
        response["Cache-Control"] = "no-store"
        return response


def _request_context(request) -> RequestMetadata:
    """Extract transient request facts at the middleware boundary."""
    return RequestMetadata(
        ip_address=get_client_ip_from_headers(request.META),
        user_agent=str(request.META.get("HTTP_USER_AGENT", "") or ""),
        session_key=str(getattr(request.session, "session_key", "") or ""),
    )
