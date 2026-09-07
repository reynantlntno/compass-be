"""Global fail-closed access and maintenance enforcement for API routes."""

from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.core.exceptions import PermissionDenied
from django.http import Http404

from apps.system.maintenance_services import (
    audit_maintenance_bypass,
    evaluate_maintenance_request,
)
from apps.system.error_services import capture_application_error_event
from apps.system.choices import ErrorCategoryChoices, ErrorSeverityChoices
from apps.common.api.errors import render_error_response
from apps.common.exceptions import DependencyFailureError


class CompassAccessModeMiddleware(MiddlewareMixin):
    """Keep a newly provisioned staging instance on its liveness surface.

    ``health_only`` is deliberately enforced before sessions, authentication,
    CSRF, URL resolution, and application views. This keeps the blank staging
    database and all user-facing workflows unreachable until the operator has
    explicitly completed the domain/provider activation gate. Invalid values
    also fail closed instead of silently becoming active.
    """

    _HEALTH_ONLY_ALLOWED_PATHS = frozenset(
        {
            "/health/",
            "/robots.txt",
            "/api/v1/system/public-status/",
        }
    )

    def process_request(self, request):
        mode = str(getattr(settings, "COMPASS_ACCESS_MODE", "") or "").strip().lower()
        if mode == "active":
            return None
        if (
            mode == "health_only"
            and request.path in self._HEALTH_ONLY_ALLOWED_PATHS
            and request.method in {"GET", "HEAD"}
        ):
            return None
        return self._blocked_response(request)

    @staticmethod
    def _blocked_response(request):
        return render_error_response(
            request,
            DependencyFailureError(retry_after=60),
            status=503,
        )


class MaintenanceModeMiddleware(MiddlewareMixin):
    """Enforce an active maintenance window after Django resolves the route.

    ``process_view`` is intentional: ``resolver_match`` is not reliable in
    request middleware, and maintenance policy is a versioned route matrix,
    never a best-effort string check of an incoming path.
    """

    def process_view(self, request, view_func, view_args, view_kwargs):
        decision = evaluate_maintenance_request(request)
        if decision["action"] == "PASS":
            return None
        if decision["action"] == "BYPASS":
            if audit_maintenance_bypass(request, decision):
                return None
            decision = {
                **decision,
                "action": "BLOCK",
                "reason_code": "MAINTENANCE_BYPASS_AUDIT_UNAVAILABLE",
                "response_format": "json",
            }
        return self._maintenance_response(request, decision)

    @staticmethod
    def _maintenance_response(request, decision):
        retry_after = int(decision.get("retry_after_seconds") or 60)
        return render_error_response(
            request,
            DependencyFailureError(retry_after=retry_after),
            status=503,
        )


class ApplicationErrorCaptureMiddleware(MiddlewareMixin):
    """Capture unhandled exceptions as redacted operational events."""

    def process_exception(self, request, exception):
        # Django owns the normal 403/404 boundary; only unexpected failures
        # need an operational Error ID and redacted capture event.
        if isinstance(exception, (Http404, PermissionDenied)):
            return None
        event = capture_application_error_event(
            category=ErrorCategoryChoices.UNKNOWN,
            severity=ErrorSeverityChoices.ERROR,
            exception=exception,
            request=request,
            actor_user=getattr(request, "user", None),
            status_code=500,
            safe_message="COMPASS could not complete this request.",
        )
        if event:
            request._compass_error_id = event.error_id
        return None
