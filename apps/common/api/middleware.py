"""HTTP request correlation and bounded API input enforcement."""

from __future__ import annotations

from django.http import JsonResponse
from django.middleware.csrf import CsrfViewMiddleware

from apps.account_security.session_cookies import session_transport_requested
from apps.common.api.constants import API_MAX_JSON_BODY_BYTES
from apps.common.api.correlation import attach_request_correlation, request_id, trace_id
from apps.common.api.errors import render_error_response
from apps.common.api.headers import apply_noindex_header
from apps.common.exceptions import PayloadTooLargeError, PermissionDeniedError


class ApiBoundaryMiddleware:
    """Set correlation headers and reject oversized JSON API requests."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        attach_request_correlation(request)
        if self._json_body_is_too_large(request):
            response = render_error_response(
                request,
                PayloadTooLargeError(),
                status=413,
            )
        elif self._session_csrf_is_invalid(request):
            # Django Ninja marks API callbacks csrf-exempt. Re-run Django's
            # canonical validator only for the explicit cookie transport and
            # translate its reason-bearing response into COMPASS's safe error
            # envelope. Bearer requests retain their existing behavior.
            response = render_error_response(
                request,
                PermissionDeniedError(),
                status=403,
            )
        else:
            response = self.get_response(request)
        self._add_headers(request, response)
        return response

    @staticmethod
    def _json_body_is_too_large(request) -> bool:
        if not str(getattr(request, "path", "") or "").startswith("/api/"):
            return False
        content_type = str((getattr(request, "META", {}) or {}).get("CONTENT_TYPE", "") or "")
        if "application/json" not in content_type.lower():
            return False
        try:
            content_length = int((getattr(request, "META", {}) or {}).get("CONTENT_LENGTH", "0") or 0)
        except (TypeError, ValueError):
            return False
        return content_length > API_MAX_JSON_BODY_BYTES

    @staticmethod
    def _session_csrf_is_invalid(request) -> bool:
        if not str(getattr(request, "path", "") or "").startswith("/api/"):
            return False
        if str(getattr(request, "method", "GET") or "GET").upper() in {
            "GET",
            "HEAD",
            "OPTIONS",
            "TRACE",
        }:
            return False
        if not session_transport_requested(request):
            return False

        def csrf_checked_callback(_request):
            return None

        validator = CsrfViewMiddleware(lambda _request: None)
        return validator.process_view(
            request,
            csrf_checked_callback,
            (),
            {},
        ) is not None

    @staticmethod
    def _add_headers(request, response):
        response["X-Request-ID"] = request_id(request)
        if trace_id(request):
            response["X-Trace-ID"] = trace_id(request)
        apply_noindex_header(response)
        path = str(getattr(request, "path", "") or "")
        signed_brand_asset_content = (
            path.startswith("/api/v1/organizations/public/branding/assets/")
            and path.endswith("/content/")
            and getattr(request, "method", "GET") == "GET"
            and bool(getattr(request, "GET", {}).get("token"))
            and getattr(response, "status_code", 500) == 200
        )
        if signed_brand_asset_content:
            # The content URL is short-lived and HMAC-bound to the asset ID;
            # the CDN may cache the image for the token lifetime.
            return
        if path.startswith((
            "/api/v1/auth/",
            "/api/v1/me/",
            "/api/v1/files/",
            "/api/v1/authority/",
            "/api/v1/policies/",
            "/api/v1/staff-accounts/",
            "/api/v1/profiles/",
            "/api/v1/inventory/",
            "/api/v1/support-needs/",
            "/api/v1/appointments/",
            "/api/v1/counseling/",
            "/api/v1/referrals/",
            "/api/v1/call-slips/",
            "/api/v1/good-moral/",
            "/api/v1/form-collections/",
            "/api/v1/exit-interviews/",
            "/api/v1/graduate-tracer/",
            "/api/v1/reports/",
            "/api/v1/notifications/",
            "/api/v1/imports/",
            "/api/v1/backups/",
            "/api/v1/system/",
            "/api/v1/organizations/",
            "/api/v1/assessments/",
            "/api/v1/audit/",
        )):
            if "no-store" not in str(response.get("Cache-Control", "")).lower():
                response["Cache-Control"] = "no-store"
        elif path.startswith("/api/v1/content/") and (
            getattr(request, "method", "GET") != "GET"
            or path.startswith("/api/v1/content/feed/")
            or path.startswith("/api/v1/content/workspace/")
            or path.startswith("/api/v1/content/contact-")
        ):
            # Authenticated feeds, staff workspaces, and contact operations
            # must never be shared or replayed by an intermediary. Public
            # institution-wide reads remain cacheable through their safe DTOs.
            if "no-store" not in str(response.get("Cache-Control", "")).lower():
                response["Cache-Control"] = "no-store"
        return response
