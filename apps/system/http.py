"""Small HTTP boundaries retained while Django moves to the API layer."""

from django.http import HttpResponse, JsonResponse

from apps.common.api.errors import render_error_response
from apps.common.api.headers import apply_noindex_header
from apps.common.exceptions import (
    BadRequestError,
    InternalError,
    MethodNotAllowedError,
    NotFoundError,
    PermissionDeniedError,
)


ROBOTS_TXT_BODY = "\n".join(
    (
        "User-agent: *",
        "Disallow: /",
        "Disallow: /api/",
        "Disallow: /admin/",
        "Disallow: /docs/",
        "Disallow: /openapi.json",
        "",
    )
)


def health_liveness(request):
    """Return the infrastructure liveness response without a template."""
    if request.method not in {"GET", "HEAD"}:
        response = render_error_response(request, MethodNotAllowedError(), status=405)
        response["Allow"] = "GET, HEAD"
        return response
    response = JsonResponse({"status": "ok", "system": "COMPASS"})
    response["X-Request-ID"] = getattr(request, "_compass_request_id", "")
    trace_id = getattr(request, "_compass_trace_id", None)
    if trace_id:
        response["X-Trace-ID"] = trace_id
    return apply_noindex_header(response)


def robots_txt(request):
    """Return the service-wide crawler directive without revealing runtime data."""

    if request.method not in {"GET", "HEAD"}:
        response = render_error_response(request, MethodNotAllowedError(), status=405)
        response["Allow"] = "GET, HEAD"
        return response
    response = HttpResponse(ROBOTS_TXT_BODY, content_type="text/plain; charset=utf-8")
    response["Cache-Control"] = "public, max-age=3600"
    response["X-Request-ID"] = getattr(request, "_compass_request_id", "")
    trace_id = getattr(request, "_compass_trace_id", None)
    if trace_id:
        response["X-Trace-ID"] = trace_id
    return apply_noindex_header(response)


def api_bad_request(request, exception):
    return render_error_response(request, BadRequestError(), status=400)


def api_forbidden(request, exception):
    return render_error_response(request, PermissionDeniedError(), status=403)


def api_not_found(request, exception):
    return render_error_response(request, NotFoundError(), status=404)


def api_internal_server_error(request):
    return render_error_response(
        request,
        InternalError(),
        status=500,
        error_id=getattr(request, "_compass_error_id", None),
    )
