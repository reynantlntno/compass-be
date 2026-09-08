"""Shared OpenAPI contract extensions for the COMPASS API."""

from __future__ import annotations

from typing import Any

from ninja import NinjaAPI
from ninja.schema import NinjaGenerateJsonSchema

from apps.common.api.schemas import ApiErrorSchema


COMMON_ERROR_STATUS_CODES = (400, 401, 403, 404, 405, 409, 413, 422, 429, 500, 503)
API_ERROR_SCHEMA_REF = "#/components/schemas/ApiErrorSchema"

_ERROR_DESCRIPTIONS = {
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    409: "Conflict",
    413: "Payload Too Large",
    422: "Unprocessable Entity",
    429: "Too Many Requests",
    500: "Internal Server Error",
    503: "Service Unavailable",
}


def _error_response(status_code: int) -> dict[str, Any]:
    return {
        "description": _ERROR_DESCRIPTIONS[status_code],
        "content": {
            "application/json": {
                "schema": {"$ref": API_ERROR_SCHEMA_REF},
            },
        },
    }


def _set_error_response(responses: dict[Any, Any], status_code: int) -> None:
    """Replace only the same status while avoiding int/string duplicates."""

    if status_code in responses:
        response_key = status_code
    elif str(status_code) in responses:
        response_key = str(status_code)
    else:
        response_key = status_code

    alternate_key = str(status_code) if response_key == status_code else status_code
    if alternate_key in responses:
        del responses[alternate_key]
    responses[response_key] = _error_response(status_code)


def add_common_error_responses(document: dict[str, Any]) -> dict[str, Any]:
    """Add the stable COMPASS error envelope to every documented operation."""

    components = document.setdefault("components", {})
    schemas = components.setdefault("schemas", {})
    schemas.setdefault(
        "ApiErrorSchema",
        ApiErrorSchema.model_json_schema(
            ref_template="#/components/schemas/{model}",
            schema_generator=NinjaGenerateJsonSchema,
            mode="validation",
        ),
    )

    for path_item in document.get("paths", {}).values():
        for operation in path_item.values():
            if not isinstance(operation, dict) or not operation.get("operationId"):
                continue
            responses = operation.setdefault("responses", {})
            for status_code in COMMON_ERROR_STATUS_CODES:
                _set_error_response(responses, status_code)

    return document


class CompassNinjaAPI(NinjaAPI):
    """Ninja API with the repository-wide OpenAPI error contract applied."""

    def get_openapi_schema(
        self,
        *,
        path_prefix: str | None = None,
        path_params: dict[str, Any] | None = None,
    ):
        document = super().get_openapi_schema(
            path_prefix=path_prefix,
            path_params=path_params,
        )
        return add_common_error_responses(document)
