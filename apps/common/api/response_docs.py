"""Small OpenAPI fragments for responses that are not JSON objects."""

from __future__ import annotations

from typing import Any


def binary_response_openapi(
    *media_types: str,
    description: str = "Binary response",
) -> dict[str, Any]:
    """Describe a successful binary response without owning route contracts.

    This helper deliberately knows nothing about operation IDs, domains, or
    DTOs. Callers provide the media types that their response adapter can
    actually emit. The runtime response remains a Django ``HttpResponse``.
    """

    unique_media_types = tuple(dict.fromkeys(media_types))
    if not unique_media_types:
        raise ValueError("At least one binary response media type is required.")

    return {
        "responses": {
            "200": {
                "description": description,
                "content": {
                    media_type: {
                        "schema": {"type": "string", "format": "binary"},
                    }
                    for media_type in unique_media_types
                },
            }
        }
    }
