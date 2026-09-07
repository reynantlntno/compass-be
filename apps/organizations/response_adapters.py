"""HTTP adapters for approved public organization assets."""

from __future__ import annotations

from django.http import FileResponse

from apps.common.api.headers import apply_noindex_header


def public_brand_asset_response(*, stream, asset_id, content_type, extension, ttl_seconds):
    """Stream an approved asset without exposing its storage identity."""

    response = FileResponse(stream, content_type=str(content_type))
    response["Content-Disposition"] = f'inline; filename="brand-asset-{asset_id}.{extension}"'
    response["X-Content-Type-Options"] = "nosniff"
    response["Cache-Control"] = (
        f"public, max-age={int(ttl_seconds)}, "
        f"s-maxage={int(ttl_seconds)}, must-revalidate"
    )
    response["Surrogate-Control"] = f"max-age={int(ttl_seconds)}"
    return apply_noindex_header(response)
