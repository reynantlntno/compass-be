# Project: COMPASS
# File: apps/documents/template_context.py
# Module: apps.documents
# Purpose: Safe context builders and validators for document rendering
# Domain boundary and service policy.
# Notes:
#   Context builders produce allowlisted, audit-safe dictionaries.
#   raw HTML, protected object keys, signed URLs, secrets, or unnecessary
#   student data) should appear in context snapshots.

from django.utils import timezone

from apps.organizations.selectors import (
    build_form_revision_snapshot,
    build_institution_profile_snapshot,
    build_office_profile_snapshot,
    get_current_institution_profile,
    get_current_office_profile,
)

FORBIDDEN_RENDER_CONTEXT_KEYS = frozenset({
    "student_number",
    "control_number",
    "counseling_notes",
    "referral_reason",
    "case_details",
    "signed_url",
    "x-amz-signature",
    "object_key",
    "storage_key",
    "secret",
    "secrets",
    "token",
    "tokens",
    "password",
    "raw_request",
    "request_payload",
})


# ---------------------------------------------------------------------------
# Snapshot builders for document generation
# ---------------------------------------------------------------------------

def build_brand_asset_snapshot(asset) -> dict:
    """Build allowlisted brand asset metadata snapshot.

    Does not include raw file content or file paths.
    """
    if not asset:
        return {}
    return {
        "id": asset.pk,
        "asset_type": asset.asset_type,
        "usage_context": asset.usage_context,
        "version_label": asset.version_label,
        "status": asset.status,
        "content_type_hint": asset.content_type_hint,
    }


def build_template_version_snapshot(version) -> dict:
    """Build allowlisted template version metadata snapshot."""
    if not version:
        return {}
    return {
        "id": version.pk,
        "template_stable_key": version.template.stable_key,
        "version_label": version.version_label,
        "internal_template_version": version.internal_template_version,
        "template_path": version.template_path,
        "template_checksum": version.template_checksum,
        "renderer_backend": version.renderer_backend,
        "output_format": version.output_format,
        "page_size": version.page_size,
        "page_orientation": version.page_orientation,
        "status": version.status,
    }


def build_renderer_snapshot(renderer) -> dict:
    """Build renderer backend/version metadata snapshot."""
    if not renderer:
        return {}
    return renderer.get_backend_info()


def build_generation_context_snapshot(
    *,
    template_version,
    renderer,
    institution_profile=None,
    office_profile=None,
    brand_asset=None,
    form_revision=None,
    owner_tuple=None,
    document_control=None,
) -> dict:
    """Build a complete, audit-safe generation context snapshot.

    This does NOT include sensitive content, student data, counseling notes,
    or secrets.
    """
    raw_document_control = dict(document_control or {})
    # Render-only branding is attached to ``print_brand`` outside this
    # snapshot. Keep the durable control record metadata-only even if an old
    # caller still supplies compatibility logo keys.
    document_control_snapshot = {
        key: value
        for key, value in raw_document_control.items()
        if key not in {"logo_data_uri", "logo_alt"}
    }
    if raw_document_control:
        brand_metadata = raw_document_control.get("brand_asset_metadata")
        primary = brand_metadata.get("primary") if isinstance(brand_metadata, dict) else None
        document_control_snapshot["primary_brand_asset_present"] = bool(
            isinstance(primary, dict) and primary.get("id")
        )
    return {
        "template_version": build_template_version_snapshot(template_version),
        "renderer": build_renderer_snapshot(renderer),
        "institution_profile": build_institution_profile_snapshot(institution_profile),
        "office_profile": build_office_profile_snapshot(office_profile),
        "brand_asset": build_brand_asset_snapshot(brand_asset),
        "form_revision": build_form_revision_snapshot(form_revision),
        "document_control": document_control_snapshot,
        "owner_tuple": owner_tuple or {},
        "generated_at": timezone.now().isoformat(),
    }


def build_current_identity_context() -> dict:
    """Build current institution/office identity for template rendering context.

    Returns allowlisted profile fields suitable for template rendering.
    Fails closed (returns empty dicts) when profiles are missing or ambiguous.
    """
    from apps.organizations.cache import (
        get_institution_identity_snapshot,
        get_office_identity_snapshot,
    )

    institution = get_institution_identity_snapshot()
    office = get_office_identity_snapshot(institution_id=institution.get("id"))
    return {
        "institution": institution,
        "office": office,
    }


def validate_render_context(context: dict, required_fields: list) -> list:
    """Validate that required fields are present in the render context.

    Returns a list of missing field names (empty if all present).
    """
    missing = []
    for field in required_fields:
        parts = field.split(".")
        value = context
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                value = None
                break
        if value is None or value == "":
            missing.append(field)
    return missing


def required_fields_from_schema(schema: dict) -> list:
    """Extract required dotted context fields from a metadata-only schema."""
    if not isinstance(schema, dict):
        return []
    required = schema.get("required_fields", schema.get("required", []))
    if not isinstance(required, list):
        return []
    return [str(field).strip() for field in required if str(field).strip()]


def allowed_fields_from_schema(schema: dict) -> list:
    """Extract allowed dotted context fields from a metadata-only schema."""
    if not isinstance(schema, dict):
        return []
    allowed = schema.get("allowed_fields", schema.get("allowed", []))
    if not isinstance(allowed, list):
        return []
    return [str(field).strip() for field in allowed if str(field).strip()]


def find_forbidden_render_context_keys(context) -> list:
    """Return forbidden key paths found anywhere in a render context."""
    found = []

    def visit(value, path=""):
        if isinstance(value, dict):
            for key, child in value.items():
                key_text = str(key)
                key_lower = key_text.lower()
                key_path = f"{path}.{key_text}" if path else key_text
                if key_lower in FORBIDDEN_RENDER_CONTEXT_KEYS:
                    found.append(key_path)
                visit(child, key_path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}[{index}]")

    visit(context or {})
    return found


def find_disallowed_render_context_keys(context: dict, allowed_fields: list) -> list:
    """Return top-level caller context keys outside an explicit allowlist."""
    if not allowed_fields:
        return []
    allowed_roots = {field.split(".", 1)[0] for field in allowed_fields}
    return [
        str(key)
        for key in (context or {}).keys()
        if str(key) not in allowed_roots
    ]
