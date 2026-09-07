"""Fixed JSON projections for institutional configuration."""

from __future__ import annotations

from datetime import date, datetime

from apps.common.contracts import to_json_value


def _iso(value):
    return value.isoformat() if isinstance(value, (date, datetime)) else value


def _safe_text(value, maximum: int = 255) -> str:
    return str(value or "").strip()[:maximum]


def _safe_schema(value) -> list[dict]:
    """Project only client-renderable form-field metadata."""
    if not isinstance(value, dict):
        return []
    raw_fields = value.get("fields", value.get("items", []))
    if not isinstance(raw_fields, list):
        return []
    fields = []
    allowed = {"key", "name", "type", "label", "required", "options", "max_length"}
    for raw in raw_fields[:100]:
        if not isinstance(raw, dict):
            continue
        item = {}
        for key in allowed:
            if key not in raw:
                continue
            current = raw[key]
            if key == "options" and isinstance(current, list):
                item[key] = [
                    {"value": _safe_text(option.get("value"), 80), "label": _safe_text(option.get("label"), 120)}
                    for option in current[:50]
                    if isinstance(option, dict)
                ]
            elif key == "required":
                item[key] = bool(current)
            elif key == "max_length":
                if isinstance(current, int) and 0 <= current <= 10000:
                    item[key] = current
            elif isinstance(current, (str, int, float, bool)):
                item[key] = _safe_text(current, 160) if isinstance(current, str) else current
        if item.get("key") or item.get("name"):
            fields.append(item)
    return fields


def institution_profile_projection(profile, *, public: bool = False) -> dict:
    if not profile:
        return {}
    result = {
        "id": str(profile.pk),
        "legal_name": _safe_text(profile.legal_name),
        "short_name": _safe_text(profile.short_name, 50),
        "address": _safe_text(profile.address, 2000),
        "main_campus": _safe_text(profile.main_campus),
        "primary_brand_color": _safe_text(profile.primary_brand_color, 30),
        "secondary_brand_color": _safe_text(profile.secondary_brand_color, 30),
        "accent_brand_color": _safe_text(profile.accent_brand_color, 30),
        "version_label": _safe_text(profile.version_label, 50),
        "status": _safe_text(profile.status, 30),
        "effective_from": _iso(profile.effective_from),
        "effective_until": _iso(profile.effective_until),
    }
    if not public:
        result.update({
            "former_name": _safe_text(profile.former_name),
            "former_short_name": _safe_text(profile.former_short_name, 50),
            "source_note": _safe_text(profile.source_note, 2000),
            "activated_at": _iso(profile.activated_at),
            "retired_at": _iso(profile.retired_at),
        })
    return result


def office_profile_projection(profile, *, public: bool = False) -> dict:
    if not profile:
        return {}
    result = {
        "id": str(profile.pk),
        "institution_id": str(profile.institution_id) if profile.institution_id else None,
        "office_name": _safe_text(profile.office_name),
        "office_short_name": _safe_text(profile.office_short_name, 50),
        "document_header_name": _safe_text(profile.document_header_name),
        "office_address": _safe_text(profile.office_address, 2000),
        "office_hours": _safe_text(profile.office_hours),
        "contact_email": _safe_text(profile.contact_email, 254),
        "contact_number": _safe_text(profile.contact_number, 50),
        "version_label": _safe_text(profile.version_label, 50),
        "status": _safe_text(profile.status, 30),
        "effective_from": _iso(profile.effective_from),
        "effective_until": _iso(profile.effective_until),
    }
    if not public:
        result.update({
            "legacy_office_name": _safe_text(profile.legacy_office_name),
            "default_signatory_name": _safe_text(profile.default_signatory_name),
            "default_signatory_title": _safe_text(profile.default_signatory_title),
            "footer_note": _safe_text(profile.footer_note, 2000),
            "source_note": _safe_text(profile.source_note, 2000),
            "activated_at": _iso(profile.activated_at),
            "retired_at": _iso(profile.retired_at),
        })
    return result


def brand_asset_projection(asset, *, public: bool = False) -> dict:
    if not asset:
        return {}
    result = {
        "id": str(asset.pk),
        "institution_id": str(asset.institution_id) if asset.institution_id else None,
        "office_id": str(asset.office_id) if asset.office_id else None,
        "asset_type": _safe_text(asset.asset_type, 30),
        "semantic_role": _safe_text(asset.semantic_role, 30),
        "owner_type": _safe_text(asset.owner_type, 20),
        "placement": _safe_text(asset.placement, 30),
        "display_order": int(getattr(asset, "display_order", 0) or 0),
        "alt_text": _safe_text(asset.alt_text),
        "usage_context": _safe_text(asset.usage_context),
        "background_variant": _safe_text(asset.background_variant, 20),
        "version_label": _safe_text(asset.version_label, 50),
        "status": _safe_text(asset.status, 30),
        "content_type": _safe_text(asset.content_type_hint, 100),
        "image_width": asset.image_width,
        "image_height": asset.image_height,
        "effective_from": _iso(asset.effective_from),
        "effective_until": _iso(asset.effective_until),
        "approved_at": _iso(asset.approved_at),
    }
    return result


def public_link_projection(link) -> dict:
    if not link:
        return {}
    return {
        "id": str(link.pk),
        "owner_type": _safe_text(link.owner_type, 20),
        "institution_id": str(link.institution_id) if link.institution_id else None,
        "office_id": str(link.office_id) if link.office_id else None,
        "link_type": _safe_text(link.link_type, 20),
        "label": _safe_text(link.label, 120),
        "url": _safe_text(link.url, 2048),
        "placement": _safe_text(link.placement, 20),
        "display_order": link.display_order,
        "status": _safe_text(link.status, 30),
        "effective_from": _iso(link.effective_from),
        "effective_until": _iso(link.effective_until),
    }


def academic_term_projection(term) -> dict:
    if not term:
        return {}
    return {
        "id": str(term.pk),
        "academic_year": _safe_text(term.academic_year, 20),
        "semester": _safe_text(term.semester, 100),
        "start_date": _iso(term.start_date),
        "end_date": _iso(term.end_date),
        "status": _safe_text(term.status, 30),
        "is_current": term.status == "ACTIVE",
        "configuration_identifier": _safe_text(term.configuration_identifier, 160),
        "approved_at": _iso(term.approved_at),
        "activated_at": _iso(term.activated_at),
        "closed_at": _iso(term.closed_at),
    }


def public_academic_term_projection(term) -> dict:
    if not term:
        return {}
    return {
        "id": str(term.pk),
        "academic_year": _safe_text(term.academic_year, 20),
        "semester": _safe_text(term.semester, 100),
        "start_date": _iso(term.start_date),
        "end_date": _iso(term.end_date),
        "status": _safe_text(term.status, 30),
        "is_current": term.status == "ACTIVE",
    }


def form_family_projection(family) -> dict:
    if not family:
        return {}
    return {
        "id": str(family.pk),
        "stable_key": _safe_text(family.stable_key, 80),
        "display_name": _safe_text(family.display_name),
        "description": _safe_text(family.description, 4000),
        "owner_office_id": str(family.owner_office_id) if family.owner_office_id else None,
        "status": _safe_text(family.status, 30),
        "current_active_revision_id": str(family.current_active_revision_id) if family.current_active_revision_id else None,
    }


def form_revision_projection(revision, *, public: bool = False) -> dict:
    if not revision:
        return {}
    result = {
        "id": str(revision.pk),
        "form_family_id": str(revision.form_family_id),
        "form_family_key": _safe_text(getattr(revision.form_family, "stable_key", ""), 80),
        "official_form_code": _safe_text(revision.official_form_code, 80),
        "official_revision": _safe_text(revision.official_revision, 50),
        "display_title": _safe_text(revision.display_title),
        "status": _safe_text(revision.status, 30),
        "effective_from": _iso(revision.effective_from),
        "effective_until": _iso(revision.effective_until),
        "is_used": bool(revision.is_used),
    }
    if public:
        result.pop("is_used", None)
        result["schema"] = _safe_schema(revision.schema_summary_json)
    else:
        result.update({
            "internal_schema_version": _safe_text(revision.internal_schema_version, 80),
            "internal_template_version": _safe_text(revision.internal_template_version, 30),
            "institution_profile_id": str(revision.institution_profile_id) if revision.institution_profile_id else None,
            "office_profile_id": str(revision.office_profile_id) if revision.office_profile_id else None,
            "source_label": _safe_text(revision.source_label),
            "approved_at": _iso(revision.approved_at),
            "submitted_at": _iso(revision.submitted_at),
            "activated_at": _iso(revision.activated_at),
            "retired_at": _iso(revision.retired_at),
            "activation_preflight": None,
        })
    return result


def document_template_projection(template) -> dict:
    if not template:
        return {}
    return {
        "id": str(template.pk),
        "stable_key": _safe_text(template.stable_key, 80),
        "display_name": _safe_text(template.display_name),
        "document_kind": _safe_text(template.document_kind, 30),
        "status": _safe_text(template.status, 30),
        "default_output_format": _safe_text(template.default_output_format, 10),
        "retention_classification": _safe_text(template.retention_classification, 30),
    }


def public_document_template_projection(template) -> dict:
    """Project only approved public template-family metadata."""

    if not template:
        return {}
    return {
        "id": str(template.pk),
        "stable_key": _safe_text(template.stable_key, 80),
        "display_name": _safe_text(template.display_name),
        "document_kind": _safe_text(template.document_kind, 30),
        "default_output_format": _safe_text(template.default_output_format, 10),
        "status": _safe_text(template.status, 30),
    }


def document_template_version_projection(version) -> dict:
    if not version:
        return {}
    return {
        "id": str(version.pk),
        "template_stable_key": _safe_text(getattr(version.template, "stable_key", ""), 80),
        "version_label": _safe_text(version.version_label, 50),
        "internal_template_version": _safe_text(version.internal_template_version, 30),
        "renderer_backend": _safe_text(version.renderer_backend, 30),
        "output_format": _safe_text(version.output_format, 10),
        "status": _safe_text(version.status, 30),
        "is_used": bool(version.is_used),
    }


def public_document_template_version_projection(version) -> dict:
    """Project only approved public template-version metadata.

    Renderer backends, internal version markers, and source/template paths are
    operational details and never belong in the anonymous configuration API.
    """

    if not version:
        return {}
    return {
        "id": str(version.pk),
        "template_stable_key": _safe_text(getattr(version.template, "stable_key", ""), 80),
        "version_label": _safe_text(version.version_label, 50),
        "output_format": _safe_text(version.output_format, 10),
        "status": _safe_text(version.status, 30),
    }
