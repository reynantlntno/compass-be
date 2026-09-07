"""Safe cached read projections for institutional identity and registries.

The organization database remains authoritative.  This module caches only
bounded metadata; it never caches model instances, file bytes, or governance
decisions used to authorize a mutation.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from django.db.models import Q
from django.utils import timezone
from django.utils.dateparse import parse_date

from apps.common.cache.backend import cached_read
from apps.common.cache.invalidation import invalidate_after_commit


def _with_expiry(value: dict[str, Any], expires_at: date | None) -> dict[str, Any]:
    return {
        "value": value,
        "_expires_at": expires_at.isoformat() if expires_at else None,
    }


def _unwrap(value: Any) -> dict:
    if not isinstance(value, dict):
        return {}
    result = value.get("value")
    return dict(result) if isinstance(result, dict) else {}


def _expiry(value: Any):
    if not isinstance(value, dict):
        return None
    raw = value.get("_expires_at")
    return parse_date(str(raw)) if raw else None


def get_institution_identity_snapshot() -> dict:
    def load():
        from apps.organizations.selectors import (
            build_institution_profile_snapshot,
            get_current_institution_profile,
        )

        profile = get_current_institution_profile()
        return _with_expiry(
            build_institution_profile_snapshot(profile),
            getattr(profile, "effective_until", None),
        )

    return _unwrap(
        cached_read(
            "organization_identity",
            "institution",
            ("institution",),
            load,
            expires_at=_expiry,
        )
    )


def get_office_identity_snapshot(*, institution_id: object | None = None) -> dict:
    target = "current"
    institution_part = str(institution_id or "current")

    def load():
        from apps.organizations.models import InstitutionProfile
        from apps.organizations.selectors import (
            build_office_profile_snapshot,
            get_current_office_profile,
        )

        institution = None
        if institution_id:
            institution = InstitutionProfile.objects.filter(pk=institution_id).first()
        office = get_current_office_profile(institution=institution)
        snapshot = build_office_profile_snapshot(office)
        if office:
            # These are public-safe contact/display fields used by shells and
            # email identity.  No actor, student, or workflow data is included.
            snapshot.update(
                {
                    "office_hours": office.office_hours,
                    "contact_email": office.contact_email,
                    "contact_number": office.contact_number,
                }
            )
        return _with_expiry(snapshot, getattr(office, "effective_until", None))

    return _unwrap(
        cached_read(
            "organization_identity",
            target,
            ("office", institution_part),
            load,
            expires_at=_expiry,
        )
    )


def get_public_identity_snapshot() -> dict:
    def load():
        from apps.organizations.selectors import (
            _institution_dto,
            _select_authoritative_institution,
            _select_authoritative_office,
        )

        institution_model = _select_authoritative_institution()
        office_model = _select_authoritative_office(institution_model)
        snapshot = {
            "institution": _institution_dto(institution_model),
            "office": {
                "display_name": str(getattr(office_model, "office_name", "") or "").strip(),
                "location": str(getattr(office_model, "office_address", "") or "").strip(),
                "office_hours": str(getattr(office_model, "office_hours", "") or "").strip(),
                "email": str(getattr(office_model, "contact_email", "") or "").strip(),
                "phone": str(getattr(office_model, "contact_number", "") or "").strip(),
            } if office_model is not None else {},
        }
        expiry_values = [
            getattr(institution_model, "effective_until", None),
            getattr(office_model, "effective_until", None),
        ]
        expiry_values = [value for value in expiry_values if value]
        return _with_expiry(snapshot, min(expiry_values) if expiry_values else None)

    return _unwrap(
        cached_read(
            "organization_identity", "public", ("public",), load, expires_at=_expiry,
        )
    )


def get_public_branding_snapshot() -> dict:
    def load():
        from apps.organizations.selectors import get_public_brand_assets

        groups = get_public_brand_assets()
        allowed = {
            "id", "delivery_path", "delivery_mode", "alt_text", "asset_type", "placement", "display_order",
            "width", "height", "content_type", "effective_from", "effective_until",
        }
        safe_groups = {
            placement: [
                {key: item.get(key) for key in allowed if key in item}
                for item in values
                if isinstance(item, dict)
            ]
            for placement, values in groups.items()
            if isinstance(values, list)
        }
        effective_dates = [
            parse_date(str(item["effective_until"]))
            for values in groups.values()
            if isinstance(values, list)
            for item in values
            if isinstance(item, dict) and item.get("effective_until")
        ]
        return _with_expiry(safe_groups, min(effective_dates) if effective_dates else None)

    return _unwrap(
        cached_read(
            "organization_branding", "public", ("public",), load, expires_at=_expiry,
        )
    )


def get_public_academic_term_snapshot() -> dict:
    def load():
        from apps.organizations.academic_year import AcademicYearConfigurationError, get_current_academic_term
        from apps.organizations.projections import public_academic_term_projection

        try:
            term = get_current_academic_term()
        except AcademicYearConfigurationError:
            term = None
        value = public_academic_term_projection(term) if term else {}
        return _with_expiry(value, getattr(term, "end_date", None))

    return _unwrap(
        cached_read(
            "organization_identity", "academic-term", ("academic-term",), load, expires_at=_expiry,
        )
    )


def get_public_document_template_snapshot() -> dict:
    def load():
        from apps.documents.models import DocumentTemplate, DocumentTemplateVersion, TemplateStatusChoices
        from apps.organizations.projections import (
            public_document_template_projection,
            public_document_template_version_projection,
        )

        templates = DocumentTemplate.objects.filter(status=TemplateStatusChoices.ACTIVE).order_by("stable_key", "pk")
        versions = DocumentTemplateVersion.objects.filter(
            status=TemplateStatusChoices.ACTIVE,
            template__status=TemplateStatusChoices.ACTIVE,
            approved_at__isnull=False,
            approved_by__isnull=False,
        ).select_related("template").order_by("template__stable_key", "-approved_at", "-pk")
        return {
            "templates": [public_document_template_projection(item) for item in templates],
            "versions": [public_document_template_version_projection(item) for item in versions],
        }

    return cached_read("document_metadata", "public-templates", ("public-templates",), load)


def get_public_form_revision_snapshot(stable_key: str) -> dict:
    def load():
        from apps.organizations.projections import form_revision_projection
        from apps.organizations.selectors import get_active_form_revision

        revision = get_active_form_revision(stable_key)
        today = timezone.localdate()
        if (
            not revision
            or not revision.approved_at
            or not revision.approved_by_id
            or (revision.effective_from and revision.effective_from > today)
            or (revision.effective_until and revision.effective_until < today)
        ):
            return _with_expiry({}, None)
        return _with_expiry(
            form_revision_projection(revision, public=True),
            revision.effective_until,
        )

    return _unwrap(
        cached_read(
            "form_metadata",
            stable_key,
            ("public", stable_key),
            load,
            expires_at=_expiry,
        )
    )


def get_brand_asset_metadata(*, asset_type: str, usage_context: str, institution_id: object | None = None) -> dict:
    target = f"{institution_id or 'global'}|{asset_type}|{usage_context}"

    def load():
        from apps.organizations.models import InstitutionProfile
        from apps.organizations.selectors import get_brand_asset_for_usage

        institution = None
        if institution_id:
            institution = InstitutionProfile.objects.filter(pk=institution_id).first()
        asset = get_brand_asset_for_usage(
            asset_type=asset_type,
            usage_context=usage_context,
            institution=institution,
        )
        if not asset:
            return {"value": {}, "_expires_at": None}
        return _with_expiry(
            {
                "id": str(asset.pk),
                "asset_type": asset.asset_type,
                "usage_context": asset.usage_context,
                "semantic_role": asset.semantic_role,
                "placement": asset.placement,
                "alt_text": asset.alt_text,
                "version_label": asset.version_label,
                "status": asset.status,
                "background_variant": asset.background_variant,
                "content_type_hint": asset.content_type_hint,
                "image_width": asset.image_width,
                "image_height": asset.image_height,
                "file_size_bytes": asset.file_size_bytes,
                "approved_at": asset.approved_at.isoformat() if asset.approved_at else None,
                "effective_until": asset.effective_until.isoformat() if asset.effective_until else None,
            },
            getattr(asset, "effective_until", None),
        )

    return _unwrap(
        cached_read(
            "organization_branding",
            target,
            (asset_type, usage_context),
            load,
            expires_at=_expiry,
        )
    )


def get_cached_form_revision_metadata(stable_key: str) -> dict:
    def load():
        from apps.organizations.selectors import build_form_revision_snapshot, get_active_form_revision

        return build_form_revision_snapshot(get_active_form_revision(stable_key))

    return cached_read("form_metadata", stable_key, (stable_key,), load)


def get_cached_public_links() -> dict:
    def load():
        from apps.organizations.selectors import _build_public_links

        groups = _build_public_links()
        safe_groups = {
            key: [
                {field: item.get(field) for field in ("label", "url", "owner_type", "owner_label", "link_type", "placement", "display_order")}
                for item in values
                if isinstance(item, dict)
            ]
            for key, values in groups.items()
            if isinstance(values, list)
        }
        effective_dates = [
            parse_date(str(item["effective_until"]))
            for values in groups.values()
            if isinstance(values, list)
            for item in values
            if isinstance(item, dict) and item.get("effective_until")
        ]
        return _with_expiry(safe_groups, min(effective_dates) if effective_dates else None)

    return _unwrap(
        cached_read(
            "organization_identity", "public-links", ("public-links",), load, expires_at=_expiry,
        )
    )


def invalidate_organization_identity_after_commit() -> None:
    invalidate_after_commit("organization_identity", "institution")
    invalidate_after_commit("organization_identity", "current")
    invalidate_after_commit("organization_identity", "public")
    invalidate_after_commit("organization_identity", "public-links")
    invalidate_after_commit("organization_identity", "academic-term")
    from apps.documents.cache import invalidate_document_metadata_after_commit
    invalidate_document_metadata_after_commit("branding")


def invalidate_organization_branding_after_commit(target: object = "global") -> None:
    invalidate_after_commit("organization_branding", target)
    invalidate_after_commit("organization_branding", "public")
    if target != "global":
        # Asset ownership/usage can be changed, leaving an unknown previous
        # target key behind.  Rotate the namespace generation as a safety net.
        invalidate_after_commit("organization_branding", "global")
    from apps.documents.cache import invalidate_document_metadata_after_commit
    invalidate_document_metadata_after_commit("branding")


def invalidate_form_metadata_after_commit(target: object = "global") -> None:
    invalidate_after_commit("form_metadata", target)
    invalidate_after_commit("form_metadata", "global")
