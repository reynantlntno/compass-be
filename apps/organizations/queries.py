"""Scoped query and projection boundary for institutional configuration."""

from __future__ import annotations

from django.db.models import Q
from django.utils import timezone

from apps.common.exceptions import PermissionDeniedError
from apps.common.contracts import PageRequest, page_queryset
from apps.documents.models import DocumentTemplate, DocumentTemplateVersion, TemplateStatusChoices
from apps.organizations.models import (
    AcademicTerm,
    AcademicTermStatusChoices,
    AssetStatusChoices,
    BrandAsset,
    FormFamily,
    FormRevision,
    FormRevisionStatusChoices,
    GovernanceStatusChoices,
    InstitutionProfile,
    OfficeProfile,
    PublicLink,
)
from apps.organizations.policies import can_view_document_governance
from apps.organizations.projections import (
    academic_term_projection,
    brand_asset_projection,
    document_template_projection,
    document_template_version_projection,
    form_family_projection,
    form_revision_projection,
    institution_profile_projection,
    office_profile_projection,
    public_link_projection,
)
from apps.organizations.selectors import (
    get_current_institution_profile,
    get_current_office_profile,
    get_public_brand_assets,
    get_public_links,
    get_active_form_revision,
)
from apps.organizations.cache import (
    get_public_academic_term_snapshot,
    get_public_branding_snapshot,
    get_public_document_template_snapshot,
    get_public_form_revision_snapshot,
    get_public_identity_snapshot,
)


def _require_governance(actor):
    if not can_view_document_governance(actor):
        raise PermissionDeniedError()


def _effective(qs, *, status_field="status"):
    today = timezone.localdate()
    return qs.filter(**{status_field: GovernanceStatusChoices.ACTIVE}).filter(
        Q(effective_from__isnull=True) | Q(effective_from__lte=today),
        Q(effective_until__isnull=True) | Q(effective_until__gte=today),
    )


def public_identity() -> dict:
    value = get_public_identity_snapshot()
    value["public_links"] = get_public_links()
    return value


def public_branding() -> dict:
    # Existing selector applies the complete approval, ownership, expiry,
    # integrity, and public-slot checks. The endpoint exposes metadata only.
    groups = get_public_branding_snapshot()
    asset_groups = (
        "header_identity",
        "footer_identity",
        "footer_identity_row",
        "footer_certifications",
        "footer_recognitions",
        "footer_privacy_credentials",
        "publication_marks",
    )
    result = {}
    for key in asset_groups:
        values = groups.get(key, [])
        result[key] = [
            {
                field: item.get(field)
                for field in (
                    "id", "delivery_path", "delivery_mode", "alt_text", "asset_type", "placement", "display_order",
                    "width", "height", "content_type", "effective_from", "effective_until",
                )
                if field in item
            }
            for item in values
        ]
    return result


def public_links() -> dict:
    return get_public_links()


def public_academic_term() -> dict:
    return get_public_academic_term_snapshot()


def public_form_revision(stable_key: str) -> dict:
    return get_public_form_revision_snapshot(stable_key)


def public_document_templates() -> dict:
    return get_public_document_template_snapshot()


def institution_profile_page(actor, request: PageRequest):
    _require_governance(actor)
    return page_queryset(InstitutionProfile.objects.order_by("-created_at", "-pk"), request, institution_profile_projection)


def institution_profile_detail(actor, object_id):
    _require_governance(actor)
    return _projection_or_none(InstitutionProfile.objects.filter(pk=object_id).first(), institution_profile_projection)


def office_profile_page(actor, request: PageRequest):
    _require_governance(actor)
    qs = OfficeProfile.objects.select_related("institution").order_by("-created_at", "-pk")
    return page_queryset(qs, request, office_profile_projection)


def office_profile_detail(actor, object_id):
    _require_governance(actor)
    return _projection_or_none(OfficeProfile.objects.select_related("institution").filter(pk=object_id).first(), office_profile_projection)


def brand_asset_page(actor, request: PageRequest):
    _require_governance(actor)
    qs = BrandAsset.objects.select_related("institution", "office").order_by("-created_at", "-pk")
    return page_queryset(qs, request, brand_asset_projection)


def brand_asset_detail(actor, object_id):
    _require_governance(actor)
    return _projection_or_none(BrandAsset.objects.select_related("institution", "office").filter(pk=object_id).first(), brand_asset_projection)


def public_link_page(actor, request: PageRequest):
    _require_governance(actor)
    qs = PublicLink.objects.select_related("institution", "office").order_by("display_order", "-created_at", "-pk")
    return page_queryset(qs, request, public_link_projection)


def public_link_detail(actor, object_id):
    _require_governance(actor)
    return _projection_or_none(PublicLink.objects.select_related("institution", "office").filter(pk=object_id).first(), public_link_projection)


def academic_term_page(actor, request: PageRequest):
    _require_governance(actor)
    return page_queryset(AcademicTerm.objects.order_by("-start_date", "-pk"), request, academic_term_projection)


def academic_term_detail(actor, object_id):
    _require_governance(actor)
    return _projection_or_none(AcademicTerm.objects.filter(pk=object_id).first(), academic_term_projection)


def form_family_page(actor, request: PageRequest):
    _require_governance(actor)
    return page_queryset(FormFamily.objects.select_related("owner_office", "current_active_revision").order_by("stable_key", "pk"), request, form_family_projection)


def form_family_detail(actor, object_id):
    _require_governance(actor)
    return _projection_or_none(FormFamily.objects.select_related("owner_office", "current_active_revision").filter(pk=object_id).first(), form_family_projection)


def form_revision_page(actor, request: PageRequest):
    _require_governance(actor)
    qs = FormRevision.objects.select_related("form_family").order_by("form_family__stable_key", "-created_at", "-pk")
    return page_queryset(qs, request, form_revision_projection)


def form_revision_detail(actor, object_id):
    _require_governance(actor)
    return _projection_or_none(FormRevision.objects.select_related("form_family").filter(pk=object_id).first(), form_revision_projection)


def document_template_page(actor, request: PageRequest):
    _require_governance(actor)
    qs = DocumentTemplate.objects.filter(status=TemplateStatusChoices.ACTIVE).order_by("stable_key", "pk")
    return page_queryset(qs, request, document_template_projection)


def document_template_detail(actor, object_id):
    _require_governance(actor)
    return _projection_or_none(DocumentTemplate.objects.filter(pk=object_id, status=TemplateStatusChoices.ACTIVE).first(), document_template_projection)


def _projection_or_none(value, projector):
    return projector(value) if value is not None else None
