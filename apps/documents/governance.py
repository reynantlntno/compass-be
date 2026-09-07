"""Document-family readiness and print-identity governance.

This module is deliberately metadata-only at its boundary.  It owns the
source-to-output registry and the decision that separates a safe preview from
an official document.  Callers cannot supply readiness, form metadata, or
branding through the render context.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from datetime import date
from enum import StrEnum
from pathlib import Path

from django.conf import settings
from django.utils import timezone

from apps.documents.models import DocumentTemplateVersion, TemplateStatusChoices
from apps.organizations.models import (
    AssetStatusChoices,
    AssetTypeChoices,
    BrandAssetOwnerChoices,
    BrandAssetRoleChoices,
    BrandAsset,
    GovernanceStatusChoices,
)
from apps.organizations.selectors import (
    get_current_institution_profile,
    get_current_office_profile,
    get_active_form_revision,
)
from apps.documents.shells import (
    DocumentShellDefinition,
    DocumentShellKey,
    SHELL_DEFINITIONS,
    resolve_document_shell,
)


class DocumentOutputIntent(StrEnum):
    PREVIEW = "PREVIEW"
    OFFICIAL = "OFFICIAL"


class DocumentReadiness(StrEnum):
    DRAFT = "DRAFT"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    OFFICIAL = "OFFICIAL"


@dataclass(frozen=True)
class DocumentFamilyDefinition:
    stable_key: str
    display_name: str
    source_path: str
    source_label: str
    source_kind: str = "official_source_form"
    official_form_code: str = ""
    official_revision: str = ""
    compass_native: bool = False
    historical_structural_reference: bool = False
    page_2_metadata_note: str = ""
    template_key: str = ""


# Paths are repository-relative and intentionally use the canonical source-form
# boundary. This is the sole source mapping used by governed output metadata.
DOCUMENT_FAMILY_REGISTRY: dict[str, DocumentFamilyDefinition] = {
    "good_moral_student": DocumentFamilyDefinition(
        "good_moral_student", "Good Moral — current student",
        "docs/source-forms/pdf/good-moral-student.pdf",
        "CNSC-OP-GCO-01F4.pdf", official_form_code="CNSC-OP-GCO-01F4",
        official_revision="0", template_key="good_moral_student",
    ),
    "student_inventory": DocumentFamilyDefinition(
        "student_inventory", "Individual Inventory",
        "docs/source-forms/pdf/individual-inventory.pdf",
        "CNSC-OP-GCO-01F5, Individual Inventory Rev.0.pdf",
        official_form_code="CNSC-OP-GCO-01F5", official_revision="0", template_key="student_inventory",
    ),
    "good_moral_graduate": DocumentFamilyDefinition(
        "good_moral_graduate", "Good Moral — graduate",
        "docs/source-forms/pdf/good-moral-graduate.pdf",
        "CNSC-OP-GCO-01F6.pdf", official_form_code="CNSC-OP-GCO-01F6",
        official_revision="0", template_key="good_moral_graduate",
    ),
    "call_slip": DocumentFamilyDefinition(
        "call_slip", "Interview Permit / Call Slip",
        "docs/source-forms/pdf/call-slip.pdf", "Call Slip.pdf",
        official_form_code="CNSC-OP-GTA-01F8", official_revision="0",
        template_key="call_slip",
    ),
    "customer_feedback_csm": DocumentFamilyDefinition(
        "customer_feedback_csm", "Customer Feedback / CSM",
        "docs/source-forms/pdf/customer-feedback.pdf", "Customer feedback.pdf",
        official_form_code="CNSC-OP-GTA-01F14", official_revision="0",
        page_2_metadata_note="The complete two-page source is one F14 Rev 0 family; page 2 has no independent code and remains pending.",
        template_key="customer_feedback_csm",
    ),
    "exit_interview": DocumentFamilyDefinition(
        "exit_interview", "Exit Interview",
        "docs/source-forms/pdf/exit-interview.pdf", "Exit Interview.pdf",
        official_form_code="CNSC-OP-GTA-01F12", official_revision="0", template_key="exit_interview",
    ),
    "students_profile": DocumentFamilyDefinition(
        "students_profile", "Students’ Profile",
        "docs/source-forms/pdf/students-profile-reference.pdf",
        "Profiling-CCMS-2025-2026 (3).pdf", source_kind="historical_structural_reference",
        official_form_code="COMPASS-RPT-STUDENTS-PROFILE", official_revision="1.0",
        compass_native=True, historical_structural_reference=True,
        template_key="students_profile",
    ),
    "referral_slip": DocumentFamilyDefinition(
        "referral_slip", "Referral Slip",
        "docs/source-forms/pdf/referral-slip.pdf", "Referral Slip.pdf",
        official_form_code="CNSC-OP-GTA-01F9", official_revision="1",
        template_key="referral_slip",
    ),
    "routine_interview": DocumentFamilyDefinition(
        "routine_interview", "Routine Interview",
        "docs/source-forms/pdf/routine-interview.pdf", "Routine Interview.pdf",
        official_form_code="CNSC-OP-GTA-01F11", official_revision="0", template_key="routine_interview",
    ),
    "graduate_tracer_survey": DocumentFamilyDefinition(
        "graduate_tracer_survey", "Graduate Tracer Survey",
        "docs/source-forms/specs/graduate-tracer.md", "Graduate Tracer specification",
        source_kind="official_source_specification",
        official_form_code="CNSC-OP-GTA-01F10", official_revision="0",
        template_key="graduate_tracer_survey",
    ),
    "public_service_guide": DocumentFamilyDefinition(
        "public_service_guide", "Public Service Guide",
        "docs/source-forms/specs/public-service-guide.md", "COMPASS content governance guide",
        source_kind="compass_native", compass_native=True,
        template_key="public_service_guide",
    ),
    # Assessment files are protected source attachments, not printable forms.
    "assessment_attachment": DocumentFamilyDefinition(
        "assessment_attachment", "Assessment source attachment", "",
        "Protected assessment attachment", source_kind="protected_source_attachment",
        compass_native=False, template_key="",
    ),
}


@dataclass(frozen=True)
class DocumentReadinessResult:
    state: DocumentReadiness
    intent: DocumentOutputIntent
    family: DocumentFamilyDefinition
    reasons: tuple[str, ...] = field(default_factory=tuple)
    template_version_label: str = ""
    form_code: str = ""
    form_revision: str = ""
    effective_from: str = ""
    source_path: str = ""
    brand_asset_version: str = ""
    shell_key: str = ""

    @property
    def is_official(self) -> bool:
        return self.state == DocumentReadiness.OFFICIAL

    @property
    def label(self) -> str:
        if self.family.stable_key == "public_service_guide" and self.state != DocumentReadiness.OFFICIAL:
            return "PREVIEW — PENDING APPROVAL"
        if self.state == DocumentReadiness.DRAFT:
            return "PREVIEW — DRAFT"
        if self.state == DocumentReadiness.PENDING_APPROVAL:
            return "PREVIEW — PENDING APPROVAL"
        return "OFFICIAL"

    def as_safe_json(self) -> dict:
        return {
            "intent": self.intent.value,
            "readiness": self.state.value,
            "label": self.label,
            "reasons": list(self.reasons),
            "template_version": self.template_version_label,
            "form_code": self.form_code,
            "form_revision": self.form_revision,
            "effective_from": self.effective_from,
            "source_path": self.source_path,
            "brand_asset_version": self.brand_asset_version,
            "shell_key": self.shell_key,
            "official": self.is_official,
        }


def get_document_family(stable_key: str) -> DocumentFamilyDefinition:
    try:
        return DOCUMENT_FAMILY_REGISTRY[stable_key]
    except KeyError as exc:
        raise ValueError(f"Unknown governed document family: {stable_key}") from exc


def validate_document_family_registry(*, base_dir=None) -> list[str]:
    """Return registry errors without mutating state.

    Archived audit paths are not allowed as authorities, and every mapped
    governed source must exist unless the family is explicitly an attachment.
    """
    root = Path(base_dir or settings.BASE_DIR)
    errors: list[str] = []
    for key, family in DOCUMENT_FAMILY_REGISTRY.items():
        if family.source_kind == "protected_source_attachment":
            continue
        if "docs/audits" in family.source_path or "archive" in family.source_path.lower():
            errors.append(f"{key}: archived authority path is not allowed")
        if not (root / family.source_path).is_file():
            errors.append(f"{key}: source file is missing ({family.source_path})")
    return errors


DOCUMENT_BRAND_SURFACES = {
    "DOCUMENT_PRINT_HEADER",
    "DOCUMENT_PRINT_HEADER_SECONDARY",
    "DOCUMENT_PRINT_FOOTER_IDENTITY",
    "DOCUMENT_PRINT_FOOTER_CAMPAIGN",
    "DOCUMENT_PRINT_FOOTER_CERTIFICATION",
    "DOCUMENT_PRINT_FOOTER_RECOGNITION",
    "DOCUMENT_PRINT_FOOTER_PRIVACY_CREDENTIAL",
}
DOCUMENT_BRAND_MIME_TYPES = frozenset({"image/png", "image/jpeg", "image/webp"})
DOCUMENT_BRAND_MAX_BYTES = 5 * 1024 * 1024


def _date_is_effective(asset: BrandAsset, today: date) -> bool:
    return bool(
        asset.effective_from
        and asset.effective_from <= today
        and (not asset.effective_until or asset.effective_until >= today)
    )


def _source_digest_matches(asset) -> bool:
    marker = "SHA-256:"
    source_note = str(getattr(asset, "source_note", "") or "")
    if marker not in source_note:
        return True
    digest_text = source_note.split(marker, 1)[1].strip().split()[0].lower()
    if len(digest_text) != 64 or any(char not in "0123456789abcdef" for char in digest_text):
        return False
    try:
        digest = hashlib.sha256()
        with asset.file.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except Exception:
        return False
    return digest.hexdigest() == digest_text


def _asset_is_renderable(asset, *, today: date) -> bool:
    if not asset or not asset.file:
        return False
    if not asset.approved_by_id or not asset.approved_at:
        return False
    if not _date_is_effective(asset, today):
        return False
    if asset.content_type_hint not in DOCUMENT_BRAND_MIME_TYPES:
        return False
    if not asset.file_size_bytes or asset.file_size_bytes > DOCUMENT_BRAND_MAX_BYTES:
        return False
    if not asset.image_width or not asset.image_height:
        return False
    if asset.image_width > 4096 or asset.image_height > 1200:
        return False
    if "demo" in str(asset.source_note or "").lower() or "unlinked" in str(asset.source_note or "").lower():
        return False
    try:
        actual_size = asset.file.size
        filename = str(asset.file.name or "").rsplit("/", 1)[-1].lower()
    except Exception:
        return False
    allowed_extensions = {
        "image/png": {".png"},
        "image/jpeg": {".jpg", ".jpeg"},
        "image/webp": {".webp"},
    }
    extension = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""
    if actual_size != asset.file_size_bytes or extension not in allowed_extensions[asset.content_type_hint]:
        return False
    return _source_digest_matches(asset)


def _document_asset_owner_matches(asset, *, institution=None, office=None) -> bool:
    if asset.owner_type == BrandAssetOwnerChoices.OFFICE:
        return bool(office and asset.office_id == office.pk and not asset.institution_id)
    if asset.owner_type == BrandAssetOwnerChoices.INSTITUTION:
        return bool(institution and asset.institution_id == institution.pk and not asset.office_id)
    return False


def select_document_brand_assets(*, institution=None, office=None) -> dict[str, list[BrandAsset] | BrandAsset | None]:
    """Select approved document-surface assets without storage URLs."""
    today = timezone.localdate()
    candidates = list(BrandAsset.objects.filter(
        status=AssetStatusChoices.ACTIVE,
    ).select_related("institution", "office").order_by("display_order", "pk"))
    eligible: list[BrandAsset] = []
    for asset in candidates:
        usage = str(asset.usage_context or "").strip().upper()
        if usage not in DOCUMENT_BRAND_SURFACES:
            continue
        if usage == "DOCUMENT_PRINT_HEADER" and asset.asset_type != AssetTypeChoices.DOCUMENT_HEADER_LOGO:
            continue
        if not _document_asset_owner_matches(asset, institution=institution, office=office):
            continue
        if _asset_is_renderable(asset, today=today):
            eligible.append(asset)

    def _scope_rank(asset):
        return 0 if office and asset.office_id == office.pk else 1

    primary = [asset for asset in eligible if str(asset.usage_context).upper() == "DOCUMENT_PRINT_HEADER"]
    primary.sort(key=lambda asset: (_scope_rank(asset), asset.display_order, asset.pk))
    selected_primary = None
    if primary:
        best_rank = _scope_rank(primary[0])
        best = [asset for asset in primary if _scope_rank(asset) == best_rank]
        selected_primary = best[0] if len(best) == 1 else None

    secondary = sorted(
        [asset for asset in eligible if str(asset.usage_context).upper() == "DOCUMENT_PRINT_HEADER_SECONDARY"],
        key=lambda asset: (asset.display_order, asset.pk),
    )
    footer = {
        "identity": [],
        "campaign": [],
        "certifications": [],
        "recognitions": [],
        "privacy_credentials": [],
    }
    footer_surface_map = {
        "DOCUMENT_PRINT_FOOTER_IDENTITY": "identity",
        "DOCUMENT_PRINT_FOOTER_CAMPAIGN": "campaign",
        "DOCUMENT_PRINT_FOOTER_CERTIFICATION": "certifications",
        "DOCUMENT_PRINT_FOOTER_RECOGNITION": "recognitions",
        "DOCUMENT_PRINT_FOOTER_PRIVACY_CREDENTIAL": "privacy_credentials",
    }
    for asset in eligible:
        group = footer_surface_map.get(str(asset.usage_context).upper())
        if group:
            footer[group].append(asset)
    privacy_assets = footer["privacy_credentials"]
    if len(privacy_assets) != 1:
        footer["privacy_credentials"] = []
    else:
        privacy_asset = privacy_assets[0]
        if not (
            privacy_asset.owner_type == BrandAssetOwnerChoices.INSTITUTION
            and privacy_asset.asset_type == AssetTypeChoices.SEAL
            and privacy_asset.semantic_role == BrandAssetRoleChoices.PRIVACY_CREDENTIAL
            and privacy_asset.institution_id == getattr(institution, "pk", None)
            and privacy_asset.office_id is None
        ):
            footer["privacy_credentials"] = []
    return {"primary": selected_primary, "secondary": secondary, "footer": footer}


def select_approved_print_header_asset(*, institution=None, office=None):
    """Select one approved/effective primary document header asset."""
    return select_document_brand_assets(institution=institution, office=office)["primary"]


def _asset_data_uri(asset) -> str:
    if not asset or not asset.file:
        return ""
    try:
        asset.file.open("rb")
        payload = asset.file.read()
        asset.file.close()
    except (OSError, ValueError):
        return ""
    if not payload or len(payload) > 5 * 1024 * 1024:
        return ""
    content_type = (asset.content_type_hint or "").strip().lower()
    if content_type not in DOCUMENT_BRAND_MIME_TYPES:
        return ""
    return f"data:{content_type};base64,{base64.b64encode(payload).decode('ascii')}"


def build_print_brand_context(*, asset=None) -> dict:
    """Return render-safe print branding; no storage paths or URLs."""
    if not asset:
        return {"logo_data_uri": "", "logo_alt": ""}
    return {
        "logo_data_uri": _asset_data_uri(asset),
        "logo_alt": (asset.alt_text or "Institutional identity")[:255],
    }


def _asset_render_context(asset) -> dict:
    if not asset:
        return {}
    return {
        "id": str(asset.pk),
        "data_uri": _asset_data_uri(asset),
        "alt_text": (asset.alt_text or "Institutional brand asset")[:255],
        "display_order": int(asset.display_order or 0),
    }


def _asset_metadata(asset, surface: str) -> dict:
    if not asset:
        return {}
    return {
        "id": str(asset.pk),
        "surface": surface,
        "status": asset.status,
        "version_label": asset.version_label,
        "content_type": asset.content_type_hint,
        "width": asset.image_width,
        "height": asset.image_height,
        "display_order": int(asset.display_order or 0),
        "effective_from": asset.effective_from.isoformat() if asset.effective_from else None,
        "effective_until": asset.effective_until.isoformat() if asset.effective_until else None,
    }


def build_document_branding_context(*, shell: DocumentShellDefinition, institution=None, office=None) -> tuple[dict, dict]:
    """Return render-only branding and a safe persisted metadata snapshot."""
    assets = select_document_brand_assets(institution=institution, office=office)
    primary = assets["primary"]
    secondary = assets["secondary"] if shell.show_secondary_header_mark else []
    footer_assets = assets["footer"] if shell.show_footer_marks else {}

    contact_rows = []
    if shell.show_contact_row and office:
        if office.contact_email:
            contact_rows.append({"label": "Email", "value": office.contact_email})
        if office.contact_number:
            contact_rows.append({"label": "Contact", "value": office.contact_number})

    render = {
        "shell_key": shell.key.value,
        "show_secondary_header_mark": shell.show_secondary_header_mark,
        "show_contact_row": shell.show_contact_row,
        "show_footer_marks": shell.show_footer_marks,
        "show_control_metadata": shell.show_control_metadata,
        "show_page_number": shell.show_page_number,
        "primary": _asset_render_context(primary),
        "secondary": [_asset_render_context(asset) for asset in secondary],
        "contact_rows": contact_rows,
        "footer": {
            group: [_asset_render_context(asset) for asset in values]
            for group, values in footer_assets.items()
        },
    }
    metadata = {
        "shell_key": shell.key.value,
        "primary": _asset_metadata(primary, "DOCUMENT_PRINT_HEADER"),
        "secondary": [_asset_metadata(asset, "DOCUMENT_PRINT_HEADER_SECONDARY") for asset in secondary],
        "footer": {
            group: [_asset_metadata(asset, f"DOCUMENT_PRINT_FOOTER_{group.upper()}") for asset in values]
            for group, values in footer_assets.items()
        },
    }
    return render, metadata


def get_preview_template_version(stable_key: str):
    """Resolve the newest safe active/draft version for an authorized preview."""
    family = get_document_family(stable_key)
    template = DocumentTemplateVersion.objects.filter(
        template__stable_key=family.template_key or stable_key,
        template__status__in=(TemplateStatusChoices.ACTIVE, TemplateStatusChoices.DRAFT),
        status__in=(TemplateStatusChoices.ACTIVE, TemplateStatusChoices.DRAFT),
    ).select_related("template", "related_form_revision").order_by(
        "-status", "-approved_at", "-pk"
    ).first()
    return template


def resolve_document_readiness(*, stable_key: str, template_version=None,
                               form_revision=None,
                               intent: DocumentOutputIntent = DocumentOutputIntent.PREVIEW) -> DocumentReadinessResult:
    family = get_document_family(stable_key)
    reasons: list[str] = []
    template_version = template_version or get_preview_template_version(stable_key)
    if not template_version:
        reasons.append("TEMPLATE_MISSING_OR_AMBIGUOUS")
    institution = get_current_institution_profile()
    office = get_current_office_profile(institution)
    if not institution:
        reasons.append("INSTITUTION_IDENTITY_UNAVAILABLE")
    if not office:
        reasons.append("OFFICE_IDENTITY_UNAVAILABLE")

    revision = form_revision or (template_version.related_form_revision if template_version else None)
    if intent == DocumentOutputIntent.OFFICIAL and (
        not family.official_form_code or not family.official_revision
    ):
        # Official output is never enabled by a runtime row alone; the source
        # registry and the active FormRevision must agree.
        reasons.append("SOURCE_FORM_METADATA_PENDING_CONFIRMATION")
    if not revision:
        reasons.append("FORM_REVISION_MISSING")
    else:
        if revision.status != GovernanceStatusChoices.ACTIVE:
            reasons.append("FORM_REVISION_NOT_ACTIVE")
        active = get_active_form_revision(revision.form_family.stable_key)
        if not active or active.pk != revision.pk:
            reasons.append("FORM_REVISION_NOT_CURRENT")
        if not revision.official_form_code or not revision.official_revision:
            reasons.append("FORM_CODE_OR_REVISION_MISSING")
        if family.official_form_code and revision.official_form_code != family.official_form_code:
            reasons.append("FORM_CODE_DOES_NOT_MATCH_GOVERNED_SOURCE")
        if family.official_revision and revision.official_revision != family.official_revision:
            reasons.append("FORM_REVISION_DOES_NOT_MATCH_GOVERNED_SOURCE")
        if not revision.effective_from:
            reasons.append("FORM_EFFECTIVE_DATE_MISSING")
        if not revision.approved_by_id or not revision.approved_at:
            reasons.append("FORM_REVISION_APPROVAL_MISSING")

    if template_version:
        if template_version.status != TemplateStatusChoices.ACTIVE:
            reasons.append("TEMPLATE_VERSION_NOT_ACTIVE")
        if template_version.template.status != TemplateStatusChoices.ACTIVE:
            reasons.append("TEMPLATE_FAMILY_NOT_ACTIVE")
        if not template_version.institution_profile_snapshot or not template_version.office_profile_snapshot:
            reasons.append("IDENTITY_SNAPSHOT_MISSING")
        if intent == DocumentOutputIntent.OFFICIAL:
            active_versions = list(
                DocumentTemplateVersion.objects.filter(
                    template=template_version.template,
                    status=TemplateStatusChoices.ACTIVE,
                ).values_list("pk", flat=True)[:2]
            )
            if len(active_versions) != 1:
                reasons.append("ACTIVE_TEMPLATE_VERSION_MISSING_OR_AMBIGUOUS")

    shell = resolve_document_shell(template_version) if template_version else None
    if not shell:
        reasons.append("DOCUMENT_SHELL_CONFIGURATION_INVALID")
    brand_assets = (
        select_document_brand_assets(institution=institution, office=office)
        if institution and office
        else {"primary": None, "secondary": [], "footer": {}}
    )
    asset = brand_assets["primary"]
    if shell and shell.require_primary_header and not asset:
        reasons.append("APPROVED_PRINT_HEADER_LOGO_MISSING_OR_AMBIGUOUS")

    # A draft template is explicitly a draft preview.  An active but incomplete
    # configuration is pending approval.  Only a complete active configuration
    # can ever be official.
    if intent == DocumentOutputIntent.OFFICIAL and (
        not template_version or template_version.status != TemplateStatusChoices.ACTIVE
    ):
        state = DocumentReadiness.PENDING_APPROVAL
    elif template_version and template_version.status == TemplateStatusChoices.DRAFT:
        state = DocumentReadiness.DRAFT
    elif reasons:
        state = DocumentReadiness.PENDING_APPROVAL
    else:
        state = DocumentReadiness.OFFICIAL

    if intent == DocumentOutputIntent.OFFICIAL and state != DocumentReadiness.OFFICIAL:
        # The caller receives the structured result and the service raises a
        # gate error; readiness itself stays truthful and inspectable.
        pass

    return DocumentReadinessResult(
        state=state,
        intent=intent,
        family=family,
        reasons=tuple(dict.fromkeys(reasons)),
        template_version_label=template_version.version_label if template_version else "",
        form_code=(revision.official_form_code if revision else "") or family.official_form_code,
        form_revision=(revision.official_revision if revision else "") or family.official_revision,
        effective_from=(revision.effective_from.isoformat() if revision and revision.effective_from else ""),
        source_path=family.source_path,
        brand_asset_version=asset.version_label if asset else "",
        shell_key=shell.key.value if shell else "",
    )


def build_document_control_context(*, stable_key: str, template_version=None,
                                   form_revision=None,
                                   intent: DocumentOutputIntent = DocumentOutputIntent.PREVIEW) -> tuple[dict, DocumentReadinessResult]:
    """Build server-owned control metadata and readiness for a render."""
    result = resolve_document_readiness(
        stable_key=stable_key,
        template_version=template_version,
        form_revision=form_revision,
        intent=intent,
    )
    institution = get_current_institution_profile()
    office = get_current_office_profile(institution)
    shell = resolve_document_shell(template_version) if template_version else None
    brand_assets = (
        select_document_brand_assets(institution=institution, office=office)
        if institution and office
        else {"primary": None, "secondary": [], "footer": {}}
    )
    asset = brand_assets["primary"]
    _render_branding, brand_metadata = build_document_branding_context(
        shell=shell or SHELL_DEFINITIONS[DocumentShellKey.COMPACT_FORM],
        institution=institution,
        office=office,
    )
    from apps.documents.cache import (
        get_cached_document_family_metadata,
        get_cached_template_metadata,
        get_cached_template_version_metadata,
    )
    from apps.organizations.cache import get_public_identity_snapshot

    return {
        **result.as_safe_json(),
        "display_name": result.family.display_name,
        "source_label": result.family.source_label,
        "source_kind": result.family.source_kind,
        "compass_native": result.family.compass_native,
        "historical_structural_reference": result.family.historical_structural_reference,
        "page_2_metadata_note": result.family.page_2_metadata_note,
        # Only safe metadata is persisted. Render-only data URIs are attached
        # to ``print_brand`` by the document service after this context is
        # built and never enter the generated-document snapshot.
        "shell": brand_metadata,
        "official": result.is_official,
        # Safe, model-free metadata is available to future API/UI adapters.
        # Rendering still uses the authoritative model and rechecks readiness.
        "identity": get_public_identity_snapshot(),
        "brand_asset_metadata": brand_metadata,
        "family_metadata": get_cached_document_family_metadata(stable_key),
        "template_metadata": get_cached_template_metadata(
            template_version.template.stable_key if template_version else stable_key,
        ),
        "template_version_metadata": get_cached_template_version_metadata(
            template_version.template.stable_key if template_version else stable_key,
        ),
    }, result
