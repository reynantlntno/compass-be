"""Public-safe and internal organization profile, brand, and form selectors."""

import hashlib
import re
from urllib.parse import urlsplit, urlunsplit

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db.models import Q
from django.utils import timezone

from apps.content.validators import validate_safe_external_url
from apps.organizations.models import (
    AssetStatusChoices,
    AssetTypeChoices,
    BrandAssetOwnerChoices,
    BrandAssetPlacementChoices,
    BrandAssetRoleChoices,
    BrandAsset,
    FormFamily,
    FormRevision,
    GovernanceStatusChoices,
    InstitutionProfile,
    OfficeProfile,
    PublicLink,
    PublicLinkOwnerChoices,
    PublicLinkPlacementChoices,
)


# ---------------------------------------------------------------------------
# Public-safe constants and helpers
# ---------------------------------------------------------------------------

PUBLIC_BRAND_ASSET_TYPES = (
    AssetTypeChoices.PUBLIC_PAGE_LOGO,
    AssetTypeChoices.LOGO_FULL,
    AssetTypeChoices.LOGO_MARK,
    AssetTypeChoices.SEAL,
)
PUBLIC_BRAND_USAGE_CONTEXTS = {
    "PUBLIC_HEADER",
    "PUBLIC_FOOTER",
    "PUBLIC_FOOTER_IDENTITY_ROW",
    "PUBLIC_FOOTER_CERTIFICATION",
    "PUBLIC_FOOTER_LOGO",
    "PUBLIC_FOOTER_PRIVACY_CREDENTIAL",
    "PUBLIC_LOGO",
    "PUBLIC_SITE_HEADER",
}
PUBLIC_IMAGE_MIME_TYPES = frozenset({"image/png", "image/jpeg", "image/webp"})
PUBLIC_IMAGE_MAX_BYTES = 5 * 1024 * 1024
PUBLIC_IMAGE_MAX_WIDTH = 4096
PUBLIC_IMAGE_MAX_HEIGHT = 1200
PUBLIC_IMAGE_EXTENSIONS = {
    "image/png": {".png"},
    "image/jpeg": {".jpg", ".jpeg"},
    "image/webp": {".webp"},
}
PUBLIC_ASSET_PLACEMENT_ROLES = {
    BrandAssetPlacementChoices.HEADER_IDENTITY: {BrandAssetRoleChoices.IDENTITY},
    BrandAssetPlacementChoices.FOOTER_IDENTITY: {BrandAssetRoleChoices.IDENTITY},
    BrandAssetPlacementChoices.FOOTER_IDENTITY_ROW: {
        BrandAssetRoleChoices.IDENTITY,
        BrandAssetRoleChoices.CAMPAIGN,
        BrandAssetRoleChoices.CERTIFICATION,
        BrandAssetRoleChoices.RECOGNITION,
    },
    BrandAssetPlacementChoices.FOOTER_CERTIFICATIONS: {BrandAssetRoleChoices.CERTIFICATION},
    BrandAssetPlacementChoices.FOOTER_RECOGNITIONS: {BrandAssetRoleChoices.RECOGNITION},
    BrandAssetPlacementChoices.FOOTER_PRIVACY_CREDENTIALS: {
        BrandAssetRoleChoices.PRIVACY_CREDENTIAL,
    },
    BrandAssetPlacementChoices.PUBLICATION_MARKS: {BrandAssetRoleChoices.PUBLICATION},
}
PUBLIC_LINK_CAP = 12
DEMO_PUBLIC_ASSET_SOURCE_PREFIX = "Demo seed from static/images/"
DEMO_PUBLIC_LINK_SOURCE_PREFIX = "Demo seed from official UCN public navigation;"
_SOURCE_DIGEST_RE = re.compile(r"SHA-256:\s*([0-9a-f]{64})", re.IGNORECASE)


def _clean(value) -> str:
    return str(value or "").strip()


def _local_demo_public_output_enabled() -> bool:
    """Allow explicitly marked demo records only in local development.

    Demo rows are useful for checking the public shell against the repository's
    committed UCN assets, but they do not carry a real approver.  Keeping this
    escape hatch tied to both DEBUG and the development environment prevents an
    unapproved seed record from becoming staging or production output.
    """
    return bool(
        getattr(settings, "DEBUG", False)
        and getattr(settings, "COMPASS_ENVIRONMENT", "") == "development"
    )


def _has_public_approval_or_local_demo(record, *, demo_source_prefix: str) -> bool:
    if record.approved_at and record.approved_by_id:
        return True
    return _local_demo_public_output_enabled() and _clean(record.source_note).startswith(
        demo_source_prefix
    )


# ---------------------------------------------------------------------------
# Internal governance: current institution profile
# ---------------------------------------------------------------------------

def get_current_institution_profile():
    """Return the single active institution profile, or None.

    Fail-closed: returns None when missing or ambiguous.
    """
    today = timezone.localdate()
    active = list(
        InstitutionProfile.objects.filter(
            status=GovernanceStatusChoices.ACTIVE,
        ).filter(
            Q(effective_from__isnull=True) | Q(effective_from__lte=today),
        ).filter(
            Q(effective_until__isnull=True) | Q(effective_until__gte=today),
        ).order_by("-effective_from", "-pk")
    )
    if len(active) == 1:
        return active[0]
    if active:
        # Ambiguous: multiple active profiles — fail closed
        return None
    return None


def _active_effective_institution_count() -> int:
    """Count active/effective institution profiles without selecting one."""
    today = timezone.localdate()
    return InstitutionProfile.objects.filter(
        status=GovernanceStatusChoices.ACTIVE,
    ).filter(
        Q(effective_from__isnull=True) | Q(effective_from__lte=today),
    ).filter(
        Q(effective_until__isnull=True) | Q(effective_until__gte=today),
    ).count()


# ---------------------------------------------------------------------------
# Internal governance: current office profile
# ---------------------------------------------------------------------------

def get_current_office_profile(institution=None):
    """Return the single active office profile for the institution, or None.

    Fail-closed: returns None when missing or ambiguous.
    """
    today = timezone.localdate()
    qs = OfficeProfile.objects.filter(
        status=GovernanceStatusChoices.ACTIVE,
    ).filter(
        Q(effective_from__isnull=True) | Q(effective_from__lte=today),
    ).filter(
        Q(effective_until__isnull=True) | Q(effective_until__gte=today),
    )
    if institution:
        offices = list(qs.filter(institution=institution).order_by("-pk"))
        if len(offices) == 1:
            return offices[0]
        return None
    # A global office is only a valid fallback when there is no active
    # institution at all.  An active institution with zero or multiple linked
    # offices must fail closed instead of silently selecting a global record.
    if _active_effective_institution_count():
        return None
    offices = list(qs.order_by("-pk"))
    if len(offices) == 1:
        return offices[0]
    return None


# ---------------------------------------------------------------------------
# Brand asset selectors
# ---------------------------------------------------------------------------

def get_brand_asset_for_usage(*, asset_type, usage_context, institution=None):
    """Return the single active brand asset matching type/usage, or None.

    Fail-closed: returns None when missing or ambiguous.
    """
    inst_scope = Q(institution__isnull=True)
    if institution:
        inst_scope |= Q(institution=institution)
    candidates = BrandAsset.objects.filter(
        inst_scope,
        status=AssetStatusChoices.ACTIVE,
        asset_type=asset_type,
    )
    eligible = [
        c for c in candidates
        if _normalized_usage_context(c.usage_context) == _normalized_usage_context(usage_context)
        and _clean(c.alt_text)
    ]
    if len(eligible) == 1:
        return eligible[0]
    return None


# ---------------------------------------------------------------------------
# Form registry selectors
# ---------------------------------------------------------------------------

def get_active_form_family(stable_key: str):
    """Return the active FormFamily for the given stable_key, or None."""
    try:
        family = FormFamily.objects.get(stable_key=stable_key)
    except FormFamily.DoesNotExist:
        return None
    if family.status == GovernanceStatusChoices.ACTIVE:
        return family
    return None


def get_active_form_revision(stable_key: str):
    """Return the currently active FormRevision for a form family, or None.

    Verifies the active revision set before trusting the cached pointer.
    """
    family = get_active_form_family(stable_key)
    if not family:
        return None
    active = list(
        FormRevision.objects.filter(
            form_family=family,
            status=GovernanceStatusChoices.ACTIVE,
        ).order_by("-approved_at", "-pk")[:2]
    )
    if len(active) != 1:
        return None

    revision = active[0]
    if (
        family.current_active_revision_id
        and family.current_active_revision_id != revision.pk
    ):
        return None
    return revision


# ---------------------------------------------------------------------------
# Snapshot builders for future generated documents
# ---------------------------------------------------------------------------

def build_institution_profile_snapshot(profile) -> dict:
    """Build allowlisted institution identity snapshot."""
    if not profile:
        return {}
    return {
        "id": profile.pk,
        "legal_name": profile.legal_name,
        "short_name": profile.short_name,
        "former_name": profile.former_name,
        "former_short_name": profile.former_short_name,
        "address": profile.address,
        "main_campus": profile.main_campus,
        "version_label": profile.version_label,
        "status": profile.status,
    }


def build_office_profile_snapshot(profile) -> dict:
    """Build allowlisted office identity snapshot."""
    if not profile:
        return {}
    return {
        "id": profile.pk,
        "office_name": profile.office_name,
        "office_short_name": profile.office_short_name,
        "legacy_office_name": profile.legacy_office_name,
        "document_header_name": profile.document_header_name,
        "office_address": profile.office_address,
        "default_signatory_name": profile.default_signatory_name,
        "default_signatory_title": profile.default_signatory_title,
        "version_label": profile.version_label,
        "status": profile.status,
    }


def build_document_identity_snapshot() -> dict:
    """Build a full identity snapshot for future generated documents."""
    from apps.organizations.cache import (
        get_institution_identity_snapshot,
        get_office_identity_snapshot,
    )

    institution = get_institution_identity_snapshot()
    office = get_office_identity_snapshot(institution_id=institution.get("id"))
    return {
        "institution": institution,
        "office": office,
        "snapshot_at": timezone.now().isoformat() if institution or office else None,
    }


def build_form_revision_snapshot(revision) -> dict:
    """Build allowlisted form revision snapshot for future generated documents."""
    if not revision:
        return {}
    return {
        "id": revision.pk,
        "form_family_key": revision.form_family.stable_key,
        "official_form_code": revision.official_form_code,
        "official_revision": revision.official_revision,
        "internal_schema_version": revision.internal_schema_version,
        "internal_template_version": revision.internal_template_version,
        "display_title": revision.display_title,
        "effective_from": revision.effective_from.isoformat() if revision.effective_from else "",
        "status": revision.status,
        "is_used": revision.is_used,
    }


# ---------------------------------------------------------------------------
# Public-safe selectors (backward-compatible with existing public site)
# ---------------------------------------------------------------------------

def _select_authoritative_institution():
    """Select exactly one active, effective institution profile.

    Public configuration must never fall back to a draft or legacy record.
    The database remains authoritative and ambiguity fails closed.
    """

    return get_current_institution_profile()


def _institution_dto(profile) -> dict:
    if profile is None:
        return {}
    return {
        "display_name": _clean(profile.legal_name),
        "former_name": _clean(profile.former_name),
        "campus": _clean(profile.main_campus),
        "address": _clean(profile.address),
    }


def get_public_institution_profile() -> dict:
    """Return allowlisted institution identity, or an empty DTO if ambiguous."""
    from apps.organizations.cache import get_public_identity_snapshot

    return get_public_identity_snapshot().get("institution", {})


def _select_authoritative_office(institution):
    today = timezone.localdate()
    offices = OfficeProfile.objects.filter(status=GovernanceStatusChoices.ACTIVE).filter(
        Q(effective_from__isnull=True) | Q(effective_from__lte=today),
        Q(effective_until__isnull=True) | Q(effective_until__gte=today),
    )
    if institution is not None:
        linked = list(offices.filter(institution=institution).order_by("pk"))
        if len(linked) == 1:
            return linked[0]
        return None

    if _active_effective_institution_count():
        return None
    global_offices = list(offices.filter(institution__isnull=True).order_by("pk"))
    return global_offices[0] if len(global_offices) == 1 else None


def get_public_office_profile() -> dict:
    """Return allowlisted office contact fields, or an empty DTO if ambiguous."""
    from apps.organizations.cache import get_public_identity_snapshot

    return get_public_identity_snapshot().get("office", {})


def _normalized_usage_context(value: str) -> str:
    return "_".join(_clean(value).upper().replace("-", " ").split())


def _public_brand_asset_dto(asset) -> dict | None:
    alt_text = _clean(asset.alt_text)
    if not alt_text or not _clean(asset.placement):
        return None
    if not asset.approved_at or not asset.approved_by_id:
        return None
    if asset.content_type_hint not in PUBLIC_IMAGE_MIME_TYPES:
        return None
    if asset.semantic_role not in PUBLIC_ASSET_PLACEMENT_ROLES.get(asset.placement, set()):
        return None
    if asset.asset_type == AssetTypeChoices.SEAL and asset.placement != BrandAssetPlacementChoices.FOOTER_PRIVACY_CREDENTIALS:
        return None
    if asset.placement == BrandAssetPlacementChoices.FOOTER_PRIVACY_CREDENTIALS:
        if (
            asset.asset_type != AssetTypeChoices.SEAL
            or asset.semantic_role != BrandAssetRoleChoices.PRIVACY_CREDENTIAL
            or asset.owner_type != BrandAssetOwnerChoices.INSTITUTION
            or not asset.institution_id
            or asset.office_id
        ):
            return None
    if (
        asset.semantic_role == BrandAssetRoleChoices.CERTIFICATION
        and asset.owner_type == BrandAssetOwnerChoices.COMPASS
    ):
        return None
    if not asset.image_width or not asset.image_height:
        return None
    if asset.image_width > PUBLIC_IMAGE_MAX_WIDTH or asset.image_height > PUBLIC_IMAGE_MAX_HEIGHT:
        return None
    if not asset.file_size_bytes or asset.file_size_bytes > PUBLIC_IMAGE_MAX_BYTES:
        return None
    if not _source_digest_matches(asset):
        return None
    try:
        actual_size = asset.file.size
        filename = asset.file.name.rsplit("/", 1)[-1].lower()
    except Exception:
        return None
    if actual_size != asset.file_size_bytes:
        return None
    extension = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""
    if extension not in PUBLIC_IMAGE_EXTENSIONS[asset.content_type_hint]:
        return None
    verification_url = _clean(asset.verification_url)
    if verification_url:
        try:
            parsed_verification_url = urlsplit(verification_url)
        except ValueError:
            return None
        if parsed_verification_url.username or parsed_verification_url.password:
            return None
        try:
            validate_safe_external_url(verification_url)
        except ValidationError:
            return None
    owner_label = "COMPASS"
    if asset.owner_type == BrandAssetOwnerChoices.INSTITUTION:
        owner_label = _clean(asset.institution.short_name if asset.institution else "")
    elif asset.owner_type == BrandAssetOwnerChoices.OFFICE:
        owner_label = _clean(asset.office.office_short_name if asset.office else "")
    elif asset.owner_type == BrandAssetOwnerChoices.PARTNER:
        owner_label = "Partner"
    if asset.owner_type in {
        BrandAssetOwnerChoices.INSTITUTION,
        BrandAssetOwnerChoices.OFFICE,
    } and not owner_label:
        return None
    return {
        "id": str(asset.pk),
        "delivery_path": f"/api/v1/organizations/public/branding/assets/{asset.pk}/",
        "delivery_mode": "signed_url",
        "alt_text": alt_text,
        "asset_type": asset.asset_type,
        "placement": asset.placement,
        "display_order": asset.display_order,
        "width": asset.image_width,
        "height": asset.image_height,
        "content_type": asset.content_type_hint,
        "effective_from": asset.effective_from.isoformat() if asset.effective_from else None,
        "effective_until": asset.effective_until.isoformat() if asset.effective_until else None,
    }


def _asset_is_effective(asset, today):
    return (
        (asset.effective_from is None or asset.effective_from <= today)
        and (asset.effective_until is None or asset.effective_until >= today)
    )


def _owner_scope_allows_asset(asset, institution, office):
    if asset.owner_type == BrandAssetOwnerChoices.INSTITUTION:
        return institution is not None and asset.institution_id == institution.pk and asset.office_id is None
    if asset.owner_type == BrandAssetOwnerChoices.OFFICE:
        return (
            office is not None
            and asset.office_id == office.pk
            and asset.institution_id is None
        )
    return asset.institution_id is None and asset.office_id is None


def _source_digest_matches(asset) -> bool:
    """Verify an optional source digest pinned in governed provenance text.

    Demo assets carry a SHA-256 digest in ``source_note`` so a changed or
    replaced local file cannot silently render as the approved-looking mark.
    Approved assets without a pinned digest continue through the normal file
    integrity and approval gates.
    """
    match = _SOURCE_DIGEST_RE.search(_clean(asset.source_note))
    if not match:
        return True
    try:
        digest = hashlib.sha256()
        with asset.file.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except Exception:
        return False
    return digest.hexdigest().lower() == match.group(1).lower()


def get_public_brand_asset(asset_id):
    """Return one approved public asset record, or ``None``.

    The public asset endpoint uses this same projection boundary as the public
    shell.  An asset URL must never become a shortcut around approval, owner,
    placement, expiry, or file-integrity checks.
    """
    try:
        asset = BrandAsset.objects.select_related("institution", "office").get(pk=asset_id)
    except (BrandAsset.DoesNotExist, TypeError, ValueError):
        return None

    institution = _select_authoritative_institution()
    office = _select_authoritative_office(institution)
    today = timezone.localdate()
    if asset.status != AssetStatusChoices.ACTIVE:
        return None
    if asset.asset_type not in PUBLIC_BRAND_ASSET_TYPES:
        return None
    if not _asset_is_effective(asset, today) or not _owner_scope_allows_asset(asset, institution, office):
        return None
    if _public_brand_asset_dto(asset) is None:
        return None
    if asset.placement == BrandAssetPlacementChoices.FOOTER_PRIVACY_CREDENTIALS:
        # The delivery endpoint must not become a side door around the
        # exactly-one institutional NPC credential rule enforced by the
        # grouped public branding projection.
        privacy_assets = get_public_brand_assets()["footer_privacy_credentials"]
        if len(privacy_assets) != 1 or privacy_assets[0]["id"] != str(asset.pk):
            return None
    return asset


def get_public_brand_assets() -> dict:
    """Return grouped, approved public identity DTOs.

    Public output is deliberately independent of the legacy JSON link fields.
    Missing, ambiguous, unapproved, expired, unsafe, or unsupported records
    are omitted rather than guessed.
    """
    institution = _select_authoritative_institution()
    office = _select_authoritative_office(institution)
    today = timezone.localdate()
    candidates = BrandAsset.objects.filter(
        status=AssetStatusChoices.ACTIVE,
        asset_type__in=PUBLIC_BRAND_ASSET_TYPES,
    ).select_related("institution", "office").order_by("placement", "display_order", "pk")

    groups = {
        "header_identity": [],
        "footer_identity": [],
        "footer_identity_row": [],
        "footer_certifications": [],
        "footer_recognitions": [],
        "footer_privacy_credentials": [],
        "publication_marks": [],
    }
    for asset in candidates:
        if not _asset_is_effective(asset, today) or not _owner_scope_allows_asset(asset, institution, office):
            continue
        dto = _public_brand_asset_dto(asset)
        if dto is None:
            continue
        group_name = {
            BrandAssetPlacementChoices.HEADER_IDENTITY: "header_identity",
            BrandAssetPlacementChoices.FOOTER_IDENTITY: "footer_identity",
            BrandAssetPlacementChoices.FOOTER_IDENTITY_ROW: "footer_identity_row",
            BrandAssetPlacementChoices.FOOTER_CERTIFICATIONS: "footer_certifications",
            BrandAssetPlacementChoices.FOOTER_RECOGNITIONS: "footer_recognitions",
            BrandAssetPlacementChoices.FOOTER_PRIVACY_CREDENTIALS: "footer_privacy_credentials",
            BrandAssetPlacementChoices.PUBLICATION_MARKS: "publication_marks",
        }.get(asset.placement)
        if group_name:
            groups[group_name].append(dto)

    # Legacy footer identity records remain safe compatibility input, but the
    # public shell renders one canonical ordered identity row.
    if groups["footer_identity"]:
        groups["footer_identity_row"] = sorted(
            [*groups["footer_identity_row"], *groups["footer_identity"]],
            key=lambda item: (item.get("display_order", 0), str(item.get("id", ""))),
        )
    groups["footer_identity"] = groups["footer_identity_row"]

    # The footer label is an institutional claim, so ambiguity must omit the
    # entire credential group rather than selecting an arbitrary seal.
    if len(groups["footer_privacy_credentials"]) != 1:
        groups["footer_privacy_credentials"] = []

    return groups


def _normalize_public_url(value):
    try:
        parsed = urlsplit(_clean(value))
        port = parsed.port
    except ValueError:
        return ""
    if parsed.scheme != "https" or not parsed.hostname:
        return ""
    if parsed.username or parsed.password:
        return ""
    host = parsed.hostname.lower().rstrip(".")
    netloc = host if port in (None, 443) else f"{host}:{port}"
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/")
    return urlunsplit(("https", netloc, path, parsed.query, ""))


def _public_link_dto(link, *, institution, office):
    if not _has_public_approval_or_local_demo(
        link,
        demo_source_prefix=DEMO_PUBLIC_LINK_SOURCE_PREFIX,
    ):
        return None
    if link.status != GovernanceStatusChoices.ACTIVE:
        return None
    today = timezone.localdate()
    if link.effective_from and link.effective_from > today:
        return None
    if link.effective_until and link.effective_until < today:
        return None
    normalized_url = _normalize_public_url(link.url)
    if not normalized_url:
        return None
    try:
        validate_safe_external_url(normalized_url)
    except ValidationError:
        return None
    if link.owner_type == PublicLinkOwnerChoices.INSTITUTION:
        if not institution or link.institution_id != institution.pk or link.office_id:
            return None
        owner_label = _clean(institution.legal_name)
    elif link.owner_type == PublicLinkOwnerChoices.OFFICE:
        if not office or link.office_id != office.pk or link.institution_id:
            return None
        owner_label = _clean(office.office_name)
    elif link.owner_type == PublicLinkOwnerChoices.COMPASS:
        if link.institution_id or link.office_id:
            return None
        owner_label = "COMPASS"
    elif link.owner_type == PublicLinkOwnerChoices.PARTNER:
        if link.institution_id or link.office_id:
            return None
        owner_label = "Partner"
    else:
        return None
    label = _clean(link.label)
    if not label:
        return None
    return {
        "label": label,
        "url": normalized_url,
        "owner_type": link.owner_type,
        "owner_label": owner_label,
        "link_type": link.link_type,
        "placement": link.placement,
        "display_order": link.display_order,
        "effective_until": link.effective_until.isoformat() if link.effective_until else None,
    }


def _build_public_links() -> dict:
    """Return approved public links grouped by ownership with global dedup/cap."""
    institution = _select_authoritative_institution()
    office = _select_authoritative_office(institution)
    groups = {
        "institution_links": [],
        "office_links": [],
        "compass_links": [],
    }
    seen = set()
    links = PublicLink.objects.filter(status=GovernanceStatusChoices.ACTIVE).select_related(
        "institution", "office"
    ).order_by("display_order", "pk")
    for link in links:
        if link.placement != PublicLinkPlacementChoices.FOOTER:
            continue
        dto = _public_link_dto(link, institution=institution, office=office)
        if dto is None or dto["url"] in seen:
            continue
        # Partner ownership remains a distinct pending product decision.  Do
        # not place it in the COMPASS group, where the footer could imply
        # institutional ownership before a dedicated public slot exists.
        if link.owner_type == PublicLinkOwnerChoices.PARTNER:
            continue
        seen.add(dto["url"])
        group_name = {
            PublicLinkOwnerChoices.INSTITUTION: "institution_links",
            PublicLinkOwnerChoices.OFFICE: "office_links",
            PublicLinkOwnerChoices.COMPASS: "compass_links",
        }[link.owner_type]
        groups[group_name].append(dto)
        if sum(len(items) for items in groups.values()) >= PUBLIC_LINK_CAP:
            break
    return groups


def get_public_links() -> dict:
    """Return approved public links through the bounded identity cache."""
    from apps.organizations.cache import get_cached_public_links

    return get_cached_public_links()


def get_governed_privacy_notice_url() -> str:
    """Return the one approved UCN privacy destination, or an unavailable state."""

    expected = "https://ucn.edu.ph/UCN/data-privacy-notice/"
    candidates = []
    for group in get_public_links().values():
        for link in group:
            if link.get("url") == expected and link.get("link_type") == PublicLinkTypeChoices.POLICY:
                candidates.append(link["url"])
    return candidates[0] if len(candidates) == 1 else ""
