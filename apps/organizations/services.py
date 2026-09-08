"""Stable-ID mutation boundary for institutional configuration.

The API and orchestration layers pass actor principals, stable identifiers,
and frozen commands into this module. ORM instances are locked and reloaded
here; they never form part of the public command contract.
"""

from __future__ import annotations

from django.core import exceptions as django_exceptions
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils import timezone

from apps.access_control.rules import is_active_nonlegacy_actor
from apps.audit.services import audit_log
from apps.common.exceptions import (
    LifecycleConflictError,
    NotFoundError,
    PermissionDeniedError,
    StaleStateError,
    ValidationError,
)
from apps.organizations.cache import (
    invalidate_form_metadata_after_commit,
    invalidate_organization_branding_after_commit,
    invalidate_organization_identity_after_commit,
)
from apps.organizations.commands import (
    BrandAssetDraftCommand,
    FormFamilyDraftCommand,
    FormRevisionDraftCommand,
    InstitutionProfileDraftCommand,
    LifecycleCommand,
    OfficeProfileDraftCommand,
    PublicLinkDraftCommand,
)
from apps.organizations.models import (
    AssetStatusChoices,
    BrandAsset,
    BrandAssetOwnerChoices,
    FormFamily,
    FormRevision,
    FormRevisionStatusChoices,
    GovernanceStatusChoices,
    InstitutionProfile,
    OfficeProfile,
    PublicLink,
    PublicLinkOwnerChoices,
)
from apps.organizations.policies import (
    can_activate_governance_record,
    can_archive_governance_record,
    can_create_governance_draft,
    can_mark_form_revision_used,
    can_retire_governance_record,
    can_upload_brand_asset,
)


_SOURCE_APP = "apps.organizations"


def _actor_allowed(actor, checker) -> None:
    if not is_active_nonlegacy_actor(actor) or not checker(actor):
        raise PermissionDeniedError()


def _validation(exc: Exception) -> ValidationError:
    field_errors = getattr(exc, "message_dict", {}) if isinstance(exc, django_exceptions.ValidationError) else {}
    return ValidationError(field_errors=field_errors if isinstance(field_errors, dict) else {})


def _save(instance, *, fields=None):
    try:
        instance.full_clean()
        if fields:
            instance.save(update_fields=fields)
        else:
            instance.save()
    except django_exceptions.ValidationError as exc:
        raise _validation(exc) from exc
    except IntegrityError as exc:
        raise LifecycleConflictError() from exc


def _reload(model, target_id, *, lock=True, related=()):
    manager = model.objects.select_related(*related)
    if lock:
        manager = manager.select_for_update()
    try:
        return manager.get(pk=target_id)
    except model.DoesNotExist as exc:
        raise NotFoundError() from exc


def _check_expected(target, command: LifecycleCommand) -> None:
    expected_status = getattr(command, "expected_status", None)
    expected_updated_at = getattr(command, "expected_updated_at", None)
    if expected_status and str(getattr(target, "status", "")) != expected_status:
        raise StaleStateError()
    if expected_updated_at and getattr(target, "updated_at", None) != expected_updated_at:
        raise StaleStateError()


def _window_overlaps(queryset, *, start, end, exclude_id=None):
    if exclude_id:
        queryset = queryset.exclude(pk=exclude_id)
    if start is not None:
        queryset = queryset.filter(Q(effective_until__isnull=True) | Q(effective_until__gte=start))
    if end is not None:
        queryset = queryset.filter(Q(effective_from__isnull=True) | Q(effective_from__lte=end))
    return queryset


def _brand_asset_scope_queryset(asset):
    queryset = BrandAsset.objects.select_for_update().filter(
        status=AssetStatusChoices.ACTIVE,
        asset_type=asset.asset_type,
        semantic_role=asset.semantic_role,
        usage_context=asset.usage_context,
        placement=asset.placement,
        owner_type=asset.owner_type,
    )
    if asset.owner_type == BrandAssetOwnerChoices.INSTITUTION:
        return queryset.filter(institution_id=asset.institution_id)
    if asset.owner_type == BrandAssetOwnerChoices.OFFICE:
        return queryset.filter(office_id=asset.office_id)
    return queryset.filter(institution__isnull=True, office__isnull=True)


def _public_link_scope_queryset(link):
    queryset = PublicLink.objects.select_for_update().filter(
        status=GovernanceStatusChoices.ACTIVE,
        owner_type=link.owner_type,
        link_type=link.link_type,
        placement=link.placement,
        url=link.url,
    )
    if link.owner_type == PublicLinkOwnerChoices.INSTITUTION:
        return queryset.filter(institution_id=link.institution_id)
    if link.owner_type == PublicLinkOwnerChoices.OFFICE:
        return queryset.filter(office_id=link.office_id)
    return queryset.filter(institution__isnull=True, office__isnull=True)


def _meta(model_name, target, *, reason_code="", version="", asset_type="", link_type="", stable_key="", form_code=""):
    value = {
        "model": model_name,
        "object_id": str(target.pk),
        "status": str(getattr(target, "status", "")),
    }
    for key, item in (
        ("reason_code", reason_code),
        ("version", version),
        ("asset_type", asset_type),
        ("link_type", link_type),
        ("stable_key", stable_key),
        ("form_code", form_code),
    ):
        if item:
            value[key] = str(item)[:255]
    return value


def _audit(action, model_name, target, actor, *, reason_code="", version="", asset_type="", link_type="", stable_key="", form_code=""):
    audit_log(
        action_type=action,
        event_category="GOVERNANCE",
        target_model=model_name,
        target_object_id=str(target.pk),
        actor_user=actor,
        source_app=_SOURCE_APP,
        metadata=_meta(
            model_name,
            target,
            reason_code=reason_code,
            version=version,
            asset_type=asset_type,
            link_type=link_type,
            stable_key=stable_key,
            form_code=form_code,
        ),
    )


@transaction.atomic
def create_institution_profile_draft(actor, command: InstitutionProfileDraftCommand):
    if not isinstance(command, InstitutionProfileDraftCommand):
        raise ValidationError()
    _actor_allowed(actor, can_create_governance_draft)
    profile = InstitutionProfile(
        legal_name=command.legal_name,
        short_name=command.short_name,
        former_name=command.former_name,
        former_short_name=command.former_short_name,
        address=command.address,
        main_campus=command.main_campus,
        primary_brand_color=command.primary_brand_color,
        secondary_brand_color=command.secondary_brand_color,
        accent_brand_color=command.accent_brand_color,
        version_label=command.version_label,
        effective_from=command.effective_from,
        effective_until=command.effective_until,
        source_note=command.source_note,
        status=GovernanceStatusChoices.DRAFT,
    )
    _save(profile)
    _audit("GOVERNANCE_CREATE", "InstitutionProfile", profile, actor, version=profile.version_label)
    return profile


@transaction.atomic
def update_institution_profile_draft(actor, target_id: str, command: InstitutionProfileDraftCommand):
    if not isinstance(command, InstitutionProfileDraftCommand):
        raise ValidationError()
    _actor_allowed(actor, can_create_governance_draft)
    profile = _reload(InstitutionProfile, target_id)
    _check_expected(profile, command)
    if profile.status != GovernanceStatusChoices.DRAFT:
        raise LifecycleConflictError()
    for field in (
        "legal_name", "short_name", "former_name", "former_short_name", "address",
        "main_campus", "primary_brand_color", "secondary_brand_color", "accent_brand_color",
        "version_label", "effective_from", "effective_until", "source_note",
    ):
        setattr(profile, field, getattr(command, field))
    _save(profile)
    return profile


@transaction.atomic
def activate_institution_profile(actor, command: LifecycleCommand):
    _actor_allowed(actor, can_activate_governance_record)
    profile = _reload(InstitutionProfile, command.target_id)
    _check_expected(profile, command)
    if profile.status != GovernanceStatusChoices.DRAFT:
        raise LifecycleConflictError()
    if not profile.legal_name.strip() or not profile.short_name.strip():
        raise ValidationError()
    if _window_overlaps(
        InstitutionProfile.objects.select_for_update().filter(status=GovernanceStatusChoices.ACTIVE),
        start=profile.effective_from, end=profile.effective_until, exclude_id=profile.pk,
    ).exists():
        raise LifecycleConflictError()
    profile.status = GovernanceStatusChoices.ACTIVE
    profile.activated_at = timezone.now()
    profile.activated_by = actor
    _save(profile)
    _audit("GOVERNANCE_ACTIVATE", "InstitutionProfile", profile, actor)
    invalidate_organization_identity_after_commit()
    return profile


@transaction.atomic
def retire_institution_profile(actor, command: LifecycleCommand):
    return _transition_profile(actor, command, InstitutionProfile, GovernanceStatusChoices.ACTIVE, GovernanceStatusChoices.RETIRED, "retired")


@transaction.atomic
def archive_institution_profile(actor, command: LifecycleCommand):
    return _transition_profile(actor, command, InstitutionProfile, GovernanceStatusChoices.RETIRED, GovernanceStatusChoices.ARCHIVED, "archived")


def _transition_profile(actor, command, model, required_status, new_status, verb):
    checker = can_retire_governance_record if verb == "retired" else can_archive_governance_record
    _actor_allowed(actor, checker)
    target = _reload(model, command.target_id)
    _check_expected(target, command)
    if target.status != required_status:
        raise LifecycleConflictError()
    target.status = new_status
    if verb == "retired":
        target.retired_at = timezone.now()
        target.retired_by = actor
    _save(target)
    _audit(f"GOVERNANCE_{verb.upper()}", model.__name__, target, actor, reason_code=command.reason_code)
    invalidate_organization_identity_after_commit()
    return target


@transaction.atomic
def create_office_profile_draft(actor, command: OfficeProfileDraftCommand):
    if not isinstance(command, OfficeProfileDraftCommand):
        raise ValidationError()
    _actor_allowed(actor, can_create_governance_draft)
    institution = _reload(InstitutionProfile, command.institution_id, lock=False) if command.institution_id else None
    profile = OfficeProfile(
        institution=institution,
        office_name=command.office_name,
        office_short_name=command.office_short_name,
        legacy_office_name=command.legacy_office_name,
        document_header_name=command.document_header_name,
        office_address=command.office_address,
        contact_email=command.contact_email,
        contact_number=command.contact_number,
        office_hours=command.office_hours,
        default_signatory_name=command.default_signatory_name,
        default_signatory_title=command.default_signatory_title,
        footer_note=command.footer_note,
        version_label=command.version_label,
        effective_from=command.effective_from,
        effective_until=command.effective_until,
        source_note=command.source_note,
        status=GovernanceStatusChoices.DRAFT,
    )
    _save(profile)
    _audit("GOVERNANCE_CREATE", "OfficeProfile", profile, actor, version=profile.version_label)
    return profile


@transaction.atomic
def update_office_profile_draft(actor, target_id: str, command: OfficeProfileDraftCommand):
    if not isinstance(command, OfficeProfileDraftCommand):
        raise ValidationError()
    _actor_allowed(actor, can_create_governance_draft)
    profile = _reload(OfficeProfile, target_id)
    _check_expected(profile, command)
    if profile.status != GovernanceStatusChoices.DRAFT:
        raise LifecycleConflictError()
    institution = _reload(InstitutionProfile, command.institution_id, lock=False) if command.institution_id else None
    for field in (
        "office_name", "office_short_name", "legacy_office_name", "document_header_name", "office_address",
        "contact_email", "contact_number", "office_hours", "default_signatory_name", "default_signatory_title",
        "footer_note", "version_label", "effective_from", "effective_until", "source_note",
    ):
        setattr(profile, field, getattr(command, field))
    profile.institution = institution
    _save(profile)
    return profile


@transaction.atomic
def activate_office_profile(actor, command: LifecycleCommand):
    _actor_allowed(actor, can_activate_governance_record)
    profile = _reload(OfficeProfile, command.target_id)
    _check_expected(profile, command)
    if profile.status != GovernanceStatusChoices.DRAFT:
        raise LifecycleConflictError()
    if not profile.office_name.strip() or not profile.office_short_name.strip():
        raise ValidationError()
    if _window_overlaps(
        OfficeProfile.objects.select_for_update().filter(status=GovernanceStatusChoices.ACTIVE, institution_id=profile.institution_id),
        start=profile.effective_from, end=profile.effective_until, exclude_id=profile.pk,
    ).exists():
        raise LifecycleConflictError()
    profile.status = GovernanceStatusChoices.ACTIVE
    profile.activated_at = timezone.now()
    profile.activated_by = actor
    _save(profile)
    _audit("GOVERNANCE_ACTIVATE", "OfficeProfile", profile, actor)
    invalidate_organization_identity_after_commit()
    return profile


@transaction.atomic
def retire_office_profile(actor, command: LifecycleCommand):
    return _transition_profile(actor, command, OfficeProfile, GovernanceStatusChoices.ACTIVE, GovernanceStatusChoices.RETIRED, "retired")


@transaction.atomic
def archive_office_profile(actor, command: LifecycleCommand):
    return _transition_profile(actor, command, OfficeProfile, GovernanceStatusChoices.RETIRED, GovernanceStatusChoices.ARCHIVED, "archived")


@transaction.atomic
def create_brand_asset_draft(actor, command: BrandAssetDraftCommand):
    if not isinstance(command, BrandAssetDraftCommand):
        raise ValidationError()
    _actor_allowed(actor, can_upload_brand_asset)
    institution = _reload(InstitutionProfile, command.institution_id, lock=False) if command.institution_id else None
    office = _reload(OfficeProfile, command.office_id, lock=False) if command.office_id else None
    if command.owner_type == BrandAssetOwnerChoices.INSTITUTION and not institution:
        raise ValidationError()
    if command.owner_type == BrandAssetOwnerChoices.OFFICE and not office:
        raise ValidationError()
    receipt = command.upload_receipt
    if receipt is None:
        raise ValidationError()
    asset = BrandAsset(
        institution=institution,
        office=office,
        asset_type=command.asset_type,
        semantic_role=command.semantic_role,
        owner_type=command.owner_type,
        placement=command.placement,
        display_order=command.display_order,
        alt_text=command.alt_text,
        usage_context=command.usage_context,
        background_variant=command.background_variant,
        version_label=command.version_label,
        source_note=command.source_note,
        effective_from=command.effective_from,
        effective_until=command.effective_until,
        content_type_hint=receipt.content_type,
        file_size_bytes=receipt.size_bytes,
        original_filename=receipt.original_filename,
        uploaded_by=actor,
        file=receipt.storage_name,
        status=AssetStatusChoices.PROVISIONAL,
    )
    _save(asset)
    _audit("GOVERNANCE_CREATE", "BrandAsset", asset, actor, asset_type=asset.asset_type)
    invalidate_organization_branding_after_commit()
    return asset


@transaction.atomic
def update_brand_asset_draft(actor, target_id: str, command: BrandAssetDraftCommand):
    if not isinstance(command, BrandAssetDraftCommand):
        raise ValidationError()
    _actor_allowed(actor, can_create_governance_draft)
    asset = _reload(BrandAsset, target_id)
    _check_expected(asset, command)
    if asset.status != AssetStatusChoices.PROVISIONAL:
        raise LifecycleConflictError()
    asset.institution = _reload(InstitutionProfile, command.institution_id, lock=False) if command.institution_id else None
    asset.office = _reload(OfficeProfile, command.office_id, lock=False) if command.office_id else None
    for field in ("asset_type", "semantic_role", "owner_type", "placement", "display_order", "alt_text", "usage_context", "background_variant", "version_label", "source_note", "effective_from", "effective_until"):
        setattr(asset, field, getattr(command, field))
    if command.upload_receipt:
        asset.file = command.upload_receipt.storage_name
        asset.content_type_hint = command.upload_receipt.content_type
        asset.file_size_bytes = command.upload_receipt.size_bytes
        asset.original_filename = command.upload_receipt.original_filename
    _save(asset)
    invalidate_organization_branding_after_commit()
    return asset


@transaction.atomic
def activate_brand_asset(actor, command: LifecycleCommand):
    _actor_allowed(actor, can_activate_governance_record)
    asset = _reload(BrandAsset, command.target_id)
    _check_expected(asset, command)
    if asset.status != AssetStatusChoices.PROVISIONAL or not asset.alt_text.strip():
        raise LifecycleConflictError()
    if _window_overlaps(
        _brand_asset_scope_queryset(asset),
        start=asset.effective_from,
        end=asset.effective_until,
        exclude_id=asset.pk,
    ).exists():
        raise LifecycleConflictError()
    asset.status = AssetStatusChoices.ACTIVE
    asset.approved_at = timezone.now()
    asset.approved_by = actor
    _save(asset)
    _audit("GOVERNANCE_ACTIVATE", "BrandAsset", asset, actor)
    invalidate_organization_branding_after_commit()
    return asset


@transaction.atomic
def retire_brand_asset(actor, command: LifecycleCommand):
    _actor_allowed(actor, can_retire_governance_record)
    asset = _reload(BrandAsset, command.target_id)
    _check_expected(asset, command)
    if asset.status != AssetStatusChoices.ACTIVE:
        raise LifecycleConflictError()
    asset.status = AssetStatusChoices.RETIRED
    asset.retired_at = timezone.now()
    asset.retired_by = actor
    _save(asset)
    _audit("GOVERNANCE_RETIRE", "BrandAsset", asset, actor, reason_code=command.reason_code)
    invalidate_organization_branding_after_commit()
    return asset


@transaction.atomic
def archive_brand_asset(actor, command: LifecycleCommand):
    _actor_allowed(actor, can_archive_governance_record)
    asset = _reload(BrandAsset, command.target_id)
    _check_expected(asset, command)
    if asset.status != AssetStatusChoices.RETIRED:
        raise LifecycleConflictError()
    asset.status = AssetStatusChoices.ARCHIVED
    _save(asset)
    _audit("GOVERNANCE_ARCHIVE", "BrandAsset", asset, actor, reason_code=command.reason_code)
    invalidate_organization_branding_after_commit()
    return asset


@transaction.atomic
def create_public_link_draft(actor, command: PublicLinkDraftCommand):
    if not isinstance(command, PublicLinkDraftCommand):
        raise ValidationError()
    _actor_allowed(actor, can_create_governance_draft)
    institution = _reload(InstitutionProfile, command.institution_id, lock=False) if command.institution_id else None
    office = _reload(OfficeProfile, command.office_id, lock=False) if command.office_id else None
    link = PublicLink(
        owner_type=command.owner_type,
        institution=institution,
        office=office,
        link_type=command.link_type,
        label=command.label,
        url=command.url,
        placement=command.placement,
        display_order=command.display_order,
        effective_from=command.effective_from,
        effective_until=command.effective_until,
        source_note=command.source_note,
        status=GovernanceStatusChoices.DRAFT,
    )
    _save(link)
    _audit("GOVERNANCE_CREATE", "PublicLink", link, actor, link_type=link.link_type)
    invalidate_organization_identity_after_commit()
    return link


@transaction.atomic
def update_public_link_draft(actor, target_id: str, command: PublicLinkDraftCommand):
    if not isinstance(command, PublicLinkDraftCommand):
        raise ValidationError()
    _actor_allowed(actor, can_create_governance_draft)
    link = _reload(PublicLink, target_id)
    _check_expected(link, command)
    if link.status != GovernanceStatusChoices.DRAFT:
        raise LifecycleConflictError()
    link.institution = _reload(InstitutionProfile, command.institution_id, lock=False) if command.institution_id else None
    link.office = _reload(OfficeProfile, command.office_id, lock=False) if command.office_id else None
    for field in ("owner_type", "link_type", "label", "url", "placement", "display_order", "effective_from", "effective_until", "source_note"):
        setattr(link, field, getattr(command, field))
    _save(link)
    invalidate_organization_identity_after_commit()
    return link


@transaction.atomic
def activate_public_link(actor, command: LifecycleCommand):
    _actor_allowed(actor, can_activate_governance_record)
    link = _reload(PublicLink, command.target_id)
    _check_expected(link, command)
    if link.status != GovernanceStatusChoices.DRAFT:
        raise LifecycleConflictError()
    if _window_overlaps(
        _public_link_scope_queryset(link),
        start=link.effective_from,
        end=link.effective_until,
        exclude_id=link.pk,
    ).exists():
        raise LifecycleConflictError()
    link.status = GovernanceStatusChoices.ACTIVE
    link.approved_at = timezone.now()
    link.approved_by = actor
    _save(link)
    _audit("GOVERNANCE_ACTIVATE", "PublicLink", link, actor)
    invalidate_organization_identity_after_commit()
    return link


@transaction.atomic
def retire_public_link(actor, command: LifecycleCommand):
    _actor_allowed(actor, can_retire_governance_record)
    link = _reload(PublicLink, command.target_id)
    _check_expected(link, command)
    if link.status != GovernanceStatusChoices.ACTIVE:
        raise LifecycleConflictError()
    link.status = GovernanceStatusChoices.RETIRED
    _save(link)
    _audit("GOVERNANCE_RETIRE", "PublicLink", link, actor, reason_code=command.reason_code)
    invalidate_organization_identity_after_commit()
    return link


@transaction.atomic
def archive_public_link(actor, command: LifecycleCommand):
    _actor_allowed(actor, can_archive_governance_record)
    link = _reload(PublicLink, command.target_id)
    _check_expected(link, command)
    if link.status != GovernanceStatusChoices.RETIRED:
        raise LifecycleConflictError()
    link.status = GovernanceStatusChoices.ARCHIVED
    _save(link)
    _audit("GOVERNANCE_ARCHIVE", "PublicLink", link, actor, reason_code=command.reason_code)
    invalidate_organization_identity_after_commit()
    return link


@transaction.atomic
def create_form_family(actor, command: FormFamilyDraftCommand):
    if not isinstance(command, FormFamilyDraftCommand):
        raise ValidationError()
    _actor_allowed(actor, can_create_governance_draft)
    owner = _reload(OfficeProfile, command.owner_office_id, lock=False) if command.owner_office_id else None
    family = FormFamily(
        stable_key=command.stable_key,
        display_name=command.display_name,
        description=command.description,
        owner_office=owner,
        source_notes=command.source_notes,
        status=GovernanceStatusChoices.DRAFT,
    )
    _save(family)
    _audit("GOVERNANCE_CREATE", "FormFamily", family, actor, stable_key=family.stable_key)
    invalidate_form_metadata_after_commit(family.stable_key)
    return family


@transaction.atomic
def update_form_family_draft(actor, target_id: str, command: FormFamilyDraftCommand):
    if not isinstance(command, FormFamilyDraftCommand):
        raise ValidationError()
    _actor_allowed(actor, can_create_governance_draft)
    family = _reload(FormFamily, target_id)
    _check_expected(family, command)
    if family.status != GovernanceStatusChoices.DRAFT:
        raise LifecycleConflictError()
    old_key = family.stable_key
    family.stable_key = command.stable_key
    family.display_name = command.display_name
    family.description = command.description
    family.owner_office = _reload(OfficeProfile, command.owner_office_id, lock=False) if command.owner_office_id else None
    family.source_notes = command.source_notes
    _save(family)
    invalidate_form_metadata_after_commit(old_key)
    invalidate_form_metadata_after_commit(family.stable_key)
    return family


@transaction.atomic
def activate_form_family(actor, command: LifecycleCommand):
    _actor_allowed(actor, can_activate_governance_record)
    family = _reload(FormFamily, command.target_id)
    _check_expected(family, command)
    if family.status != GovernanceStatusChoices.DRAFT:
        raise LifecycleConflictError()
    family.status = GovernanceStatusChoices.ACTIVE
    _save(family)
    _audit("GOVERNANCE_ACTIVATE", "FormFamily", family, actor, stable_key=family.stable_key)
    invalidate_form_metadata_after_commit(family.stable_key)
    return family


def _transition_form_family(actor, command, expected, new, action, checker):
    _actor_allowed(actor, checker)
    family = _reload(FormFamily, command.target_id)
    _check_expected(family, command)
    if family.status != expected:
        raise LifecycleConflictError()
    family.status = new
    _save(family)
    _audit(action, "FormFamily", family, actor, reason_code=command.reason_code, stable_key=family.stable_key)
    invalidate_form_metadata_after_commit(family.stable_key)
    return family


@transaction.atomic
def retire_form_family(actor, command: LifecycleCommand):
    return _transition_form_family(actor, command, GovernanceStatusChoices.ACTIVE, GovernanceStatusChoices.RETIRED, "GOVERNANCE_RETIRE", can_retire_governance_record)


@transaction.atomic
def archive_form_family(actor, command: LifecycleCommand):
    return _transition_form_family(actor, command, GovernanceStatusChoices.RETIRED, GovernanceStatusChoices.ARCHIVED, "GOVERNANCE_ARCHIVE", can_archive_governance_record)


@transaction.atomic
def mark_form_revision_used_by_id(actor, revision_id: str, *, system_context=False):
    if not can_mark_form_revision_used(actor, system_context=system_context):
        raise PermissionDeniedError()
    revision = _reload(FormRevision, revision_id)
    if revision.status != FormRevisionStatusChoices.ACTIVE:
        raise LifecycleConflictError()
    if not revision.is_used:
        revision.is_used = True
        revision.first_used_at = timezone.now()
        _save(revision, fields=["is_used", "first_used_at", "updated_at"])
        _audit("GOVERNANCE_MARK_USED", "FormRevision", revision, actor, form_code=revision.official_form_code)
    return revision
