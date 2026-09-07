"""Stable-ID lifecycle services for academic terms and form revisions."""

from __future__ import annotations

from pathlib import Path

from django.conf import settings
from django.core import exceptions as django_exceptions
from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.access_control.rules import is_active_nonlegacy_actor
from apps.audit.services import audit_log
from apps.common.exceptions import (
    DependencyFailureError,
    LifecycleConflictError,
    NotFoundError,
    PermissionDeniedError,
    StaleStateError,
    ValidationError,
)
from apps.common.lifecycle import LifecycleContract
from apps.documents.governance import get_document_family
from apps.documents.models import DocumentTemplateVersion, TemplateStatusChoices
from apps.organizations.cache import invalidate_form_metadata_after_commit
from apps.organizations.commands import (
    AcademicTermDraftCommand,
    FormRevisionDraftCommand,
    FormRevisionSourceCommand,
    LifecycleCommand,
    RolloverPreviewCommand,
    RollbackCommand,
)
from apps.organizations.models import (
    AcademicTerm,
    AcademicTermStatusChoices,
    AcademicTermTransition,
    ActivationRegisterEntry,
    ActivationRegisterStatusChoices,
    ActivationRegisterTransition,
    FormFamily,
    FormRevision,
    FormRevisionStatusChoices,
    GovernanceStatusChoices,
    academic_term_lifecycle_write,
)
from apps.organizations.policies import (
    can_approve_office_governance,
    can_mark_form_revision_used,
    can_prepare_office_governance,
)
from apps.system.readiness_services import release_identity


_SOURCE_APP = "apps.organizations"

_ACADEMIC_TERM_LIFECYCLE = LifecycleContract(
    "organizations.academic_term",
    {
        "": {AcademicTermStatusChoices.DRAFT},
        AcademicTermStatusChoices.DRAFT: {
            AcademicTermStatusChoices.DRAFT,
            AcademicTermStatusChoices.PENDING_APPROVAL,
        },
        AcademicTermStatusChoices.PENDING_APPROVAL: {
            AcademicTermStatusChoices.PENDING_APPROVAL,
            AcademicTermStatusChoices.DRAFT,
            AcademicTermStatusChoices.APPROVED,
        },
        AcademicTermStatusChoices.APPROVED: {
            AcademicTermStatusChoices.APPROVED,
            AcademicTermStatusChoices.ACTIVE,
        },
        AcademicTermStatusChoices.ACTIVE: {
            AcademicTermStatusChoices.ACTIVE,
            AcademicTermStatusChoices.CLOSED,
        },
        AcademicTermStatusChoices.CLOSED: {
            AcademicTermStatusChoices.CLOSED,
            AcademicTermStatusChoices.ACTIVE,
            AcademicTermStatusChoices.ARCHIVED,
        },
        AcademicTermStatusChoices.ARCHIVED: set(),
    },
)


def _validate_term_transition(from_status, to_status):
    _ACADEMIC_TERM_LIFECYCLE.validate_transition(
        str(from_status or ""),
        str(to_status),
    )


def _allowed(actor, *, approve=False):
    if not is_active_nonlegacy_actor(actor):
        raise PermissionDeniedError()
    if not (can_approve_office_governance(actor) if approve else can_prepare_office_governance(actor)):
        raise PermissionDeniedError()


def _validation(exc):
    values = getattr(exc, "message_dict", {})
    return ValidationError(field_errors=values if isinstance(values, dict) else {})


def _save(instance, fields=None):
    try:
        instance.full_clean()
        if isinstance(instance, AcademicTerm):
            with academic_term_lifecycle_write():
                instance.save(update_fields=fields) if fields else instance.save()
        else:
            instance.save(update_fields=fields) if fields else instance.save()
    except django_exceptions.ValidationError as exc:
        raise _validation(exc) from exc
    except IntegrityError as exc:
        raise LifecycleConflictError() from exc


def _get(model, target_id, *, lock=True, related=()):
    manager = model.objects.select_related(*related)
    if lock:
        manager = manager.select_for_update()
    try:
        return manager.get(pk=target_id)
    except model.DoesNotExist as exc:
        raise NotFoundError() from exc


def _check_expected(target, command):
    if getattr(command, "expected_status", None) and target.status != command.expected_status:
        raise StaleStateError()
    if getattr(command, "expected_updated_at", None) and target.updated_at != command.expected_updated_at:
        raise StaleStateError()


def _term_meta(term):
    return {
        "model": "AcademicTerm",
        "object_id": str(term.pk),
        "academic_year": term.academic_year[:20],
        "semester": term.semester[:100],
        "status": term.status,
        "configuration_identifier": term.configuration_identifier[:160],
    }


def _term_audit(action, term, actor, reason_code):
    audit_log(
        action_type=action,
        event_category="GOVERNANCE",
        target_model="organizations.AcademicTerm",
        target_object_id=str(term.pk),
        actor_user=actor,
        source_app=_SOURCE_APP,
        metadata={**_term_meta(term), "reason_code": reason_code[:80]},
    )


def _term_transition(term, from_status, actor, action, reason_code, evidence=None):
    identity = release_identity()
    return AcademicTermTransition.objects.create(
        term=term,
        action=action,
        from_status=from_status or "",
        to_status=term.status,
        actor_user=actor,
        reason_code=reason_code[:80],
        configuration_identifier=term.configuration_identifier[:160],
        effective_at=timezone.now(),
        rollback_condition="Only before dependent records exist and while the prior term remains applicable.",
        rollback_reference="academic_term.rollback.runbook",
        release_version=identity.get("version", "")[:64],
        build_id=identity.get("build_id", "")[:128],
        safe_evidence=evidence or {},
    )


@transaction.atomic
def create_academic_term_draft(actor, command: AcademicTermDraftCommand):
    if not isinstance(command, AcademicTermDraftCommand):
        raise ValidationError()
    _allowed(actor)
    term = AcademicTerm(
        academic_year=command.academic_year,
        semester=command.semester,
        start_date=command.start_date,
        end_date=command.end_date,
        configuration_identifier=command.configuration_identifier,
        source_reference=command.source_reference,
        source_note=command.source_note,
        status=AcademicTermStatusChoices.DRAFT,
    )
    _validate_term_transition("", term.status)
    _save(term)
    _term_transition(term, "", actor, "CREATED", "TERM_DRAFT_CREATED")
    _term_audit("ACADEMIC_TERM_DRAFT_CREATED", term, actor, "TERM_DRAFT_CREATED")
    return term


@transaction.atomic
def update_academic_term_draft(actor, target_id: str, command: AcademicTermDraftCommand):
    if not isinstance(command, AcademicTermDraftCommand):
        raise ValidationError()
    _allowed(actor)
    term = _get(AcademicTerm, target_id)
    _check_expected(term, command)
    if term.status != AcademicTermStatusChoices.DRAFT:
        raise LifecycleConflictError()
    for field in ("academic_year", "semester", "start_date", "end_date", "configuration_identifier", "source_reference", "source_note"):
        setattr(term, field, getattr(command, field))
    _save(term)
    return term


@transaction.atomic
def submit_academic_term_for_approval(actor, command: LifecycleCommand):
    _allowed(actor)
    term = _get(AcademicTerm, command.target_id)
    _check_expected(term, command)
    if term.status != AcademicTermStatusChoices.DRAFT:
        raise LifecycleConflictError()
    old = term.status
    _validate_term_transition(old, AcademicTermStatusChoices.PENDING_APPROVAL)
    term.status = AcademicTermStatusChoices.PENDING_APPROVAL
    _save(term, ["status", "updated_at"])
    _term_transition(term, old, actor, "SUBMITTED", command.reason_code or "TERM_SUBMITTED")
    return term


@transaction.atomic
def approve_academic_term(actor, command: LifecycleCommand):
    _allowed(actor, approve=True)
    term = _get(AcademicTerm, command.target_id)
    _check_expected(term, command)
    if term.status != AcademicTermStatusChoices.PENDING_APPROVAL:
        raise LifecycleConflictError()
    old = term.status
    _validate_term_transition(old, AcademicTermStatusChoices.APPROVED)
    term.status = AcademicTermStatusChoices.APPROVED
    term.approved_by = actor
    term.approved_at = timezone.now()
    _save(term, ["status", "approved_by", "approved_at", "updated_at"])
    _term_transition(term, old, actor, "APPROVED", command.reason_code or "TERM_APPROVED")
    return term


@transaction.atomic
def activate_academic_term(actor, command: LifecycleCommand):
    _allowed(actor, approve=True)
    candidate = _get(AcademicTerm, command.target_id)
    _check_expected(candidate, command)
    if candidate.status != AcademicTermStatusChoices.APPROVED:
        raise LifecycleConflictError()
    if not candidate.configuration_identifier:
        raise ValidationError()
    current = AcademicTerm.objects.select_for_update().filter(status=AcademicTermStatusChoices.ACTIVE).exclude(pk=candidate.pk).first()
    now = timezone.now()
    if current:
        old = current.status
        _validate_term_transition(old, AcademicTermStatusChoices.CLOSED)
        current.status = AcademicTermStatusChoices.CLOSED
        current.closed_by = actor
        current.closed_at = now
        _save(current, ["status", "closed_by", "closed_at", "updated_at"])
        _term_transition(current, old, actor, "CLOSED_BY_ROLLOVER", "TERM_ROLLOVER_CLOSED")
    old = candidate.status
    _validate_term_transition(old, AcademicTermStatusChoices.ACTIVE)
    candidate.status = AcademicTermStatusChoices.ACTIVE
    candidate.activated_by = actor
    candidate.activated_at = now
    _save(candidate, ["status", "activated_by", "activated_at", "updated_at"])
    _term_transition(candidate, old, actor, "ACTIVATED", command.reason_code or "TERM_ACTIVATED", {"prior_term_closed": bool(current)})
    _term_audit("ACADEMIC_TERM_ACTIVATED", candidate, actor, command.reason_code or "TERM_ACTIVATED")
    return candidate


@transaction.atomic
def close_academic_term(actor, command: LifecycleCommand):
    _allowed(actor, approve=True)
    term = _get(AcademicTerm, command.target_id)
    _check_expected(term, command)
    if term.status != AcademicTermStatusChoices.ACTIVE:
        raise LifecycleConflictError()
    old = term.status
    _validate_term_transition(old, AcademicTermStatusChoices.CLOSED)
    term.status = AcademicTermStatusChoices.CLOSED
    term.closed_by = actor
    term.closed_at = timezone.now()
    _save(term, ["status", "closed_by", "closed_at", "updated_at"])
    _term_transition(term, old, actor, "CLOSED", command.reason_code or "TERM_CLOSED")
    return term


@transaction.atomic
def archive_academic_term(actor, command: LifecycleCommand):
    _allowed(actor, approve=True)
    term = _get(AcademicTerm, command.target_id)
    _check_expected(term, command)
    if term.status != AcademicTermStatusChoices.CLOSED:
        raise LifecycleConflictError()
    old = term.status
    _validate_term_transition(old, AcademicTermStatusChoices.ARCHIVED)
    term.status = AcademicTermStatusChoices.ARCHIVED
    _save(term, ["status", "updated_at"])
    _term_transition(term, old, actor, "ARCHIVED", command.reason_code or "TERM_ARCHIVED")
    return term


def _term_provider_counts(term):
    providers = []
    checks = (
        ("inventory", "apps.inventory.models", "academic_year"),
        ("reports", "apps.reports.models", "academic_year"),
        ("exit_interview", "apps.exit_interviews.models", "academic_year"),
        ("graduate_tracer", "apps.graduate_tracer.models", "academic_year"),
        ("collections", "apps.form_collection.models", "academic_year"),
    )
    for key, module_name, field_name in checks:
        result = {"key": key, "status": "NOT_CONFIGURED", "count": 0}
        try:
            module = __import__(module_name, fromlist=["*"])
            candidates = [model for name in dir(module) if not name.startswith("_") for model in [getattr(module, name)] if hasattr(model, "_meta") and any(field.name == field_name for field in model._meta.fields)]
            if not candidates:
                result["status"] = "NO_TERM_FIELD"
            else:
                result.update(status="READY", count=min(sum(model.objects.filter(**{field_name: term.academic_year}).count() for model in candidates[:4]), 100000))
        except Exception:
            result.update(status="BLOCKED", reason_code="PROVIDER_UNAVAILABLE")
        providers.append(result)
    providers.append({
        "key": "lifecycle_rules",
        "status": "READY",
        "count": 0,
        "reason_code": "METADATA_ONLY_PROVIDER",
    })
    return providers


def build_term_rollover_preview(actor, command: RolloverPreviewCommand):
    if not isinstance(command, RolloverPreviewCommand):
        raise ValidationError()
    _allowed(actor, approve=True)
    term = _get(AcademicTerm, command.term_id, lock=False)
    prior = _get(AcademicTerm, command.prior_term_id, lock=False) if command.prior_term_id else None
    return {
        "academic_year": term.academic_year,
        "semester": term.semester,
        "prior_term": prior.academic_year if prior else "",
        "providers": _term_provider_counts(term),
        "rollback": {
            "status": "PENDING_REVIEW",
            "condition": "Prior term dates must remain applicable and no dependent records may exist under the new term.",
            "reference": "academic_term.rollback.runbook",
        },
    }


@transaction.atomic
def rollback_academic_term(actor, command: RollbackCommand):
    _allowed(actor, approve=True)
    active = _get(AcademicTerm, command.term_id)
    prior = _get(AcademicTerm, command.prior_term_id)
    _check_expected(active, command)
    if active.status != AcademicTermStatusChoices.ACTIVE or prior.status != AcademicTermStatusChoices.CLOSED:
        raise LifecycleConflictError()
    today = timezone.localdate()
    if not prior.start_date <= today <= prior.end_date:
        raise LifecycleConflictError()
    preview = build_term_rollover_preview(actor, RolloverPreviewCommand(command.term_id, command.prior_term_id))
    if any(item.get("status") == "BLOCKED" or item.get("count", 0) for item in preview["providers"]):
        raise LifecycleConflictError()
    _validate_term_transition(AcademicTermStatusChoices.ACTIVE, AcademicTermStatusChoices.CLOSED)
    active.status = AcademicTermStatusChoices.CLOSED
    active.closed_by = actor
    active.closed_at = timezone.now()
    _save(active, ["status", "closed_by", "closed_at", "updated_at"])
    _validate_term_transition(AcademicTermStatusChoices.CLOSED, AcademicTermStatusChoices.ACTIVE)
    prior.status = AcademicTermStatusChoices.ACTIVE
    prior.activated_by = actor
    prior.activated_at = timezone.now()
    _save(prior, ["status", "activated_by", "activated_at", "updated_at"])
    _term_transition(active, AcademicTermStatusChoices.ACTIVE, actor, "ROLLED_BACK", command.reason_code, {"restored_term": prior.academic_year})
    return prior


def _revision_meta(revision):
    return {
        "model": "FormRevision",
        "object_id": str(revision.pk),
        "family": revision.form_family.stable_key,
        "status": revision.status,
        "official_revision": revision.official_revision[:50],
        "is_used": bool(revision.is_used),
    }


def _revision_audit(action, revision, actor, reason_code=""):
    audit_log(
        action_type=action,
        event_category="GOVERNANCE",
        target_model="organizations.FormRevision",
        target_object_id=str(revision.pk),
        actor_user=actor,
        source_app=_SOURCE_APP,
        metadata={**_revision_meta(revision), "reason_code": reason_code[:80]},
    )


@transaction.atomic
def create_form_revision_draft(actor, command: FormRevisionDraftCommand):
    if not isinstance(command, FormRevisionDraftCommand):
        raise ValidationError()
    _allowed(actor)
    family = _get(FormFamily, command.form_family_id)
    revision = FormRevision(
        form_family=family,
        official_form_code=command.official_form_code,
        official_revision=command.official_revision,
        internal_schema_version=command.internal_schema_version,
        internal_template_version=command.internal_template_version,
        display_title=command.display_title,
        institution_profile_id=command.institution_profile_id,
        office_profile_id=command.office_profile_id,
        source_document_reference=command.source_document_reference,
        source_label=command.source_label,
        schema_summary_json={
            "fields": [
                {
                    "key": field.key,
                    "name": field.name,
                    "type": field.type,
                    "label": field.label,
                    "required": field.required,
                    "options": [{"value": option.value, "label": option.label} for option in field.options],
                    "max_length": field.max_length,
                }
                for field in command.schema_summary
            ]
        },
        printable_template_path=command.printable_template_path,
        source_notes=command.source_notes,
        effective_from=command.effective_from,
        effective_until=command.effective_until,
        status=FormRevisionStatusChoices.DRAFT,
    )
    _save(revision)
    _revision_audit("GOVERNANCE_CREATE", revision, actor)
    invalidate_form_metadata_after_commit(family.stable_key)
    return revision


@transaction.atomic
def update_form_revision_draft(actor, target_id: str, command: FormRevisionDraftCommand):
    if not isinstance(command, FormRevisionDraftCommand):
        raise ValidationError()
    _allowed(actor)
    revision = _get(FormRevision, target_id, related=("form_family",))
    _check_expected(revision, command)
    if revision.status != FormRevisionStatusChoices.DRAFT or revision.is_used:
        raise LifecycleConflictError()
    if str(revision.form_family_id) != str(command.form_family_id):
        raise ValidationError()
    for field in ("official_form_code", "official_revision", "internal_schema_version", "internal_template_version", "display_title", "source_document_reference", "source_label", "printable_template_path", "source_notes", "effective_from", "effective_until"):
        setattr(revision, field, getattr(command, field))
    revision.institution_profile_id = command.institution_profile_id
    revision.office_profile_id = command.office_profile_id
    revision.schema_summary_json = {
        "fields": [
            {
                "key": field.key,
                "name": field.name,
                "type": field.type,
                "label": field.label,
                "required": field.required,
                "options": [{"value": option.value, "label": option.label} for option in field.options],
                "max_length": field.max_length,
            }
            for field in command.schema_summary
        ]
    }
    _save(revision)
    invalidate_form_metadata_after_commit(revision.form_family.stable_key)
    return revision


def _form_revision_activation_preflight(revision):
    blockers = []
    family = revision.form_family
    if family.status != GovernanceStatusChoices.ACTIVE:
        blockers.append("FORM_FAMILY_NOT_ACTIVE")
    if not revision.effective_from:
        blockers.append("EFFECTIVE_DATE_MISSING")
    try:
        definition = get_document_family(family.stable_key)
    except (TypeError, ValueError, LookupError):
        definition = None
        blockers.append("UNKNOWN_DOCUMENT_FAMILY")
    if definition:
        if getattr(definition, "official_form_code", None) and not revision.official_form_code:
            blockers.append("OFFICIAL_CODE_MISSING")
        if getattr(definition, "official_revision", None) and not revision.official_revision:
            blockers.append("OFFICIAL_REVISION_MISSING")
    if not revision.source_document_reference and not revision.source_protected_file_id:
        blockers.append("CONTROLLING_SOURCE_MISSING")
    elif revision.source_document_reference and not revision.source_protected_file_id:
        source = revision.source_document_reference.strip()
        if source.startswith("/") or ".." in Path(source).parts:
            blockers.append("CONTROLLING_SOURCE_PATH_UNSAFE")
        elif source.startswith("docs/") and not (Path(settings.BASE_DIR) / source).is_file():
            blockers.append("CONTROLLING_SOURCE_NOT_READY")
    if not revision.internal_template_version and not revision.printable_template_path:
        blockers.append("TEMPLATE_VERSION_MISSING")
    if not revision.institution_profile_id or not revision.office_profile_id:
        blockers.append("IDENTITY_PROFILE_MISSING")
    template_ready = DocumentTemplateVersion.objects.filter(related_form_revision=revision, status=TemplateStatusChoices.ACTIVE).exists()
    if not template_ready and not revision.printable_template_path:
        blockers.append("DOCUMENT_TEMPLATE_NOT_READY")
    return {"ready": not blockers, "blockers": blockers, "status": "READY" if not blockers else "BLOCKED", "safe_template": bool(template_ready or revision.printable_template_path)}


def form_revision_activation_preflight(actor, command: LifecycleCommand):
    _allowed(actor, approve=True)
    revision = _get(FormRevision, command.target_id, lock=False, related=("form_family",))
    return _form_revision_activation_preflight(revision)


@transaction.atomic
def submit_form_revision_for_approval(actor, command: LifecycleCommand):
    _allowed(actor)
    revision = _get(FormRevision, command.target_id, related=("form_family",))
    _check_expected(revision, command)
    if revision.status != FormRevisionStatusChoices.DRAFT:
        raise LifecycleConflictError()
    revision.status = FormRevisionStatusChoices.PENDING_APPROVAL
    revision.submitted_by = actor
    revision.submitted_at = timezone.now()
    _save(revision, ["status", "submitted_by", "submitted_at", "updated_at"])
    _revision_audit("FORM_REVISION_SUBMITTED", revision, actor, command.reason_code)
    return revision


@transaction.atomic
def approve_form_revision(actor, command: LifecycleCommand):
    _allowed(actor, approve=True)
    revision = _get(FormRevision, command.target_id, related=("form_family",))
    _check_expected(revision, command)
    if revision.status != FormRevisionStatusChoices.PENDING_APPROVAL:
        raise LifecycleConflictError()
    revision.status = FormRevisionStatusChoices.APPROVED
    revision.approved_by = actor
    revision.approved_at = timezone.now()
    _save(revision, ["status", "approved_by", "approved_at", "updated_at"])
    _revision_audit("FORM_REVISION_APPROVED", revision, actor, command.reason_code)
    return revision


@transaction.atomic
def activate_form_revision(actor, command: LifecycleCommand):
    _allowed(actor, approve=True)
    revision = _get(FormRevision, command.target_id, related=("form_family", "institution_profile", "office_profile"))
    _check_expected(revision, command)
    if revision.status != FormRevisionStatusChoices.APPROVED or revision.is_used:
        raise LifecycleConflictError()
    preflight = _form_revision_activation_preflight(revision)
    if not preflight["ready"]:
        raise ValidationError(field_errors={"activation": preflight["blockers"]})
    family = _get(FormFamily, revision.form_family_id)
    if FormRevision.objects.select_for_update().filter(form_family_id=family.pk, status=FormRevisionStatusChoices.ACTIVE).exists():
        raise LifecycleConflictError()
    from apps.organizations.selectors import build_institution_profile_snapshot, build_office_profile_snapshot
    revision.institution_profile_snapshot = build_institution_profile_snapshot(revision.institution_profile)
    revision.office_profile_snapshot = build_office_profile_snapshot(revision.office_profile)
    revision.status = FormRevisionStatusChoices.ACTIVE
    revision.activated_by = actor
    revision.activated_at = timezone.now()
    _save(revision)
    family.status = GovernanceStatusChoices.ACTIVE
    family.current_active_revision_id = revision.pk
    _save(family, ["status", "current_active_revision", "updated_at"])
    _revision_audit("FORM_REVISION_ACTIVATED", revision, actor, command.reason_code)
    invalidate_form_metadata_after_commit(family.stable_key)
    return revision


@transaction.atomic
def retire_form_revision(actor, command: LifecycleCommand):
    _allowed(actor, approve=True)
    revision = _get(FormRevision, command.target_id, related=("form_family",))
    _check_expected(revision, command)
    if revision.status != FormRevisionStatusChoices.ACTIVE:
        raise LifecycleConflictError()
    revision.status = FormRevisionStatusChoices.RETIRED
    revision.retired_by = actor
    revision.retired_at = timezone.now()
    _save(revision, ["status", "retired_by", "retired_at", "updated_at"])
    family = _get(FormFamily, revision.form_family_id)
    if family.current_active_revision_id == revision.pk:
        family.current_active_revision_id = None
        _save(family, ["current_active_revision", "updated_at"])
    _revision_audit("FORM_REVISION_RETIRED", revision, actor, command.reason_code)
    invalidate_form_metadata_after_commit(family.stable_key)
    return revision


@transaction.atomic
def archive_form_revision(actor, command: LifecycleCommand):
    _allowed(actor, approve=True)
    revision = _get(FormRevision, command.target_id, related=("form_family",))
    _check_expected(revision, command)
    if revision.status != FormRevisionStatusChoices.RETIRED:
        raise LifecycleConflictError()
    revision.status = FormRevisionStatusChoices.ARCHIVED
    _save(revision, ["status", "updated_at"])
    _revision_audit("FORM_REVISION_ARCHIVED", revision, actor, command.reason_code)
    invalidate_form_metadata_after_commit(revision.form_family.stable_key)
    return revision


@transaction.atomic
def clone_form_revision(actor, command: LifecycleCommand):
    _allowed(actor)
    source = _get(FormRevision, command.target_id, related=("form_family",))
    _check_expected(source, command)
    if source.status not in {FormRevisionStatusChoices.ACTIVE, FormRevisionStatusChoices.RETIRED}:
        raise LifecycleConflictError()
    count = FormRevision.objects.filter(form_family_id=source.form_family_id, official_form_code=source.official_form_code, official_revision=source.official_revision).count()
    clone = FormRevision(
        form_family=source.form_family,
        official_form_code=source.official_form_code,
        legacy_form_code=source.legacy_form_code,
        official_revision=source.official_revision,
        internal_schema_version=f"{source.internal_schema_version}-draft-{count + 1}",
        internal_template_version=source.internal_template_version,
        display_title=source.display_title,
        institution_profile_id=source.institution_profile_id,
        office_profile_id=source.office_profile_id,
        source_document_reference=source.source_document_reference,
        source_notes=f"Cloned from revision {source.pk}.",
        source_protected_file_id=source.source_protected_file_id,
        source_label=source.source_label,
        source_checksum=source.source_checksum,
        schema_summary_json=source.schema_summary_json,
        printable_template_path=source.printable_template_path,
        effective_from=source.effective_from,
        effective_until=source.effective_until,
        status=FormRevisionStatusChoices.DRAFT,
    )
    _save(clone)
    _revision_audit("FORM_REVISION_CLONED", clone, actor)
    invalidate_form_metadata_after_commit(source.form_family.stable_key)
    return clone


@transaction.atomic
def attach_form_revision_source(actor, command: FormRevisionSourceCommand):
    if not isinstance(command, FormRevisionSourceCommand):
        raise ValidationError()
    _allowed(actor)
    if not command.upload_receipt_id:
        raise ValidationError()
    revision = _get(FormRevision, command.revision_id, related=("form_family",))
    _check_expected(revision, command)
    if revision.status != FormRevisionStatusChoices.DRAFT:
        raise LifecycleConflictError()
    from apps.security.models import FileStatusChoices, ProtectedFile, PurposeChoices
    try:
        protected = ProtectedFile.objects.select_for_update().get(pk=command.upload_receipt_id)
    except ProtectedFile.DoesNotExist as exc:
        raise NotFoundError() from exc
    if protected.status != FileStatusChoices.ACTIVE or protected.purpose != PurposeChoices.FORM_SOURCE_ATTACHMENT:
        raise ValidationError()
    revision.source_protected_file = protected
    revision.source_label = command.source_label or protected.original_filename_display or "Source attachment"
    revision.source_checksum = protected.checksum_sha256
    _save(revision, ["source_protected_file", "source_label", "source_checksum", "updated_at"])
    _revision_audit("FORM_REVISION_SOURCE_ATTACHED", revision, actor)
    return revision


REGISTER_CATALOG = (
    ("student-guidance-workspace", "Student Guidance Workspace", "POLICY", "portal.student_guidance", "Head Guidance", "student_guidance.workspace"),
    ("good-moral-exit-prerequisite", "Exit Interview prerequisite", "POLICY_CENTER", "good_moral.exit_prerequisite", "Head Guidance", "good_moral.exit_prerequisite"),
    ("academic-term", "Academic term", "DATABASE_MODEL", "organizations.AcademicTerm", "Head Guidance", "academic_term"),
    ("form-document-readiness", "Form and document readiness", "DATABASE_MODEL", "organizations.FormRevision", "Head Guidance", "forms.readiness"),
    ("release-identity", "Release identity", "DEPLOYMENT_CONFIG", "COMPASS_RELEASE_VERSION+COMPASS_BUILD_ID", "IT Admin", "release.identity"),
    ("worker-outbox", "Worker and outbox", "RUNTIME_HEALTH", "notifications.OutboxEvent", "IT Admin", "notifications.worker"),
    ("maintenance-backup", "Maintenance and backup", "RUNTIME_HEALTH", "system+backups", "IT Admin", "operations.backup_maintenance"),
    ("feature-flags", "Feature flags", "POLICY_CENTER", "system.feature_flags", "IT Admin", "system.feature_flags"),
    ("unlinked-assets", "Provisional asset readiness", "DATABASE_MODEL", "organizations.BrandAsset", "Head Guidance", "branding.asset"),
)


@transaction.atomic
def seed_activation_register(actor=None):
    created = 0
    for stable_key, title, source_kind, source_key, owner_role, configuration_identifier in REGISTER_CATALOG:
        entry, was_created = ActivationRegisterEntry.objects.get_or_create(
            stable_key=stable_key,
            defaults={
                "title": title,
                "item_type": "POLICY" if "policy" in stable_key else "READINESS",
                "status": ActivationRegisterStatusChoices.PROPOSED,
                "source_kind": source_kind,
                "source_key": source_key,
                "owner_role": owner_role,
                "configuration_identifier": configuration_identifier,
                "rollback_condition": "Use the governance corrective runbook; no automatic rollback.",
            },
        )
        if was_created:
            created += 1
            ActivationRegisterTransition.objects.create(
                entry=entry,
                from_status="",
                to_status=entry.status,
                actor_user=actor,
                reason_code="REGISTER_CATALOG_SEEDED",
                configuration_identifier=configuration_identifier,
                evidence={},
            )
    return created
