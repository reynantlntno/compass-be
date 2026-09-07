# Project: COMPASS
# File: apps/support_needs/services.py
# Module: apps.support_needs
# Purpose: Service layer for student support-need state transitions, policy
#          checks, and audit records.
# Notes: Services accept ``actor + stable support-need ID + typed command``.
#   This domain never imports Inventory models, selectors, or encryption
#   readers; Inventory-derived records are written only through the typed
#   primitives invoked by the ``apps.orchestration`` composition boundary.

import datetime

from apps.common.exceptions import NotFoundError, PermissionDeniedError, ValidationError
from apps.common.django_adapters import ModelValidationError
from django.db import transaction
from django.utils import timezone

from apps.audit.services import audit_log, audit_sensitive_view
from apps.profiles.models import StudentProfile
from apps.support_needs.choices import SupportNeedSourceType, SupportNeedStatus
from apps.support_needs.models import StudentSupportNeed, SupportNeedType
from apps.support_needs.commands import (
    UNSET,
    SupportNeedCreateCommand,
    SupportNeedInventoryReviewCommand,
    SupportNeedMaterializationCommand,
    SupportNeedReasonCommand,
    SupportNeedUpdateCommand,
)
from apps.support_needs.policies import (
    can_archive_support_need,
    can_create_support_need,
    can_dispute_support_need,
    can_mark_support_need_needs_review,
    can_update_support_need,
    can_verify_support_need,
)


CONTROLLED_REASON_CODES = frozenset({
    "routine_review",
    "incorrect_entry",
    "obsolete_data",
    "student_disputed",
    "source_response_changed",
    "inventory_reopened",
    "stale",
    "incorrect",
    "expired",
    "retired",
    "disputed",
    "deactivated",
    "archived",
    "needs_review",
    "other",
})

_LIVE_STATUSES = (
    SupportNeedStatus.DRAFT,
    SupportNeedStatus.ACTIVE,
    SupportNeedStatus.NEEDS_REVIEW,
    SupportNeedStatus.VERIFIED,
)


def _validated_reason_code(reason_code, default):
    """Return a bounded lifecycle reason without accepting free text."""

    value = reason_code or default
    if not isinstance(value, str) or value not in CONTROLLED_REASON_CODES:
        raise ValidationError("Choose an approved reason for this action.")
    return value


def _reason_from_command(command) -> str:
    if command is None:
        return ""
    if not isinstance(command, SupportNeedReasonCommand):
        raise ValidationError("This action requires a typed SupportNeedReasonCommand.")
    return command.reason_code


def locked_support_need(support_need_id):
    """One canonical locked-record helper for every support-need mutation."""

    normalized = str(support_need_id or "").strip()
    if not normalized:
        raise ValidationError("A Student Support Need reference is required.")
    return (
        StudentSupportNeed.objects.select_for_update()
        .select_related("student_profile", "support_need_type")
        .filter(pk=normalized)
        .first()
    )


def _locked_support_need_or_raise(support_need_id):
    record = locked_support_need(support_need_id)
    if record is None:
        raise NotFoundError("Student Support Need not found or access denied.")
    return record


def _persist_support_need(record):
    """Validate and persist without leaking Django model errors."""

    try:
        record.full_clean()
    except ModelValidationError as exc:
        raw_fields = getattr(exc, "message_dict", {})
        field_errors = {
            str(field): [str(message) for message in messages[:3]]
            for field, messages in raw_fields.items()
        }
        raise ValidationError(
            "Student Support Need data is invalid.",
            field_errors=field_errors,
        ) from None
    record.save()
    return record


def _safe_audit_metadata(**values):
    """Allow only non-identifying lifecycle/source codes in generic audits."""

    allowed = {"action", "status", "status_from", "status_to", "source_type", "reason_code", "context"}
    return {key: value for key, value in values.items() if key in allowed and value not in (None, "")}


def _log_denied(actor, action: str, target_object_id="None") -> None:
    audit_log(
        action_type="support_need_access_denied",
        event_category="SECURITY",
        severity="WARNING",
        target_model="StudentSupportNeed",
        target_object_id=str(target_object_id),
        actor_user=actor,
        metadata=_safe_audit_metadata(action=action),
    )


@transaction.atomic
def create_support_need(actor, command: SupportNeedCreateCommand) -> StudentSupportNeed:
    """Create a manual candidate after policy validation.

    Inventory provenance cannot be supplied through this boundary: the
    ``individual_inventory`` source type is reserved for the Inventory
    submission orchestration flow and its typed primitive below.
    """

    if not isinstance(command, SupportNeedCreateCommand):
        raise ValidationError("Support Need creation requires a SupportNeedCreateCommand.")
    if command.source_type == SupportNeedSourceType.INDIVIDUAL_INVENTORY:
        raise ValidationError(
            "Inventory-derived Student Support Needs are created when an Inventory is submitted."
        )

    student_profile = (
        StudentProfile.objects.select_related("user")
        .only("id", "user_id")
        .filter(pk=command.student_profile_id)
        .first()
    )
    support_need_type = (
        SupportNeedType.objects.filter(key=command.support_need_type_key, is_active=True).first()
    )
    if support_need_type is None:
        raise ValidationError("The Student Support Needs catalog is unavailable.")

    if not can_create_support_need(actor, student_profile):
        _log_denied(actor, "create")
        raise PermissionDeniedError(
            "You do not have permission to create Student Support Needs for this student."
        )

    with transaction.atomic():
        # Manual records retain the existing single-active-record rule.
        existing = (
            StudentSupportNeed.objects.select_for_update()
            .filter(
                student_profile=student_profile,
                support_need_type=support_need_type,
                source_inventory_snapshot__isnull=True,
                status__in=_LIVE_STATUSES,
            )
            .first()
        )
        if existing:
            raise ValidationError(
                "An active Student Support Needs record of this type already exists for this student."
            )
        evidence = dict(command.evidence_summary) if command.evidence_summary else None
        support_need = StudentSupportNeed(
            student_profile=student_profile,
            support_need_type=support_need_type,
            status=SupportNeedStatus.DRAFT,
            source_type=command.source_type,
            source_snapshot_label=command.source_snapshot_label or None,
            evidence_summary_json=evidence,
            effective_from=command.effective_from,
            effective_until=command.effective_until,
            review_due_at=command.review_due_at,
            recorded_by=actor,
        )
        _persist_support_need(support_need)

    audit_log(
        action_type="support_need_created",
        event_category="DATA_ACCESS",
        severity="INFO",
        target_model="StudentSupportNeed",
        target_object_id=str(support_need.id),
        actor_user=actor,
        metadata=_safe_audit_metadata(source_type=command.source_type, status=support_need.status)
    )
    return support_need


@transaction.atomic
def update_support_need(
    actor, support_need_id: str, command: SupportNeedUpdateCommand
) -> StudentSupportNeed:
    """Update bounded operational fields only.

    Student, type, source, and provenance bindings are immutable; archived
    records can no longer be edited.
    """

    if not isinstance(command, SupportNeedUpdateCommand):
        raise ValidationError("Support Need updates require a SupportNeedUpdateCommand.")

    with transaction.atomic():
        support_need = _locked_support_need_or_raise(support_need_id)
        if not can_update_support_need(actor, support_need):
            _log_denied(actor, "update", support_need.pk)
            raise PermissionDeniedError("You do not have permission to update this Student Support Need.")
        if support_need.status == SupportNeedStatus.ARCHIVED:
            raise ValidationError("Archived Student Support Needs records cannot be edited.")

        updatable_fields = ["effective_from", "effective_until", "review_due_at", "source_snapshot_label"]
        for field in updatable_fields:
            value = getattr(command, field)
            if value is not UNSET:
                setattr(support_need, field, value or None)

        if command.evidence_summary is not UNSET:
            support_need.evidence_summary_json = (
                dict(command.evidence_summary) if command.evidence_summary else None
            )

        _persist_support_need(support_need)

    audit_log(
        action_type="support_need_updated",
        event_category="DATA_ACCESS",
        severity="INFO",
        target_model="StudentSupportNeed",
        target_object_id=str(support_need.id),
        actor_user=actor,
        metadata=_safe_audit_metadata(status=support_need.status)
    )
    return support_need


@transaction.atomic
def verify_support_need(
    actor, support_need_id: str, command: SupportNeedReasonCommand | None = None,
) -> StudentSupportNeed:
    """Transition a record to the verified state."""

    reason_code = _validated_reason_code(_reason_from_command(command), "routine_review")

    with transaction.atomic():
        support_need = _locked_support_need_or_raise(support_need_id)
        if not can_verify_support_need(actor, support_need):
            _log_denied(actor, "verify", support_need.pk)
            raise PermissionDeniedError("You do not have permission to verify this Student Support Need.")
        if support_need.status not in {
            SupportNeedStatus.DRAFT,
            SupportNeedStatus.ACTIVE,
            SupportNeedStatus.NEEDS_REVIEW,
        }:
            raise ValidationError("This record cannot be verified from its current state.")
        support_need.status = SupportNeedStatus.VERIFIED
        support_need.verified_by = actor
        support_need.verified_at = timezone.now()
        support_need.metadata_json = {**(support_need.metadata_json or {}), "review_code": reason_code}
        _persist_support_need(support_need)

    audit_log(
        action_type="support_need_verified",
        event_category="DATA_ACCESS",
        severity="INFO",
        target_model="StudentSupportNeed",
        target_object_id=str(support_need.id),
        actor_user=actor,
        metadata=_safe_audit_metadata(status=support_need.status, reason_code=reason_code)
    )
    return support_need


@transaction.atomic
def mark_support_need_needs_review(
    actor, support_need_id: str, command: SupportNeedReasonCommand | None = None
) -> StudentSupportNeed:
    """Flag a record as needing review."""

    reason_code = _validated_reason_code(_reason_from_command(command), "needs_review")

    with transaction.atomic():
        support_need = _locked_support_need_or_raise(support_need_id)
        if not can_mark_support_need_needs_review(actor, support_need):
            raise PermissionDeniedError("You do not have permission to modify this Student Support Need.")
        if support_need.status in {SupportNeedStatus.INACTIVE, SupportNeedStatus.ARCHIVED}:
            raise ValidationError("This record cannot be moved to review from its current state.")
        support_need.status = SupportNeedStatus.NEEDS_REVIEW
        support_need.reviewed_by = None
        support_need.reviewed_at = None
        support_need.metadata_json = {
            **(support_need.metadata_json or {}),
            "needs_review_reason": reason_code,
        }
        _persist_support_need(support_need)

    audit_log(
        action_type="support_need_marked_needs_review",
        event_category="DATA_ACCESS",
        severity="INFO",
        target_model="StudentSupportNeed",
        target_object_id=str(support_need.id),
        actor_user=actor,
        metadata=_safe_audit_metadata(reason_code=reason_code, status=support_need.status)
    )
    return support_need


@transaction.atomic
def dispute_support_need(
    actor, support_need_id: str, command: SupportNeedReasonCommand | None = None
) -> StudentSupportNeed:
    """Transition a record to the disputed state."""

    reason_code = _validated_reason_code(_reason_from_command(command), "student_disputed")

    with transaction.atomic():
        support_need = _locked_support_need_or_raise(support_need_id)
        if not can_dispute_support_need(actor, support_need):
            raise PermissionDeniedError("You do not have permission to dispute this Student Support Need.")
        if support_need.status in {SupportNeedStatus.INACTIVE, SupportNeedStatus.ARCHIVED}:
            raise ValidationError("This record cannot be disputed from its current state.")
        support_need.status = SupportNeedStatus.DISPUTED
        support_need.disputed_at = timezone.now()
        support_need.metadata_json = {**(support_need.metadata_json or {}), "dispute_reason": reason_code}
        _persist_support_need(support_need)

    audit_log(
        action_type="support_need_disputed",
        event_category="DATA_ACCESS",
        severity="INFO",
        target_model="StudentSupportNeed",
        target_object_id=str(support_need.id),
        actor_user=actor,
        metadata=_safe_audit_metadata(reason_code=reason_code, status=support_need.status)
    )
    return support_need


@transaction.atomic
def deactivate_support_need(
    actor, support_need_id: str, command: SupportNeedReasonCommand | None = None
) -> StudentSupportNeed:
    """Transition a record to the inactive state."""

    reason_code = _validated_reason_code(_reason_from_command(command), "deactivated")

    with transaction.atomic():
        support_need = _locked_support_need_or_raise(support_need_id)
        if not can_update_support_need(actor, support_need):
            raise PermissionDeniedError("You do not have permission to deactivate this Student Support Need.")
        if support_need.status == SupportNeedStatus.ARCHIVED:
            raise ValidationError("This record is already archived.")
        support_need.status = SupportNeedStatus.INACTIVE
        support_need.metadata_json = {
            **(support_need.metadata_json or {}),
            "deactivation_reason": reason_code,
        }
        _persist_support_need(support_need)

    audit_log(
        action_type="support_need_deactivated",
        event_category="DATA_ACCESS",
        severity="INFO",
        target_model="StudentSupportNeed",
        target_object_id=str(support_need.id),
        actor_user=actor,
        metadata=_safe_audit_metadata(reason_code=reason_code, status=support_need.status)
    )
    return support_need


@transaction.atomic
def archive_support_need(
    actor, support_need_id: str, command: SupportNeedReasonCommand | None = None
) -> StudentSupportNeed:
    """Archive a student support need."""

    reason_code = _validated_reason_code(_reason_from_command(command), "archived")

    with transaction.atomic():
        support_need = _locked_support_need_or_raise(support_need_id)
        if not can_archive_support_need(actor, support_need):
            _log_denied(actor, "archive", support_need.pk)
            raise PermissionDeniedError("You do not have permission to archive this Student Support Need.")
        if support_need.status == SupportNeedStatus.ARCHIVED:
            raise ValidationError("This record is already archived.")
        support_need.status = SupportNeedStatus.ARCHIVED
        support_need.archived_by = actor
        support_need.archived_at = timezone.now()
        support_need.metadata_json = {**(support_need.metadata_json or {}), "archival_reason": reason_code}
        _persist_support_need(support_need)

    audit_log(
        action_type="support_need_archived",
        event_category="DATA_ACCESS",
        severity="INFO",
        target_model="StudentSupportNeed",
        target_object_id=str(support_need.id),
        actor_user=actor,
        metadata=_safe_audit_metadata(reason_code=reason_code, status=support_need.status)
    )
    return support_need


@transaction.atomic
def record_inventory_derived_support_need(
    actor,
    command: SupportNeedMaterializationCommand,
) -> StudentSupportNeed:
    """Typed primitive for the Inventory submission orchestration flow.

    Called only by ``apps.orchestration`` after it has derived a bounded
    candidate.  All provenance arrives as opaque stable references; this
    module imports nothing from the Inventory domain.  Idempotency is
    enforced by locking the existing (snapshot, type) row before writing and
    by the database uniqueness constraint as the final guard.
    """

    if not isinstance(command, SupportNeedMaterializationCommand):
        raise ValidationError(
            "Inventory-derived support needs require a typed materialization command."
        )

    student_profile = StudentProfile.objects.filter(pk=command.student_profile_id).first()
    support_need_type = SupportNeedType.objects.filter(pk=command.support_need_type_id).first()
    if student_profile is None or support_need_type is None:
        raise ValidationError("The Student Support Needs catalog is unavailable.")

    with transaction.atomic():
        support_need = (
            StudentSupportNeed.objects.select_for_update()
            .filter(
                source_inventory_snapshot_id=command.source_inventory_snapshot_id,
                support_need_type=support_need_type,
            )
            .first()
        )
        if support_need is None:
            support_need = StudentSupportNeed(
                student_profile=student_profile,
                support_need_type=support_need_type,
                status=SupportNeedStatus.DRAFT,
                source_type=SupportNeedSourceType.INDIVIDUAL_INVENTORY,
                source_app_label="inventory",
                source_model_name="studentinventorystatushistory",
                source_object_id=command.source_object_id,
                source_snapshot_label=command.source_snapshot_label or None,
                source_inventory_snapshot_id=command.source_inventory_snapshot_id,
                source_submission_history_id=command.source_submission_history_id,
                source_mapping_version=command.source_mapping_version,
                evidence_summary_json=dict(command.evidence_summary),
                # A submission-triggered record is system-derived; do not
                # surface the student's account identity as a human recorder.
                recorded_by=None,
            )
        else:
            # Refresh source evidence/provenance while leaving every counselor
            # lifecycle decision untouched.
            support_need.source_type = SupportNeedSourceType.INDIVIDUAL_INVENTORY
            support_need.source_app_label = "inventory"
            support_need.source_model_name = "studentinventorystatushistory"
            support_need.source_object_id = command.source_object_id
            support_need.source_snapshot_label = command.source_snapshot_label or None
            support_need.source_submission_history_id = command.source_submission_history_id
            support_need.source_mapping_version = command.source_mapping_version
            support_need.evidence_summary_json = dict(command.evidence_summary)
        _persist_support_need(support_need)

    audit_log(
        action_type="support_need_materialized",
        event_category="DATA_ACCESS",
        severity="INFO",
        target_model="StudentSupportNeed",
        target_object_id=str(support_need.pk),
        actor_user=actor,
        metadata=_safe_audit_metadata(
            source_type=SupportNeedSourceType.INDIVIDUAL_INVENTORY,
            status=support_need.status,
        ),
    )
    return support_need


@transaction.atomic
def pause_inventory_derived_records_for_review(
    actor,
    command: SupportNeedInventoryReviewCommand,
) -> list:
    """Reopen-boundary primitive: pause Inventory-derived decisions.

    Locks every live record bound to the given opaque snapshot reference and
    moves it to ``needs_review`` with a controlled reason code.  Called by
    the orchestration composition boundary only.
    """

    if not isinstance(command, SupportNeedInventoryReviewCommand):
        raise ValidationError(
            "Inventory support review requires a typed review command."
        )
    reason_code = _validated_reason_code(command.reason_code, "inventory_reopened")

    queryset = (
        StudentSupportNeed.objects.select_for_update()
        .select_related("support_need_type")
        .filter(
            source_inventory_snapshot_id=command.source_inventory_snapshot_id,
            status__in=[
                SupportNeedStatus.DRAFT,
                SupportNeedStatus.ACTIVE,
                SupportNeedStatus.VERIFIED,
            ],
        )
        .order_by("support_need_type_id")
    )
    if command.support_need_type_ids:
        queryset = queryset.filter(
            support_need_type_id__in=list(command.support_need_type_ids)
        )
    updated = []
    for support_need in queryset:
        support_need.status = SupportNeedStatus.NEEDS_REVIEW
        support_need.reviewed_by = None
        support_need.reviewed_at = None
        support_need.metadata_json = {
            **(support_need.metadata_json or {}),
            "needs_review_reason": "inventory_reopened",
        }
        _persist_support_need(support_need)
        updated.append(support_need)
        audit_log(
            action_type="support_need_inventory_reopened",
            event_category="DATA_ACCESS",
            severity="INFO",
            target_model="StudentSupportNeed",
            target_object_id=str(support_need.pk),
            actor_user=actor,
            metadata=_safe_audit_metadata(
                source_type=SupportNeedSourceType.INDIVIDUAL_INVENTORY,
                status=support_need.status,
                reason_code="inventory_reopened",
            ),
        )
    return updated


def audit_support_need_sensitive_view(actor, support_need: StudentSupportNeed, context: str = None) -> None:
    """Log an audit event when a counselor views sensitive support details."""

    audit_sensitive_view(
        actor_user=actor,
        target_model="StudentSupportNeed",
        target_object_id=str(support_need.id),
        metadata=_safe_audit_metadata(context=context or "detail"),
    )
