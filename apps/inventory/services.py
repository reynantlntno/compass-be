# Project: COMPASS
# File: apps/inventory/services.py
# Module: apps.inventory
# Purpose: Service layer for managing StudentInventorySnapshot workflows.
# Domain boundary and service policy.
# Notes: Services accept ``actor + stable snapshot ID (or academic year) +
#   typed command`` only.  Cross-domain workflows (support-need
#   materialization, privacy acceptance, report projection facts) belong to
#   ``apps.orchestration`` and are never invoked from this module.

from django.core import signing
from django.db import transaction
from django.utils import timezone

from apps.common.exceptions import (
    PermissionDeniedError,
    StaleStateError,
    ValidationError,
    WorkflowError,
)
from apps.audit.services import audit_status_transition
from apps.access_control.rules import (
    is_active_nonlegacy_actor,
    is_student,
    owns_student_profile,
)
from apps.inventory.models import (
    StudentInventorySnapshot,
    StudentInventoryStatusHistory,
    InventoryStatusChoices,
    INVENTORY_SCHEMA_VERSION,
)
from apps.inventory.commands import (
    InventoryDraftCommand,
    InventoryDraftCreateCommand,
    InventoryReopenCommand,
    InventorySubmitCommand,
)
from apps.inventory.policies import can_reopen_inventory
from apps.organizations.academic_year import validate_academic_year
from apps.inventory.encryption import (
    InventoryEncryptionError,
    create_confidential_snapshot,
    record_reopen_reason,
    read_confidential_snapshot,
    update_draft_data,
    validate_snapshot_before_submit,
)
from apps.profiles.models import StudentProfile
from apps.security.exceptions import FieldEncryptionError


REOPEN_STATE_SALT = "compass.inventory.reopen-state.v1"
REOPEN_STATE_MAX_AGE = 24 * 60 * 60


def _raise_confidential_validation_error():
    raise ValidationError("Inventory confidential data is unavailable.")


def _require_active_actor(actor):
    """Validate an active, non-legacy actor before any state change."""

    if actor is None or not is_active_nonlegacy_actor(actor):
        raise PermissionDeniedError("An active account is required for this action.")
    return actor


def _own_student_profile(actor) -> StudentProfile:
    """Resolve the acting student's own profile; students never act on others."""

    profile = StudentProfile.objects.filter(user=actor).only("id", "user_id").first()
    if profile is None or not owns_student_profile(actor, profile):
        raise PermissionDeniedError("You do not have an Individual Inventory record.")
    return profile


def locked_inventory_snapshot(snapshot_id):
    """One canonical locked-snapshot helper for every inventory mutation."""

    normalized = str(snapshot_id or "").strip()
    if not normalized:
        raise ValidationError("An inventory snapshot reference is required.")
    return (
        StudentInventorySnapshot.objects.select_for_update()
        .select_related("student_profile", "student_profile__user")
        .filter(pk=normalized)
        .first()
    )


def _locked_snapshot_or_raise(snapshot_id):
    snapshot = locked_inventory_snapshot(snapshot_id)
    if snapshot is None:
        raise WorkflowError("The inventory snapshot was not found.")
    return snapshot


def _assert_expected_updated_at(snapshot, expected_updated_at) -> None:
    """Reject writes based on an older observed state."""

    if not expected_updated_at:
        return
    current = snapshot.updated_at.isoformat() if snapshot.updated_at else ""
    if current != str(expected_updated_at):
        raise StaleStateError("The inventory snapshot changed before this update.")


def build_inventory_reopen_state_token(snapshot) -> str:
    """Create a signed optimistic-concurrency token for the review form."""

    return signing.dumps(
        {
            "snapshot_id": snapshot.pk,
            "status": snapshot.status,
            "submitted_at": snapshot.submitted_at.isoformat() if snapshot.submitted_at else "",
            "updated_at": snapshot.updated_at.isoformat() if snapshot.updated_at else "",
        },
        salt=REOPEN_STATE_SALT,
    )


def _assert_reopen_state_token(snapshot, token: str) -> None:
    if not token:
        return
    try:
        payload = signing.loads(token, salt=REOPEN_STATE_SALT, max_age=REOPEN_STATE_MAX_AGE)
    except (signing.BadSignature, signing.SignatureExpired, TypeError, ValueError):
        raise WorkflowError("This correction request is no longer current.") from None
    expected = {
        "snapshot_id": snapshot.pk,
        "status": snapshot.status,
        "submitted_at": snapshot.submitted_at.isoformat() if snapshot.submitted_at else "",
        "updated_at": snapshot.updated_at.isoformat() if snapshot.updated_at else "",
    }
    if payload != expected:
        raise WorkflowError("This correction request is no longer current.")


def _next_submission_sequence(snapshot) -> int:
    latest = (
        StudentInventoryStatusHistory.objects.filter(
            snapshot=snapshot,
            to_status=InventoryStatusChoices.SUBMITTED,
        )
        .order_by("-submission_sequence")
        .values_list("submission_sequence", flat=True)
        .first()
    )
    return (latest or 0) + 1


def latest_submission_history(snapshot):
    """Return the newest submitted history row for a snapshot."""

    return (
        StudentInventoryStatusHistory.objects.filter(
            snapshot=snapshot,
            to_status=InventoryStatusChoices.SUBMITTED,
        )
        .order_by("-submission_sequence")
        .first()
    )


def _record_submission_history(
    snapshot,
    *,
    actor_user,
    status_from: str,
    transitioned_at=None,
    is_baseline: bool = False,
):
    """Persist one encrypted immutable copy of a locked submission."""

    try:
        confidential = read_confidential_snapshot(snapshot)
        history = StudentInventoryStatusHistory.objects.create(
            snapshot=snapshot,
            from_status="" if is_baseline else status_from,
            to_status=InventoryStatusChoices.SUBMITTED,
            actor=actor_user,
            transitioned_at=transitioned_at or timezone.now(),
            schema_key=snapshot.schema_key,
            schema_version=snapshot.schema_version,
            submission_sequence=_next_submission_sequence(snapshot),
            is_baseline=is_baseline,
            submitted_data_encrypted=confidential.data,
        )
    except (InventoryEncryptionError, FieldEncryptionError):
        _raise_confidential_validation_error()
    return history


def _ensure_submitted_history(snapshot):
    """Capture a legacy submitted payload before its first correction."""

    history = latest_submission_history(snapshot)
    if history:
        return history
    return _record_submission_history(
        snapshot,
        actor_user=snapshot.student_profile.user,
        status_from="",
        transitioned_at=snapshot.submitted_at or timezone.now(),
        is_baseline=True,
    )


@transaction.atomic
def get_or_create_current_inventory_draft(
    actor, command: InventoryDraftCreateCommand
) -> StudentInventorySnapshot:
    """Retrieve the student's draft/reopened snapshot or create one safely.

    Duplicate creation for the same academic year is idempotent: the existing
    editable snapshot is returned instead of raising.  A submitted snapshot
    for the year remains a lifecycle conflict.
    """

    _require_active_actor(actor)
    if not isinstance(command, InventoryDraftCreateCommand):
        raise ValidationError("Draft creation requires a typed InventoryDraftCreateCommand.")
    if not is_student(actor):
        raise PermissionDeniedError(
            "Only the owning student may open an Individual Inventory draft."
        )
    student_profile = _own_student_profile(actor)
    academic_year = validate_academic_year(command.academic_year)

    snapshot = StudentInventorySnapshot.objects.select_for_update().filter(
        student_profile=student_profile,
        academic_year=academic_year
    ).first()

    if snapshot:
        if snapshot.status == InventoryStatusChoices.SUBMITTED:
            raise WorkflowError(
                "Cannot access draft because the inventory for this academic year is already submitted."
            )
        return snapshot

    # Create new draft snapshot
    try:
        return create_confidential_snapshot(
            student_profile=student_profile,
            academic_year=academic_year,
            status=InventoryStatusChoices.DRAFT,
        )
    except (InventoryEncryptionError, FieldEncryptionError):
        _raise_confidential_validation_error()


@transaction.atomic
def save_inventory_draft(
    actor, snapshot_id: str, command: InventoryDraftCommand
) -> StudentInventorySnapshot:
    """Owner-only answer save for a draft or reopened snapshot.

    Accepts only the explicitly validated Inventory answer object carried by
    the typed command.  Submitted snapshots stay locked.
    """

    _require_active_actor(actor)
    if not isinstance(command, InventoryDraftCommand):
        raise ValidationError("Inventory drafts require a validated InventoryDraftCommand.")

    snapshot = _locked_snapshot_or_raise(snapshot_id)
    if (
        not is_student(actor)
        or not owns_student_profile(actor, snapshot.student_profile)
    ):
        raise PermissionDeniedError("You do not have permission to edit this inventory draft.")
    if snapshot.status == InventoryStatusChoices.SUBMITTED:
        raise WorkflowError("Cannot save draft changes to a locked submitted snapshot.")
    if snapshot.status not in {
        InventoryStatusChoices.DRAFT,
        InventoryStatusChoices.REOPENED_FOR_CORRECTION,
    }:
        raise WorkflowError("This inventory snapshot is not editable in its current state.")
    _assert_expected_updated_at(snapshot, command.expected_updated_at)

    try:
        return update_draft_data(snapshot.pk, dict(command.answers))
    except (InventoryEncryptionError, FieldEncryptionError):
        _raise_confidential_validation_error()


@transaction.atomic
def submit_inventory_snapshot(
    actor, snapshot_id: str, command: InventorySubmitCommand
) -> StudentInventorySnapshot:
    """Single-domain submission primitive: lock, validate, transition, audit.

    Cross-domain side effects (support-need materialization, privacy
    acceptance, report projection facts) run through ``apps.orchestration``
    around this primitive inside the caller's transaction.
    """

    if not isinstance(command, InventorySubmitCommand):
        raise ValidationError("Inventory submission requires a typed InventorySubmitCommand.")
    _require_active_actor(actor)
    if not is_student(actor):
        raise PermissionDeniedError("Only the owning student may submit an Individual Inventory.")
    if not command.privacy_acknowledged:
        raise ValidationError(
            "The Individual Inventory privacy notice must be acknowledged before submission."
        )

    snapshot = _locked_snapshot_or_raise(snapshot_id)
    student_profile = snapshot.student_profile
    if not owns_student_profile(actor, student_profile):
        raise PermissionDeniedError(
            "You do not have permission to submit this inventory snapshot."
        )
    if snapshot.status == InventoryStatusChoices.SUBMITTED:
        raise WorkflowError("This inventory snapshot is already submitted and locked.")
    _assert_expected_updated_at(snapshot, command.expected_updated_at)

    try:
        validate_snapshot_before_submit(snapshot)
    except (InventoryEncryptionError, FieldEncryptionError):
        _raise_confidential_validation_error()

    status_from = snapshot.status
    snapshot.status = InventoryStatusChoices.SUBMITTED
    snapshot.submitted_at = timezone.now()
    snapshot.schema_version = INVENTORY_SCHEMA_VERSION
    snapshot.save(update_fields=["status", "submitted_at", "schema_version", "updated_at"])

    submission_history = _record_submission_history(
        snapshot,
        actor_user=student_profile.user,
        status_from=status_from,
        transitioned_at=snapshot.submitted_at,
    )

    # Log audit event
    audit_status_transition(
        actor_user=student_profile.user,
        target_model="inventory.StudentInventorySnapshot",
        target_object_id=snapshot.id,
        metadata={
            "snapshot_id": snapshot.id,
            "student_profile_id": student_profile.id,
            "actor_id": student_profile.user.id,
            "status_from": status_from,
            "status_to": InventoryStatusChoices.SUBMITTED,
            "academic_year": snapshot.academic_year,
            "schema_key": snapshot.schema_key,
            "schema_version": snapshot.schema_version,
            "history_id": submission_history.id,
        }
    )

    return snapshot


@transaction.atomic
def reopen_inventory_for_correction(
    actor, snapshot_id: str, command: InventoryReopenCommand
) -> StudentInventorySnapshot:
    """Counselor/Head-only reopen of a submitted snapshot.

    Requires current authority plus matching scope, records the encrypted
    operational reason, and registers the student notification through the
    outbox.  Related derived support needs and report projection facts are
    updated by the orchestration workflow that composes this primitive.
    """

    _require_active_actor(actor)
    if not isinstance(command, InventoryReopenCommand):
        raise ValidationError("Inventory reopening requires a typed InventoryReopenCommand.")

    snapshot = _locked_snapshot_or_raise(snapshot_id)
    student_profile = snapshot.student_profile

    # Validate the signed state before the final policy check.  A retry of a
    # form submitted after another transition must become a workflow conflict
    # (with no new evidence), while an unsigned/direct call still fails closed
    # through the active-counselor policy below.
    _assert_reopen_state_token(snapshot, command.expected_state_token)

    # Scoped coverage validation check.  The policy also rejects every
    # non-submitted state, including unsupported legacy values.
    if not can_reopen_inventory(actor, snapshot):
        raise PermissionDeniedError(
            "You are not authorized to reopen this student's inventory snapshot."
        )

    _ensure_submitted_history(snapshot)

    status_from = snapshot.status
    try:
        snapshot = record_reopen_reason(snapshot.pk, command.reason)
    except (InventoryEncryptionError, FieldEncryptionError):
        _raise_confidential_validation_error()
    snapshot.status = InventoryStatusChoices.REOPENED_FOR_CORRECTION
    snapshot.reopened_at = timezone.now()
    snapshot.reopened_by = actor
    snapshot.save(update_fields=["status", "reopened_at", "reopened_by", "updated_at"])

    correction_history = StudentInventoryStatusHistory.objects.create(
        snapshot=snapshot,
        from_status=status_from,
        to_status=InventoryStatusChoices.REOPENED_FOR_CORRECTION,
        actor=actor,
        transitioned_at=snapshot.reopened_at,
        schema_key=snapshot.schema_key,
        schema_version=snapshot.schema_version,
        reason_encrypted=command.reason,
    )

    # Log audit event (reopen_reason is sensitive operational text and is
    # forbidden in generic audit metadata).
    audit_status_transition(
        actor_user=actor,
        target_model="inventory.StudentInventorySnapshot",
        target_object_id=snapshot.id,
        metadata={
            "snapshot_id": snapshot.id,
            "student_profile_id": student_profile.id,
            "actor_id": actor.id,
            "status_from": status_from,
            "status_to": InventoryStatusChoices.REOPENED_FOR_CORRECTION,
            "academic_year": snapshot.academic_year,
            "schema_key": snapshot.schema_key,
            "schema_version": snapshot.schema_version,
            "history_id": correction_history.id,
        }
    )

    from apps.notifications.dispatch import enqueue_notification_event

    enqueue_notification_event(
        "inventory.correction_requested",
        {
            "history_id": correction_history.id,
            "snapshot_id": snapshot.id,
            # The client-owned action URL is intentionally not invented in the
            # backend during the API migration. The Next.js client will add
            # its route when the notification contract is finalized.
            "action_path": "",
        },
        related_object=correction_history,
        event_key=f"inventory.correction_requested:{correction_history.id}",
    )

    return snapshot
