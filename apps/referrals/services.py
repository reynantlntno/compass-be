# Project: COMPASS
# File: apps/referrals/services.py
# Module: apps.referrals
# Purpose: Transactional referral lifecycle, action, and assignment mutations.
# Domain boundary and service policy.

from apps.common.exceptions import PermissionDeniedError, ValidationError, WorkflowError, NotFoundError
from django.db import transaction
from django.contrib.auth import get_user_model
from django.utils import timezone

from apps.access_control.rules import is_gco_staff, is_head_guidance
from apps.audit.services import audit_assignment_change, audit_log, audit_status_transition
from apps.referrals.models import (
    Referral,
    ReferralAction,
    ReferralActionCodeChoices,
    ReferralActionOutcomeCodeChoices,
    ReferralAssignmentChangeTypeChoices,
    ReferralAssignmentHistory,
    ReferralReasonCategoryChoices,
    ReferralReassignmentRequest,
    ReferralReassignmentStatusChoices,
    ReferralSourceTypeChoices,
    ReferralStatusChoices,
    ReferralStatusHistory,
    ReferralWorkflowReasonCodeChoices,
)
from apps.referrals.commands import (
    ReferralActionCommand,
    ReferralAssignmentCommand,
    ReferralDraftCommand,
    ReferralReassignmentDecisionCommand,
    ReferralReassignmentRequestCommand,
    ReferralSubmitCommand,
    ReferralTransitionCommand,
    UNSET,
)
from apps.referrals.encryption import (
    ACTION_CONFIDENTIAL_FIELDS,
    ASSIGNMENT_DETAIL,
    REFERRAL_ACTION,
    REFERRAL_CONFIDENTIAL_FIELDS,
    REFERRAL_SUBMISSION,
    REASSIGNMENT_CONFIDENTIAL_FIELDS,
    REASSIGNMENT_DECISION,
    REASSIGNMENT_REQUEST,
    STATUS_DETAIL,
    ReferralEncryptionError,
    classify_group,
    initialize_group,
    prepare_group_write,
    read_group,
)
from apps.referrals.policies import (
    can_add_referral_action,
    can_assign_referral,
    can_begin_referral_review,
    can_cancel_referral,
    can_close_referral,
    can_create_referral_draft,
    can_decide_referral_reassignment,
    can_escalate_referral,
    can_receive_referral,
    can_reassign_referral,
    can_reopen_referral,
    can_request_referral_reassignment,
    can_set_referral_action_required,
    can_submit_referral,
    can_view_referral_safe_metadata,
)
from apps.referrals.reference_codes import generate_referral_reference_code
from apps.common.request_dedup import RequestKeyPolicy, validate_and_lock_request_key


_REFERRAL_REQUEST_KEY_POLICY = RequestKeyPolicy("referrals", max_length=100)


class ReferralPermissionError(PermissionDeniedError):
    pass


class ReferralTransitionError(WorkflowError):
    pass


class ReferralValidationError(ValidationError):
    pass


def _role_class(actor):
    if is_head_guidance(actor):
        return "head_guidance"
    if is_gco_staff(actor):
        return "gco_staff"
    return "counselor"


def _safe_metadata(event_code, **extra):
    return {"event_code": event_code, **extra}


def _validate_code(value, allowed_values, message, *, allow_blank=False):
    if allow_blank and not value:
        return
    if value not in allowed_values:
        raise ReferralValidationError(message)


def _validate_reason_code(reason_code):
    _validate_code(
        reason_code,
        ReferralWorkflowReasonCodeChoices.values,
        "Select an approved structured reason code.",
    )


def _audit_event(event_code, actor, referral, **metadata):
    audit_log(
        action_type=event_code,
        event_category="WORKFLOW",
        target_model="referrals.Referral",
        target_object_id=str(referral.pk),
        actor_user=actor,
        reference_code=referral.reference_code,
        source_app="referrals",
        metadata=_safe_metadata(event_code, actor_role_class=_role_class(actor), **metadata),
    )


def _audit_transition(event_code, actor, referral, from_status, to_status, reason_code=""):
    audit_status_transition(
        actor_user=actor,
        target_model="referrals.Referral",
        target_object_id=str(referral.pk),
        reference_code=referral.reference_code,
        source_app="referrals",
        metadata=_safe_metadata(
            event_code,
            from_status=from_status,
            to_status=to_status,
            reason_code=reason_code,
            actor_role_class=_role_class(actor),
        ),
    )


def _locked(reference_code):
    return (
        Referral.objects.select_for_update(of=("self",))
        .defer(*REFERRAL_CONFIDENTIAL_FIELDS)
        .select_related("student", "student__student_profile", "assigned_counselor")
        .get(reference_code=str(reference_code or "").strip())
    )


def _get_referral(reference_code):
    try:
        return _locked(reference_code)
    except Referral.DoesNotExist as exc:
        raise NotFoundError() from exc


def _get_user(user_id, *, required=True):
    if user_id in (None, ""):
        if required:
            raise ValidationError("The account reference is required.")
        return None
    try:
        return get_user_model().objects.get(pk=str(user_id))
    except get_user_model().DoesNotExist as exc:
        raise NotFoundError() from exc


def _history(referral, actor, from_status, to_status, reason_code="", reason_detail="", request_key=""):
    history = ReferralStatusHistory(
        referral=referral,
        from_status=from_status,
        to_status=to_status,
        actor=actor,
        reason_code=reason_code,
        reason_detail=reason_detail,
        transitioned_at=timezone.now(),
        request_key=request_key,
    )
    try:
        initialize_group(history, STATUS_DETAIL, reason_detail)
        history.save(force_insert=True)
    except (ValidationError, ReferralEncryptionError) as exc:
        raise ReferralValidationError("The referral history could not be saved.") from exc
    return history


@transaction.atomic
def create_referral_draft(actor, target_student_id, command: ReferralDraftCommand, request_key):
    if not isinstance(command, ReferralDraftCommand):
        raise ReferralValidationError("Referral creation requires a ReferralDraftCommand.")
    target_student = _get_user(target_student_id)
    if not can_create_referral_draft(actor, target_student):
        raise ReferralPermissionError("You do not have permission to create this referral.")
    _validate_code(
        command.source_type,
        ReferralSourceTypeChoices.values,
        "Select an approved referral source type.",
    )
    _validate_code(
        command.reason_category_code or ReferralReasonCategoryChoices.UNCATEGORIZED,
        ReferralReasonCategoryChoices.values,
        "Select an approved referral reason category.",
    )
    request_key = validate_and_lock_request_key(_REFERRAL_REQUEST_KEY_POLICY, request_key)
    existing = Referral.objects.defer(*REFERRAL_CONFIDENTIAL_FIELDS).filter(
        creation_request_key=request_key,
        created_by=actor,
        student=target_student,
    ).first()
    if existing:
        return existing
    profile = target_student.student_profile
    try:
        referral = Referral(
            reference_code=generate_referral_reference_code(),
            student=target_student,
            source_type=command.source_type,
            referred_by_user=_get_user(command.referred_by_user_id, required=False),
            referrer_display_snapshot=command.referrer_display_snapshot,
            reason_text=command.reason_text,
            reason_category_code=command.reason_category_code or "UNCATEGORIZED",
            occurred_at=command.occurred_at,
            source_signed_on=command.source_signed_on,
            course_snapshot=command.course_snapshot or profile.program,
            year_level_snapshot=command.year_level_snapshot or (str(profile.year_level) if profile.year_level else ""),
            block_snapshot=command.block_snapshot,
            created_by=actor,
            updated_by=actor,
            creation_request_key=request_key,
        )
        initialize_group(referral, REFERRAL_SUBMISSION, command.reason_text)
        referral.save(force_insert=True)
    except (ValidationError, ReferralEncryptionError) as exc:
        raise ReferralValidationError("The referral draft could not be saved.") from exc
    _history(referral, actor, "", ReferralStatusChoices.DRAFT, request_key=request_key)
    _audit_event("REFERRAL_CREATE", actor, referral, to_status=ReferralStatusChoices.DRAFT)
    return referral


@transaction.atomic
def submit_referral(actor, reference_code, command: ReferralSubmitCommand):
    if not isinstance(command, ReferralSubmitCommand):
        raise ReferralValidationError("Referral submission requires a ReferralSubmitCommand.")
    current = _get_referral(reference_code)
    if current.status == ReferralStatusChoices.SUBMITTED and can_view_referral_safe_metadata(actor, current):
        return current
    if not can_submit_referral(actor, current):
        raise ReferralPermissionError("You do not have permission to submit this referral.")
    _validate_code(
        command.reason_category_code if command.has("reason_category_code") else current.reason_category_code,
        ReferralReasonCategoryChoices.values,
        "Select an approved referral reason category.",
    )
    reason_text = command.reason_text if command.has("reason_text") else read_group(actor, current, REFERRAL_SUBMISSION)
    try:
        confidential_fields = prepare_group_write(current, REFERRAL_SUBMISSION, reason_text)
    except ReferralEncryptionError as exc:
        raise ReferralValidationError("The referral reason could not be saved.") from exc
    changed_metadata = []
    for field in ("reason_category_code", "course_snapshot", "year_level_snapshot", "block_snapshot", "referrer_display_snapshot", "occurred_at", "source_signed_on"):
        if command.has(field):
            setattr(current, field, getattr(command, field))
            changed_metadata.append(field)
    current.submitted_at = timezone.now()
    current.submitted_by = actor
    current.updated_by = actor
    current.status = ReferralStatusChoices.SUBMITTED
    try:
        current.save(update_fields=[
            *confidential_fields,
            *changed_metadata,
            "submitted_at",
            "submitted_by",
            "updated_by",
            "status",
            "updated_at",
        ])
    except ValidationError as exc:
        raise ReferralValidationError("Complete the required source evidence before submitting.") from exc
    _history(current, actor, ReferralStatusChoices.DRAFT, ReferralStatusChoices.SUBMITTED)
    _audit_transition("REFERRAL_SUBMIT", actor, current, ReferralStatusChoices.DRAFT, ReferralStatusChoices.SUBMITTED)
    from apps.referrals.notification_services import enqueue_referral_event
    enqueue_referral_event("created", current)
    return current


def _transition(actor, reference_code, *, target, allowed_from, policy, event_code, reason_code="", reason_detail="", updates=None, reason_required=False):
    current = _get_referral(reference_code)
    if current.status == target and can_view_referral_safe_metadata(actor, current):
        if reason_required:
            _validate_reason_code(reason_code)
        return current
    if current.status not in allowed_from:
        if not can_view_referral_safe_metadata(actor, current):
            raise ReferralPermissionError("You do not have permission to update this referral.")
        raise ReferralTransitionError("The referral is no longer in the expected state.")
    if not policy(actor, current):
        raise ReferralPermissionError("You do not have permission to update this referral.")
    if reason_required:
        _validate_reason_code(reason_code)
    previous = current.status
    current.status = target
    current.updated_by = actor
    for field, value in (updates or {}).items():
        setattr(current, field, value)
    try:
        current.save(update_fields=[
            "status",
            "updated_by",
            *(updates or {}).keys(),
            "updated_at",
        ])
    except ValidationError as exc:
        raise ReferralValidationError("The referral could not be updated.") from exc
    _history(current, actor, previous, target, reason_code=reason_code, reason_detail=reason_detail)
    _audit_transition(event_code, actor, current, previous, target, reason_code)
    from apps.referrals.notification_services import enqueue_referral_event
    enqueue_referral_event("status_changed", current)
    return current


@transaction.atomic
def receive_referral(actor, reference_code, command: ReferralTransitionCommand | None = None):
    command = command or ReferralTransitionCommand(reason_code=ReferralWorkflowReasonCodeChoices.WORKFLOW_PROGRESSION)
    return _transition(
        actor, reference_code, target=ReferralStatusChoices.RECEIVED,
        allowed_from={ReferralStatusChoices.SUBMITTED}, policy=can_receive_referral,
        event_code="REFERRAL_RECEIVE", reason_code=command.reason_code, reason_detail=command.reason_detail,
        updates={"received_at": timezone.now(), "received_by": actor},
    )


@transaction.atomic
def begin_referral_review(actor, reference_code, command: ReferralTransitionCommand | None = None):
    command = command or ReferralTransitionCommand(reason_code=ReferralWorkflowReasonCodeChoices.WORKFLOW_PROGRESSION)
    return _transition(
        actor, reference_code, target=ReferralStatusChoices.UNDER_REVIEW,
        allowed_from={ReferralStatusChoices.RECEIVED, ReferralStatusChoices.ACTION_REQUIRED, ReferralStatusChoices.ESCALATED}, policy=can_begin_referral_review,
        event_code="REFERRAL_BEGIN_REVIEW", reason_code=command.reason_code, reason_detail=command.reason_detail,
    )


@transaction.atomic
def add_referral_action(actor, reference_code, command: ReferralActionCommand, request_key):
    if not isinstance(command, ReferralActionCommand):
        raise ReferralValidationError("Referral actions require a ReferralActionCommand.")
    current = _get_referral(reference_code)
    action_code = command.action_code
    if not can_view_referral_safe_metadata(actor, current) or current.status in {
        ReferralStatusChoices.DRAFT,
        ReferralStatusChoices.CLOSED,
        ReferralStatusChoices.CANCELLED,
    }:
        raise ReferralPermissionError("You do not have permission to add this action.")
    _validate_code(
        action_code,
        ReferralActionCodeChoices.values,
        "Select an approved referral action code.",
    )
    _validate_code(
        command.outcome_code,
        ReferralActionOutcomeCodeChoices.values,
        "Select an approved action outcome code.",
        allow_blank=True,
    )
    if not can_add_referral_action(actor, current, action_code):
        raise ReferralPermissionError("You do not have permission to add this action.")
    request_key = validate_and_lock_request_key(_REFERRAL_REQUEST_KEY_POLICY, request_key)
    existing = ReferralAction.objects.defer(*ACTION_CONFIDENTIAL_FIELDS).filter(
        referral=current,
        request_key=request_key,
    ).first()
    if existing:
        return existing
    action = ReferralAction(
        referral=current,
        action_code=action_code,
        outcome_code=command.outcome_code,
        remarks=command.remarks,
        performed_by=actor,
        performed_at=timezone.now(),
        request_key=request_key,
    )
    try:
        initialize_group(action, REFERRAL_ACTION, command.remarks)
        action.save(force_insert=True)
    except (ValidationError, ReferralEncryptionError) as exc:
        raise ReferralValidationError("The referral action could not be saved.") from exc
    _audit_event("REFERRAL_ADD_ACTION", actor, current, action_code=action_code)
    return action


@transaction.atomic
def set_referral_action_required(actor, reference_code, command: ReferralTransitionCommand):
    if not isinstance(command, ReferralTransitionCommand):
        raise ReferralValidationError("Action-required transitions require a ReferralTransitionCommand.")
    return _transition(
        actor, reference_code, target=ReferralStatusChoices.ACTION_REQUIRED,
        allowed_from={ReferralStatusChoices.UNDER_REVIEW, ReferralStatusChoices.ACTION_REQUIRED},
        policy=can_set_referral_action_required, event_code="REFERRAL_SET_ACTION_REQUIRED", reason_code=command.reason_code, reason_detail=command.reason_detail,
        reason_required=True,
    )


@transaction.atomic
def request_referral_reassignment(actor, reference_code, command: ReferralReassignmentRequestCommand, request_key):
    if not isinstance(command, ReferralReassignmentRequestCommand):
        raise ReferralValidationError("Reassignment requests require a ReferralReassignmentRequestCommand.")
    current = _get_referral(reference_code)
    if not can_request_referral_reassignment(actor, current):
        raise ReferralPermissionError("You do not have permission to request reassignment.")
    _validate_reason_code(command.request_reason_code)
    request_key = validate_and_lock_request_key(_REFERRAL_REQUEST_KEY_POLICY, request_key)
    existing = ReferralReassignmentRequest.objects.defer(*REASSIGNMENT_CONFIDENTIAL_FIELDS).filter(
        referral=current,
        request_key=request_key,
    ).first()
    if existing:
        return existing
    if current.reassignment_requests.filter(status=ReferralReassignmentStatusChoices.PENDING).exists():
        raise ReferralValidationError("A reassignment request is already pending.")
    try:
        request = ReferralReassignmentRequest(
            referral=current,
            requester=actor,
            current_counselor_snapshot=current.assigned_counselor,
            proposed_counselor=_get_user(command.proposed_counselor_id, required=False),
            request_reason_code=command.request_reason_code,
            request_detail=command.request_detail,
            request_key=request_key,
        )
        initialize_group(request, REASSIGNMENT_REQUEST, command.request_detail)
        initialize_group(request, REASSIGNMENT_DECISION, "")
        request.save(force_insert=True)
    except (ValidationError, ReferralEncryptionError) as exc:
        raise ReferralValidationError("The reassignment request could not be saved.") from exc
    _audit_event("REFERRAL_REASSIGN_REQUEST", actor, current, reason_code=request.request_reason_code)
    return request


def _assign_locked(actor, current, target, reason_code, event_code):
    previous = current.assigned_counselor
    if previous and previous.pk == target.pk:
        return current, False
    current.assigned_counselor = target
    current.updated_by = actor
    try:
        current.save(update_fields=["assigned_counselor", "updated_by", "updated_at"])
    except ValidationError as exc:
        raise ReferralValidationError("The counselor assignment could not be saved.") from exc
    change_type = ReferralAssignmentChangeTypeChoices.REASSIGNMENT if previous else ReferralAssignmentChangeTypeChoices.INITIAL_ASSIGNMENT
    history = ReferralAssignmentHistory(
        referral=current, from_counselor=previous, to_counselor=target, changed_by=actor,
        reason_code=reason_code, change_type=change_type, changed_at=timezone.now(),
    )
    try:
        initialize_group(history, ASSIGNMENT_DETAIL, "")
        history.save(force_insert=True)
    except (ValidationError, ReferralEncryptionError) as exc:
        raise ReferralValidationError("The assignment history could not be saved.") from exc
    audit_assignment_change(
        actor_user=actor, target_model="referrals.Referral", target_object_id=str(current.pk),
        reference_code=current.reference_code, source_app="referrals",
        metadata=_safe_metadata(event_code, reason_code=reason_code, assignment_changed=True, actor_role_class=_role_class(actor)),
    )
    from apps.referrals.notification_services import enqueue_referral_event
    enqueue_referral_event("assigned", current)
    return current, True


@transaction.atomic
def assign_referral_counselor(actor, reference_code, command: ReferralAssignmentCommand):
    if not isinstance(command, ReferralAssignmentCommand):
        raise ReferralValidationError("Referral assignment requires a ReferralAssignmentCommand.")
    current = _get_referral(reference_code)
    target = _get_user(command.counselor_id)
    if not can_assign_referral(actor, current, target):
        raise ReferralPermissionError("You do not have permission to assign this referral.")
    _validate_reason_code(command.reason_code)
    if current.assigned_counselor_id and current.assigned_counselor_id != target.pk:
        raise ReferralTransitionError("Use the reassignment workflow for an assigned referral.")
    return _assign_locked(actor, current, target, command.reason_code, "REFERRAL_ASSIGN")[0]


@transaction.atomic
def reassign_referral_counselor(actor, reference_code, command: ReferralAssignmentCommand):
    if not isinstance(command, ReferralAssignmentCommand):
        raise ReferralValidationError("Referral reassignment requires a ReferralAssignmentCommand.")
    current = _get_referral(reference_code)
    target = _get_user(command.counselor_id)
    if not can_reassign_referral(actor, current, target):
        raise ReferralPermissionError("You do not have permission to reassign this referral.")
    _validate_reason_code(command.reason_code)
    return _assign_locked(actor, current, target, command.reason_code, "REFERRAL_REASSIGN")[0]


@transaction.atomic
def decide_referral_reassignment(actor, request_id, command: ReferralReassignmentDecisionCommand):
    if not isinstance(command, ReferralReassignmentDecisionCommand):
        raise ReferralValidationError("Referral reassignment decisions require a validated command.")
    locked_request = (
        ReferralReassignmentRequest.objects.select_for_update(of=("self",))
        .defer(*REASSIGNMENT_CONFIDENTIAL_FIELDS)
        .select_related("proposed_counselor", "current_counselor_snapshot")
        .get(pk=str(request_id))
    )
    if not can_decide_referral_reassignment(actor, locked_request):
        raise ReferralPermissionError("You do not have permission to decide this request.")
    decision_state = classify_group(locked_request, REASSIGNMENT_DECISION)
    if not decision_state.valid_combination or decision_state.lifecycle_state != "uninitialized":
        raise ReferralTransitionError("The reassignment request decision state is invalid.")
    current = _get_referral(locked_request.referral.reference_code)
    decision = command.decision
    if decision not in {ReferralReassignmentStatusChoices.APPROVED, ReferralReassignmentStatusChoices.DECLINED}:
        raise ReferralValidationError("Select an approved decision code.")
    if decision == ReferralReassignmentStatusChoices.APPROVED and not locked_request.proposed_counselor:
        raise ReferralValidationError("An approved request requires a proposed counselor.")
    _validate_reason_code(command.decision_code)
    if decision == ReferralReassignmentStatusChoices.APPROVED:
        if locked_request.current_counselor_snapshot_id != current.assigned_counselor_id:
            raise ReferralTransitionError("The referral assignment changed after this request was created.")
        if locked_request.proposed_counselor_id == current.assigned_counselor_id:
            raise ReferralTransitionError("The requested counselor is already assigned.")
        if not can_reassign_referral(actor, current, locked_request.proposed_counselor):
            raise ReferralValidationError("The proposed counselor is no longer available.")
    locked_request.status = decision
    locked_request.decider = actor
    locked_request.decided_at = timezone.now()
    locked_request.decision_code = command.decision_code
    try:
        confidential_fields = prepare_group_write(
            locked_request,
            REASSIGNMENT_DECISION,
            command.decision_detail,
        )
        locked_request.save(update_fields=[
            "status",
            "decider",
            "decided_at",
            "decision_code",
            *confidential_fields,
            "updated_at",
        ])
    except (ValidationError, ReferralEncryptionError) as exc:
        raise ReferralValidationError("The reassignment decision could not be saved.") from exc
    _audit_event("REFERRAL_REASSIGN_DECISION", actor, current, decision_code=locked_request.decision_code, decision=decision)
    if decision == ReferralReassignmentStatusChoices.APPROVED:
        _assign_locked(actor, current, locked_request.proposed_counselor, locked_request.decision_code or locked_request.request_reason_code, "REFERRAL_REASSIGN")
    return locked_request


@transaction.atomic
def escalate_referral_for_head_review(actor, reference_code, command: ReferralTransitionCommand):
    if not isinstance(command, ReferralTransitionCommand):
        raise ReferralValidationError("Escalation requires a ReferralTransitionCommand.")
    return _transition(
        actor, reference_code, target=ReferralStatusChoices.ESCALATED,
        allowed_from={ReferralStatusChoices.UNDER_REVIEW, ReferralStatusChoices.ACTION_REQUIRED},
        policy=can_escalate_referral, event_code="REFERRAL_ESCALATE", reason_code=command.reason_code, reason_detail=command.reason_detail,
        reason_required=True,
    )


@transaction.atomic
def close_referral(actor, reference_code, command: ReferralTransitionCommand):
    if not isinstance(command, ReferralTransitionCommand):
        raise ReferralValidationError("Referral closure requires a ReferralTransitionCommand.")
    referral = _transition(
        actor, reference_code, target=ReferralStatusChoices.CLOSED,
        allowed_from={ReferralStatusChoices.UNDER_REVIEW, ReferralStatusChoices.ACTION_REQUIRED, ReferralStatusChoices.ESCALATED},
        policy=can_close_referral, event_code="REFERRAL_CLOSE", reason_code=command.reason_code, reason_detail=command.reason_detail,
        updates={"closed_at": timezone.now(), "closed_by": actor, "close_reason_code": command.reason_code},
        reason_required=True,
    )
    if command.reason_code == ReferralWorkflowReasonCodeChoices.WORK_COMPLETED:
        from apps.orchestration.commands import FeedbackInvitationCommand
        from apps.orchestration.use_cases import issue_feedback_invitation_for_completed_source

        issue_feedback_invitation_for_completed_source(
            actor,
            FeedbackInvitationCommand("referral", str(referral.pk))
        )
    return referral


@transaction.atomic
def cancel_referral(actor, reference_code, command: ReferralTransitionCommand):
    if not isinstance(command, ReferralTransitionCommand):
        raise ReferralValidationError("Referral cancellation requires a ReferralTransitionCommand.")
    return _transition(
        actor, reference_code, target=ReferralStatusChoices.CANCELLED,
        allowed_from={ReferralStatusChoices.DRAFT, ReferralStatusChoices.SUBMITTED, ReferralStatusChoices.RECEIVED, ReferralStatusChoices.UNDER_REVIEW, ReferralStatusChoices.ACTION_REQUIRED, ReferralStatusChoices.ESCALATED},
        policy=can_cancel_referral, event_code="REFERRAL_CANCEL", reason_code=command.reason_code, reason_detail=command.reason_detail,
        updates={"cancelled_at": timezone.now(), "cancelled_by": actor, "cancel_reason_code": command.reason_code},
        reason_required=True,
    )


@transaction.atomic
def reopen_referral(actor, reference_code, command: ReferralTransitionCommand):
    if not isinstance(command, ReferralTransitionCommand):
        raise ReferralValidationError("Referral reopening requires a ReferralTransitionCommand.")
    return _transition(
        actor, reference_code, target=ReferralStatusChoices.UNDER_REVIEW,
        allowed_from={ReferralStatusChoices.CLOSED}, policy=can_reopen_referral,
        event_code="REFERRAL_REOPEN", reason_code=command.reason_code, reason_detail=command.reason_detail,
        updates={"reopened_at": timezone.now(), "reopened_by": actor, "reopen_reason_code": command.reason_code},
        reason_required=True,
    )
