# Project: COMPASS
# File: apps/exit_interviews/services.py
# Module: apps.exit_interviews
# Purpose: Service layer for managing Exit Interview assignments and responses
# Domain boundary and service policy.

import uuid
from django.db import transaction
from apps.common.exceptions import PermissionDeniedError, StaleStateError, ValidationError
from apps.common.verified_access import VerifiedFormAccessPrincipal
from django.utils import timezone
from apps.common.exceptions import WorkflowError

from apps.exit_interviews.models import (
    ExitInterviewAssignment,
    ExitInterviewResponse,
    AssignmentStatus,
    ExitResponseStatus,
    RATING_MATRIX_FIELDS,
    FEEDBACK_COMMENT_FIELDS,
)
from apps.profiles.models import StudentProfile, StudentLifecycleChoices
from apps.organizations.models import FormRevision, GovernanceStatusChoices
from apps.exit_interviews.reference_codes import generate_exit_interview_reference_code
from apps.organizations.academic_year import resolve_current_academic_year
from apps.inventory.eligibility import has_current_submitted_inventory
from apps.audit.services import audit_log, audit_status_transition, audit_assignment_change
from apps.orchestration.commands import FormInvitationLifecycleCommand, FormRevisionUsageCommand
from apps.orchestration.use_cases import (
    mark_form_invitation_submitted_for_composition,
    mark_form_revision_used_for_composition,
    resolve_verified_invitation_for_composition,
    start_form_invitation_draft_for_composition,
)
from apps.exit_interviews.commands import (
    ExitInterviewAcknowledgeCommand,
    ExitInterviewAssignmentCommand,
    ExitInterviewAssignmentReassignCommand,
    ExitInterviewDraftCommand,
    ExitInterviewLifecycleCommand,
    ExitInterviewReasonCommand,
    ExitInterviewStartCommand,
)


class ExitInterviewValidationError(ValidationError):
    """Custom validation error for exit interview workflow."""
    pass


def _sync_response_argument(original, locked):
    """Preserve the historical service API while mutating a locked row."""
    for field in (
        "status", "reference_code", "submitted_at", "reopened_by_id", "reopened_at",
        "reopen_reason", "voided_by_id", "voided_at", "void_reason",
    ):
        if field in getattr(locked, "get_deferred_fields", lambda: set())():
            continue
        if hasattr(locked, field):
            setattr(original, field, getattr(locked, field))


def _locked_response_queryset(*related_fields):
    """Lock only lifecycle metadata; never materialize Exit answers to mutate status."""
    from apps.exit_interviews.selectors import EXIT_RESPONSE_SENSITIVE_FIELDS

    return ExitInterviewResponse.objects.select_for_update(
        of=("self",)
    ).select_related(*related_fields).defer(*EXIT_RESPONSE_SENSITIVE_FIELDS)


def _safe_graduation_year(value) -> str:
    """Return a bounded cohort label without accepting free-form respondent data."""
    normalized = " ".join(str(value or "").split())
    return normalized[:20] if normalized else ""


def resolve_exit_graduation_year_snapshot(student_profile, *, form_collection=None) -> str:
    """Resolve the authoritative cohort metadata captured on an Exit response.

    Active assignment metadata is authoritative for manually assigned cohorts.
    Collection metadata is the fallback for token/collection responses. The current
    academic year and respondent payload are deliberately not used.
    """
    assignments = ExitInterviewAssignment.objects.filter(
        student=student_profile,
        status=AssignmentStatus.ASSIGNED,
    )
    assignment = assignments.order_by("-assigned_at").first()
    if assignment and isinstance(assignment.metadata_json, dict):
        snapshot = _safe_graduation_year(assignment.metadata_json.get("graduation_year"))
        if snapshot:
            return snapshot

    collection_metadata = getattr(form_collection, "metadata_json", None)
    if isinstance(collection_metadata, dict):
        return _safe_graduation_year(collection_metadata.get("graduation_year"))
    return ""


def _rating_value(ratings: dict, key: str):
    """Safely pull a 1-5 integer rating from a ratings dict, returning None when unset.

    Allows matrix columns to be normalized at write time while keeping the
    same None / N/A semantics across optional matrix items.
    """
    if not ratings:
        return None
    value = ratings.get(key)
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def check_exit_eligibility(student_profile: StudentProfile, academic_year: str, bypass_inventory: bool = False) -> str:
    """Checks if a student is eligible to complete the Exit Interview.

    Returns the eligibility source ('lifecycle', 'assignment', 'collection') if eligible,
    otherwise raises ExitInterviewValidationError.
    """
    # 1. Check for manual/counselor assignment first
    has_assignment = ExitInterviewAssignment.objects.filter(
        student=student_profile,
        status=AssignmentStatus.ASSIGNED
    ).exists()
    
    if has_assignment:
        source = "assignment"
    # 2. Check graduating status
    elif student_profile.lifecycle_status in (StudentLifecycleChoices.GRADUATING, StudentLifecycleChoices.GRADUATED, StudentLifecycleChoices.ALUMNI):
        source = "lifecycle"
    # 3. Fail closed if not eligible
    else:
        raise ExitInterviewValidationError("Student is not eligible for Exit Interview intake.")

    # 4. Enforce current-year inventory if not bypassed
    if not bypass_inventory:
        if not has_current_submitted_inventory(student_profile, academic_year):
            raise ExitInterviewValidationError(
                f"Access Denied: Submission of the Individual Inventory for academic year "
                f"{academic_year} is required before accessing the Exit Interview."
            )
            
    return source


@transaction.atomic
def _create_exit_assignment_legacy(
    student_profile: StudentProfile,
    assigned_by,
    due_at=None,
    collection=None,
    metadata_json=None
) -> ExitInterviewAssignment:
    """Creates a manual Exit Interview assignment for a student."""
    # Prevent duplicate active assignments
    existing = ExitInterviewAssignment.objects.filter(
        student=student_profile,
        status=AssignmentStatus.ASSIGNED
    ).first()
    if existing:
        return existing

    assignment = ExitInterviewAssignment.objects.create(
        student=student_profile,
        assigned_by=assigned_by,
        due_at=due_at,
        collection=collection,
        status=AssignmentStatus.ASSIGNED,
        metadata_json=metadata_json or {}
    )

    audit_assignment_change(
        actor_user=assigned_by,
        target_model="exit_interviews.ExitInterviewAssignment",
        target_object_id=str(assignment.id),
        metadata={"assignment_scope": "student_bound"}
    )

    from apps.exit_interviews.notification_services import enqueue_exit_interview_event
    enqueue_exit_interview_event("reminder", assignment=assignment)

    return assignment


@transaction.atomic
def _start_exit_response_legacy(
    student_profile: StudentProfile,
    form_revision: FormRevision,
    eligibility_source: str,
    form_collection=None,
    form_invitation=None,
    metadata_json=None
) -> ExitInterviewResponse:
    """Initializes a new Exit Interview response draft for the student."""
    academic_year = resolve_current_academic_year()

    # Exit Interview response uniqueness constraint: One active official response per student per AY
    existing = ExitInterviewResponse.objects.filter(
        student=student_profile,
        academic_year=academic_year,
        status__in=(ExitResponseStatus.DRAFT, ExitResponseStatus.SUBMITTED, ExitResponseStatus.REOPENED_FOR_CORRECTION)
    ).first()
    
    if existing:
        if existing.status == ExitResponseStatus.SUBMITTED:
            raise ExitInterviewValidationError(
                f"You have already submitted an Exit Interview response for the academic year {academic_year}."
            )
        return existing

    if form_invitation:
        start_form_invitation_draft_for_composition(
            FormInvitationLifecycleCommand(str(form_invitation.pk))
        )

    temp_ref = f"DRAFT-EIT-{uuid.uuid4().hex[:8]}"

    response = ExitInterviewResponse.objects.create(
        reference_code=temp_ref,
        student=student_profile,
        lifecycle_snapshot=student_profile.lifecycle_status,
        program_snapshot=student_profile.program or "",
        college_snapshot=student_profile.college or "",
        academic_year=academic_year,
        graduation_year_snapshot=resolve_exit_graduation_year_snapshot(
            student_profile,
            form_collection=form_collection,
        ),
        eligibility_source=eligibility_source,
        form_family=form_revision.form_family,
        form_revision=form_revision,
        form_collection=form_collection,
        form_invitation=form_invitation,
        status=ExitResponseStatus.DRAFT,
        metadata_json=metadata_json or {}
    )

    audit_log(
        action_type="EXIT_DRAFT_STARTED",
        event_category="WORKFLOW",
        target_model="exit_interviews.ExitInterviewResponse",
        target_object_id=str(response.id),
        actor_user=student_profile.user,
        metadata={"eligibility_source": eligibility_source}
    )

    return response


@transaction.atomic
def _save_exit_draft_legacy(
    response: ExitInterviewResponse,
    response_json: dict,
    actor_user,
    normalized_payload: dict = None,
) -> ExitInterviewResponse:
    """Saves answers as a draft response.

    ``response_json`` always stores the full structured form shape. The optional
    ``normalized_payload`` maps normalized model columns (matrix ratings,
    demographics, suggestions) to their values so per-item report aggregation
    works without reading the JSON blob.
    """
    response = ExitInterviewResponse.objects.select_for_update().get(pk=response.pk)
    if response.status not in (ExitResponseStatus.DRAFT, ExitResponseStatus.REOPENED_FOR_CORRECTION):
        raise ExitInterviewValidationError("Cannot update response that is already submitted.")

    response.response_json = response_json or {}

    if normalized_payload:
        from apps.exit_interviews.models import RATING_MATRIX_FIELDS
        for field, value in normalized_payload.items():
            if field in RATING_MATRIX_FIELDS:
                setattr(response, field, _rating_value(normalized_payload, field))
            elif hasattr(response, field):
                setattr(response, field, value)

    response.save(update_fields=None)
    return response


@transaction.atomic
def _submit_exit_response_legacy(
    response: ExitInterviewResponse,
    actor_user,
    ip_address: str = None,
    user_agent: str = None
) -> ExitInterviewResponse:
    """Officially submits the Exit Interview response and locks details."""
    original_response = response
    response = _locked_response_queryset("form_revision", "form_invitation", "student").get(pk=response.pk)
    if response.status not in (ExitResponseStatus.DRAFT, ExitResponseStatus.REOPENED_FOR_CORRECTION):
        raise ExitInterviewValidationError("Response is already submitted or closed.")

    # Revision must be active
    if response.form_revision.status != GovernanceStatusChoices.ACTIVE:
        raise ExitInterviewValidationError("Cannot submit against an inactive form revision.")

    # Generate reference code using EIT prefix
    ref_code = generate_exit_interview_reference_code(response.academic_year)
    response.reference_code = ref_code
    response.status = ExitResponseStatus.SUBMITTED
    response.submitted_at = timezone.now()
    response.save()

    # Mark form revision as used in governance service
    mark_form_revision_used_for_composition(
        actor_user,
        FormRevisionUsageCommand(
            str(response.form_revision_id),
            system_context=True,
        ),
    )

    # Call collection token hook if tokenized
    if response.form_invitation:
        mark_form_invitation_submitted_for_composition(
            FormInvitationLifecycleCommand(str(response.form_invitation_id))
        )

    # Update manual assignments if exists
    ExitInterviewAssignment.objects.filter(
        student=response.student,
        status=AssignmentStatus.ASSIGNED
    ).update(status=AssignmentStatus.COMPLETED)

    audit_log(
        action_type="EXIT_SUBMITTED",
        event_category="WORKFLOW",
        target_model="exit_interviews.ExitInterviewResponse",
        target_object_id=str(response.id),
        actor_user=actor_user,
        reference_code=ref_code,
        ip_address=ip_address,
        user_agent=user_agent,
        source_app="exit_interviews",
        metadata={"academic_year": response.academic_year}
    )

    from apps.exit_interviews.notification_services import enqueue_exit_interview_event
    enqueue_exit_interview_event("submitted", response=response)

    _sync_response_argument(original_response, response)
    return response


@transaction.atomic
def _reopen_exit_response_legacy(
    response: ExitInterviewResponse,
    actor_user,
    reason: str,
    ip_address: str = None,
    user_agent: str = None
) -> ExitInterviewResponse:
    """Allows staff/counselor to reopen a submitted exit response for correction."""
    from apps.exit_interviews.policies import can_reopen_exit_interview
    original_response = response
    response = _locked_response_queryset("student").get(pk=response.pk)
    if not can_reopen_exit_interview(actor_user, response):
        raise PermissionDeniedError("You do not have permission to reopen this exit response.")
    if response.status != ExitResponseStatus.SUBMITTED:
        raise ExitInterviewValidationError("Only a submitted response may be reopened.")

    old_status = response.status
    response.status = ExitResponseStatus.REOPENED_FOR_CORRECTION
    response.reopened_by = actor_user
    response.reopened_at = timezone.now()
    response.reopen_reason = reason
    response.save()

    # Reopen assignment
    ExitInterviewAssignment.objects.filter(
        student=response.student,
        status=AssignmentStatus.COMPLETED
    ).update(status=AssignmentStatus.ASSIGNED)

    audit_status_transition(
        actor_user=actor_user,
        target_model="exit_interviews.ExitInterviewResponse",
        target_object_id=str(response.id),
        reference_code=response.reference_code,
        metadata={"old_status": old_status, "new_status": response.status}
    )

    from apps.exit_interviews.notification_services import enqueue_exit_interview_event
    enqueue_exit_interview_event("status_changed", response=response)

    _sync_response_argument(original_response, response)
    return response


@transaction.atomic
def _void_exit_response_legacy(
    response: ExitInterviewResponse,
    actor_user,
    reason: str,
    ip_address: str = None,
    user_agent: str = None
) -> ExitInterviewResponse:
    """Voids an exit response."""
    from apps.exit_interviews.policies import can_reopen_exit_interview
    original_response = response
    response = _locked_response_queryset("student").get(pk=response.pk)
    if not can_reopen_exit_interview(actor_user, response):
        raise PermissionDeniedError("You do not have permission to void this exit response.")
    if response.status not in (ExitResponseStatus.SUBMITTED, ExitResponseStatus.REOPENED_FOR_CORRECTION):
        raise ExitInterviewValidationError("Only an active response may be voided.")

    old_status = response.status
    response.status = ExitResponseStatus.VOIDED
    response.voided_by = actor_user
    response.voided_at = timezone.now()
    response.void_reason = reason
    response.save()

    audit_status_transition(
        actor_user=actor_user,
        target_model="exit_interviews.ExitInterviewResponse",
        target_object_id=str(response.id),
        reference_code=response.reference_code,
        metadata={"old_status": old_status, "new_status": response.status}
    )

    from apps.exit_interviews.notification_services import enqueue_exit_interview_event
    enqueue_exit_interview_event("status_changed", response=response)

    _sync_response_argument(original_response, response)
    return response


@transaction.atomic
def _archive_exit_response_legacy(
    response: ExitInterviewResponse,
    actor_user,
    ip_address: str = None,
    user_agent: str = None
) -> ExitInterviewResponse:
    """Archives an exit response."""
    from apps.exit_interviews.policies import can_reopen_exit_interview
    original_response = response
    response = _locked_response_queryset("student").get(pk=response.pk)
    if not can_reopen_exit_interview(actor_user, response):
        raise PermissionDeniedError("You do not have permission to archive this exit response.")
    if response.status != ExitResponseStatus.SUBMITTED:
        raise ExitInterviewValidationError("Only a submitted response may be archived.")

    old_status = response.status
    response.status = ExitResponseStatus.ARCHIVED
    response.save()

    audit_status_transition(
        actor_user=actor_user,
        target_model="exit_interviews.ExitInterviewResponse",
        target_object_id=str(response.id),
        reference_code=response.reference_code,
        metadata={"old_status": old_status, "new_status": response.status}
    )

    _sync_response_argument(original_response, response)
    return response


@transaction.atomic
def _acknowledge_exit_response_legacy(response: ExitInterviewResponse, actor_user) -> ExitInterviewResponse:
    """Record a counselor acknowledgment without reading Exit answers."""
    from apps.exit_interviews.policies import can_acknowledge_exit_interview

    original_response = response
    response = _locked_response_queryset("student").get(pk=response.pk)
    if not can_acknowledge_exit_interview(actor_user, response):
        raise PermissionDeniedError("You do not have permission to acknowledge this Exit Interview response.")
    if response.status not in (ExitResponseStatus.SUBMITTED, ExitResponseStatus.ARCHIVED):
        raise ExitInterviewValidationError("Only a submitted or archived response may be acknowledged.")
    response.counselor_acknowledged_at = timezone.now()
    response.counselor_acknowledged_by = actor_user
    response.save(update_fields=["counselor_acknowledged_at", "counselor_acknowledged_by", "updated_at"])
    audit_status_transition(
        actor_user=actor_user,
        target_model="exit_interviews.ExitInterviewResponse",
        target_object_id=str(response.id),
        reference_code=response.reference_code,
        metadata={"status": response.status, "acknowledged": True},
    )
    _sync_response_argument(original_response, response)
    return response


# ---------------------------------------------------------------------------
# Canonical stable-reference service boundary
# ---------------------------------------------------------------------------


def _check_updated_at(value, expected):
    if expected and value.updated_at.isoformat() != expected:
        raise StaleStateError()


def _response_for_update(reference_code):
    response = _locked_response_queryset("student", "form_revision", "form_invitation", "form_collection").filter(reference_code=reference_code).first()
    if response is None:
        raise ValidationError("The Exit Interview response was not found.")
    return response


def _validate_answer_set(response, answers):
    if answers.form_revision_id != str(response.form_revision_id):
        raise ValidationError("Answers belong to a different form revision.")
    values = dict(answers.values)
    allowed = set(RATING_MATRIX_FIELDS) | {
        "civil_status", "program_schedule", "suggestions", *FEEDBACK_COMMENT_FIELDS,
    }
    unknown = set(values) - allowed
    if unknown:
        raise ValidationError("The answer set contains unsupported fields.")
    for field in RATING_MATRIX_FIELDS:
        if field in values and values[field] not in (None, ""):
            try:
                if not 1 <= int(values[field]) <= 5:
                    raise ValueError
            except (TypeError, ValueError):
                raise ValidationError("Rating answers must be between 1 and 5.") from None
    return values


@transaction.atomic
def create_exit_assignment(actor, command: ExitInterviewAssignmentCommand) -> ExitInterviewAssignment:
    if not isinstance(command, ExitInterviewAssignmentCommand):
        raise ValidationError("Exit Interview assignments require a typed command.")
    student = StudentProfile.objects.filter(pk=command.student_profile_id).first()
    if student is None:
        raise ValidationError("The student profile was not found.")
    from apps.exit_interviews.policies import can_manage_exit_assignments
    if not can_manage_exit_assignments(actor, student):
        raise PermissionDeniedError()
    collection = None
    if command.collection_id:
        from apps.form_collection.models import FormCollection
        collection = FormCollection.objects.filter(pk=command.collection_id).first()
        if collection is None:
            raise ValidationError("The Form Collection was not found.")
    metadata = {"graduation_year": command.graduation_year} if command.graduation_year else None
    return _create_exit_assignment_legacy(actor=actor, student_profile=student, assigned_by=actor, due_at=command.due_at, collection=collection, metadata_json=metadata)


@transaction.atomic
def reassign_exit_assignment(actor, command: ExitInterviewAssignmentReassignCommand) -> ExitInterviewAssignment:
    if not isinstance(command, ExitInterviewAssignmentReassignCommand):
        raise ValidationError("Exit Interview reassignment requires a typed command.")
    assignment = ExitInterviewAssignment.objects.select_for_update().select_related("student").filter(pk=command.assignment_id).first()
    if assignment is None:
        raise ValidationError("The Exit Interview assignment was not found.")
    _check_updated_at(assignment, command.expected_updated_at)
    student = StudentProfile.objects.filter(pk=command.student_profile_id).first()
    if student is None:
        raise ValidationError("The student profile was not found.")
    from apps.exit_interviews.policies import can_manage_exit_assignments
    if not can_manage_exit_assignments(actor, assignment.student) or not can_manage_exit_assignments(actor, student):
        raise PermissionDeniedError()
    old_student_id = str(assignment.student_id)
    assignment.student = student
    assignment.due_at = command.due_at
    assignment.metadata_json = (
        {"graduation_year": command.graduation_year}
        if command.graduation_year
        else dict(assignment.metadata_json or {})
    )
    assignment.save(update_fields=["student", "due_at", "metadata_json", "updated_at"])
    audit_assignment_change(
        actor_user=actor,
        target_model="exit_interviews.ExitInterviewAssignment",
        target_object_id=str(assignment.id),
        metadata={"old_student_id": old_student_id, "new_student_id": str(student.pk)},
    )
    return assignment


@transaction.atomic
def start_exit_response(actor, command: ExitInterviewStartCommand) -> ExitInterviewResponse:
    if not isinstance(command, ExitInterviewStartCommand):
        raise ValidationError("Exit Interview start requires a typed command.")
    from apps.exit_interviews.policies import can_start_exit_interview

    invitation = None
    collection = None
    if isinstance(actor, VerifiedFormAccessPrincipal):
        if command.form_invitation_id and command.form_invitation_id != actor.invitation_id:
            raise PermissionDeniedError()
        if command.form_revision_id != actor.form_revision_id:
            raise PermissionDeniedError()
        invitation = resolve_verified_invitation_for_composition(
            actor,
            expected_target_form_key="exit_interview",
        )
        student = invitation.linked_student
        if student is None:
            raise PermissionDeniedError()
        if command.student_profile_id and command.student_profile_id != str(student.pk):
            raise PermissionDeniedError()
        collection = invitation.collection
    else:
        if command.form_invitation_id:
            # An invitation UUID is not proof of verified access. Tokenized
            # response starts must arrive through the verified principal path.
            raise PermissionDeniedError()
        student = StudentProfile.objects.filter(pk=command.student_profile_id).first()
        if student is None:
            raise ValidationError("The student profile was not found.")
        if not can_start_exit_interview(actor, student):
            raise PermissionDeniedError()
        if command.form_collection_id:
            from apps.form_collection.models import FormCollection

            collection = FormCollection.objects.filter(pk=command.form_collection_id).first()
            if collection is None:
                raise ValidationError("The Form Collection was not found.")

    if collection is not None and command.form_collection_id and command.form_collection_id != str(collection.pk):
        raise PermissionDeniedError()
    if collection is not None and collection.form_revision_id and str(collection.form_revision_id) != str(command.form_revision_id):
        raise PermissionDeniedError()
    revision = FormRevision.objects.select_related("form_family").filter(pk=command.form_revision_id).first()
    if revision is None or revision.status != GovernanceStatusChoices.ACTIVE:
        raise ValidationError("The selected form revision is not active.")
    academic_year = command.academic_year or resolve_current_academic_year()
    eligibility_source = check_exit_eligibility(student, academic_year)
    return _start_exit_response_legacy(
        student_profile=student,
        form_revision=revision,
        eligibility_source=eligibility_source,
        form_collection=collection,
        form_invitation=invitation,
    )


@transaction.atomic
def save_exit_draft(actor, reference_code: str, command: ExitInterviewDraftCommand) -> ExitInterviewResponse:
    if not isinstance(command, ExitInterviewDraftCommand):
        raise ValidationError("Exit Interview draft saves require a typed command.")
    response = _response_for_update(reference_code)
    _check_updated_at(response, command.expected_updated_at)
    if isinstance(actor, VerifiedFormAccessPrincipal):
        if not actor.matches_response(response):
            raise PermissionDeniedError()
    else:
        from apps.exit_interviews.policies import can_submit_exit_interview, can_view_exit_free_text
        if actor is None or not (can_submit_exit_interview(actor, response) or can_view_exit_free_text(actor, response)):
            raise PermissionDeniedError()
    values = _validate_answer_set(response, command.answers)
    normalized = {key: value for key, value in values.items() if key in set(RATING_MATRIX_FIELDS) or hasattr(response, key)}
    return _save_exit_draft_legacy(response, values, actor, normalized_payload=normalized)


@transaction.atomic
def submit_exit_response(actor, reference_code: str, command: ExitInterviewLifecycleCommand | None = None, *, ip_address: str = None, user_agent: str = None) -> ExitInterviewResponse:
    command = command or ExitInterviewLifecycleCommand()
    if not isinstance(command, ExitInterviewLifecycleCommand):
        raise ValidationError("Exit Interview submission requires a typed command.")
    response = _response_for_update(reference_code)
    _check_updated_at(response, command.expected_updated_at)
    if isinstance(actor, VerifiedFormAccessPrincipal):
        if not actor.matches_response(response):
            raise PermissionDeniedError()
        audit_actor = None
    else:
        from apps.exit_interviews.policies import can_submit_exit_interview
        if actor is None or not can_submit_exit_interview(actor, response):
            raise PermissionDeniedError()
        audit_actor = actor
    return _submit_exit_response_legacy(response, audit_actor, ip_address=ip_address, user_agent=user_agent)


def _staff_lifecycle(actor, reference_code, command, operation):
    if not isinstance(command, ExitInterviewReasonCommand | ExitInterviewLifecycleCommand):
        raise ValidationError("Exit Interview lifecycle requires a typed command.")
    response = _response_for_update(reference_code)
    _check_updated_at(response, command.expected_updated_at)
    return operation(response, actor, getattr(command, "reason", ""))


def reopen_exit_response(actor, reference_code: str, command: ExitInterviewReasonCommand) -> ExitInterviewResponse:
    return _staff_lifecycle(actor, reference_code, command, _reopen_exit_response_legacy)


def void_exit_response(actor, reference_code: str, command: ExitInterviewReasonCommand) -> ExitInterviewResponse:
    return _staff_lifecycle(actor, reference_code, command, _void_exit_response_legacy)


def archive_exit_response(actor, reference_code: str, command: ExitInterviewLifecycleCommand) -> ExitInterviewResponse:
    return _staff_lifecycle(actor, reference_code, command, lambda response, user, _reason: _archive_exit_response_legacy(response, user))


@transaction.atomic
def acknowledge_exit_response(actor, reference_code: str, command: ExitInterviewAcknowledgeCommand | None = None) -> ExitInterviewResponse:
    command = command or ExitInterviewAcknowledgeCommand()
    if not isinstance(command, ExitInterviewAcknowledgeCommand):
        raise ValidationError("Exit Interview acknowledgement requires a typed command.")
    response = _response_for_update(reference_code)
    _check_updated_at(response, command.expected_updated_at)
    return _acknowledge_exit_response_legacy(response, actor)
