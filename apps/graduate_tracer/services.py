# Project: COMPASS
# File: apps/graduate_tracer/services.py
# Module: apps.graduate_tracer
# Purpose: Service layer for managing Graduate Tracer Survey (GTS) response workflow
# Domain boundary and service policy.

import uuid
from django.db import transaction
from apps.common.exceptions import PermissionDeniedError, StaleStateError, ValidationError
from apps.common.verified_access import VerifiedFormAccessPrincipal
from django.utils import timezone

from apps.graduate_tracer.models import GraduateTracerResponse, GTSResponseStatus, EmploymentStatus
from apps.profiles.models import StudentProfile, StudentLifecycleChoices
from apps.organizations.models import FormRevision, GovernanceStatusChoices
from apps.graduate_tracer.reference_codes import generate_graduate_tracer_reference_code
from apps.organizations.academic_year import resolve_current_academic_year
from apps.audit.services import audit_log, audit_status_transition
from apps.orchestration.commands import FormInvitationLifecycleCommand, FormRevisionUsageCommand
from apps.orchestration.use_cases import (
    mark_form_invitation_submitted_for_composition,
    mark_form_revision_used_for_composition,
    resolve_verified_invitation_for_composition,
    start_form_invitation_draft_for_composition,
)
from apps.graduate_tracer.commands import (
    GraduateTracerDraftCommand,
    GraduateTracerLifecycleCommand,
    GraduateTracerStartCommand,
)


class GTSValidationError(ValidationError):
    """Custom validation error for Graduate Tracer Survey workflow."""
    pass


GTS_ALLOWED_ANSWER_FIELDS = frozenset({
    "telephone_number", "sex", "region_of_origin", "province", "received_honors",
    "employment_status", "presently_employed", "present_employment_category",
    "business_line", "place_of_work", "is_first_job", "first_job_related",
    "first_job_search_duration", "first_job_level", "current_job_level",
    "initial_gross_earnings", "curriculum_relevant", "contact_listing_consent",
    "baccalaureate", "professional_examinations", "trainings", "advance_studies",
    "employment_history", "job_history", "educational_background",
})


def check_gts_eligibility(student_profile: StudentProfile) -> None:
    """Checks if student has graduate/alumni lifecycle status for GTS access."""
    if student_profile.lifecycle_status not in (StudentLifecycleChoices.GRADUATED, StudentLifecycleChoices.ALUMNI):
        raise GTSValidationError("Only graduated or alumni students can complete the Graduate Tracer Survey.")


@transaction.atomic
def _start_gts_response_legacy(
    student_profile: StudentProfile = None,
    unlinked_submission = None,
    form_revision: FormRevision = None,
    form_collection = None,
    form_invitation = None,
    metadata_json = None
) -> GraduateTracerResponse:
    """Starts or loads a GTS response draft."""
    academic_year = resolve_current_academic_year()

    # Uniqueness: One active response per student/unlinked record per form revision/collection
    query = GraduateTracerResponse.objects.filter(
        form_revision=form_revision,
        status__in=(GTSResponseStatus.DRAFT, GTSResponseStatus.SUBMITTED, GTSResponseStatus.REOPENED_FOR_CORRECTION)
    )
    if student_profile:
        query = query.filter(student=student_profile)
    elif unlinked_submission:
        query = query.filter(unlinked_submission=unlinked_submission)
    else:
        raise GTSValidationError("Either student profile or unlinked record is required to start GTS.")

    existing = query.first()
    if existing:
        if existing.status == GTSResponseStatus.SUBMITTED:
            raise GTSValidationError("You have already submitted a response for this survey.")
        return existing

    if form_invitation:
        start_form_invitation_draft_for_composition(
            FormInvitationLifecycleCommand(str(form_invitation.pk))
        )

    temp_ref = f"DRAFT-GTS-{uuid.uuid4().hex[:8]}"

    response = GraduateTracerResponse.objects.create(
        reference_code=temp_ref,
        student=student_profile,
        unlinked_submission=unlinked_submission,
        lifecycle_snapshot=student_profile.lifecycle_status if student_profile else "PROVISIONAL",
        program_snapshot=student_profile.program if student_profile else (unlinked_submission.program_snapshot or ""),
        college_snapshot=student_profile.college if student_profile else "",
        graduation_year=academic_year,
        form_family=form_revision.form_family,
        form_revision=form_revision,
        form_collection=form_collection,
        form_invitation=form_invitation,
        status=GTSResponseStatus.DRAFT,
        metadata_json=metadata_json or {}
    )

    audit_log(
        action_type="GTS_DRAFT_STARTED",
        event_category="WORKFLOW",
        target_model="graduate_tracer.GraduateTracerResponse",
        target_object_id=str(response.id),
        actor_user=student_profile.user if student_profile else None,
        metadata={"form_invitation_id": str(form_invitation.id) if form_invitation else None}
    )

    return response


@transaction.atomic
def _save_gts_draft_legacy(
    response: GraduateTracerResponse,
    response_json: dict,
    actor_user=None
) -> GraduateTracerResponse:
    """Saves GTS draft answers."""
    if response.status not in (GTSResponseStatus.DRAFT, GTSResponseStatus.REOPENED_FOR_CORRECTION):
        raise GTSValidationError("Cannot update response that is already submitted.")

    response.response_json = response_json

    # Derive the high-level EmploymentStatus enum used by reports from the
    # Q16 presently-employed answer. Q18 employment-category is preserved
    # separately for finer-grained reporting.
    presently = response_json.get("presently_employed", "") or response_json.get("employment_status", "")
    if presently == "Yes":
        response.employment_status = EmploymentStatus.EMPLOYED
    elif presently == "No":
        response.employment_status = EmploymentStatus.UNEMPLOYED
    elif presently == "Never Employed":
        response.employment_status = EmploymentStatus.NEVER_EMPLOYED
    elif presently == "Self-employed":
        response.employment_status = EmploymentStatus.SELF_EMPLOYED

    first_job_rel = response_json.get("first_job_related")
    if first_job_rel in ("Yes", True):
        response.first_job_related = True
    elif first_job_rel in ("No", False):
        response.first_job_related = False

    response.contact_listing_consent = response_json.get("contact_listing_consent", False)
    if response.contact_listing_consent:
        response.consent_given_at = timezone.now()

    # Normalized source-form columns (single-value reportable answers).
    response.telephone_number = response_json.get("telephone_number", "") or ""
    response.sex = response_json.get("sex", "") or ""
    response.region_of_origin = response_json.get("region_of_origin", "") or ""
    response.province = response_json.get("province", "") or ""
    response.received_honors = response_json.get("received_honors")
    response.presently_employed = response_json.get("presently_employed", "") or ""
    response.present_employment_category = response_json.get("present_employment_category", "") or ""
    response.business_line = response_json.get("business_line", "") or ""
    response.place_of_work = response_json.get("place_of_work", "") or ""

    is_first_job = response_json.get("is_first_job")
    if is_first_job in ("Yes", True):
        response.is_first_job = True
    elif is_first_job in ("No", False):
        response.is_first_job = False
    else:
        response.is_first_job = None

    response.first_job_search_duration = response_json.get("first_job_search_duration", "") or ""
    response.first_job_level = response_json.get("first_job_level", "") or ""
    response.current_job_level = response_json.get("current_job_level", "") or ""
    response.initial_gross_earnings = response_json.get("initial_gross_earnings", "") or ""

    curriculum_relevant = response_json.get("curriculum_relevant")
    if curriculum_relevant in ("Yes", True):
        response.curriculum_relevant = True
    elif curriculum_relevant in ("No", False):
        response.curriculum_relevant = False
    else:
        response.curriculum_relevant = None

    response.save()
    return response


@transaction.atomic
def _submit_gts_response_legacy(
    response: GraduateTracerResponse,
    actor_user=None,
    ip_address: str = None,
    user_agent: str = None
) -> GraduateTracerResponse:
    """Submits the Graduate Tracer Survey response and locks details."""
    if response.status not in (GTSResponseStatus.DRAFT, GTSResponseStatus.REOPENED_FOR_CORRECTION):
        raise GTSValidationError("Response is already submitted or closed.")

    # Revision must be active
    if response.form_revision.status != GovernanceStatusChoices.ACTIVE:
        raise GTSValidationError("Cannot submit against an inactive form revision.")

    ref_code = generate_graduate_tracer_reference_code(response.graduation_year)
    response.reference_code = ref_code
    response.status = GTSResponseStatus.SUBMITTED
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

    audit_log(
        action_type="GTS_SUBMITTED",
        event_category="WORKFLOW",
        target_model="graduate_tracer.GraduateTracerResponse",
        target_object_id=str(response.id),
        actor_user=actor_user,
        reference_code=ref_code,
        ip_address=ip_address,
        user_agent=user_agent,
        source_app="graduate_tracer",
        metadata={"employment_status": response.employment_status}
    )

    from apps.graduate_tracer.notification_services import enqueue_gts_event
    enqueue_gts_event("submitted", response)

    return response


@transaction.atomic
def _reopen_gts_response_legacy(
    response: GraduateTracerResponse,
    actor_user,
    reason: str,
    ip_address: str = None,
    user_agent: str = None
) -> GraduateTracerResponse:
    """Allows staff/counselor to reopen a submitted GTS response for correction."""
    from apps.graduate_tracer.policies import can_reopen_gts
    if not can_reopen_gts(actor_user, response):
        raise PermissionDeniedError("You do not have permission to reopen this GTS response.")

    old_status = response.status
    response.status = GTSResponseStatus.REOPENED_FOR_CORRECTION
    response.reopened_by = actor_user
    response.reopened_at = timezone.now()
    response.reopen_reason = reason
    response.save()

    audit_status_transition(
        actor_user=actor_user,
        target_model="graduate_tracer.GraduateTracerResponse",
        target_object_id=str(response.id),
        reference_code=response.reference_code,
        metadata={"old_status": old_status, "new_status": response.status, "reason": reason}
    )

    from apps.graduate_tracer.notification_services import enqueue_gts_event
    enqueue_gts_event("status_changed", response)

    return response


@transaction.atomic
def _void_gts_response_legacy(
    response: GraduateTracerResponse,
    actor_user,
    reason: str,
    ip_address: str = None,
    user_agent: str = None
) -> GraduateTracerResponse:
    """Voids a GTS response."""
    from apps.graduate_tracer.policies import can_reopen_gts
    if not can_reopen_gts(actor_user, response):
        raise PermissionDeniedError("You do not have permission to void this GTS response.")

    old_status = response.status
    response.status = GTSResponseStatus.VOIDED
    response.voided_by = actor_user
    response.voided_at = timezone.now()
    response.void_reason = reason
    response.save()

    audit_status_transition(
        actor_user=actor_user,
        target_model="graduate_tracer.GraduateTracerResponse",
        target_object_id=str(response.id),
        reference_code=response.reference_code,
        metadata={"old_status": old_status, "new_status": response.status, "reason": reason}
    )

    from apps.graduate_tracer.notification_services import enqueue_gts_event
    enqueue_gts_event("status_changed", response)

    return response


@transaction.atomic
def _archive_gts_response_legacy(
    response: GraduateTracerResponse,
    actor_user,
    ip_address: str = None,
    user_agent: str = None
) -> GraduateTracerResponse:
    """Archives a GTS response."""
    from apps.graduate_tracer.policies import can_reopen_gts
    if not can_reopen_gts(actor_user, response):
        raise PermissionDeniedError("You do not have permission to archive this GTS response.")

    old_status = response.status
    response.status = GTSResponseStatus.ARCHIVED
    response.save()

    audit_status_transition(
        actor_user=actor_user,
        target_model="graduate_tracer.GraduateTracerResponse",
        target_object_id=str(response.id),
        reference_code=response.reference_code,
        metadata={"old_status": old_status, "new_status": response.status}
    )

    return response


# ---------------------------------------------------------------------------
# Canonical stable-reference service boundary
# ---------------------------------------------------------------------------


def _check_updated_at(value, expected):
    if expected and value.updated_at.isoformat() != expected:
        raise StaleStateError()


def _locked_response(reference_code):
    response = GraduateTracerResponse.objects.select_for_update().select_related(
        "student", "form_revision", "form_collection", "form_invitation", "form_revision__form_family",
    ).filter(reference_code=reference_code).first()
    if response is None:
        raise ValidationError("The Graduate Tracer response was not found.")
    return response


def _validate_gts_answers(response, answers):
    if answers.form_revision_id != str(response.form_revision_id):
        raise ValidationError("Answers belong to a different form revision.")
    values = dict(answers.values)
    schema = response.form_revision.schema_summary_json or {}
    declared_fields = schema.get("fields") if isinstance(schema, dict) else None
    allowed = set(declared_fields) if isinstance(declared_fields, (list, tuple, set)) and declared_fields else set(GTS_ALLOWED_ANSWER_FIELDS)
    unknown = set(values) - allowed
    if unknown:
        raise ValidationError("The answer set contains unsupported fields.")
    return values


@transaction.atomic
def start_gts_response(actor, command: GraduateTracerStartCommand) -> GraduateTracerResponse:
    if not isinstance(command, GraduateTracerStartCommand):
        raise ValidationError("Graduate Tracer start requires a typed command.")
    student = StudentProfile.objects.filter(pk=command.student_profile_id).first() if command.student_profile_id else None
    form_collection = None
    form_invitation = None
    unlinked_submission = None
    if isinstance(actor, VerifiedFormAccessPrincipal):
        if command.form_invitation_id and command.form_invitation_id != actor.invitation_id:
            raise PermissionDeniedError()
        if command.form_revision_id != actor.form_revision_id:
            raise PermissionDeniedError()
        form_invitation = resolve_verified_invitation_for_composition(
            actor,
            expected_target_form_key="graduate_tracer",
        )
        student = form_invitation.linked_student
        if actor.student_profile_id and student is None:
            raise PermissionDeniedError()
        if command.student_profile_id and (student is None or command.student_profile_id != str(student.pk)):
            raise PermissionDeniedError()
        if actor.unlinked_submission_id and command.unlinked_submission_id and actor.unlinked_submission_id != command.unlinked_submission_id:
            raise PermissionDeniedError()
    elif command.form_invitation_id:
        # A bare invitation UUID is not a verified-access proof.
        raise PermissionDeniedError()

    if student is not None:
        from apps.graduate_tracer.policies import can_start_gts
        if not isinstance(actor, VerifiedFormAccessPrincipal) and not can_start_gts(actor, student):
            raise PermissionDeniedError()
        check_gts_eligibility(student)
    elif not isinstance(actor, VerifiedFormAccessPrincipal) and (actor is not None or not command.form_invitation_id):
        raise PermissionDeniedError()
    form_revision = FormRevision.objects.select_related("form_family").filter(pk=command.form_revision_id).first()
    if form_revision is None or form_revision.status != GovernanceStatusChoices.ACTIVE:
        raise ValidationError("The selected form revision is not active.")
    if isinstance(actor, VerifiedFormAccessPrincipal):
        form_collection = form_invitation.collection
        if command.form_collection_id and command.form_collection_id != str(form_collection.pk):
            raise PermissionDeniedError()
        if command.unlinked_submission_id and actor.unlinked_submission_id and command.unlinked_submission_id != actor.unlinked_submission_id:
            raise PermissionDeniedError()
        if actor.unlinked_submission_id:
            from apps.form_collection.models import UnlinkedFormSubmission
            unlinked_submission = UnlinkedFormSubmission.objects.filter(pk=actor.unlinked_submission_id).first()
            if unlinked_submission is None:
                raise ValidationError("The unlinked submission was not found.")
    elif command.form_collection_id:
        from apps.form_collection.models import FormCollection
        form_collection = FormCollection.objects.filter(pk=command.form_collection_id).first()
        if form_collection is None:
            raise ValidationError("The Form Collection was not found.")
    if command.form_invitation_id and not isinstance(actor, VerifiedFormAccessPrincipal):
        from apps.form_collection.models import FormInvitation, FormInvitationStatus
        form_invitation = FormInvitation.objects.select_for_update().select_related("collection").filter(pk=command.form_invitation_id).first()
        if form_invitation is None or form_invitation.status not in (FormInvitationStatus.VERIFIED, FormInvitationStatus.DRAFT_STARTED):
            raise ValidationError("A verified Graduate Tracer invitation is required.")
        if str(form_invitation.collection.form_revision_id) != str(form_revision.pk):
            raise ValidationError("The invitation and form revision do not match.")
        form_collection = form_collection or form_invitation.collection
        if student and form_invitation.linked_student_id and str(form_invitation.linked_student_id) != str(student.pk):
            raise PermissionDeniedError()
        if student is None and form_invitation.status not in (FormInvitationStatus.VERIFIED, FormInvitationStatus.DRAFT_STARTED):
            raise PermissionDeniedError()
    if command.unlinked_submission_id:
        from apps.form_collection.models import UnlinkedFormSubmission
        unlinked_submission = UnlinkedFormSubmission.objects.filter(pk=command.unlinked_submission_id).first()
        if unlinked_submission is None:
            raise ValidationError("The unlinked submission was not found.")
    return _start_gts_response_legacy(
        student_profile=student,
        unlinked_submission=unlinked_submission,
        form_revision=form_revision,
        form_collection=form_collection,
        form_invitation=form_invitation,
    )


@transaction.atomic
def save_gts_draft(actor, reference_code: str, command: GraduateTracerDraftCommand) -> GraduateTracerResponse:
    if not isinstance(command, GraduateTracerDraftCommand):
        raise ValidationError("Graduate Tracer draft saves require a typed command.")
    response = _locked_response(reference_code)
    _check_updated_at(response, command.expected_updated_at)
    if isinstance(actor, VerifiedFormAccessPrincipal):
        if not actor.matches_response(response):
            raise PermissionDeniedError()
    elif actor is None or response.student_id is None or str(getattr(actor, "student_profile", None).pk if getattr(actor, "student_profile", None) else "") != str(response.student_id):
        raise PermissionDeniedError()
    values = _validate_gts_answers(response, command.answers)
    return _save_gts_draft_legacy(response, values, actor)


@transaction.atomic
def submit_gts_response(actor, reference_code: str, command: GraduateTracerLifecycleCommand | None = None, *, ip_address: str = None, user_agent: str = None) -> GraduateTracerResponse:
    command = command or GraduateTracerLifecycleCommand()
    if not isinstance(command, GraduateTracerLifecycleCommand):
        raise ValidationError("Graduate Tracer submission requires a typed command.")
    response = _locked_response(reference_code)
    _check_updated_at(response, command.expected_updated_at)
    if isinstance(actor, VerifiedFormAccessPrincipal):
        if not actor.matches_response(response):
            raise PermissionDeniedError()
        audit_actor = None
    elif actor is None or response.student_id is None or str(getattr(actor, "student_profile", None).pk if getattr(actor, "student_profile", None) else "") != str(response.student_id):
        raise PermissionDeniedError()
    else:
        audit_actor = actor
    return _submit_gts_response_legacy(response, audit_actor, ip_address=ip_address, user_agent=user_agent)


def _gts_staff_lifecycle(actor, reference_code, command, operation):
    if not isinstance(command, GraduateTracerLifecycleCommand):
        raise ValidationError("Graduate Tracer lifecycle requires a typed command.")
    response = _locked_response(reference_code)
    _check_updated_at(response, command.expected_updated_at)
    return operation(response, actor, command.reason)


def reopen_gts_response(actor, reference_code: str, command: GraduateTracerLifecycleCommand) -> GraduateTracerResponse:
    return _gts_staff_lifecycle(actor, reference_code, command, _reopen_gts_response_legacy)


def void_gts_response(actor, reference_code: str, command: GraduateTracerLifecycleCommand) -> GraduateTracerResponse:
    return _gts_staff_lifecycle(actor, reference_code, command, _void_gts_response_legacy)


def archive_gts_response(actor, reference_code: str, command: GraduateTracerLifecycleCommand) -> GraduateTracerResponse:
    return _gts_staff_lifecycle(actor, reference_code, command, lambda response, user, _reason: _archive_gts_response_legacy(response, user))
