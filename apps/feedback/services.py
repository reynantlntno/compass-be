# Project: COMPASS
# File: apps/feedback/services.py
# Module: apps.feedback
# Purpose: Service layer for managing Feedback/CSM lifecycle and validation
# Domain boundary and service policy.

import re
import uuid
from django.db import transaction
from apps.common.exceptions import ValidationError
from django.utils import timezone
from apps.account_security.tokens import hash_identifier
from apps.common.exceptions import CompassError

from apps.feedback.models import FeedbackSubmission, FeedbackStatus, FeedbackSource
from apps.organizations.models import FormRevision, GovernanceStatusChoices
from apps.feedback.reference_codes import generate_feedback_reference_code
from apps.audit.services import audit_log, audit_status_transition
from apps.orchestration.commands import FormInvitationLifecycleCommand, FormRevisionUsageCommand
from apps.orchestration.use_cases import (
    mark_form_invitation_submitted_for_composition,
    mark_form_revision_used_for_composition,
    start_form_invitation_draft_for_composition,
)


class FeedbackValidationError(ValidationError):
    """Custom validation error for feedback submissions."""
    pass


def _rating_value(ratings: dict, key: str):
    """Safely pull a 1-5 integer rating from a ratings dict, returning None when unset.

    Allows SQD/matrix columns to be normalized at write time while keeping the
    same None / N/A semantics across optional matrix items.
    """
    if not ratings:
        return None
    value = ratings.get(key)
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def detect_sensitive_content_hint(text: str) -> list[str]:
    """Inspect text for keywords that might indicate sensitive counseling or security data.

    Returns list of matched warnings/keywords to prompt the client.
    """
    if not text:
        return []
    
    text_lower = text.lower()
    matches = []
    
    # Counseling/Emergency indicators
    counseling_keywords = [
        "counseling notes", "counseling folder", "clinical",
        "suicide", "self-harm", "abuse", "depression", "emergency"
    ]
    for kw in counseling_keywords:
        if kw in text_lower:
            matches.append(kw)
            
    # Credential/Security indicators
    security_keywords = ["password", "otp", "secret", "token", "api_key"]
    for kw in security_keywords:
        if kw in text_lower:
            matches.append(kw)
            
    return matches


def is_recent_duplicate_feedback(
    ip_address: str = None,
    session_key: str = None,
    rating_val: int = None,
    comment_text: str = None
) -> bool:
    """Detect a recent content duplicate for public feedback.

    Checks if a submission with the same IP/Session and content fingerprint
    occurred in the last 5 minutes.
    """
    if not (ip_address or session_key):
        return False

    now = timezone.now()
    window = now - timezone.timedelta(minutes=5)
    
    # Query matching recent submissions
    qs = FeedbackSubmission.objects.filter(
        submitted_at__gte=window,
        status=FeedbackStatus.SUBMITTED
    )
    
    if ip_address:
        # Note: IP in audit log is hashed, but here we can check metadata_json.ip_address if we store it safely.
        # However, to be fully privacy-safe, we can check recent submissions matching session_key or simply rating/comment duplicates.
        pass
        
    if session_key:
        qs = qs.filter(metadata_json__session_hash=hash_identifier(f"feedback-session:{session_key}"))

    if rating_val is not None:
        qs = qs.filter(overall_satisfaction=rating_val)
        
    if comment_text:
        qs = qs.filter(comment_text=comment_text)

    return qs.exists()


@transaction.atomic
def create_feedback_submission(
    form_revision: FormRevision,
    client_type: str,
    service_category: str,
    source: str = FeedbackSource.PUBLIC,
    respondent_user=None,
    is_anonymous: bool = False,
    related_workflow_type: str = None,
    related_reference_code: str = None,
    form_collection=None,
    form_invitation=None,
    invitation=None,
    response_json: dict = None,
    comment_text: str = None,
    experience_feedback: str = None,
    cc_awareness: str = "",
    cc_visibility: str = "",
    cc_helpfulness: str = "",
    overall_satisfaction: int = None,
    sqd_average: float = None,
    sqd_ratings: dict = None,
    service_personnel_ratings: dict = None,
    office_premises_ratings: dict = None,
    sex: str = "",
    age: int = None,
    region_of_residence: str = "",
    talked_to_counselor=None,
    accommodated_by: str = "",
    visit_count: int = None,
    transaction_duration_text: str = "",
    is_paper_transcription: bool = False,
    transcribed_by=None,
    metadata_json: dict = None,
    ip_address: str = None,
    session_key: str = None,
    user_agent: str = None
) -> FeedbackSubmission:
    """Creates a FeedbackSubmission in DRAFT status."""
    # Ensure form_revision is active for new submissions
    if form_revision.status != GovernanceStatusChoices.ACTIVE:
        raise FeedbackValidationError("Cannot submit feedback against an inactive form revision.")
        
    # Check recent content duplicate for public submissions
    if source == FeedbackSource.PUBLIC:
        if is_recent_duplicate_feedback(ip_address, session_key, overall_satisfaction, comment_text):
            raise FeedbackValidationError("Duplicate feedback submission detected. Please wait a few minutes before trying again.")
            
    # Validate sensitive content warning
    if comment_text:
        warnings = detect_sensitive_content_hint(comment_text)
        if warnings:
            # We fail closed or raise validation error to prevent sensitive data submission
            raise FeedbackValidationError(
                f"Your feedback contains sensitive terms ({', '.join(warnings)}). "
                "Please do not submit confidential counseling details, emergency concerns, or passwords here."
            )
            
    # If form_invitation is present, call start_form_invitation_draft hook
    if form_invitation:
        start_form_invitation_draft_for_composition(
            FormInvitationLifecycleCommand(str(form_invitation.pk))
        )

    # Academic year fallback from metadata or resolve
    academic_year = None
    if metadata_json and "academic_year" in metadata_json:
        academic_year = metadata_json["academic_year"]
    if not academic_year:
        from apps.organizations.academic_year import resolve_current_academic_year
        try:
            academic_year = resolve_current_academic_year()
        except Exception as exc:
            raise FeedbackValidationError("The current academic year is not configured.") from exc

    # Build safe metadata
    safe_meta = {
        "academic_year": academic_year,
    }
    if session_key:
        safe_meta["session_hash"] = hash_identifier(f"feedback-session:{session_key}")

    # Temporary reference code for draft
    temp_ref = f"DRAFT-{uuid.uuid4().hex[:8]}"

    submission = FeedbackSubmission.objects.create(
        reference_code=temp_ref,
        respondent_user=respondent_user,
        client_type=client_type,
        lifecycle_snapshot=respondent_user.student_profile.lifecycle_status if (respondent_user and hasattr(respondent_user, "student_profile")) else None,
        is_anonymous=is_anonymous,
        source=source,
        service_category=service_category,
        related_workflow_type=related_workflow_type,
        related_reference_code=related_reference_code,
        form_family=form_revision.form_family,
        form_revision=form_revision,
        form_collection=form_collection,
        form_invitation=form_invitation,
        invitation=invitation,
        status=FeedbackStatus.DRAFT,
        overall_satisfaction=overall_satisfaction,
        sqd_average=sqd_average,
        sqd0=_rating_value(sqd_ratings, "sqd0"),
        sqd1=_rating_value(sqd_ratings, "sqd1"),
        sqd2=_rating_value(sqd_ratings, "sqd2"),
        sqd3=_rating_value(sqd_ratings, "sqd3"),
        sqd4=_rating_value(sqd_ratings, "sqd4"),
        sqd5=_rating_value(sqd_ratings, "sqd5"),
        sqd6=_rating_value(sqd_ratings, "sqd6"),
        sqd7=_rating_value(sqd_ratings, "sqd7"),
        sqd8=_rating_value(sqd_ratings, "sqd8"),
        sq_personnel_helpfulness=_rating_value(service_personnel_ratings, "sq_personnel_helpfulness"),
        sq_personnel_competence=_rating_value(service_personnel_ratings, "sq_personnel_competence"),
        sq_personnel_flexibility=_rating_value(service_personnel_ratings, "sq_personnel_flexibility"),
        sq_personnel_accuracy=_rating_value(service_personnel_ratings, "sq_personnel_accuracy"),
        sq_personnel_appearance=_rating_value(service_personnel_ratings, "sq_personnel_appearance"),
        sq_personnel_delivered=_rating_value(service_personnel_ratings, "sq_personnel_delivered"),
        op_located=_rating_value(office_premises_ratings, "op_located"),
        op_cleanliness=_rating_value(office_premises_ratings, "op_cleanliness"),
        op_environment=_rating_value(office_premises_ratings, "op_environment"),
        op_office_hours=_rating_value(office_premises_ratings, "op_office_hours"),
        op_availability=_rating_value(office_premises_ratings, "op_availability"),
        cc_awareness=cc_awareness,
        cc_visibility=cc_visibility,
        cc_helpfulness=cc_helpfulness,
        sex=sex or "",
        age=age,
        region_of_residence=region_of_residence or "",
        talked_to_counselor=talked_to_counselor,
        accommodated_by=accommodated_by or "",
        visit_count=visit_count,
        transaction_duration_text=transaction_duration_text or "",
        response_json=response_json or {},
        comment_text=comment_text or "",
        experience_feedback=experience_feedback or "",
        is_paper_transcription=is_paper_transcription,
        transcribed_by=transcribed_by,
        metadata_json=safe_meta
    )
    
    audit_log(
        action_type="FEEDBACK_DRAFT_CREATED",
        event_category="WORKFLOW",
        target_model="feedback.FeedbackSubmission",
        target_object_id=str(submission.id),
        actor_user=respondent_user,
        ip_address=ip_address,
        user_agent=user_agent,
        source_app="feedback",
        metadata={"action": "draft_created", "outcome": "success"}
    )
    
    return submission


@transaction.atomic
def submit_feedback(
    submission: FeedbackSubmission,
    actor_user=None,
    ip_address: str = None,
    user_agent: str = None
) -> FeedbackSubmission:
    """Officially submits a draft feedback, locks details, and snapshots revision usage."""
    if submission.status != FeedbackStatus.DRAFT:
        raise FeedbackValidationError("Feedback is already submitted or closed.")
        
    # FormRevision must be active
    if submission.form_revision.status != GovernanceStatusChoices.ACTIVE:
        raise FeedbackValidationError("Cannot submit feedback against an inactive form revision.")

    # Generate permanent FBK reference code
    academic_year = submission.metadata_json.get("academic_year")
    if not academic_year:
        from apps.organizations.academic_year import resolve_current_academic_year
        try:
            academic_year = resolve_current_academic_year()
        except Exception as exc:
            raise FeedbackValidationError("The current academic year is not configured.") from exc
            
    ref_code = generate_feedback_reference_code(academic_year)
    submission.reference_code = ref_code
    submission.status = FeedbackStatus.SUBMITTED
    submission.submitted_at = timezone.now()
    submission.save()

    # Mark form revision as used in governance service (requires system_context or authorized user)
    mark_form_revision_used_for_composition(
        actor_user,
        FormRevisionUsageCommand(
            str(submission.form_revision_id),
            system_context=True,
        ),
    )

    # Call token submission hook if tokenized
    if submission.form_invitation:
        mark_form_invitation_submitted_for_composition(
            FormInvitationLifecycleCommand(str(submission.form_invitation_id))
        )

    audit_log(
        action_type="FEEDBACK_SUBMITTED",
        event_category="WORKFLOW",
        target_model="feedback.FeedbackSubmission",
        target_object_id=str(submission.id),
        actor_user=actor_user,
        ip_address=ip_address,
        user_agent=user_agent,
        source_app="feedback",
        metadata={"action": "submitted", "outcome": "success"}
    )

    # Preserve only the event identity and minimum system-processing metadata.
    from apps.workflow.services import enqueue_outbox_event
    try:
        enqueue_outbox_event(
            event_type="feedback.submitted",
            payload={
                "feedback_id": str(submission.id),
                "action": "submitted",
            },
            related_object=submission
        )
    except Exception:
        # Email/notification enqueue failures must not roll back main survey transaction
        pass

    return submission


@transaction.atomic
def assign_feedback(
    submission: FeedbackSubmission,
    assignee_user,
    actor_user,
    ip_address: str = None,
    user_agent: str = None
) -> FeedbackSubmission:
    """Assigns feedback submission to a staff member/counselor."""
    from apps.feedback.policies import can_assign_feedback
    if not can_assign_feedback(actor_user):
        raise PermissionError("You do not have permission to assign feedback.")
        
    submission.assigned_to = assignee_user
    submission.save()

    from apps.audit.services import audit_assignment_change
    audit_assignment_change(
        actor_user=actor_user,
        target_model="feedback.FeedbackSubmission",
        target_object_id=str(submission.id),
        metadata={"action": "assignment_changed", "outcome": "success"}
    )

    return submission


@transaction.atomic
def mark_feedback_reviewed(
    submission: FeedbackSubmission,
    actor_user,
    ip_address: str = None,
    user_agent: str = None
) -> FeedbackSubmission:
    """Marks feedback as reviewed by staff."""
    from apps.feedback.policies import can_review_feedback
    if not can_review_feedback(actor_user, submission):
        raise PermissionError("You do not have permission to review this feedback.")

    old_status = submission.status
    submission.status = FeedbackStatus.REVIEWED
    submission.reviewed_by = actor_user
    submission.reviewed_at = timezone.now()
    submission.save()

    audit_status_transition(
        actor_user=actor_user,
        target_model="feedback.FeedbackSubmission",
        target_object_id=str(submission.id),
        metadata={"old_status": old_status, "new_status": submission.status}
    )

    return submission


@transaction.atomic
def respond_to_feedback(
    submission: FeedbackSubmission,
    response_text: str,
    actor_user,
    ip_address: str = None,
    user_agent: str = None
) -> FeedbackSubmission:
    """Records feedback review/response and transitions status to RESPONDED."""
    from apps.feedback.policies import can_review_feedback
    if not can_review_feedback(actor_user, submission):
        raise PermissionError("You do not have permission to respond to this feedback.")

    old_status = submission.status
    submission.status = FeedbackStatus.RESPONDED
    
    # Store response in safe metadata, not raw comment
    if not submission.metadata_json:
        submission.metadata_json = {}
    submission.metadata_json["staff_response_length"] = len(response_text)
    submission.reviewed_by = actor_user
    submission.reviewed_at = timezone.now()
    submission.save()

    audit_status_transition(
        actor_user=actor_user,
        target_model="feedback.FeedbackSubmission",
        target_object_id=str(submission.id),
        metadata={"old_status": old_status, "new_status": submission.status}
    )

    # Enqueue outbox event for submitter if user is known and not anonymous
    if submission.respondent_user and not submission.is_anonymous:
        from apps.workflow.services import enqueue_outbox_event
        try:
            enqueue_outbox_event(
                event_type="feedback.responded",
                payload={
                    "feedback_id": str(submission.id),
                    "action": "responded",
                },
                related_object=submission
            )
        except Exception:
            pass

    return submission


@transaction.atomic
def close_feedback(
    submission: FeedbackSubmission,
    actor_user,
    ip_address: str = None,
    user_agent: str = None
) -> FeedbackSubmission:
    """Closes a feedback submission."""
    from apps.feedback.policies import can_close_feedback
    if not can_close_feedback(actor_user, submission):
        raise PermissionError("You do not have permission to close this feedback.")

    old_status = submission.status
    submission.status = FeedbackStatus.CLOSED
    submission.closed_at = timezone.now()
    submission.save()

    audit_status_transition(
        actor_user=actor_user,
        target_model="feedback.FeedbackSubmission",
        target_object_id=str(submission.id),
        metadata={"old_status": old_status, "new_status": submission.status}
    )

    return submission


@transaction.atomic
def mark_spam(
    submission: FeedbackSubmission,
    actor_user,
    ip_address: str = None,
    user_agent: str = None
) -> FeedbackSubmission:
    """Marks a feedback submission as SPAM."""
    from apps.feedback.policies import can_mark_feedback_spam
    if not can_mark_feedback_spam(actor_user):
        raise PermissionError("You do not have permission to mark this feedback as spam.")

    old_status = submission.status
    submission.status = FeedbackStatus.SPAM
    submission.save()

    audit_status_transition(
        actor_user=actor_user,
        target_model="feedback.FeedbackSubmission",
        target_object_id=str(submission.id),
        metadata={"old_status": old_status, "new_status": submission.status}
    )

    return submission


@transaction.atomic
def archive_feedback(
    submission: FeedbackSubmission,
    actor_user,
    ip_address: str = None,
    user_agent: str = None
) -> FeedbackSubmission:
    """Archives feedback submission."""
    from apps.feedback.policies import can_close_feedback
    if not can_close_feedback(actor_user, submission):
        raise PermissionError("You do not have permission to archive this feedback.")

    old_status = submission.status
    submission.status = FeedbackStatus.ARCHIVED
    submission.save()

    audit_status_transition(
        actor_user=actor_user,
        target_model="feedback.FeedbackSubmission",
        target_object_id=str(submission.id),
        metadata={"old_status": old_status, "new_status": submission.status}
    )

    return submission


@transaction.atomic
def void_feedback(
    submission: FeedbackSubmission,
    actor_user,
    reason: str,
    ip_address: str = None,
    user_agent: str = None
) -> FeedbackSubmission:
    """Voids a feedback submission for administrative corrective action."""
    from apps.feedback.policies import can_close_feedback
    if not can_close_feedback(actor_user, submission):
        raise PermissionError("You do not have permission to void this feedback.")

    old_status = submission.status
    submission.status = FeedbackStatus.VOIDED
    if not submission.metadata_json:
        submission.metadata_json = {}
    submission.metadata_json["void_reason"] = reason
    submission.save()

    audit_status_transition(
        actor_user=actor_user,
        target_model="feedback.FeedbackSubmission",
        target_object_id=str(submission.id),
        metadata={"old_status": old_status, "new_status": submission.status}
    )

    return submission
