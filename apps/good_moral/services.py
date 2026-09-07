# Project: COMPASS
# File: apps/good_moral/services.py
# Module: apps.good_moral
# Purpose: Service layer transitions for Good Moral request lifecycle
# Domain boundary and service policy.

import logging
from django.db import transaction
from django.utils import timezone
from apps.common.exceptions import (
    CompassError,
    ErrorCode,
    NotFoundError,
    PermissionDeniedError,
    ValidationError,
)

from apps.good_moral.models import (
    GoodMoralRequest,
    GoodMoralStatusChoices,
    RequestTypeChoices,
    ReceiptStatusChoices,
    DrySealStatusChoices,
    DrySealConfirmationMethodChoices,
    OSSDVerificationStatusChoices,
)
from apps.good_moral.policies import (
    can_create_request,
    can_submit_request,
    can_cancel_request,
    can_encode_receipt_metadata,
    can_verify_receipt_metadata,
    can_start_review,
    can_assign_reviewer,
    can_hold_request,
    can_approve_request,
    can_reject_request,
    can_generate_request_document,
    can_mark_printed,
    can_confirm_dry_seal,
    can_release_request,
    can_void_request,
    can_supersede_request,
    can_archive_request,
    can_update_draft,
)
from apps.good_moral.document_services import generate_good_moral_document_by_reference
from apps.orchestration.commands import DocumentLifecycleCommand, FeedbackInvitationCommand
from apps.orchestration.use_cases import (
    issue_feedback_invitation_for_completed_source,
    archive_document_for_composition,
    release_document_for_composition,
    void_document_for_composition,
)
from apps.good_moral.reference_codes import generate_good_moral_reference_code
from apps.organizations.academic_year import resolve_current_academic_year
from apps.audit.services import audit_log

logger = logging.getLogger(__name__)


class GoodMoralServiceError(CompassError):
    """Raised when a Good Moral service operation fails."""
    code = ErrorCode.LIFECYCLE_CONFLICT
    public_message = "The Good Moral request is not in a state that permits this action."


class GoodMoralPolicyError(GoodMoralServiceError):
    """Raised when a policy check denies a Good Moral transition."""
    code = ErrorCode.PERMISSION
    public_message = "You do not have permission to perform this Good Moral action."


def _request_audit_meta(request):
    return {
        "model": "GoodMoralRequest",
        "object_id": str(request.pk),
        "reference_code": request.reference_code,
        "status": request.status,
        "request_type": request.request_type,
        "applicant_lifecycle_status": request.applicant_lifecycle_status,
        "receipt_status": request.receipt_status,
        "dry_seal_status": request.dry_seal_status,
        "dry_seal_confirmation_method": request.dry_seal_confirmation_method,
        "dry_seal_confirmed_by_id": request.dry_seal_confirmed_by_id,
        "dry_seal_confirmed_at": request.dry_seal_confirmed_at.isoformat() if request.dry_seal_confirmed_at else "",
        "ossd_verification_status": request.ossd_verification_status,
    }


def _audit_transition(action_type, user, request, *, extra_metadata=None):
    metadata = _request_audit_meta(request)
    metadata.update(extra_metadata or {})
    audit_log(
        action_type=action_type,
        event_category="WORKFLOW",
        target_model="GoodMoralRequest",
        target_object_id=str(request.pk),
        actor_user=user,
        reference_code=request.reference_code,
        source_app="apps.good_moral",
        metadata=metadata,
    )


# ---------------------------------------------------------------------------
# Service Actions
# ---------------------------------------------------------------------------

def _create_draft(
    *,
    actor,
    requester_user,
    purpose_text,
    student_profile=None,
    academic_year=None,
    semester="",
    major="",
    graduation_date=None,
) -> GoodMoralRequest:
    """Create a draft Good Moral request, snapshotting the student details.

    The certificate variant is derived from the applicant lifecycle snapshot;
    callers cannot select the student/graduate template themselves.
    """
    if not purpose_text or len(purpose_text.strip()) == 0:
        raise GoodMoralServiceError("Purpose text is required.")
    if len(purpose_text) > 500:
        raise GoodMoralServiceError("Purpose text must not exceed 500 characters.")

    # 1. Resolve student profile
    if not student_profile and hasattr(requester_user, "student_profile"):
        student_profile = requester_user.student_profile

    if not student_profile:
        raise GoodMoralServiceError("Student profile is required to request a Good Moral certificate.")

    from apps.good_moral.lifecycle import GoodMoralVariantError, derive_request_type
    try:
        request_type = derive_request_type(student_profile)
    except GoodMoralVariantError as exc:
        raise GoodMoralServiceError(str(exc)) from exc
    lifecycle_status = student_profile.lifecycle_status
    if lifecycle_status in {"GRADUATING", "GRADUATED", "ALUMNI"} and not graduation_date:
        raise GoodMoralServiceError(
            "A graduation date is required for graduating, graduated, or alumni requests."
        )

    if not can_create_request(
        actor,
        student_profile,
        requester_user=requester_user,
    ):
        raise GoodMoralPolicyError("Permission denied: cannot create Good Moral request.")

    with transaction.atomic():
        # Serialize duplicate checks and reference allocation per student.
        from apps.profiles.models import StudentProfile

        student_profile = StudentProfile.objects.select_for_update().select_related("user").get(
            pk=student_profile.pk
        )
        if not academic_year:
            try:
                academic_year = resolve_current_academic_year()
            except Exception as exc:
                raise GoodMoralServiceError() from exc

        active_requests = GoodMoralRequest.objects.filter(
            requester_user=requester_user,
            request_type=request_type,
            applicant_academic_year=academic_year,
        ).exclude(
            status__in=[
                GoodMoralStatusChoices.REJECTED,
                GoodMoralStatusChoices.CANCELLED,
                GoodMoralStatusChoices.VOIDED,
                GoodMoralStatusChoices.ARCHIVED,
            ]
        )
        if active_requests.exists():
            raise GoodMoralServiceError()

        try:
            reference_code = generate_good_moral_reference_code(academic_year)
        except Exception as exc:
            raise GoodMoralServiceError() from exc

        display_name = student_profile.user.get_full_name() or student_profile.user.username
        lifecycle_status = student_profile.lifecycle_status
        campus = student_profile.campus or "Main Campus"
        college = student_profile.college
        department = student_profile.department
        program = student_profile.program
        year_level_str = str(student_profile.year_level) if student_profile.year_level else ""

        request = GoodMoralRequest.objects.create(
            reference_code=reference_code,
            request_type=request_type,
            requester_user=requester_user,
            student_profile=student_profile,
            applicant_display_name=display_name,
            applicant_lifecycle_status=lifecycle_status,
            applicant_campus=campus,
            applicant_college=college,
            applicant_department=department,
            applicant_program_degree=program,
            applicant_year_level=year_level_str,
            applicant_major=major,
            applicant_semester=semester,
            applicant_academic_year=academic_year,
            applicant_graduation_date=graduation_date,
            purpose_text=purpose_text,
            status=GoodMoralStatusChoices.DRAFT,
        )

    _audit_transition("GOOD_MORAL_DRAFT_CREATED", actor, request)
    return request


def _submit_request(user, request) -> GoodMoralRequest:
    """Submit a draft request."""
    with transaction.atomic():
        request = GoodMoralRequest.objects.select_for_update().get(pk=request.pk)
        if request.status != GoodMoralStatusChoices.DRAFT:
            raise GoodMoralServiceError(f"Cannot submit request in status '{request.status}'.")

        if not can_submit_request(user, request):
            raise GoodMoralPolicyError("Permission denied: cannot submit this request.")

        from apps.good_moral.exit_prerequisite import enforce_exit_prerequisite, ExitPrerequisiteError
        try:
            enforce_exit_prerequisite(request, gate="submission")
        except ExitPrerequisiteError as exc:
            raise GoodMoralServiceError(str(exc)) from exc

        request.status = GoodMoralStatusChoices.SUBMITTED
        request.save()

    _audit_transition("GOOD_MORAL_SUBMITTED", user, request)
    return request


def _assign_reviewer(user, request, reviewer) -> GoodMoralRequest:
    """Assign an active, in-scope counselor to the review workflow."""
    with transaction.atomic():
        request = GoodMoralRequest.objects.select_for_update().get(pk=request.pk)
        if not can_assign_reviewer(user, request, reviewer):
            raise GoodMoralPolicyError("Permission denied: cannot assign Good Moral reviewer.")

        previous_reviewer_id = request.assigned_reviewer_id
        request.assigned_reviewer = reviewer
        request.save(update_fields=["assigned_reviewer", "updated_at"])

    _audit_transition(
        "GOOD_MORAL_REVIEWER_ASSIGNED",
        user,
        request,
        extra_metadata={
            "reviewer_user_id": str(reviewer.pk),
            "previous_reviewer_user_id": (
                str(previous_reviewer_id) if previous_reviewer_id else ""
            ),
        },
    )
    return request


def _cancel_request(user, request, reason_code="") -> GoodMoralRequest:
    """Cancel a request (student cancel early status or staff cancel)."""
    with transaction.atomic():
        request = GoodMoralRequest.objects.select_for_update().get(pk=request.pk)
        if not can_cancel_request(user, request):
            raise GoodMoralPolicyError("Permission denied: cannot cancel request.")

        if request.status in (
            GoodMoralStatusChoices.GENERATED,
            GoodMoralStatusChoices.PRINTED,
            GoodMoralStatusChoices.RELEASED,
            GoodMoralStatusChoices.VOIDED,
            GoodMoralStatusChoices.ARCHIVED,
        ):
            raise GoodMoralServiceError(f"Cannot cancel request in status '{request.status}'.")

        request.status = GoodMoralStatusChoices.CANCELLED
        request.cancelled_by = user
        request.cancelled_at = timezone.now()
        request.terminal_reason_code = reason_code
        request.save()

    _audit_transition("GOOD_MORAL_CANCELLED", user, request)
    return request


def _update_receipt_metadata(user, request, *, receipt_number, receipt_date, receipt_amount) -> GoodMoralRequest:
    """Encode manual receipt details."""
    with transaction.atomic():
        request = GoodMoralRequest.objects.select_for_update().get(pk=request.pk)
        if not can_encode_receipt_metadata(user, request):
            raise GoodMoralPolicyError("Permission denied: cannot encode receipt metadata.")

        if request.status in (
            GoodMoralStatusChoices.RELEASED,
            GoodMoralStatusChoices.VOIDED,
            GoodMoralStatusChoices.ARCHIVED,
            GoodMoralStatusChoices.CANCELLED,
        ):
            raise GoodMoralServiceError(f"Cannot update receipt for request in status '{request.status}'.")

        request.official_receipt_number = receipt_number
        request.official_receipt_date = receipt_date
        request.official_receipt_amount = receipt_amount
        request.receipt_status = ReceiptStatusChoices.ENCODED
        request.receipt_encoded_by = user
        request.receipt_encoded_at = timezone.now()

        if request.status in (GoodMoralStatusChoices.SUBMITTED, GoodMoralStatusChoices.FOR_PAYMENT):
            request.status = GoodMoralStatusChoices.PAYMENT_ENCODED

        request.save()

    _audit_transition("GOOD_MORAL_RECEIPT_ENCODED", user, request)
    return request


def _verify_receipt_metadata(user, request, *, approved: bool, rejection_code="") -> GoodMoralRequest:
    """Verify or reject receipt details."""
    with transaction.atomic():
        request = GoodMoralRequest.objects.select_for_update().get(pk=request.pk)
        if not can_verify_receipt_metadata(user, request):
            raise GoodMoralPolicyError("Permission denied: cannot verify receipt metadata.")

        if request.receipt_status != ReceiptStatusChoices.ENCODED:
            raise GoodMoralServiceError("Receipt must be encoded before verification.")

        if approved:
            request.receipt_status = ReceiptStatusChoices.VERIFIED
            request.receipt_verified_by = user
            request.receipt_verified_at = timezone.now()
            if request.status == GoodMoralStatusChoices.PAYMENT_ENCODED:
                request.status = GoodMoralStatusChoices.FOR_RECORD_CHECKING
        else:
            request.receipt_status = ReceiptStatusChoices.REJECTED
            request.receipt_verified_by = user
            request.receipt_verified_at = timezone.now()
            request.receipt_rejection_code = rejection_code
            request.status = GoodMoralStatusChoices.FOR_PAYMENT

        request.save()

    action = "GOOD_MORAL_RECEIPT_VERIFIED" if approved else "GOOD_MORAL_RECEIPT_REJECTED"
    _audit_transition(action, user, request)
    return request


def _start_review(user, request) -> GoodMoralRequest:
    """Assign counselor reviewer and begin record checking."""
    with transaction.atomic():
        request = GoodMoralRequest.objects.select_for_update().get(pk=request.pk)
        if not can_start_review(user, request):
            raise GoodMoralPolicyError("Permission denied: cannot start review.")

        valid_statuses = (
            GoodMoralStatusChoices.PAYMENT_ENCODED,
            GoodMoralStatusChoices.FOR_RECORD_CHECKING,
            GoodMoralStatusChoices.PENDING_MANUAL_OSSD_VERIFICATION,
            GoodMoralStatusChoices.ON_HOLD_FOR_REVIEW,
        )
        if request.status not in valid_statuses:
            raise GoodMoralServiceError(f"Cannot start review from status '{request.status}'.")

        request.assigned_reviewer = user
        request.status = GoodMoralStatusChoices.FOR_RECORD_CHECKING
        request.save()

    _audit_transition("GOOD_MORAL_REVIEW_STARTED", user, request)
    return request


def _change_ossd_verification(user, request, *, status: str) -> GoodMoralRequest:
    """Update OSSD verification status for graduate tracking."""
    with transaction.atomic():
        request = GoodMoralRequest.objects.select_for_update().get(pk=request.pk)
        if not can_start_review(user, request):
            raise GoodMoralPolicyError("Permission denied: cannot modify OSSD verification.")

        if status not in OSSDVerificationStatusChoices.values:
            raise GoodMoralServiceError(f"Invalid OSSD verification status '{status}'.")

        request.ossd_verification_status = status

        if status == OSSDVerificationStatusChoices.PENDING:
            request.status = GoodMoralStatusChoices.PENDING_MANUAL_OSSD_VERIFICATION
        elif status == OSSDVerificationStatusChoices.VERIFIED:
            if request.status == GoodMoralStatusChoices.PENDING_MANUAL_OSSD_VERIFICATION:
                request.status = GoodMoralStatusChoices.FOR_RECORD_CHECKING

        request.save()

    _audit_transition("GOOD_MORAL_OSSD_STATUS_CHANGED", user, request)
    return request


def _hold_request(user, request, *, reason_code, note="") -> GoodMoralRequest:
    """Put a request on hold for clarification or outstanding clearance issues."""
    with transaction.atomic():
        request = GoodMoralRequest.objects.select_for_update().get(pk=request.pk)
        if not can_hold_request(user, request):
            raise GoodMoralPolicyError("Permission denied: cannot hold request.")

        if request.status in (
            GoodMoralStatusChoices.RELEASED,
            GoodMoralStatusChoices.VOIDED,
            GoodMoralStatusChoices.ARCHIVED,
            GoodMoralStatusChoices.CANCELLED,
            GoodMoralStatusChoices.REJECTED,
        ):
            raise GoodMoralServiceError(f"Cannot hold request in status '{request.status}'.")

        request.status = GoodMoralStatusChoices.ON_HOLD_FOR_REVIEW
        request.hold_rejection_reason_code = reason_code
        request.office_only_note = note
        request.reviewed_by = user
        request.reviewed_at = timezone.now()
        request.save()

    _audit_transition("GOOD_MORAL_HELD", user, request)
    return request


def _approve_request(user, request, *, signatory_name, signatory_title) -> GoodMoralRequest:
    """Human approval of the Good Moral Character request."""
    with transaction.atomic():
        request = GoodMoralRequest.objects.select_for_update().get(pk=request.pk)
        if not can_approve_request(user, request):
            raise GoodMoralPolicyError("Permission denied: cannot approve request.")

        valid_statuses = (
            GoodMoralStatusChoices.FOR_RECORD_CHECKING,
            GoodMoralStatusChoices.ON_HOLD_FOR_REVIEW,
            GoodMoralStatusChoices.FOR_APPROVAL,
        )
        if request.status not in valid_statuses:
            raise GoodMoralServiceError(f"Cannot approve request from status '{request.status}'.")

        if not signatory_name or not signatory_title:
            raise GoodMoralServiceError("Signatory name and title are required for approval.")

        from apps.good_moral.exit_prerequisite import enforce_exit_prerequisite, ExitPrerequisiteError
        try:
            enforce_exit_prerequisite(request, gate="approval")
        except ExitPrerequisiteError as exc:
            raise GoodMoralServiceError(str(exc)) from exc

        request.status = GoodMoralStatusChoices.APPROVED_FOR_GENERATION
        request.approved_by = user
        request.approved_at = timezone.now()
        request.approval_signatory_name = signatory_name
        request.approval_signatory_title = signatory_title
        request.save()

    _audit_transition("GOOD_MORAL_APPROVED", user, request)
    return request


def _reject_request(user, request, *, reason_code, note="") -> GoodMoralRequest:
    """Human rejection of the request."""
    with transaction.atomic():
        request = GoodMoralRequest.objects.select_for_update().get(pk=request.pk)
        if not can_reject_request(user, request):
            raise GoodMoralPolicyError("Permission denied: cannot reject request.")

        if request.status in (
            GoodMoralStatusChoices.RELEASED,
            GoodMoralStatusChoices.VOIDED,
            GoodMoralStatusChoices.ARCHIVED,
            GoodMoralStatusChoices.CANCELLED,
            GoodMoralStatusChoices.REJECTED,
        ):
            raise GoodMoralServiceError(f"Cannot reject request in status '{request.status}'.")

        request.status = GoodMoralStatusChoices.REJECTED
        request.hold_rejection_reason_code = reason_code
        request.office_only_note = note
        request.reviewed_by = user
        request.reviewed_at = timezone.now()
        request.save()

        from apps.good_moral.notification_services import enqueue_good_moral_event
        enqueue_good_moral_event("rejected", request)

    _audit_transition("GOOD_MORAL_REJECTED", user, request)
    return request


def _generate_certificate_document(user, request) -> GoodMoralRequest:
    """Generate and store the official PDF certificate for the approved request."""
    # Delegation logic inside document_services wrapper with state assertions
    from apps.good_moral.document_services import _generate_good_moral_document

    return _generate_good_moral_document(user, request)


def _mark_printed(user, request) -> GoodMoralRequest:
    """Record that the certificate document has been printed physically."""
    with transaction.atomic():
        request = GoodMoralRequest.objects.select_for_update().get(pk=request.pk)
        if not can_mark_printed(user, request):
            raise GoodMoralPolicyError("Permission denied: cannot print document.")

        if request.status not in (GoodMoralStatusChoices.GENERATED, GoodMoralStatusChoices.PRINTED):
            raise GoodMoralServiceError(f"Cannot print request in status '{request.status}'.")

        request.status = GoodMoralStatusChoices.PRINTED
        request.printed_by = user
        request.printed_at = timezone.now()
        request.save()

    _audit_transition("GOOD_MORAL_PRINTED", user, request)
    return request


def _confirm_dry_seal(user, request) -> GoodMoralRequest:
    """Record an external Registrar dry-seal confirmation after handoff."""
    with transaction.atomic():
        request = GoodMoralRequest.objects.select_for_update().get(pk=request.pk)
        if request.dry_seal_status == DrySealStatusChoices.SEALED:
            raise GoodMoralServiceError("Registrar dry-seal confirmation has already been recorded.")
        if not can_confirm_dry_seal(user, request):
            raise GoodMoralPolicyError("Permission denied: cannot confirm Registrar dry seal.")

        from apps.access_control.rules import is_student, is_counselor, is_gco_staff
        if is_student(user):
            method = DrySealConfirmationMethodChoices.STUDENT_ATTESTED
        elif is_counselor(user):
            method = DrySealConfirmationMethodChoices.COUNSELOR_RECORDED
        elif is_gco_staff(user):
            method = DrySealConfirmationMethodChoices.GCO_STAFF_RECORDED
        else:
            raise GoodMoralPolicyError("Only the student or authorized GCO personnel may confirm the external seal.")

        request.dry_seal_status = DrySealStatusChoices.SEALED
        request.dry_seal_confirmation_method = method
        request.dry_seal_confirmed_by = user
        request.dry_seal_confirmed_at = timezone.now()

        request.save()

    _audit_transition(
        "GOOD_MORAL_REGISTRAR_SEAL_CONFIRMED",
        user,
        request,
        extra_metadata={"confirmation_method": request.dry_seal_confirmation_method},
    )
    return request


def _release_certificate(user, request) -> GoodMoralRequest:
    """Formally release the certificate to the claimant student."""
    with transaction.atomic():
        request = GoodMoralRequest.objects.select_for_update().get(pk=request.pk)
        if not can_release_request(user, request):
            raise GoodMoralPolicyError("Permission denied: cannot release certificate.")

        if request.status != GoodMoralStatusChoices.PRINTED:
            raise GoodMoralServiceError(f"Cannot release request in status '{request.status}'. Must be PRINTED.")

        if not request.generated_document:
            raise GoodMoralServiceError("Cannot release request: generated document is missing.")

        from apps.good_moral.exit_prerequisite import enforce_exit_prerequisite, ExitPrerequisiteError
        try:
            enforce_exit_prerequisite(request, gate="release")
        except ExitPrerequisiteError as exc:
            raise GoodMoralServiceError(str(exc)) from exc

        # Use the shared document lifecycle service so the document-level
        # release policy and audit event are retained as well.
        release_document_for_composition(
            user,
            DocumentLifecycleCommand(str(request.generated_document_id)),
        )

        request.status = GoodMoralStatusChoices.RELEASED
        request.released_by = user
        request.released_at = timezone.now()
        request.save()

        issue_feedback_invitation_for_completed_source(
            user,
            FeedbackInvitationCommand("good_moral", str(request.pk))
        )
        from apps.good_moral.notification_services import enqueue_good_moral_event
        enqueue_good_moral_event("released", request)

    _audit_transition("GOOD_MORAL_RELEASED", user, request)
    return request


def _void_request(user, request, *, reason_code) -> GoodMoralRequest:
    """Void a generated/released request and rescind document validity."""
    with transaction.atomic():
        request = GoodMoralRequest.objects.select_for_update().get(pk=request.pk)
        if not can_void_request(user, request):
            raise GoodMoralPolicyError("Permission denied: cannot void request.")

        # Can only void once generated/printed/released
        valid_statuses = (
            GoodMoralStatusChoices.GENERATED,
            GoodMoralStatusChoices.PRINTED,
            GoodMoralStatusChoices.RELEASED,
        )
        if request.status not in valid_statuses:
            raise GoodMoralServiceError(f"Cannot void request in status '{request.status}'.")

        # Void associated GeneratedDocument through the shared lifecycle
        # service so the document-level void audit is retained as well.
        if request.generated_document:
            void_document_for_composition(
                user,
                DocumentLifecycleCommand(
                    str(request.generated_document_id),
                    reason_code=reason_code,
                ),
            )

        request.status = GoodMoralStatusChoices.VOIDED
        request.voided_by = user
        request.voided_at = timezone.now()
        request.terminal_reason_code = reason_code
        request.save()

    _audit_transition("GOOD_MORAL_VOIDED", user, request)
    return request


def _supersede_certificate(user, request) -> GoodMoralRequest:
    """Void the current certificate and reopen the request for re-generation."""
    with transaction.atomic():
        request = GoodMoralRequest.objects.select_for_update().get(pk=request.pk)
        if not can_supersede_request(user, request):
            raise GoodMoralPolicyError("Permission denied: cannot supersede certificate.")

        valid_statuses = (
            GoodMoralStatusChoices.GENERATED,
            GoodMoralStatusChoices.PRINTED,
            GoodMoralStatusChoices.RELEASED,
        )
        if request.status not in valid_statuses:
            raise GoodMoralServiceError(
                f"Cannot supersede request in status '{request.status}'."
            )
        document = request.generated_document
        if not document:
            raise GoodMoralServiceError("Cannot supersede request: generated document is missing.")

        old_status = request.status
        void_document_for_composition(
            user,
            DocumentLifecycleCommand(
                str(document.pk),
                reason_code="superseded",
            ),
        )

        request.generated_document = None
        request.generated_by = None
        request.generated_at = None
        request.generation_failure_code = ""
        request.printed_by = None
        request.printed_at = None
        request.dry_seal_status = DrySealStatusChoices.PENDING
        request.dry_seal_confirmation_method = ""
        request.dry_seal_confirmed_by = None
        request.dry_seal_confirmed_at = None
        request.released_by = None
        request.released_at = None
        request.status = GoodMoralStatusChoices.APPROVED_FOR_GENERATION
        request.save()

    _audit_transition(
        "GOOD_MORAL_DOCUMENT_SUPERSEDED",
        user,
        request,
        extra_metadata={
            "status_from": old_status,
            "superseded_document_reference": document.reference_code,
        },
    )
    return request


def _archive_request(user, request) -> GoodMoralRequest:
    """Archive an old request record."""
    with transaction.atomic():
        request = GoodMoralRequest.objects.select_for_update().get(pk=request.pk)
        if not can_archive_request(user, request):
            raise GoodMoralPolicyError("Permission denied: cannot archive request.")

        # Generated documents must pass through the document lifecycle policy;
        # an issued certificate is archived only after it has been voided.
        if request.generated_document:
            archive_document_for_composition(
                user,
                DocumentLifecycleCommand(str(request.generated_document_id)),
            )

        request.status = GoodMoralStatusChoices.ARCHIVED
        request.archived_by = user
        request.archived_at = timezone.now()
        request.save()

    _audit_transition("GOOD_MORAL_ARCHIVED", user, request)
    return request


# ---------------------------------------------------------------------------
# Stable-reference application boundary
# ---------------------------------------------------------------------------

def _require_service_actor(actor):
    from apps.access_control.rules import is_active_nonlegacy_actor

    if not is_active_nonlegacy_actor(actor):
        raise PermissionDeniedError()
    return actor


def _load_request_for_service(actor, reference_code, *, lock=False):
    _require_service_actor(actor)
    normalized = str(reference_code or "").strip()
    if not normalized or len(normalized) > 30:
        raise ValidationError("reference_code is invalid.")
    queryset = GoodMoralRequest.objects.select_related(
        "requester_user",
        "student_profile",
        "student_profile__user",
        "assigned_reviewer",
        "generated_document",
        "generated_document__template_version",
        "generated_document__template_version__template",
        "generated_document__protected_file",
    )
    if lock:
        queryset = queryset.select_for_update()
    try:
        return queryset.get(reference_code=normalized)
    except GoodMoralRequest.DoesNotExist as exc:
        raise NotFoundError() from exc


def _load_user(user_id, field_name):
    from apps.accounts.models import User

    try:
        return User.objects.get(pk=user_id, is_active=True, is_superuser=False)
    except (User.DoesNotExist, ValueError, TypeError) as exc:
        raise NotFoundError() from exc


def _check_expected_updated_at(request, expected_updated_at):
    if not expected_updated_at:
        return
    from datetime import datetime

    try:
        expected = datetime.fromisoformat(expected_updated_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError("expected_updated_at is invalid.") from exc
    current = request.updated_at
    if current is None or expected != current:
        from apps.common.exceptions import StaleStateError

        raise StaleStateError()


def create_draft(*, actor, command):
    from apps.good_moral.commands import GoodMoralDraftCommand
    from apps.profiles.models import StudentProfile

    _require_service_actor(actor)
    if not isinstance(command, GoodMoralDraftCommand):
        raise ValidationError("Good Moral draft creation requires a typed command.")
    requester = _load_user(command.requester_user_id, "requester_user_id")
    try:
        student_profile = StudentProfile.objects.select_related("user").get(
            pk=command.student_profile_id,
        )
    except (StudentProfile.DoesNotExist, ValueError, TypeError) as exc:
        raise NotFoundError() from exc
    if student_profile.user_id != requester.pk:
        raise ValidationError("The requester must own the selected student profile.")
    return _create_draft(
        actor=actor,
        requester_user=requester,
        student_profile=student_profile,
        purpose_text=command.purpose_text,
        academic_year=command.academic_year,
        semester=command.semester,
        major=command.major,
        graduation_date=command.graduation_date,
    )


def update_draft(*, actor, reference_code, command):
    from apps.good_moral.commands import GoodMoralDraftUpdateCommand, UNSET

    if not isinstance(command, GoodMoralDraftUpdateCommand):
        raise ValidationError("Good Moral draft update requires a typed command.")
    with transaction.atomic():
        request = _load_request_for_service(actor, reference_code, lock=True)
        if not can_update_draft(actor, request):
            raise GoodMoralPolicyError()
        _check_expected_updated_at(request, command.expected_updated_at)
        changed = []
        for field in ("purpose_text", "semester", "major", "graduation_date"):
            value = getattr(command, field)
            if value is not UNSET:
                if field == "purpose_text" and not value:
                    raise ValidationError("purpose_text is required.")
                setattr(request, field, value)
                changed.append(field)
        if not changed:
            raise ValidationError("At least one draft field is required.")
        from apps.good_moral.lifecycle import validate_request_variant, GoodMoralVariantError

        try:
            validate_request_variant(request)
        except GoodMoralVariantError as exc:
            raise ValidationError(str(exc)) from exc
        changed.append("updated_at")
        request.save(update_fields=changed)
        _audit_transition("GOOD_MORAL_DRAFT_UPDATED", actor, request)
        return request


def submit_request(*, actor, reference_code, command=None):
    from apps.good_moral.commands import GoodMoralLifecycleCommand

    if command is not None and not isinstance(command, GoodMoralLifecycleCommand):
        raise ValidationError("Good Moral submission requires a typed lifecycle command.")
    return _submit_request(actor, _load_request_for_service(actor, reference_code))


def cancel_request(*, actor, reference_code, command):
    from apps.good_moral.commands import GoodMoralReasonCommand

    if not isinstance(command, GoodMoralReasonCommand):
        raise ValidationError("Good Moral cancellation requires a typed reason command.")
    return _cancel_request(actor, _load_request_for_service(actor, reference_code), command.reason_code)


def encode_receipt(*, actor, reference_code, command):
    from apps.good_moral.commands import GoodMoralReceiptEncodeCommand

    if not isinstance(command, GoodMoralReceiptEncodeCommand):
        raise ValidationError("Receipt encoding requires a typed command.")
    return _update_receipt_metadata(
        actor,
        _load_request_for_service(actor, reference_code),
        receipt_number=command.receipt_number,
        receipt_date=command.receipt_date,
        receipt_amount=command.receipt_amount,
    )


def verify_receipt(*, actor, reference_code, command):
    from apps.good_moral.commands import GoodMoralReceiptVerificationCommand

    if not isinstance(command, GoodMoralReceiptVerificationCommand):
        raise ValidationError("Receipt verification requires a typed command.")
    return _verify_receipt_metadata(
        actor,
        _load_request_for_service(actor, reference_code),
        approved=command.approved,
        rejection_code=command.rejection_code,
    )


def start_review(*, actor, reference_code, command=None):
    from apps.good_moral.commands import GoodMoralLifecycleCommand

    if command is not None and not isinstance(command, GoodMoralLifecycleCommand):
        raise ValidationError("Review start requires a typed lifecycle command.")
    return _start_review(actor, _load_request_for_service(actor, reference_code))


def assign_reviewer(*, actor, reference_code, command):
    from apps.good_moral.commands import GoodMoralReviewerCommand

    if not isinstance(command, GoodMoralReviewerCommand):
        raise ValidationError("Reviewer assignment requires a typed command.")
    reviewer = _load_user(command.reviewer_user_id, "reviewer_user_id")
    return _assign_reviewer(actor, _load_request_for_service(actor, reference_code), reviewer)


def change_ossd_verification(*, actor, reference_code, command):
    from apps.good_moral.commands import GoodMoralOssdVerificationCommand

    if not isinstance(command, GoodMoralOssdVerificationCommand):
        raise ValidationError("OSSD verification requires a typed command.")
    return _change_ossd_verification(
        actor,
        _load_request_for_service(actor, reference_code),
        status=command.status,
    )


def hold_request(*, actor, reference_code, command):
    from apps.good_moral.commands import GoodMoralReasonCommand

    if not isinstance(command, GoodMoralReasonCommand):
        raise ValidationError("Holding a request requires a typed reason command.")
    return _hold_request(
        actor,
        _load_request_for_service(actor, reference_code),
        reason_code=command.reason_code,
        note=command.note,
    )


def approve_request(*, actor, reference_code, command):
    from apps.good_moral.commands import GoodMoralApprovalCommand

    if not isinstance(command, GoodMoralApprovalCommand):
        raise ValidationError("Good Moral approval requires a typed command.")
    return _approve_request(
        actor,
        _load_request_for_service(actor, reference_code),
        signatory_name=command.signatory_name,
        signatory_title=command.signatory_title,
    )


def reject_request(*, actor, reference_code, command):
    from apps.good_moral.commands import GoodMoralReasonCommand

    if not isinstance(command, GoodMoralReasonCommand):
        raise ValidationError("Good Moral rejection requires a typed reason command.")
    return _reject_request(
        actor,
        _load_request_for_service(actor, reference_code),
        reason_code=command.reason_code,
        note=command.note,
    )


def generate_certificate(*, actor, reference_code, command=None):
    from apps.good_moral.commands import GoodMoralLifecycleCommand

    if command is not None and not isinstance(command, GoodMoralLifecycleCommand):
        raise ValidationError("Certificate generation requires a typed lifecycle command.")
    _require_service_actor(actor)
    return generate_good_moral_document_by_reference(
        actor=actor,
        reference_code=reference_code,
    )


def mark_printed(*, actor, reference_code, command=None):
    from apps.good_moral.commands import GoodMoralLifecycleCommand

    if command is not None and not isinstance(command, GoodMoralLifecycleCommand):
        raise ValidationError("Print recording requires a typed lifecycle command.")
    return _mark_printed(actor, _load_request_for_service(actor, reference_code))


def confirm_dry_seal(*, actor, reference_code, command=None):
    from apps.good_moral.commands import GoodMoralLifecycleCommand

    if command is not None and not isinstance(command, GoodMoralLifecycleCommand):
        raise ValidationError("Dry-seal confirmation requires a typed lifecycle command.")
    return _confirm_dry_seal(actor, _load_request_for_service(actor, reference_code))


def release_certificate(*, actor, reference_code, command=None):
    from apps.good_moral.commands import GoodMoralLifecycleCommand

    if command is not None and not isinstance(command, GoodMoralLifecycleCommand):
        raise ValidationError("Certificate release requires a typed lifecycle command.")
    return _release_certificate(actor, _load_request_for_service(actor, reference_code))


def void_request(*, actor, reference_code, command):
    from apps.good_moral.commands import GoodMoralReasonCommand

    if not isinstance(command, GoodMoralReasonCommand):
        raise ValidationError("Voiding a Good Moral request requires a typed reason command.")
    return _void_request(
        actor,
        _load_request_for_service(actor, reference_code),
        reason_code=command.reason_code,
    )


def supersede_certificate(*, actor, reference_code, command=None):
    from apps.good_moral.commands import GoodMoralLifecycleCommand

    if command is not None and not isinstance(command, GoodMoralLifecycleCommand):
        raise ValidationError("Certificate supersession requires a typed lifecycle command.")
    return _supersede_certificate(actor, _load_request_for_service(actor, reference_code))


def archive_request(*, actor, reference_code, command):
    from apps.good_moral.commands import GoodMoralArchiveCommand

    if not isinstance(command, GoodMoralArchiveCommand):
        raise ValidationError("Good Moral archival requires a typed command.")
    request = _archive_request(actor, _load_request_for_service(actor, reference_code))
    if command.reason_code:
        request.terminal_reason_code = command.reason_code
        request.save(update_fields=["terminal_reason_code", "updated_at"])
    return request
