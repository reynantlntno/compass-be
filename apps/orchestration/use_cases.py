"""Explicit cross-domain application workflows.

This module is the only runtime composition edge allowed to coordinate domain
mutations.  Callers provide an authenticated actor and typed stable-ID
commands; each domain service remains responsible for its own policy,
lifecycle, audit, and field-sensitivity rules.
"""

from __future__ import annotations

from django.db import transaction

from apps.common.exceptions import NotFoundError, ValidationError

from .commands import (
    ActivationDeliveryCancellationCommand,
    CompleteCounselingSessionCommand,
    ContactReplyDeliveryCancellationCommand,
    ContactReplyDeliveryCommand,
    DocumentLifecycleCommand,
    DocumentRenderCommand,
    FeedbackInvitationCommand,
    FormInvitationLifecycleCommand,
    FormSubmissionMatchCommand,
    FormRevisionUsageCommand,
    InventoryReopenWorkflowCommand,
    InventoryReviewCommand,
    InventorySubmitWorkflowCommand,
    InventorySupportNeedsCommand,
    LinkedAppointmentCommand,
    LinkedCounselingSessionCommand,
    PrivacyAcceptanceCommand,
    ReferralCallSlipCommand,
    StudentActivationInvitationCommand,
    StudentActivationInvitationReissueCommand,
)


def _get_or_not_found(model, object_id, label: str):
    try:
        return model.objects.get(pk=object_id)
    except model.DoesNotExist as exc:
        raise NotFoundError(f"{label} was not found.") from exc


def _lock_linked_records(*, appointment_id=None, session_id=None):
    """Lock schedule coordination, then appointment, then counseling session.

    Both directions of the linked workflow use this order.  A session without
    an appointment is still locked safely as a single-domain record.
    """

    from apps.appointments.availability_services import lock_schedule_scope
    from apps.appointments.models import Appointment
    from apps.counseling.models import CounselingSession

    # Schedule changes and linked lifecycle transitions share the office lock.
    # Acquiring it before discovering/locking the linked rows prevents the
    # appointment-first path from deadlocking with availability management.
    lock_schedule_scope()

    if appointment_id is not None:
        appointment = (
            Appointment.objects.select_for_update()
            .select_related("student", "assigned_counselor")
            .filter(pk=appointment_id)
            .first()
        )
        if appointment is None:
            raise NotFoundError("The appointment was not found.")
        session = (
            CounselingSession.objects.select_for_update()
            .select_related("appointment", "student", "assigned_counselor")
            .filter(appointment_id=appointment.pk)
            .first()
        )
        return appointment, session

    if session_id is None:
        raise ValidationError("A linked appointment or counseling session is required.")

    appointment_id = (
        CounselingSession.objects.filter(pk=session_id)
        .values_list("appointment_id", flat=True)
        .first()
    )
    appointment = None
    if appointment_id is not None:
        appointment = (
            Appointment.objects.select_for_update()
            .select_related("student", "assigned_counselor")
            .filter(pk=appointment_id)
            .first()
        )
        if appointment is None:
            raise NotFoundError("The linked appointment was not found.")

    session = (
        CounselingSession.objects.select_for_update()
        .select_related("appointment", "student", "assigned_counselor")
        .filter(pk=session_id)
        .first()
    )
    if session is None:
        raise NotFoundError("The counseling session was not found.")
    return appointment, session


def _require_scheduled_link(session) -> None:
    from apps.counseling.models import SessionStatusChoices

    if session is not None and session.status != SessionStatusChoices.SCHEDULED:
        raise ValidationError("The linked counseling session is no longer available for this action.")


@transaction.atomic
def create_or_open_session_from_scheduled_appointment(actor, command: LinkedAppointmentCommand):
    """Return the scheduled appointment's one session, creating it once.

    This is the only sanctioned cross-domain edge for opening a counseling
    session from an appointment. Lock order is office/schedule coordination,
    then the appointment, then the linked counseling session.
    """

    if not isinstance(command, LinkedAppointmentCommand):
        raise ValidationError(
            "Opening a session requires a typed orchestration command."
        )

    from apps.appointments.models import AppointmentStatusChoices
    from apps.counseling.commands import SessionCreateCommand
    from apps.counseling.models import (
        CounselingSession,
        SessionModeChoices,
        SessionSourceChoices,
        SessionTypeChoices,
    )
    from apps.counseling.policies import can_create_session_for, can_view_session
    from apps.counseling.services import (
        DuplicateCounselingSessionError,
        SessionPermissionError,
        SessionValidationError,
        create_session,
    )
    from apps.appointments.models import AppointmentModeChoices, AppointmentTypeChoices

    # Lock order: schedule coordination, appointment, then session.
    appointment, existing = _lock_linked_records(appointment_id=command.appointment_id)

    if appointment.status != AppointmentStatusChoices.SCHEDULED:
        raise ValidationError(
            "Create/Open Session is available only while the appointment is scheduled."
        )

    if existing is not None:
        if not can_view_session(actor, existing):
            from apps.common.exceptions import PermissionDeniedError

            raise PermissionDeniedError("You do not have permission to open this session.")
        if existing.session_mode == SessionModeChoices.ONLINE:
            from apps.counseling.commands import ECounselingCreateCommand
            from apps.counseling.ecounseling_services import attach_ecounseling_to_session

            attach_ecounseling_to_session(
                actor,
                existing,
                ECounselingCreateCommand(
                    student_id=str(existing.student_id),
                    assigned_counselor_id=(
                        str(existing.assigned_counselor_id)
                        if existing.assigned_counselor_id is not None
                        else None
                    ),
                    session_type=existing.session_type,
                    scheduled_start_at=existing.scheduled_start_at,
                    scheduled_end_at=existing.scheduled_end_at,
                ),
            )
        return existing, False

    if appointment.assigned_counselor_id is None:
        raise ValidationError("Assign a counselor before creating the session.")
    if not all(
        (
            appointment.confirmed_date,
            appointment.confirmed_start_time,
            appointment.confirmed_end_time,
        )
    ):
        raise ValidationError("The appointment schedule is incomplete.")
    if not can_create_session_for(
        actor,
        appointment.student,
        appointment=appointment,
        assigned_counselor=appointment.assigned_counselor,
        source=SessionSourceChoices.APPOINTMENT,
    ):
        from apps.common.exceptions import PermissionDeniedError

        raise PermissionDeniedError("You do not have permission to create this session.")

    import datetime

    from django.utils import timezone

    def _aware_at(date_value, time_value):
        combined = datetime.datetime.combine(date_value, time_value)
        if timezone.is_naive(combined):
            return timezone.make_aware(combined, timezone.get_current_timezone())
        return combined

    session_type_map = {
        AppointmentTypeChoices.COUNSELING: SessionTypeChoices.COUNSELING,
        AppointmentTypeChoices.ROUTINE_INTERVIEW: SessionTypeChoices.ROUTINE_INTERVIEW,
        AppointmentTypeChoices.FOLLOW_UP: SessionTypeChoices.FOLLOW_UP,
        AppointmentTypeChoices.OTHER: SessionTypeChoices.ADMINISTRATIVE_INTERVIEW,
    }
    session_mode_map = {
        AppointmentModeChoices.ONSITE: SessionModeChoices.ONSITE,
        AppointmentModeChoices.ONLINE: SessionModeChoices.ONLINE,
    }

    create_command = SessionCreateCommand(
        student_id=str(appointment.student_id),
        appointment_reference=appointment.reference_code,
        assigned_counselor_id=str(appointment.assigned_counselor_id),
        session_type=session_type_map[appointment.appointment_type],
        session_mode=session_mode_map[appointment.appointment_mode],
        session_source=SessionSourceChoices.APPOINTMENT,
        # Do not copy the student-provided appointment reason into notes.
        concern_summary="",
        scheduled_start_at=_aware_at(
            appointment.confirmed_date,
            appointment.confirmed_start_time,
        ),
        scheduled_end_at=_aware_at(
            appointment.confirmed_date,
            appointment.confirmed_end_time,
        ),
    )
    try:
        session = create_session(actor, create_command)
        created = True
    except DuplicateCounselingSessionError:
        session = (
            CounselingSession.objects.select_for_update()
            .filter(appointment=appointment)
            .first()
        )
        if session is None:
            raise
        if not can_view_session(actor, session):
            from apps.common.exceptions import PermissionDeniedError

            raise PermissionDeniedError("You do not have permission to open this session.")
        created = False

    if created:
        from apps.appointments.notification_services import enqueue_appointment_event

        enqueue_appointment_event("session_ready", appointment, actor=actor)
    return session, created


@transaction.atomic
def cancel_appointment_with_linked_session(actor, command: LinkedAppointmentCommand):
    """Cancel an appointment and its still-scheduled counseling session."""

    if not isinstance(command, LinkedAppointmentCommand):
        raise ValidationError("Appointment cancellation requires a typed orchestration command.")
    appointment, session = _lock_linked_records(appointment_id=command.appointment_id)
    _require_scheduled_link(session)

    from apps.appointments.commands import AppointmentCancellationCommand
    from apps.appointments.services import cancel_appointment
    from apps.counseling.commands import SessionCancellationCommand
    from apps.counseling.services import cancel_session

    appointment = cancel_appointment(
        actor,
        appointment.reference_code,
        AppointmentCancellationCommand(reason=command.reason),
    )
    if session is not None:
        session = cancel_session(
            actor,
            session.reference_code,
            SessionCancellationCommand(reason="The linked appointment was cancelled."),
        )
    return appointment


@transaction.atomic
def mark_appointment_no_show_with_linked_session(actor, command: LinkedAppointmentCommand):
    """Mark an appointment and its still-scheduled counseling session no-show."""

    if not isinstance(command, LinkedAppointmentCommand):
        raise ValidationError("Appointment no-show requires a typed orchestration command.")
    appointment, session = _lock_linked_records(appointment_id=command.appointment_id)
    _require_scheduled_link(session)

    from apps.appointments.commands import AppointmentNoShowCommand
    from apps.appointments.services import mark_no_show
    from apps.counseling.services import mark_session_no_show

    appointment = mark_no_show(actor, appointment.reference_code, AppointmentNoShowCommand())
    if session is not None:
        mark_session_no_show(actor, session.reference_code)
    return appointment


@transaction.atomic
def cancel_counseling_session_with_linked_appointment(
    actor,
    command: LinkedCounselingSessionCommand,
):
    """Cancel a counseling session and its linked appointment atomically."""

    if not isinstance(command, LinkedCounselingSessionCommand):
        raise ValidationError("Session cancellation requires a typed orchestration command.")
    appointment, session = _lock_linked_records(session_id=command.session_id)
    _require_scheduled_link(session)

    from apps.appointments.commands import AppointmentCancellationCommand
    from apps.appointments.services import cancel_appointment
    from apps.counseling.commands import SessionCancellationCommand
    from apps.counseling.services import cancel_session

    if appointment is not None:
        appointment = cancel_appointment(
            actor,
            appointment.reference_code,
            AppointmentCancellationCommand(
                reason=command.reason
                or "The linked counseling session was cancelled by the office.",
            ),
        )
    session = cancel_session(
        actor,
        session.reference_code,
        SessionCancellationCommand(reason=command.reason),
    )
    return session


@transaction.atomic
def mark_counseling_session_no_show_with_linked_appointment(
    actor,
    command: LinkedCounselingSessionCommand,
):
    """Mark a counseling session and its linked appointment no-show atomically."""

    if not isinstance(command, LinkedCounselingSessionCommand):
        raise ValidationError("Session no-show requires a typed orchestration command.")
    appointment, session = _lock_linked_records(session_id=command.session_id)
    _require_scheduled_link(session)

    from apps.appointments.commands import AppointmentNoShowCommand
    from apps.appointments.services import mark_no_show
    from apps.counseling.services import mark_session_no_show

    if appointment is not None:
        mark_no_show(actor, appointment.reference_code, AppointmentNoShowCommand())
    session = mark_session_no_show(actor, session.reference_code)
    return session


@transaction.atomic
def complete_counseling_session_with_linked_appointment(
    actor,
    command: CompleteCounselingSessionCommand,
):
    """Complete counseling, its appointment, and feedback invitation atomically."""

    if not isinstance(command, CompleteCounselingSessionCommand):
        raise ValidationError("Session completion requires a typed orchestration command.")
    appointment, session = _lock_linked_records(session_id=command.session_id)

    from apps.appointments.commands import AppointmentCompletionCommand
    from apps.appointments.services import complete_appointment
    from apps.counseling.services import complete_session

    session = complete_session(actor, session.reference_code, command.note)
    if appointment is not None:
        complete_appointment(
            actor,
            appointment.reference_code,
            AppointmentCompletionCommand(
                actual_start_time=session.actual_started_at,
                actual_end_time=session.actual_ended_at,
            ),
        )

    issue_feedback_invitation_for_completed_source(
        actor,
        FeedbackInvitationCommand("counseling_session", str(session.pk)),
    )
    return session


@transaction.atomic
def issue_feedback_invitation_for_completed_source(actor, command: FeedbackInvitationCommand):
    """Create the one feedback invitation for an approved completed source."""

    if not isinstance(command, FeedbackInvitationCommand):
        raise ValidationError("Feedback invitations require a typed orchestration command.")

    if command.workflow_type == "counseling_session":
        from apps.counseling.models import CounselingSession

        source = _get_or_not_found(CounselingSession, command.source_id, "The counseling session")
    elif command.workflow_type == "call_slip":
        from apps.call_slips.models import CallSlip

        source = _get_or_not_found(CallSlip, command.source_id, "The call slip")
    elif command.workflow_type == "referral":
        from apps.referrals.models import Referral

        source = _get_or_not_found(Referral, command.source_id, "The referral")
    elif command.workflow_type == "good_moral":
        from apps.good_moral.models import GoodMoralRequest

        source = _get_or_not_found(GoodMoralRequest, command.source_id, "The Good Moral request")
    else:  # The command validates this; keep the branch fail-closed.
        raise ValidationError("The feedback workflow type is not supported.")

    from apps.feedback.invitation_services import issue_for_completed_source

    return issue_for_completed_source(command.workflow_type, source, actor=actor)


def mark_form_revision_used_for_composition(
    actor,
    command: FormRevisionUsageCommand,
):
    if not isinstance(command, FormRevisionUsageCommand):
        raise ValidationError("Form revision usage requires a typed orchestration command.")
    from apps.organizations.services import mark_form_revision_used_by_id

    return mark_form_revision_used_by_id(
        actor,
        command.revision_id,
        system_context=command.system_context,
    )


def start_form_invitation_draft_for_composition(command: FormInvitationLifecycleCommand):
    if not isinstance(command, FormInvitationLifecycleCommand):
        raise ValidationError("Form invitation lifecycle requires a typed orchestration command.")
    from apps.form_collection.services import start_invitation_draft

    return start_invitation_draft(command.invitation_id)


def mark_form_invitation_submitted_for_composition(command: FormInvitationLifecycleCommand):
    if not isinstance(command, FormInvitationLifecycleCommand):
        raise ValidationError("Form invitation lifecycle requires a typed orchestration command.")
    from apps.form_collection.services import consume_invitation

    return consume_invitation(command.invitation_id)


def resolve_verified_invitation_for_composition(
    principal,
    *,
    expected_target_form_key: str,
):
    """Resolve a verified form-access principal at the composition boundary."""
    from apps.common.verified_access import VerifiedFormAccessPrincipal
    from apps.form_collection.services import get_verified_invitation_for_principal

    if not isinstance(principal, VerifiedFormAccessPrincipal):
        raise ValidationError("Verified form access requires a typed principal.")
    return get_verified_invitation_for_principal(
        principal,
        expected_target_form_key=expected_target_form_key,
    )


@transaction.atomic
def link_form_submission_for_composition(actor, command: FormSubmissionMatchCommand):
    """Resolve one unlinked submission through the composition boundary."""
    if not isinstance(command, FormSubmissionMatchCommand) or not command.student_profile_id:
        raise ValidationError("A linked form submission requires a typed student target.")
    from apps.form_collection.commands import ManualMatchDecisionCommand
    from apps.form_collection.services import link_unlinked_submission

    return link_unlinked_submission(
        actor,
        command.record_id,
        ManualMatchDecisionCommand(
            student_profile_id=command.student_profile_id,
            reason=command.reason,
            expected_updated_at=command.expected_updated_at,
        ),
    )


@transaction.atomic
def reject_form_submission_match_for_composition(actor, command: FormSubmissionMatchCommand):
    """Reject one ambiguous match through the composition boundary."""
    if not isinstance(command, FormSubmissionMatchCommand):
        raise ValidationError("Form submission matching requires a typed command.")
    from apps.form_collection.commands import ManualMatchDecisionCommand
    from apps.form_collection.services import reject_unlinked_match

    return reject_unlinked_match(
        actor,
        command.record_id,
        ManualMatchDecisionCommand(
            reason=command.reason,
            expected_updated_at=command.expected_updated_at,
        ),
    )


@transaction.atomic
def materialize_support_needs_for_inventory(actor, command: InventorySupportNeedsCommand):
    """Materialize Inventory-derived support needs (idempotent by snapshot/type).

    Lock order: the Inventory snapshot first, then its submission-history row.
    Confidential answers are read only through the Inventory encryption reader
    and are reduced to bounded candidate DTOs before any Support Needs
    primitive runs; raw answers never cross this boundary.
    """

    if not isinstance(command, InventorySupportNeedsCommand):
        raise ValidationError("Inventory support materialization requires a typed orchestration command.")

    from apps.access_control.rules import is_active_nonlegacy_actor
    from apps.common.exceptions import PermissionDeniedError

    if not is_active_nonlegacy_actor(actor):
        raise PermissionDeniedError("An active account is required for this workflow.")

    from apps.inventory.encryption import InventoryEncryptionError, read_confidential_snapshot
    from apps.inventory.models import (
        InventoryStatusChoices,
        StudentInventorySnapshot,
        StudentInventoryStatusHistory,
    )
    from apps.security.exceptions import FieldEncryptionError
    from apps.support_needs.models import SupportNeedType
    from apps.support_needs.services import (
        pause_inventory_derived_records_for_review,
        record_inventory_derived_support_need,
    )

    from .support_needs_mapping import (
        SUPPORT_CONTEXT_MAPPING_VERSION,
        build_candidate_evidence,
        build_source_label,
        build_support_need_candidates,
    )

    snapshot = (
        StudentInventorySnapshot.objects.select_for_update()
        .select_related("student_profile")
        .only(
            "id",
            "student_profile_id",
            "student_profile__user_id",
            "academic_year",
            "schema_version",
            "status",
        )
        .filter(pk=str(command.snapshot_id))
        .first()
    )
    if snapshot is None:
        raise NotFoundError("The inventory snapshot was not found.")
    if str(snapshot.student_profile.user_id) != str(actor.pk):
        raise PermissionDeniedError("This workflow is limited to the inventory owner.")
    if snapshot.status != InventoryStatusChoices.SUBMITTED:
        raise ValidationError("Inventory support materialization requires a submitted snapshot.")

    # Lock the exact submission-history provenance row for this submission.
    if command.submission_history_id is not None:
        submission_history = (
            StudentInventoryStatusHistory.objects.select_for_update()
            .filter(pk=str(command.submission_history_id), snapshot_id=snapshot.pk)
            .first()
        )
        if submission_history is None or submission_history.to_status != InventoryStatusChoices.SUBMITTED:
            raise ValidationError("Inventory submission provenance is invalid.")
    else:
        submission_history = (
            StudentInventoryStatusHistory.objects.select_for_update()
            .filter(snapshot=snapshot, to_status=InventoryStatusChoices.SUBMITTED)
            .order_by("-submission_sequence")
            .first()
        )
        if submission_history is None:
            raise ValidationError("Inventory submission provenance is unavailable.")

    try:
        data = read_confidential_snapshot(snapshot).data
    except (InventoryEncryptionError, FieldEncryptionError):
        raise ValidationError("Inventory confidential source is unavailable.") from None

    # A pre-support_needs.materialization legacy submission has no support section.  Preserve that
    # snapshot and its existing workflow history unchanged; new 2.1.0 form
    # saves always include the section (even while a draft is incomplete).
    if "support_context" not in data:
        return []

    candidates = build_support_need_candidates(data)
    snapshot_meta = {
        "academic_year": snapshot.academic_year,
        "schema_version": snapshot.schema_version,
    }
    source_label = build_source_label(**snapshot_meta)

    changed_type_ids = []
    for candidate in candidates:
        support_need_type = SupportNeedType.objects.filter(key=candidate.support_need_key).first()
        if support_need_type is None:
            continue
        if candidate.is_positive:
            active_type = SupportNeedType.objects.filter(
                key=candidate.support_need_key, is_active=True
            ).first()
            if active_type is None:
                # The enclosing submission transaction rolls back safely when
                # deployment data is incomplete for an explicit positive
                # response. No/Decline never creates a record.
                raise ValidationError("Student Support Needs catalog is unavailable.")
            evidence = build_candidate_evidence(
                snapshot_meta=snapshot_meta,
                submission_sequence=getattr(submission_history, "submission_sequence", None),
                candidate=candidate,
            )
            from apps.support_needs.commands import SupportNeedMaterializationCommand

            record_inventory_derived_support_need(
                actor,
                SupportNeedMaterializationCommand(
                    student_profile_id=str(snapshot.student_profile_id),
                    support_need_type_id=str(active_type.pk),
                    evidence_summary=evidence,
                    source_snapshot_label=source_label,
                    source_inventory_snapshot_id=str(snapshot.pk),
                    source_submission_history_id=str(submission_history.pk),
                    source_object_id=str(submission_history.pk),
                    source_mapping_version=SUPPORT_CONTEXT_MAPPING_VERSION,
                ),
            )
        elif candidate.is_source_changed:
            changed_type_ids.append(support_need_type.pk)

    if changed_type_ids:
        from apps.support_needs.commands import SupportNeedInventoryReviewCommand

        pause_inventory_derived_records_for_review(
            actor,
            SupportNeedInventoryReviewCommand(
                source_inventory_snapshot_id=str(snapshot.pk),
                reason_code="source_response_changed",
                support_need_type_ids=tuple(str(value) for value in changed_type_ids),
            ),
        )


def mark_inventory_support_needs_for_review(actor, command: InventoryReviewCommand):
    """Reopen companion: pause derived support-need decisions for review."""

    if not isinstance(command, InventoryReviewCommand):
        raise ValidationError("Inventory support review requires a typed orchestration command.")
    from apps.support_needs.services import pause_inventory_derived_records_for_review

    from apps.support_needs.commands import SupportNeedInventoryReviewCommand

    return pause_inventory_derived_records_for_review(
        actor,
        SupportNeedInventoryReviewCommand(
            source_inventory_snapshot_id=str(command.snapshot_id),
        ),
    )


@transaction.atomic
def submit_inventory_workflow(actor, command: InventorySubmitWorkflowCommand):
    """Combined submission: submit, derive, and record privacy atomically.

    Lock order: the Inventory snapshot first, then its submission-history row,
    then existing support needs for the snapshot.  A failure in support-need
    materialization or privacy acceptance rolls back the entire submission.
    """

    if not isinstance(command, InventorySubmitWorkflowCommand):
        raise ValidationError("Inventory submission requires a typed orchestration command.")

    from apps.inventory.commands import InventorySubmitCommand
    from apps.inventory.services import (
        latest_submission_history,
        submit_inventory_snapshot,
    )

    snapshot = submit_inventory_snapshot(
        actor,
        str(command.snapshot_id),
        InventorySubmitCommand(
            privacy_acknowledged=bool(command.privacy_acknowledged),
            expected_updated_at=command.expected_updated_at,
        ),
    )

    # students_profile_aggregate projections are derived only after the source is locked.  A
    # missing authoritative cohort deliberately does not fall back to the
    # mutable StudentProfile or block the student's Inventory submission.
    from apps.inventory.models import StudentAcademicCohort
    from apps.reports.profiling import materialize_profiling_fact

    if StudentAcademicCohort.objects.filter(
        student_profile_id=snapshot.student_profile_id,
        academic_year=snapshot.academic_year,
    ).exists():
        materialize_profiling_fact(snapshot)

    # support_needs.materialization derivation.  Catalog/configuration failures stay content-free;
    # the enclosing transaction rolls the whole submission back.
    submission_history = latest_submission_history(snapshot)
    try:
        materialize_support_needs_for_inventory(
            actor,
            InventorySupportNeedsCommand(
                str(snapshot.pk),
                str(submission_history.pk) if submission_history is not None else None,
            )
        )
    except (ValidationError, NotFoundError):
        raise

    # privacy.boundary binds the submitted snapshot to the exact Inventory notice
    # revision.  The event uses a HMAC-safe subject reference and is part of
    # this transaction, so an unavailable/ambiguous notice rolls back submit.
    record_privacy_acceptance_for_composition(
        snapshot.student_profile.user,
        PrivacyAcceptanceCommand(
            notice_identifier="individual-inventory",
            purpose_workflow="individual_inventory",
            subject_reference=f"student:{snapshot.student_profile.user_id}",
            source_route="api",
        ),
    )
    return snapshot


@transaction.atomic
def reopen_inventory_workflow(actor, command: InventoryReopenWorkflowCommand):
    """Combined reopen: reopen the snapshot and pause derived support needs."""

    if not isinstance(command, InventoryReopenWorkflowCommand):
        raise ValidationError("Inventory reopening requires a typed orchestration command.")

    from apps.inventory.commands import InventoryReopenCommand
    from apps.inventory.services import reopen_inventory_for_correction
    from apps.reports.profiling import mark_profiling_fact_reopened

    snapshot = reopen_inventory_for_correction(
        actor,
        str(command.snapshot_id),
        InventoryReopenCommand(
            reason=command.reason,
            expected_state_token=command.expected_state_token,
        ),
    )

    mark_profiling_fact_reopened(snapshot)
    mark_inventory_support_needs_for_review(actor, InventoryReviewCommand(str(snapshot.pk)))
    return snapshot


def record_privacy_acceptance_for_composition(actor, command: PrivacyAcceptanceCommand):
    if not isinstance(command, PrivacyAcceptanceCommand):
        raise ValidationError("Privacy acceptance requires a typed orchestration command.")
    from apps.privacy.services import record_acceptance, resolve_current_notice

    notice = resolve_current_notice(command.notice_identifier, command.purpose_workflow)
    if notice is None:
        raise ValidationError("The privacy notice is temporarily unavailable.")
    return record_acceptance(
        notice_revision=notice,
        purpose_workflow=command.purpose_workflow,
        subject_reference=command.subject_reference,
        actor=actor,
        source_route=command.source_route,
    )


def render_document_for_composition(actor, command: DocumentRenderCommand):
    if not isinstance(command, DocumentRenderCommand):
        raise ValidationError("Document rendering requires a typed orchestration command.")
    from apps.documents.models import DocumentTemplateVersion
    from apps.documents.services import render_and_store_document
    from apps.organizations.models import FormRevision
    from apps.accounts.models import User

    template_version = _get_or_not_found(
        DocumentTemplateVersion,
        command.template_version_id,
        "The document template version",
    )
    form_revision = None
    if command.form_revision_id is not None:
        form_revision = _get_or_not_found(FormRevision, command.form_revision_id, "The form revision")
    generated_for_user = None
    if command.generated_for_user_id is not None:
        generated_for_user = _get_or_not_found(User, command.generated_for_user_id, "The document recipient")

    from apps.documents.governance import DocumentOutputIntent

    try:
        output_intent = DocumentOutputIntent(command.output_intent)
    except ValueError as exc:
        raise ValidationError("The document output intent is invalid.") from exc

    return render_and_store_document(
        user=actor,
        template_version=template_version,
        render_context=dict(command.render_context),
        academic_year=command.academic_year,
        form_revision=form_revision,
        generated_for_user=generated_for_user,
        owning_app_label=command.owning_app_label,
        owning_model_name=command.owning_model_name,
        owning_object_id=command.owning_object_id,
        access_policy_key=command.access_policy_key,
        system_context=command.system_context,
        output_intent=output_intent,
    )


def release_document_for_composition(actor, command: DocumentLifecycleCommand):
    if not isinstance(command, DocumentLifecycleCommand):
        raise ValidationError("Document release requires a typed orchestration command.")
    from apps.documents.commands import GeneratedDocumentLifecycleCommand
    from apps.documents.services import release_generated_document

    return release_generated_document(
        user=actor,
        command=GeneratedDocumentLifecycleCommand(document_id=command.document_id),
    )


def void_document_for_composition(actor, command: DocumentLifecycleCommand):
    if not isinstance(command, DocumentLifecycleCommand):
        raise ValidationError("Document voiding requires a typed orchestration command.")
    from apps.documents.commands import GeneratedDocumentLifecycleCommand
    from apps.documents.services import void_generated_document

    return void_generated_document(
        user=actor,
        command=GeneratedDocumentLifecycleCommand(
            document_id=command.document_id,
            reason_code=command.reason_code,
        ),
    )


def archive_document_for_composition(actor, command: DocumentLifecycleCommand):
    if not isinstance(command, DocumentLifecycleCommand):
        raise ValidationError("Document archival requires a typed orchestration command.")
    from apps.documents.commands import GeneratedDocumentLifecycleCommand
    from apps.documents.services import archive_generated_document

    return archive_generated_document(
        user=actor,
        command=GeneratedDocumentLifecycleCommand(document_id=command.document_id),
    )


@transaction.atomic
def create_student_activation_invitation_for_import(
    actor,
    command: StudentActivationInvitationCommand,
):
    if not isinstance(command, StudentActivationInvitationCommand):
        raise ValidationError("Student activation requires a typed orchestration command.")
    from apps.student_activation.services import (
        issue_activation_invitation_for_user_id,
        queue_activation_delivery_by_id,
    )

    receipt = issue_activation_invitation_for_user_id(
        command.user_id,
        created_by=actor,
        validity_days=command.validity_days,
        source_view=command.source_view,
    )
    queue_activation_delivery_by_id(receipt.invitation_id)
    from apps.student_activation.commands import ActivationInvitationReceipt
    return ActivationInvitationReceipt(
        invitation_id=receipt.invitation_id,
        expires_at=receipt.expires_at,
        delivery_queued=True,
    )


@transaction.atomic
def reissue_student_activation_invitation_for_import(
    actor,
    command: StudentActivationInvitationReissueCommand,
):
    """Reissue and register delivery from the composition boundary."""
    if not isinstance(command, StudentActivationInvitationReissueCommand):
        raise ValidationError("Student activation reissue requires a typed orchestration command.")
    from apps.student_activation.services import (
        queue_activation_delivery_by_id,
        reissue_activation_invitation_by_id,
    )

    receipt = reissue_activation_invitation_by_id(
        command.invitation_id,
        actor_user=actor,
        reason=command.reason,
        expected_updated_at=command.expected_updated_at,
    )
    queue_activation_delivery_by_id(receipt.invitation_id)
    from apps.student_activation.commands import ActivationInvitationReceipt
    return ActivationInvitationReceipt(
        invitation_id=receipt.invitation_id,
        expires_at=receipt.expires_at,
        delivery_queued=True,
    )


def sync_contact_reply_delivery_for_composition(command: ContactReplyDeliveryCommand):
    if not isinstance(command, ContactReplyDeliveryCommand):
        raise ValidationError("Contact delivery synchronization requires a typed orchestration command.")
    from apps.notifications.services import sync_contact_reply_delivery_state_by_id

    return sync_contact_reply_delivery_state_by_id(command.delivery_id)


def cancel_contact_reply_delivery_for_composition(
    actor,
    command: ContactReplyDeliveryCancellationCommand,
):
    if not isinstance(command, ContactReplyDeliveryCancellationCommand):
        raise ValidationError("Contact delivery cancellation requires a typed orchestration command.")
    from apps.notifications.commands import EmailDeliveryCancelCommand
    from apps.notifications.services import cancel_email_delivery

    return cancel_email_delivery(
        delivery_id=command.delivery_id,
        command=EmailDeliveryCancelCommand(reason=command.reason_code),
        actor=actor,
    )


def cancel_activation_deliveries_for_composition(command: ActivationDeliveryCancellationCommand):
    if not isinstance(command, ActivationDeliveryCancellationCommand):
        raise ValidationError("Activation delivery cancellation requires a typed orchestration command.")
    from apps.notifications.services import cancel_pending_email_deliveries

    return cancel_pending_email_deliveries(
        template_key=command.template_key,
        related_object_ids=command.invitation_ids,
        reason=command.reason_code,
    )


def retry_contact_reply_delivery(actor, command: ContactReplyDeliveryCommand):
    if not isinstance(command, ContactReplyDeliveryCommand):
        raise ValidationError("Contact delivery retry requires a typed orchestration command.")
    from apps.notifications.commands import EmailDeliveryRetryCommand
    from apps.notifications.services import retry_email_delivery

    return retry_email_delivery(
        actor=actor,
        delivery_id=command.delivery_id,
        command=EmailDeliveryRetryCommand(),
    )


@transaction.atomic
def create_call_slip_from_referral_workflow(actor, command: ReferralCallSlipCommand, request_key):
    """Create or reissue a Call Slip from a Referral in one locked workflow.

    The Call Slip domain primitive owns its referral-first lock order and
    domain policies; this function is the only composition entry point used
    by API callers so the linked mutation cannot bypass that boundary.
    """
    if not isinstance(command, ReferralCallSlipCommand):
        raise ValidationError("Referral Call Slip creation requires a typed orchestration command.")
    from apps.call_slips.commands import CallSlipCreateFromReferralCommand
    from apps.call_slips.services import create_call_slip_from_referral

    return create_call_slip_from_referral(
        actor,
        CallSlipCreateFromReferralCommand(
            referral_reference=command.referral_reference,
            reissued_from_reference=command.reissued_from_reference,
            reissue_reason_code=command.reissue_reason_code,
            destination_code=command.destination_code,
            report_to_destination=command.report_to_destination,
            mode=command.mode,
            student_safe_location=command.student_safe_location,
            student_safe_instructions=command.student_safe_instructions,
            office_only_remarks=command.office_only_remarks,
        ),
        request_key,
    )
