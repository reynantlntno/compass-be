"""Service-bound CSM invitation orchestration and privacy-safe delivery."""

from datetime import timedelta

from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.access_control.rules import is_gco_staff
from apps.common.exceptions import PermissionDeniedError as PermissionDenied, ValidationError
from apps.audit.services import audit_log
from apps.feedback.models import (
    CSMInvitation,
    CSMInvitationStatus,
    CSMServiceFamily,
)
from apps.notifications.dispatch import enqueue_notification_event


INVITATION_LIFETIME = timedelta(days=30)


def _event_key(workflow_type, object_pk, completed_at):
    return f"{workflow_type}:{object_pk}:{completed_at.isoformat()}"


def refresh_invitation_expiry(invitation, *, now=None):
    now = now or timezone.now()
    if (
        invitation.status == CSMInvitationStatus.AVAILABLE
        and invitation.expires_at <= now
    ):
        invitation.status = CSMInvitationStatus.EXPIRED
        invitation.save(update_fields=["status", "updated_at"])
    return invitation


def _deliver(invitation, *, actor=None):
    """Record a send attempt and enqueue its durable delivery event."""
    invitation = CSMInvitation.objects.select_for_update().get(pk=invitation.pk)
    refresh_invitation_expiry(invitation)
    if invitation.status != CSMInvitationStatus.AVAILABLE:
        raise ValidationError("This feedback invitation is no longer available.")

    now = timezone.now()
    invitation.first_sent_at = invitation.first_sent_at or now
    invitation.last_sent_at = now
    invitation.send_count += 1
    invitation.save(
        update_fields=[
            "first_sent_at",
            "last_sent_at",
            "send_count",
            "updated_at",
        ]
    )

    enqueue_notification_event(
        "feedback.csm_invitation",
        {
            "invitation_id": str(invitation.pk),
            "action": "feedback_invitation",
            "status": "Available",
            "send_count": invitation.send_count,
        },
        related_object=invitation,
        event_key=f"csm_invitation:{invitation.pk}:{invitation.send_count}",
    )

    audit_log(
        action_type="CSM_INVITATION_SENT",
        event_category="WORKFLOW",
        target_model="feedback.CSMInvitation",
        target_object_id=str(invitation.pk),
        actor_user=actor,
        source_app="feedback",
        metadata={
            "service_family": invitation.service_family,
            "send_count": invitation.send_count,
        },
    )
    return invitation


@transaction.atomic
def issue_invitation(
    *,
    student,
    service_family,
    service_label,
    service_category,
    workflow_type,
    reference_code,
    object_pk,
    completed_at,
    actor=None,
    deliver=True,
):
    if not student:
        raise ValidationError("A completed service requires a student account.")
    if not completed_at:
        raise ValidationError("A completed service timestamp is required.")

    completion_event_key = _event_key(workflow_type, object_pk, completed_at)
    invitation = CSMInvitation.objects.select_for_update().filter(
        completion_event_key=completion_event_key
    ).first()
    created = False
    if invitation is None:
        try:
            with transaction.atomic():
                invitation = CSMInvitation.objects.create(
                    student=student,
                    service_family=service_family,
                    service_label=service_label,
                    service_category=service_category,
                    related_workflow_type=workflow_type,
                    related_reference_code=reference_code,
                    completion_event_key=completion_event_key,
                    completed_at=completed_at,
                    expires_at=completed_at + INVITATION_LIFETIME,
                    issued_by=actor,
                )
                created = True
        except IntegrityError:
            invitation = CSMInvitation.objects.select_for_update().get(
                completion_event_key=completion_event_key
            )

    if invitation.student_id != student.pk:
        raise ValidationError("The completion event is already bound to another recipient.")
    refresh_invitation_expiry(invitation)
    if deliver and (created or actor is not None):
        invitation = _deliver(invitation, actor=actor)
    return invitation, created


def _session_contract(session):
    from apps.counseling.models import SessionStatusChoices, SessionTypeChoices

    if session.status != SessionStatusChoices.COMPLETED or not session.completed_at:
        raise ValidationError("Only a completed counseling service can receive feedback.")
    if session.session_type == SessionTypeChoices.TRIAGE:
        raise ValidationError("Urgent-support sessions do not create feedback invitations.")
    if session.session_type == SessionTypeChoices.ADMINISTRATIVE_INTERVIEW:
        category = "Others"
        label = "Guidance Office interview"
    else:
        category = "Counseling"
        label = session.get_session_type_display()
    return {
        "student": session.student,
        "service_family": CSMServiceFamily.COUNSELING,
        "service_label": label,
        "service_category": category,
        "workflow_type": "counseling_session",
        "reference_code": session.reference_code,
        "object_pk": session.pk,
        "completed_at": session.completed_at,
    }


def _call_slip_contract(slip):
    from apps.call_slips.models import (
        COUNSELOR_TIME_PURPOSES,
        CallSlipPurposeCodeChoices,
        CallSlipStatusChoices,
    )

    if (
        slip.status != CallSlipStatusChoices.ATTENDED
        or not slip.attendance_recorded_at
    ):
        raise ValidationError("Only an attended call slip can receive feedback.")
    if slip.purpose_code in COUNSELOR_TIME_PURPOSES:
        category, label = "Counseling", "Guidance Office counseling assistance"
    elif slip.purpose_code == CallSlipPurposeCodeChoices.DOCUMENT_FOLLOW_UP:
        category, label = "Request for Certification", "Certificate request assistance"
    else:
        category, label = "Others", "Guidance Office assistance"
    return {
        "student": slip.student,
        "service_family": CSMServiceFamily.CALL_SLIP,
        "service_label": label,
        "service_category": category,
        "workflow_type": "call_slip",
        "reference_code": slip.reference_code,
        "object_pk": slip.pk,
        "completed_at": slip.attendance_recorded_at,
    }


def _good_moral_contract(request_obj):
    from apps.good_moral.models import GoodMoralStatusChoices

    if (
        request_obj.status != GoodMoralStatusChoices.RELEASED
        or not request_obj.released_at
    ):
        raise ValidationError("Only a released certificate service can receive feedback.")
    return {
        "student": request_obj.requester_user,
        "service_family": CSMServiceFamily.GOOD_MORAL,
        "service_label": "Good Moral Certificate service",
        "service_category": "Request for Certification",
        "workflow_type": "good_moral",
        "reference_code": request_obj.reference_code,
        "object_pk": request_obj.pk,
        "completed_at": request_obj.released_at,
    }


def _referral_contract(referral):
    from apps.referrals.models import (
        ReferralStatusChoices,
        ReferralWorkflowReasonCodeChoices,
    )

    if (
        referral.status != ReferralStatusChoices.CLOSED
        or referral.close_reason_code
        != ReferralWorkflowReasonCodeChoices.WORK_COMPLETED
        or not referral.closed_at
    ):
        raise ValidationError("Only completed referral assistance can receive feedback.")
    return {
        "student": referral.student,
        "service_family": CSMServiceFamily.REFERRAL,
        "service_label": "Referral assistance",
        "service_category": "Others",
        "workflow_type": "referral",
        "reference_code": referral.reference_code,
        "object_pk": referral.pk,
        "completed_at": referral.closed_at,
    }


CONTRACT_BUILDERS = {
    "counseling_session": _session_contract,
    "call_slip": _call_slip_contract,
    "good_moral": _good_moral_contract,
    "referral": _referral_contract,
}


def _can_send_for_source(actor, workflow_type, source):
    if not actor or not actor.is_authenticated or not actor.is_active:
        return False
    if workflow_type == "counseling_session":
        from apps.counseling.policies import can_view_session

        return source.assigned_counselor_id == actor.pk and can_view_session(actor, source)
    if workflow_type == "call_slip":
        from apps.call_slips.policies import can_view_call_slip_sensitive_detail

        if is_gco_staff(actor):
            return can_view_call_slip_sensitive_detail(actor, source)
        return (
            source.assigned_counselor_id == actor.pk
            and can_view_call_slip_sensitive_detail(actor, source)
        )
    if workflow_type == "referral":
        from apps.referrals.policies import can_view_referral_safe_metadata

        if is_gco_staff(actor):
            return can_view_referral_safe_metadata(actor, source)
        return (
            source.assigned_counselor_id == actor.pk
            and can_view_referral_safe_metadata(actor, source)
        )
    if workflow_type == "good_moral":
        from apps.good_moral.policies import can_view_request

        return is_gco_staff(actor) and can_view_request(actor, source)
    return False


def get_invitation_for_source(workflow_type, source):
    builder = CONTRACT_BUILDERS.get(workflow_type)
    if builder is None:
        return None
    try:
        contract = builder(source)
    except ValidationError:
        return None
    return CSMInvitation.objects.filter(
        completion_event_key=_event_key(
            workflow_type,
            contract["object_pk"],
            contract["completed_at"],
        )
    ).first()


def can_send_for_source(actor, workflow_type, source):
    if not _can_send_for_source(actor, workflow_type, source):
        return False
    try:
        CONTRACT_BUILDERS[workflow_type](source)
    except ValidationError:
        return False
    invitation = get_invitation_for_source(workflow_type, source)
    if invitation:
        refresh_invitation_expiry(invitation)
        return invitation.status == CSMInvitationStatus.AVAILABLE
    return True


@transaction.atomic
def send_for_source(actor, workflow_type, source):
    builder = CONTRACT_BUILDERS.get(workflow_type)
    if builder is None:
        raise ValidationError("Unsupported feedback service.")
    if not _can_send_for_source(actor, workflow_type, source):
        raise PermissionDenied("You cannot send feedback invitations for this service.")
    contract = builder(source)
    return issue_invitation(**contract, actor=actor, deliver=True)[0]


def issue_for_completed_source(workflow_type, source, *, actor):
    """System trigger used only from an authoritative completion transaction."""
    builder = CONTRACT_BUILDERS[workflow_type]
    return issue_invitation(**builder(source), actor=actor, deliver=True)[0]
