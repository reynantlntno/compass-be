"""Cross-domain notification handlers executed by the outbox worker."""

from django.utils import timezone

from apps.notifications.dispatch import fan_out_notification


def handle_feedback_lifecycle_event(payload, outbox_event):
    """Acknowledge feedback lifecycle events that have no outbound notice.

    Feedback submission/review state is already persisted and audited by the
    feedback domain.  Registering the event explicitly keeps the outbox
    contract complete without inventing a second notification workflow.
    """
    return None


def handle_csm_invitation_event(payload, outbox_event):
    from apps.feedback.models import CSMInvitation

    invitation = CSMInvitation.objects.select_related("student").get(pk=payload["invitation_id"])
    expires_on = invitation.expires_at.strftime("%B %d, %Y")
    context = {
        "action": "feedback_invitation",
        "status": "Available",
        "service_label": invitation.service_label,
        "expires_on": expires_on,
    }
    fan_out_notification(
        event_key=outbox_event.event_key,
        notification_type="csm_invitation",
        recipients=[invitation.student],
        title="Share feedback about a completed service",
        body_preview=f"Feedback for {invitation.service_label} is available until {expires_on}.",
        related_object=invitation,
        metadata=context,
        email_context=context,
        subject="COMPASS: Feedback Invitation Available",
        preference_type="csm_invitation",
    )


def handle_contact_submission_event(payload, outbox_event):
    from apps.content.models import PublicContactSubmission
    from apps.content.selectors import get_contact_alert_recipients

    submission = PublicContactSubmission.objects.get(pk=payload["submission_id"])
    recipients = get_contact_alert_recipients()
    metadata = {
        "action": "submitted",
        "status": "Received",
        "submission_type": submission.get_submission_type_display(),
    }
    fan_out_notification(
        event_key=outbox_event.event_key,
        notification_type="contact_submission_received",
        recipients=recipients,
        title="New Contact Submission",
        body_preview=f"A new public submission ({submission.get_submission_type_display()}) has been received.",
        related_object=submission,
        metadata=metadata,
    )


def handle_contact_reply_event(payload, outbox_event):
    """Queue one external reply from a UUID-only outbox payload."""
    from apps.content.models import ContactReply, ContactReplyStatus
    from apps.notifications.services import build_email_delivery_key, enqueue_email_from_template

    reply = (
        ContactReply.objects.select_related("submission")
        .defer("reply_body_encrypted", "submission__message_body_encrypted")
        .filter(pk=payload.get("reply_id"))
        .first()
    )
    if not reply or reply.status not in {ContactReplyStatus.APPROVED, ContactReplyStatus.QUEUED}:
        return
    email = (reply.submission.email or "").strip()
    if not email:
        return
    context = {"reply_id": str(reply.pk)}
    delivery_key = build_email_delivery_key(
        recipient_user=None,
        recipient_email=email,
        template_key="contact_reply",
        context=context,
        related_object=reply,
        purpose=f"{outbox_event.event_key}:contact_reply",
    )
    delivery = enqueue_email_from_template(
        recipient_user=None,
        recipient_email=email,
        template_key="contact_reply",
        context=context,
        subject="COMPASS contact response",
        related_object=reply,
        delivery_key=delivery_key,
        purpose=f"{outbox_event.event_key}:contact_reply",
        respect_preferences=False,
    )
    if delivery:
        ContactReply.objects.filter(pk=reply.pk).update(
            delivery=delivery,
            status=ContactReplyStatus.QUEUED,
            delivery_state=delivery.delivery_state,
        )


def handle_ecounseling_consent_event(payload, outbox_event):
    from apps.counseling.models import ECounselingSession

    session = ECounselingSession.objects.select_related("counseling_session__student").get(pk=payload["session_id"])
    student = session.counseling_session.student
    fan_out_notification(
        event_key=outbox_event.event_key,
        notification_type="ecounseling_recording_consent_requested",
        recipients=[student],
        title="Recording consent request",
        body_preview="Please review the optional recording notice for your upcoming online counseling session.",
        related_object=session,
        metadata={"action": "consent_requested", "status": "Pending"},
    )


def handle_student_activation_invitation_event(payload, outbox_event):
    """Queue a UUID-only activation delivery for an inactive student."""
    from apps.student_activation.models import StudentActivationInvitation
    from apps.account_security.activation import ActivationPurpose, activation_profile
    from apps.notifications.services import build_email_delivery_key, enqueue_email_from_template

    reference = str(payload.get("invitation_id") or "")
    invitation = (
        StudentActivationInvitation.objects.select_related("user")
        .filter(token_reference=reference)
        .first()
    )
    if not invitation:
        return
    user = invitation.user
    if (
        user.is_active
        or invitation.used_at
        or invitation.revoked_at
        or invitation.expires_at <= timezone.now()
        or invitation.token_version != activation_profile(ActivationPurpose.STUDENT).version
    ):
        return
    context = {"invitation_id": reference}
    delivery_key = build_email_delivery_key(
        recipient_user=user,
        template_key="student_activation",
        context=context,
        related_object=invitation,
        purpose=f"{outbox_event.event_key}:student_activation",
    )
    enqueue_email_from_template(
        recipient_user=user,
        template_key="student_activation",
        context=context,
        subject="COMPASS student account activation",
        related_object=invitation,
        delivery_key=delivery_key,
        purpose=f"{outbox_event.event_key}:student_activation",
        respect_preferences=False,
    )


def handle_staff_account_invitation_event(payload, outbox_event):
    """Queue a UUID-only staff activation delivery."""
    from apps.accounts.models import StaffAccountInvitation
    from apps.notifications.services import build_email_delivery_key, enqueue_email_from_template

    reference = str(payload.get("invitation_id") or "")
    invitation = StaffAccountInvitation.objects.select_related("user").filter(
        token_reference=reference,
    ).first()
    now = timezone.now()
    if (
        not invitation or invitation.used_at or invitation.revoked_at
        or invitation.expires_at <= now or invitation.user.is_active
        or invitation.user.is_superuser or invitation.user.role != invitation.role_snapshot
    ):
        return
    context = {"invitation_id": reference}
    delivery_key = build_email_delivery_key(
        recipient_user=invitation.user,
        template_key="staff_activation",
        context=context,
        related_object=invitation,
        purpose=f"{outbox_event.event_key}:staff_activation",
    )
    enqueue_email_from_template(
        recipient_user=invitation.user,
        template_key="staff_activation",
        context=context,
        subject="COMPASS staff account activation",
        related_object=invitation,
        delivery_key=delivery_key,
        purpose=f"{outbox_event.event_key}:staff_activation",
        respect_preferences=False,
    )
