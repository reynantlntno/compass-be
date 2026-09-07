"""Transactional referral notification events and safe recipient handling."""

from apps.notifications.dispatch import enqueue_notification_event, fan_out_notification, safe_display_name
from apps.notifications.recipients import authorized_queue_readers


STUDENT_STATUS_LABELS = {
    "SUBMITTED": "Submitted",
    "RECEIVED": "Received",
    "UNDER_REVIEW": "Under review",
    "ACTION_REQUIRED": "Action may be needed",
    "ESCALATED": "Under review",
    "CLOSED": "Completed",
    "CANCELLED": "Cancelled",
}


def enqueue_referral_event(event, referral, *, action=None):
    action = action or event
    enqueue_notification_event(
        f"referral.{event}",
        {
            "referral_id": str(referral.pk),
            "action": action,
            "status": str(referral.status),
        },
        related_object=referral,
        event_key=f"referral:{referral.pk}:{event}:{referral.updated_at.isoformat()}",
    )


def _referral_readers(referral):
    from apps.referrals.policies import can_view_referral_safe_metadata

    return authorized_queue_readers(can_view_referral_safe_metadata, referral)


def handle_referral_event(payload, outbox_event):
    from apps.referrals.models import Referral

    referral = Referral.objects.select_related("student", "assigned_counselor").get(pk=payload["referral_id"])
    action = payload["action"]
    status = referral.status
    status_label = STUDENT_STATUS_LABELS.get(status, "Updated")
    student_name = safe_display_name(referral.student)
    counselor_name = safe_display_name(referral.assigned_counselor, fallback="") if referral.assigned_counselor_id else ""
    staff_context = {
        "action": action,
        "status": referral.get_status_display(),
        "reference_code": referral.reference_code,
        "student_name": student_name,
        "counselor_name": counselor_name,
    }

    staff_recipients = list(_referral_readers(referral))
    if referral.assigned_counselor_id:
        staff_recipients.append(referral.assigned_counselor)

    if action in {"created", "assigned", "status_changed"} and staff_recipients:
        fan_out_notification(
            event_key=f"{outbox_event.event_key}:staff",
            notification_type="referral_created" if action == "created" else "referral_assigned" if action == "assigned" else "referral_status_update",
            recipients=staff_recipients,
            title="New referral" if action == "created" else "Referral assignment" if action == "assigned" else "Referral status update",
            body_preview="A referral is ready for Guidance processing." if action == "created" else "A referral assignment has changed." if action == "assigned" else "A referral status update is available.",
            related_object=referral,
            metadata=staff_context,
            email_context=staff_context,
            subject="COMPASS: Referral Update",
        )

    if action == "status_changed" and status in STUDENT_STATUS_LABELS:
        student_context = {
            "action": action,
            "status": status_label,
            "reference_code": referral.reference_code,
        }
        fan_out_notification(
            event_key=f"{outbox_event.event_key}:student",
            notification_type="referral_status_update",
            recipients=[referral.student],
            title="Referral status update",
            body_preview="A safe referral status update is available in COMPASS.",
            related_object=referral,
            metadata=student_context,
            email_context=student_context,
            subject="COMPASS: Referral Update",
        )

    if action == "assigned" and referral.student:
        student_context = {
            "action": "counselor_assigned",
            "status": "Assigned",
            "reference_code": referral.reference_code,
            "counselor_name": counselor_name,
        }
        fan_out_notification(
            event_key=f"{outbox_event.event_key}:student",
            notification_type="counselor_assigned",
            recipients=[referral.student],
            title="Counselor assigned",
            body_preview="A counselor has been assigned to this referral.",
            related_object=referral,
            metadata=student_context,
            email_context=student_context,
            subject="COMPASS: Counselor Assignment Update",
        )
