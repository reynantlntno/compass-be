"""Transactional Graduate Tracer notification events."""

from apps.notifications.dispatch import enqueue_notification_event, fan_out_notification, safe_display_name
from apps.notifications.recipients import authorized_queue_readers


def enqueue_gts_event(event, response):
    enqueue_notification_event(
        f"graduate_tracer.{event}",
        {
            "response_id": str(response.pk),
            "action": event,
            "status": str(response.status),
        },
        related_object=response,
        event_key=f"graduate_tracer:{response.pk}:{event}:{response.updated_at.isoformat()}",
    )


def enqueue_gts_reminder(token):
    enqueue_notification_event(
        "graduate_tracer.reminder",
        {
            "access_id": str(token.pk),
            "action": "reminder",
            "status": "Available",
        },
        related_object=token,
        event_key=f"graduate_tracer:reminder:{token.pk}",
    )


def handle_gts_event(payload, outbox_event):
    from apps.graduate_tracer.models import GraduateTracerResponse

    response = GraduateTracerResponse.objects.select_related("student__user").get(pk=payload["response_id"])
    # Older durable events recorded only the response identifier. Derive the
    # action from the registered event type so those rows remain processable.
    action = payload.get("action") or outbox_event.event_type.rsplit(".", 1)[-1]
    if action == "submitted":
        from apps.graduate_tracer.policies import can_view_gts_response

        readers = authorized_queue_readers(can_view_gts_response, response)
        fan_out_notification(
            event_key=outbox_event.event_key,
            notification_type="gts_submitted",
            recipients=readers,
            title="Graduate Tracer submitted",
            body_preview=f"{safe_display_name(response.student)} submitted a Graduate Tracer Survey for queue review.",
            related_object=response,
            metadata={"action": action, "status": "Submitted", "reference_code": response.reference_code, "student_name": safe_display_name(response.student)},
        )
    elif action == "status_changed" and response.status in {"REOPENED_FOR_CORRECTION", "VOIDED"} and response.student:
        context = {"action": action, "status": response.get_status_display(), "reference_code": response.reference_code}
        fan_out_notification(
            event_key=outbox_event.event_key,
            notification_type="gts_status_update",
            recipients=[response.student.user],
            title="Graduate Tracer status update",
            body_preview="Your Graduate Tracer status has changed. Open COMPASS for the current information.",
            related_object=response,
            metadata=context,
            email_context=context,
            subject="COMPASS: Graduate Tracer Update",
        )


def handle_gts_reminder(payload, outbox_event):
    from apps.form_collection.models import FormInvitation

    token = FormInvitation.objects.select_related("linked_student__user", "collection").get(pk=payload["access_id"])
    if not token.linked_student:
        return
    context = {"action": "reminder", "status": "Available"}
    fan_out_notification(
        event_key=outbox_event.event_key,
        notification_type="gts_reminder",
        recipients=[token.linked_student.user],
        title="Graduate Tracer reminder",
        body_preview="A Graduate Tracer Survey is ready in COMPASS.",
        related_object=token,
        metadata=context,
        email_context=context,
        subject="COMPASS: Graduate Tracer Update",
    )
