"""Transactional form-collection notification events."""

from apps.notifications.dispatch import enqueue_notification_event, fan_out_notification


def enqueue_collection_linked_event(token):
    enqueue_notification_event(
        "form_collection.delivered",
        {
            "access_id": str(token.pk),
            "action": "delivered",
            "status": "Available",
        },
        related_object=token,
        event_key=f"form_collection:delivered:{token.pk}",
    )


def handle_collection_event(payload, outbox_event):
    from apps.form_collection.models import FormInvitation
    from apps.audit.services import audit_log

    token = FormInvitation.objects.select_related("linked_student__user", "collection").get(pk=payload["access_id"])
    if not token.linked_student:
        audit_log(
            action_type="COLLECTION_NOTIFICATION_SUPPRESSED_UNLINKED",
            event_category="NOTIFICATION",
            target_model="form_collection.FormInvitation",
            target_object_id=str(token.pk),
            source_app="form_collection",
            metadata={"event_type": outbox_event.event_type, "reason": "unlinked_recipient"},
        )
        return
    context = {
        "action": "delivered",
        "status": "Available",
        "collection_title": token.collection.name,
    }
    fan_out_notification(
        event_key=outbox_event.event_key,
        notification_type="collection_delivered",
        recipients=[token.linked_student.user],
        title="Collection available",
        body_preview="A COMPASS form collection is available.",
        related_object=token,
        metadata=context,
        email_context=context,
        subject="COMPASS: Form Collection Available",
    )
