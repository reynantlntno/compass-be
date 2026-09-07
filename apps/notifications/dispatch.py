"""Shared transactional notification outbox dispatch helpers."""

import hashlib
import hmac
import json

from django.conf import settings
from django.db import transaction

from apps.audit.services import audit_log
from apps.notifications.catalog import canonical_notification_type, get_notification_definition
from apps.notifications.services import (
    build_email_delivery_key,
    enqueue_email_from_template,
    enqueue_notification,
)


def build_notification_dedupe_key(event_key: str, recipient_user, notification_type: str) -> str:
    """Return a non-sensitive unique key for one event/recipient notification."""
    seed = {
        "event_key": str(event_key),
        "recipient_id": str(recipient_user.pk),
        "notification_type": canonical_notification_type(notification_type),
    }
    serialized = json.dumps(seed, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(settings.SECRET_KEY.encode("utf-8"), serialized, hashlib.sha256).hexdigest()


def enqueue_notification_event(event_type: str, payload: dict, *, related_object=None, event_key=None):
    """Enqueue a safe domain event in the existing workflow outbox."""
    from apps.workflow.services import enqueue_outbox_event

    return enqueue_outbox_event(
        event_type=event_type,
        payload=payload,
        related_object=related_object,
        event_key=event_key,
    )


def _unique_active_recipients(recipients):
    unique = {}
    for recipient in recipients or []:
        if recipient and getattr(recipient, "is_active", False):
            unique[recipient.pk] = recipient
    return list(unique.values())


@transaction.atomic
def fan_out_notification(
    *,
    event_key: str,
    notification_type: str,
    recipients,
    title: str,
    body_preview: str,
    related_object=None,
    metadata=None,
    email_context=None,
    subject=None,
    priority=None,
    preference_type=None,
):
    """Create idempotent in-app and queued-email channels for one event."""
    canonical_type = canonical_notification_type(notification_type)
    definition = get_notification_definition(canonical_type)
    channel = definition["channel"]
    template_key = definition.get("template_key")
    priority = priority or definition.get("priority", "normal")
    metadata = metadata or {}
    email_context = email_context if email_context is not None else metadata
    recipients = _unique_active_recipients(recipients)

    if not recipients:
        audit_log(
            action_type="NOTIFICATION_NO_RECIPIENTS",
            event_category="NOTIFICATION",
            target_model=related_object.__class__.__name__ if related_object else "notifications.Notification",
            target_object_id=str(related_object.pk) if related_object else "",
            source_app="notifications",
            metadata={"notification_type": canonical_type, "event_key_hash": hashlib.sha256(str(event_key).encode()).hexdigest()[:16]},
        )
        return []

    created = []
    for recipient in recipients:
        dedupe_key = build_notification_dedupe_key(event_key, recipient, canonical_type)
        notification = enqueue_notification(
            recipient_user=recipient,
            notification_type=canonical_type,
            title=title,
            body_preview=body_preview,
            channel_intent=channel,
            related_object=related_object,
            priority=priority,
            metadata=metadata,
            dedupe_key=dedupe_key,
        )
        created.append(notification)

        if channel in {"email", "both"} and template_key:
            delivery_key = build_email_delivery_key(
                recipient_user=recipient,
                template_key=template_key,
                context=email_context,
                notification=notification,
                related_object=related_object,
                purpose=f"{event_key}:{canonical_type}",
            )
            enqueue_email_from_template(
                recipient_user=recipient,
                template_key=template_key,
                context=email_context,
                subject=subject,
                notification=notification,
                related_object=related_object,
                delivery_key=delivery_key,
                purpose=f"{event_key}:{canonical_type}",
                preference_type=preference_type or canonical_type,
            )
    return created


def safe_display_name(user_or_profile, fallback="A student") -> str:
    """Return a bounded plain-text display name for authorized copy only."""
    user = getattr(user_or_profile, "user", user_or_profile)
    name = " ".join(
        part for part in [getattr(user, "first_name", ""), getattr(user, "last_name", "")] if part
    ).strip()
    return (name or fallback).replace("\r", " ").replace("\n", " ")[:120]
