"""Fixed JSON projection boundary for the notifications domain."""

import re


def _safe_delivery_summary(value: str | None) -> str:
    """Return only a bounded operational summary, even for legacy rows."""
    text = str(value or "")
    text = re.sub(r"https?://\S+", "[url removed]", text)
    text = re.sub(r"\btoken(?:=|:)\S+", "token=[removed]", text, flags=re.IGNORECASE)
    text = re.sub(
        r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}",
        "[address removed]",
        text,
        flags=re.IGNORECASE,
    )
    return text.strip()[:240]

def notification_projection(notification) -> dict:
    if notification is None:
        return {}
    return {
        "id": str(notification.pk),
        "notification_type": notification.notification_type,
        "title": notification.title,
        "body_preview": notification.body_preview,
        "status": notification.status,
        "priority": notification.priority,
        "channel_intent": notification.channel_intent,
        "created_at": notification.created_at.isoformat() if notification.created_at else None,
        "read_at": notification.read_at.isoformat() if notification.read_at else None,
        "archived_at": notification.archived_at.isoformat() if notification.archived_at else None,
    }


def notification_type_projection(notification_type: str, definition: dict) -> dict:
    return {
        "notification_type": notification_type,
        "category": definition.get("category", ""),
        "label": definition.get("label", ""),
        "description": definition.get("description", ""),
        "channel": definition.get("channel", "in_app"),
        "priority": definition.get("priority", "normal"),
        "preference_policy": definition.get("preference_policy", "user"),
    }


def notification_preference_projection(notification_type: str, definition: dict, preference=None) -> dict:
    mandatory = definition.get("preference_policy", "user") == "mandatory_security"
    return {
        **notification_type_projection(notification_type, definition),
        "in_app_enabled": True if mandatory or preference is None else bool(preference.in_app_enabled),
        "email_enabled": True if mandatory or preference is None else bool(preference.email_enabled),
        "overridden": preference is not None,
        "mandatory": mandatory,
    }


def technical_delivery_projection(delivery) -> dict:
    if delivery is None:
        return {}
    return {
        "id": str(delivery.pk),
        "template_key": delivery.template_key,
        "status": delivery.status,
        "delivery_state": delivery.delivery_state,
        "attempts": delivery.attempts,
        "max_attempts": delivery.max_attempts,
        "next_retry_at": delivery.next_retry_at.isoformat() if delivery.next_retry_at else None,
        "last_error_code": delivery.last_error_code,
        "last_error_safe_summary": _safe_delivery_summary(delivery.last_error_safe_summary),
        "created_at": delivery.created_at.isoformat() if delivery.created_at else None,
        "sent_at": delivery.sent_at.isoformat() if delivery.sent_at else None,
        "provider_status_updated_at": (
            delivery.provider_status_updated_at.isoformat()
            if delivery.provider_status_updated_at else None
        ),
    }
