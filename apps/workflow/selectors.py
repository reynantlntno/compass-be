from apps.workflow.models import IdempotencyKey, OutboxEvent
from apps.access_control.rules import is_active_nonlegacy_actor


def get_idempotency_key_by_hash(key_hash: str, action_scope: str):
    """Retrieves an idempotency key by its hash and scope."""
    return IdempotencyKey.objects.filter(key_hash=key_hash, action_scope=action_scope).first()


def get_user_idempotency_keys(user):
    """Retrieves all idempotency keys associated with a specific user."""
    if not is_active_nonlegacy_actor(user):
        return IdempotencyKey.objects.none()
    return IdempotencyKey.objects.filter(actor_user=user)


def get_outbox_event_by_key(event_key: str):
    """Retrieves an outbox event by its unique event key."""
    return OutboxEvent.objects.filter(event_key=event_key).first()
