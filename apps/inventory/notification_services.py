"""Transactional notifications for the authenticated Inventory workflow."""

from apps.notifications.dispatch import fan_out_notification
from apps.workflow.services import normalize_safe_response_path


def handle_inventory_correction_event(payload, outbox_event):
    """Notify the linked student without exposing Inventory content."""

    from apps.inventory.models import StudentInventoryStatusHistory

    history = (
        StudentInventoryStatusHistory.objects.select_related(
            "snapshot__student_profile__user"
        ).get(pk=payload["history_id"])
    )
    snapshot = history.snapshot
    student = snapshot.student_profile.user
    action_path = normalize_safe_response_path(payload.get("action_path")) or ""
    context = {
        "action": "correction_requested",
        "status": "Update requested",
        "action_path": action_path,
    }
    fan_out_notification(
        event_key=outbox_event.event_key,
        notification_type="inventory_correction_requested",
        recipients=[student],
        title="Individual Inventory update requested",
        body_preview=(
            "The Guidance Office reopened your Individual Inventory for correction. "
            "Review it in COMPASS and submit the updated version."
        ),
        related_object=snapshot,
        metadata=context,
        email_context=context,
        subject="COMPASS: Individual Inventory Update Requested",
        preference_type="inventory_correction_requested",
    )
