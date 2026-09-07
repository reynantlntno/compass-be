"""Actor-aware query boundary for the notifications domain."""

from apps.common.contracts import PageRequest, PageResult
from apps.access_control.rules import is_active_nonlegacy_actor
from apps.audit.services import audit_log
from apps.notifications.catalog import preference_catalog
from apps.notifications.policies import can_view_email_delivery
from apps.notifications.projections import (
    notification_preference_projection,
    notification_projection,
    notification_type_projection,
    technical_delivery_projection,
)


def _audit_access(*, actor, action_type: str, target_model: str, target_object_id: str, metadata=None) -> None:
    if not is_active_nonlegacy_actor(actor):
        return
    audit_log(
        action_type=action_type,
        event_category="NOTIFICATION",
        target_model=target_model,
        target_object_id=str(target_object_id or ""),
        actor_user=actor,
        source_app="notifications",
        metadata=metadata or {},
    )
from apps.notifications.selectors import (
    get_email_deliveries,
    get_email_delivery_by_id,
    get_user_notification_by_id,
    get_user_notifications,
    get_user_preferences,
)


def notification_page(actor, page: PageRequest, *, status_filter=None) -> PageResult:
    queryset = get_user_notifications(actor, status_filter=status_filter)
    rows = queryset[page.offset:page.offset + page.page_size]
    total = queryset.count()
    _audit_access(
        actor=actor,
        action_type="NOTIFICATION_INBOX_ACCESSED",
        target_model="accounts.User",
        target_object_id=actor.pk,
        metadata={"status_filter": status_filter or "all", "result_count": total},
    )
    return PageResult(
        items=tuple(notification_projection(row) for row in rows),
        page=page.page,
        page_size=page.page_size,
        total=total,
    )


def notification_detail(actor, notification_id):
    value = get_user_notification_by_id(actor, notification_id)
    if value is not None:
        _audit_access(
            actor=actor,
            action_type="NOTIFICATION_ACCESSED",
            target_model="notifications.Notification",
            target_object_id=value.pk,
            metadata={"notification_type": value.notification_type},
        )
    return notification_projection(value) if value is not None else None


def unread_notification_count(actor) -> int:
    count = get_user_notifications(actor, status_filter="unread").count()
    _audit_access(
        actor=actor,
        action_type="NOTIFICATION_UNREAD_COUNT_ACCESSED",
        target_model="accounts.User",
        target_object_id=actor.pk,
        metadata={"result_count": count},
    )
    return count


def preference_page(actor, page: PageRequest) -> PageResult:
    if not is_active_nonlegacy_actor(actor):
        return PageResult(items=(), page=page.page, page_size=page.page_size, total=0)
    overrides = {
        row.notification_type: row
        for row in get_user_preferences(actor)
    }
    entries = []
    for notification_type, definition in preference_catalog():
        entries.append(notification_preference_projection(
            notification_type,
            definition,
            overrides.get(notification_type),
        ))
    _audit_access(
        actor=actor,
        action_type="NOTIFICATION_PREFERENCES_ACCESSED",
        target_model="accounts.User",
        target_object_id=actor.pk,
        metadata={"catalog_count": len(entries)},
    )
    return PageResult(
        items=tuple(entries[page.offset:page.offset + page.page_size]),
        page=page.page,
        page_size=page.page_size,
        total=len(entries),
    )


def preference_detail_by_id(actor, preference_id):
    if not is_active_nonlegacy_actor(actor):
        return None
    value = get_user_preferences(actor).filter(pk=preference_id).first()
    if value is None:
        return None
    definition = preference_catalog()
    definitions = dict(definition)
    notification_definition = definitions.get(value.notification_type)
    if notification_definition is None:
        return None
    return notification_preference_projection(
        value.notification_type,
        notification_definition,
        value,
    )


def preference_catalog_page(page: PageRequest) -> PageResult:
    entries = tuple(
        notification_type_projection(notification_type, definition)
        for notification_type, definition in preference_catalog()
    )
    return PageResult(
        items=entries[page.offset:page.offset + page.page_size],
        page=page.page,
        page_size=page.page_size,
        total=len(entries),
    )


def technical_delivery_page(actor, page: PageRequest, *, status_filter=None, delivery_state=None, template_key=None) -> PageResult:
    queryset = get_email_deliveries(
        actor,
        status_filter=status_filter,
        delivery_state=delivery_state,
        template_key=template_key,
    )
    rows = queryset[page.offset:page.offset + page.page_size]
    total = queryset.count()
    if can_view_email_delivery(actor):
        _audit_access(
            actor=actor,
            action_type="EMAIL_DELIVERY_METADATA_ACCESSED",
            target_model="notifications.EmailDelivery",
            target_object_id="",
            metadata={"result_count": total},
        )
    return PageResult(
        items=tuple(technical_delivery_projection(row) for row in rows),
        page=page.page,
        page_size=page.page_size,
        total=total,
    )


def technical_delivery_detail(actor, delivery_id):
    value = get_email_delivery_by_id(actor, delivery_id)
    if value is not None:
        _audit_access(
            actor=actor,
            action_type="EMAIL_DELIVERY_METADATA_ACCESSED",
            target_model="notifications.EmailDelivery",
            target_object_id=value.pk,
            metadata={"template_key": value.template_key},
        )
    return technical_delivery_projection(value) if value is not None else None
