"""Django Ninja adapter for owned notifications and technical delivery state."""

from __future__ import annotations

from uuid import UUID

from ninja import Router, Schema

from apps.access_control.authority import has_fixed_capability
from apps.access_control.capabilities import Capability
from apps.audit.services import audit_log
from apps.common.api.idempotency import ApiMutationOutcome, run_api_mutation
from apps.common.api.operations import prepare_api_operation
from apps.common.api.pagination import PageQuery, PageSizeQuery, page_request_from_values
from apps.common.api.schemas import PageResultSchema
from apps.common.contracts import ContractValidationError
from apps.common.exceptions import NotFoundError, PermissionDeniedError, ValidationError
from apps.access_control.rules import is_active_nonlegacy_actor
from apps.notifications.catalog import get_notification_definition
from apps.notifications.commands import (
    DeadLetterReason,
    EmailDeliveryDeadLetterCommand,
    EmailDeliveryRetryCommand,
    NotificationArchiveCommand,
    NotificationPreferenceUpdateCommand,
    NotificationReadCommand,
)
from apps.notifications.projections import (
    notification_preference_projection,
    notification_projection,
    technical_delivery_projection,
)
from apps.notifications.queries import (
    notification_detail,
    notification_page,
    preference_detail_by_id,
    preference_catalog_page,
    preference_page,
    technical_delivery_detail,
    technical_delivery_page,
    unread_notification_count,
)
from apps.notifications.services import (
    archive_notification,
    mark_email_delivery_dead,
    mark_notification_read,
    retry_email_delivery,
    update_notification_preference,
)


router = Router(tags=["notifications"])


class NotificationSchema(Schema):
    id: str
    notification_type: str
    title: str
    body_preview: str
    status: str
    priority: str
    channel_intent: str
    created_at: str | None = None
    read_at: str | None = None
    archived_at: str | None = None


class UnreadCountSchema(Schema):
    unread_count: int


class NotificationTypeSchema(Schema):
    notification_type: str
    category: str
    label: str
    description: str
    channel: str
    priority: str
    preference_policy: str


class NotificationPreferenceSchema(NotificationTypeSchema):
    in_app_enabled: bool
    email_enabled: bool
    overridden: bool
    mandatory: bool


class NotificationPreferenceUpdateSchema(Schema):
    in_app_enabled: bool
    email_enabled: bool


class NotificationStatusSchema(Schema):
    expected_status: str | None = None


class TechnicalDeliverySchema(Schema):
    id: str
    template_key: str
    status: str
    delivery_state: str
    attempts: int
    max_attempts: int
    next_retry_at: str | None = None
    last_error_code: str | None = None
    last_error_safe_summary: str
    created_at: str | None = None
    sent_at: str | None = None
    provider_status_updated_at: str | None = None


class DeadLetterSchema(Schema):
    reason: str


class NotificationPageSchema(PageResultSchema):
    items: list[NotificationSchema]


class NotificationTypePageSchema(PageResultSchema):
    items: list[NotificationTypeSchema]


class NotificationPreferencePageSchema(PageResultSchema):
    items: list[NotificationPreferenceSchema]


class TechnicalDeliveryPageSchema(PageResultSchema):
    items: list[TechnicalDeliverySchema]


def _actor(request):
    return request.auth.user


def _page(page: PageQuery, page_size: PageSizeQuery):
    try:
        return page_request_from_values(page, page_size)
    except ContractValidationError as exc:
        raise ValidationError() from exc


def _payload(payload):
    return payload.dict() if payload is not None else {}


def _run(request, operation_id, payload, operation, replay):
    prepared = prepare_api_operation(request, operation_id)
    return run_api_mutation(
        request,
        operation_id,
        payload,
        operation,
        replay,
        prepared_operation=prepared,
    )


def _notification_replay(actor, key):
    value = notification_detail(actor, key.related_object_id)
    return value or None


def _preference_replay(actor, key):
    return preference_detail_by_id(actor, key.related_object_id)


def _delivery_replay(actor, key):
    return technical_delivery_detail(actor, key.related_object_id) or None


def _notification_outcome(notification):
    return ApiMutationOutcome(
        value=notification_projection(notification),
        related_object=notification,
        safe_response_path=f"/api/v1/notifications/{notification.pk}/",
    )


def _preference_outcome(preference):
    definition = get_notification_definition(preference.notification_type)
    return ApiMutationOutcome(
        value=notification_preference_projection(preference.notification_type, definition, preference),
        related_object=preference,
        safe_response_path=f"/api/v1/notifications/preferences/{preference.notification_type}/",
    )


def _update_preference_outcome(actor, command):
    return _preference_outcome(update_notification_preference(actor=actor, command=command))


def _delivery_outcome(delivery):
    return ApiMutationOutcome(
        value=technical_delivery_projection(delivery),
        related_object=delivery,
        safe_response_path=f"/api/v1/notifications/delivery/{delivery.pk}/",
    )


def _require_delivery_access(actor):
    if not is_active_nonlegacy_actor(actor) or not has_fixed_capability(actor, Capability.NOTIFICATIONS_DELIVERY_OPERATE):
        audit_log(
            action_type="POLICY_DENIAL",
            event_category="SECURITY",
            target_model="notifications.EmailDelivery",
            target_object_id="",
            actor_user=actor,
            source_app="notifications",
            metadata={"reason": "technical_delivery_capability_required"},
        )
        raise PermissionDeniedError()


@router.get("/", response=NotificationPageSchema, operation_id="notifications_list")
def list_notifications(request, page: PageQuery, page_size: PageSizeQuery):
    status_filter = str(request.GET.get("status", "") or "").strip() or None
    if status_filter not in {None, "unread", "read", "archived"}:
        raise ValidationError(field_errors={"status": ["Invalid notification status."]})
    return notification_page(_actor(request), _page(page, page_size), status_filter=status_filter).as_dict()


@router.get("/unread-count/", response=UnreadCountSchema, operation_id="notifications_unread_count")
def unread_count(request):
    return {"unread_count": unread_notification_count(_actor(request))}


@router.get("/preferences/catalog/", response=NotificationTypePageSchema, operation_id="notifications_preferences_catalog")
def list_preference_catalog(request, page: PageQuery, page_size: PageSizeQuery):
    return preference_catalog_page(_page(page, page_size)).as_dict()


@router.get("/preferences/", response=NotificationPreferencePageSchema, operation_id="notifications_preferences_list")
def list_preferences(request, page: PageQuery, page_size: PageSizeQuery):
    return preference_page(_actor(request), _page(page, page_size)).as_dict()


@router.put("/preferences/{notification_type}/", response=NotificationPreferenceSchema, operation_id="notifications_preference_update")
def update_preference(request, notification_type: str, payload: NotificationPreferenceUpdateSchema):
    command = NotificationPreferenceUpdateCommand(
        notification_type=notification_type,
        in_app_enabled=payload.in_app_enabled,
        email_enabled=payload.email_enabled,
    )
    actor = _actor(request)
    return _run(
        request,
        "notifications_preference_update",
        {"notification_type": command.notification_type, "in_app_enabled": command.in_app_enabled, "email_enabled": command.email_enabled},
        lambda: _update_preference_outcome(actor, command),
        lambda key: _preference_replay(actor, key),
    )


@router.get("/delivery/", response=TechnicalDeliveryPageSchema, operation_id="notifications_delivery_list")
def list_delivery_metadata(request, page: PageQuery, page_size: PageSizeQuery):
    actor = _actor(request)
    _require_delivery_access(actor)
    status_filter = str(request.GET.get("status", "") or "").strip() or None
    delivery_state = str(request.GET.get("delivery_state", "") or "").strip() or None
    template_key = str(request.GET.get("template_key", "") or "").strip() or None
    if status_filter not in {None, "pending", "processing", "sent", "failed", "dead", "cancelled"}:
        raise ValidationError(field_errors={"status": ["Invalid delivery status."]})
    if delivery_state not in {None, "queued", "sending", "sent", "delayed", "failed", "retry_exhausted", "bounced", "cancelled"}:
        raise ValidationError(field_errors={"delivery_state": ["Invalid delivery state."]})
    if template_key is not None and len(template_key) > 100:
        raise ValidationError(field_errors={"template_key": ["Template key is too long."]})
    return technical_delivery_page(
        actor,
        _page(page, page_size),
        status_filter=status_filter,
        delivery_state=delivery_state,
        template_key=template_key,
    ).as_dict()


@router.get("/delivery/{delivery_id}/", response=TechnicalDeliverySchema, operation_id="notifications_delivery_detail")
def view_delivery_metadata(request, delivery_id: UUID):
    actor = _actor(request)
    _require_delivery_access(actor)
    value = technical_delivery_detail(actor, delivery_id)
    if value is None:
        raise NotFoundError()
    return value


@router.get("/{notification_id}/", response=NotificationSchema, operation_id="notifications_detail")
def view_notification(request, notification_id: UUID):
    value = notification_detail(_actor(request), notification_id)
    if value is None:
        raise NotFoundError()
    return value


@router.post("/{notification_id}/read/", response=NotificationSchema, operation_id="notifications_read")
def read_notification(request, notification_id: UUID, payload: NotificationStatusSchema | None = None):
    actor = _actor(request)
    command = NotificationReadCommand(expected_status=payload.expected_status if payload else None)
    return _run(
        request,
        "notifications_read",
        {"notification_id": str(notification_id), **_payload(payload)},
        lambda: _notification_outcome(mark_notification_read(actor=actor, notification_id=notification_id, command=command)),
        lambda key: _notification_replay(actor, key),
    )


@router.post("/{notification_id}/archive/", response=NotificationSchema, operation_id="notifications_archive")
def archive_notification_api(request, notification_id: UUID, payload: NotificationStatusSchema | None = None):
    actor = _actor(request)
    command = NotificationArchiveCommand(expected_status=payload.expected_status if payload else None)
    return _run(
        request,
        "notifications_archive",
        {"notification_id": str(notification_id), **_payload(payload)},
        lambda: _notification_outcome(archive_notification(actor=actor, notification_id=notification_id, command=command)),
        lambda key: _notification_replay(actor, key),
    )


@router.post("/delivery/{delivery_id}/retry/", response=TechnicalDeliverySchema, operation_id="notifications_delivery_retry")
def retry_delivery(request, delivery_id: UUID):
    actor = _actor(request)
    _require_delivery_access(actor)
    command = EmailDeliveryRetryCommand()
    return _run(
        request,
        "notifications_delivery_retry",
        {"delivery_id": str(delivery_id)},
        lambda: _delivery_outcome(retry_email_delivery(actor=actor, delivery_id=delivery_id, command=command)),
        lambda key: _delivery_replay(actor, key),
    )


@router.post("/delivery/{delivery_id}/dead-letter/", response=TechnicalDeliverySchema, operation_id="notifications_delivery_dead_letter")
def dead_letter_delivery(request, delivery_id: UUID, payload: DeadLetterSchema):
    actor = _actor(request)
    _require_delivery_access(actor)
    try:
        command = EmailDeliveryDeadLetterCommand(reason=DeadLetterReason(payload.reason))
    except ValueError as exc:
        raise ValidationError(field_errors={"reason": ["Unsupported dead-letter reason."]}) from exc
    return _run(
        request,
        "notifications_delivery_dead_letter",
        {"delivery_id": str(delivery_id), "reason": command.reason.value},
        lambda: _delivery_outcome(mark_email_delivery_dead(actor=actor, delivery_id=delivery_id, command=command)),
        lambda key: _delivery_replay(actor, key),
    )
