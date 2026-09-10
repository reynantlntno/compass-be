import hashlib
import hmac
import json
import re
from datetime import timedelta
from django.db import models, transaction
from django.db.utils import IntegrityError
from django.utils import timezone
from django.conf import settings
from apps.audit.services import audit_log
from apps.notifications.models import Notification, NotificationPreference, EmailDelivery
from apps.notifications.email_adapters import DjangoEmailAdapter, EmailDeliveryError
from apps.access_control.rules import is_active_nonlegacy_actor
from apps.notifications.catalog import get_notification_definition
from apps.notifications.commands import (
    DeadLetterReason,
    EmailDeliveryCancelCommand,
    EmailDeliveryDeadLetterCommand,
    EmailDeliveryRetryCommand,
    NotificationArchiveCommand,
    NotificationBulkArchiveCommand,
    NotificationPreferenceUpdateCommand,
    NotificationReadCommand,
)
from apps.common.exceptions import (
    LifecycleConflictError,
    NotFoundError,
    PermissionDeniedError,
    ValidationError,
)


def _safe_error_summary(value: str, fallback="Notification delivery failed.") -> str:
    text = str(value or "")
    text = re.sub(r"https?://\S+", "[url removed]", text)
    text = re.sub(r"\btoken(?:=|:)\S+", "token=[removed]", text, flags=re.IGNORECASE)
    text = re.sub(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", "[address removed]", text, flags=re.IGNORECASE)
    return (text.strip()[:500] or fallback)


# --------------------------------------------------------------------------
# Preference Checks
# --------------------------------------------------------------------------
def is_in_app_enabled(user, notification_type: str) -> bool:
    """Checks whether the user enables in-app alerts for this notification type."""
    from apps.notifications.catalog import notification_preference_keys

    try:
        if get_notification_definition(notification_type).get("preference_policy") == "mandatory_security":
            return True
    except (KeyError, ValueError):
        pass

    preferences = NotificationPreference.objects.filter(
        user=user,
        notification_type__in=notification_preference_keys(notification_type),
    )
    preference_map = {preference.notification_type: preference for preference in preferences}
    pref = next(
        (preference_map[key] for key in notification_preference_keys(notification_type) if key in preference_map),
        None,
    )
    if pref:
        return pref.in_app_enabled
    return True


def is_email_enabled(user, notification_type: str) -> bool:
    """Checks whether the user enables email alerts for this notification type."""
    from apps.notifications.catalog import notification_preference_keys

    try:
        if get_notification_definition(notification_type).get("preference_policy") == "mandatory_security":
            return True
    except (KeyError, ValueError):
        pass

    preferences = NotificationPreference.objects.filter(
        user=user,
        notification_type__in=notification_preference_keys(notification_type),
    )
    preference_map = {preference.notification_type: preference for preference in preferences}
    pref = next(
        (preference_map[key] for key in notification_preference_keys(notification_type) if key in preference_map),
        None,
    )
    if pref:
        return pref.email_enabled
    return True


# --------------------------------------------------------------------------
# Notification Services
# --------------------------------------------------------------------------
@transaction.atomic
def enqueue_notification(
    recipient_user,
    notification_type: str,
    title: str,
    body_preview: str,
    channel_intent: str = "both",
    related_object=None,
    priority: str = "normal",
    metadata: dict = None,
    dedupe_key: str = None,
) -> Notification | None:
    """
    Enqueues an in-app notification record if preferences permit.
    Also validates metadata using the default outbox validator.
    """
    from apps.workflow.services import validate_outbox_payload
    validate_outbox_payload(notification_type, metadata or {})

    if not is_in_app_enabled(recipient_user, notification_type):
        audit_log(
            action_type="NOTIFICATION_PREFERENCE_SUPPRESSED",
            event_category="NOTIFICATION",
            target_model="accounts.User",
            target_object_id=recipient_user.id,
            source_app="notifications",
            metadata={"notification_type": notification_type}
        )
        return None

    role_snap = recipient_user.role if hasattr(recipient_user, "role") else ""

    defaults = {
        "recipient_user": recipient_user,
        "recipient_role_snapshot": role_snap,
        "notification_type": notification_type,
        "title": title,
        "body_preview": body_preview,
        "related_object_type": related_object.__class__.__name__ if related_object else None,
        "related_object_id": str(related_object.pk) if related_object else None,
        "status": "unread",
        "priority": priority,
        "channel_intent": channel_intent,
        "metadata_json": metadata or {},
    }
    if dedupe_key:
        try:
            notif, created = Notification.objects.get_or_create(
                dedupe_key=dedupe_key,
                defaults=defaults,
            )
        except IntegrityError:
            notif = Notification.objects.select_for_update().get(dedupe_key=dedupe_key)
            created = False
        if not created and (
            notif.recipient_user_id != recipient_user.pk
            or notif.notification_type != notification_type
        ):
            raise ValueError("Notification dedupe key already belongs to another notification")
    else:
        notif = Notification.objects.create(**defaults)
        created = True

    if created:
        audit_log(
            action_type="NOTIFICATION_CREATED",
            event_category="NOTIFICATION",
            target_model="notifications.Notification",
            target_object_id=notif.id,
            source_app="notifications",
            metadata={
                "notification_type": notification_type,
                "recipient_id": str(recipient_user.id),
            }
        )
    return notif


@transaction.atomic
def mark_notification_read(*, actor, notification_id, command: NotificationReadCommand) -> Notification:
    """Mark one owned notification read after an internal lock/reload."""
    if not isinstance(command, NotificationReadCommand):
        raise ValidationError("Notification read requires a typed command.")
    if not is_active_nonlegacy_actor(actor):
        raise PermissionDeniedError()
    notification = Notification.objects.select_for_update().filter(pk=notification_id).first()
    if notification is None or notification.recipient_user_id != actor.pk:
        raise NotFoundError()
    if command.expected_status is not None and notification.status != command.expected_status:
        raise LifecycleConflictError()
    if notification.status != "read":
        notification.status = "read"
        notification.read_at = timezone.now()
        notification.save(update_fields=["status", "read_at"])
        audit_log(
            action_type="NOTIFICATION_READ",
            event_category="NOTIFICATION",
            target_model="notifications.Notification",
            target_object_id=notification.id,
            actor_user=actor,
            source_app="notifications",
        )
    return notification


@transaction.atomic
def archive_notification(*, actor, notification_id, command: NotificationArchiveCommand) -> Notification:
    """Archive one owned notification after an internal lock/reload."""
    if not isinstance(command, NotificationArchiveCommand):
        raise ValidationError("Notification archive requires a typed command.")
    if not is_active_nonlegacy_actor(actor):
        raise PermissionDeniedError()
    notification = Notification.objects.select_for_update().filter(pk=notification_id).first()
    if notification is None or notification.recipient_user_id != actor.pk:
        raise NotFoundError()
    if command.expected_status is not None and notification.status != command.expected_status:
        raise LifecycleConflictError()
    if notification.status != "archived":
        notification.status = "archived"
        notification.archived_at = timezone.now()
        notification.save(update_fields=["status", "archived_at"])
        audit_log(
            action_type="NOTIFICATION_ARCHIVED",
            event_category="NOTIFICATION",
            target_model="notifications.Notification",
            target_object_id=notification.id,
            actor_user=actor,
            source_app="notifications",
        )
    return notification


@transaction.atomic
def archive_notifications_bulk(*, actor, command: NotificationBulkArchiveCommand) -> tuple[Notification, ...]:
    """Archive owned notifications as one all-or-nothing state transition."""
    if not isinstance(command, NotificationBulkArchiveCommand):
        raise ValidationError("Bulk notification archive requires a typed command.")
    if not is_active_nonlegacy_actor(actor):
        raise PermissionDeniedError()

    requested_ids = tuple(item.notification_id for item in command.items)
    locked_rows = list(
        Notification.objects.select_for_update()
        .filter(recipient_user_id=actor.pk, pk__in=requested_ids)
        .order_by("pk")
    )
    if len(locked_rows) != len(requested_ids):
        raise NotFoundError()

    by_id = {notification.pk: notification for notification in locked_rows}
    selected = tuple(by_id[item.notification_id] for item in command.items)
    for item, notification in zip(command.items, selected):
        if notification.status != item.expected_status:
            raise LifecycleConflictError()

    archived_at = timezone.now()
    for notification in selected:
        notification.status = "archived"
        notification.archived_at = archived_at
        notification.save(update_fields=["status", "archived_at"])
        audit_log(
            action_type="NOTIFICATION_ARCHIVED",
            event_category="NOTIFICATION",
            target_model="notifications.Notification",
            target_object_id=notification.id,
            actor_user=actor,
            source_app="notifications",
        )
    return selected


@transaction.atomic
def update_notification_preference(*, actor, command: NotificationPreferenceUpdateCommand) -> NotificationPreference:
    """Create or replace one actor-owned, catalog-approved preference."""
    if not isinstance(command, NotificationPreferenceUpdateCommand):
        raise ValidationError("Notification preferences require a typed command.")
    if not is_active_nonlegacy_actor(actor):
        raise PermissionDeniedError()
    notification_type = command.notification_type.strip()
    try:
        definition = get_notification_definition(notification_type)
    except (KeyError, ValueError) as exc:
        raise ValidationError(field_errors={"notification_type": ["Unsupported notification type."]}) from exc
    if definition.get("preference_policy") == "mandatory_security" and (
        not command.in_app_enabled or not command.email_enabled
    ):
        field_errors = {}
        if not command.in_app_enabled:
            field_errors["in_app_enabled"] = ["This notification is mandatory."]
        if not command.email_enabled:
            field_errors["email_enabled"] = ["This notification is mandatory."]
        raise ValidationError("Mandatory security notifications cannot be disabled.", field_errors=field_errors)
    preference, created = NotificationPreference.objects.select_for_update().get_or_create(
        user_id=actor.pk,
        notification_type=notification_type,
        defaults={
            "in_app_enabled": command.in_app_enabled,
            "email_enabled": command.email_enabled,
        },
    )
    if not created:
        preference.in_app_enabled = command.in_app_enabled
        preference.email_enabled = command.email_enabled
        preference.save(update_fields=["in_app_enabled", "email_enabled", "updated_at"])
    audit_log(
        action_type="NOTIFICATION_PREFERENCE_UPDATED",
        event_category="NOTIFICATION",
        target_model="notifications.NotificationPreference",
        target_object_id=preference.id,
        actor_user=actor,
        source_app="notifications",
        metadata={"notification_type": notification_type},
    )
    return preference


# --------------------------------------------------------------------------
# Email Delivery Services
# --------------------------------------------------------------------------
def build_email_delivery_key(
    recipient_user=None,
    template_key: str = "",
    context: dict | None = None,
    recipient_email: str = "",
    notification: Notification = None,
    related_object=None,
    purpose: str = "",
) -> str:
    """Builds a deterministic non-sensitive delivery key from stable inputs."""
    recipient_id = str(recipient_user.pk) if recipient_user is not None else "external"
    normalized_email = (recipient_email or getattr(recipient_user, "email", "") or "").strip().lower()
    recipient_email_hash = hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        normalized_email.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    related_type = related_object.__class__.__name__ if related_object else ""
    related_id = str(related_object.pk) if related_object else ""
    notification_id = str(notification.pk) if notification else ""
    seed = {
        "template_key": template_key,
        "recipient_id": recipient_id,
        "recipient_email_hash": recipient_email_hash,
        "notification_id": notification_id,
        "related_object_type": related_type,
        "related_object_id": related_id,
        "purpose": purpose,
        "context_hash": hashlib.sha256(
            json.dumps(context or {}, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }
    return hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        json.dumps(seed, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


@transaction.atomic
def enqueue_email_from_template(
    recipient_user=None,
    template_key: str = "",
    context: dict | None = None,
    recipient_email: str = "",
    subject: str = None,
    notification: Notification = None,
    related_object=None,
    delivery_key: str = None,
    purpose: str = "",
    preference_type: str = "",
    respect_preferences: bool = True,
) -> EmailDelivery | None:
    """
    Transactionally registers an email delivery task.
    Validates template existence, context schema requirements, and safety allowlist.
    """
    from apps.notifications.cache import get_cached_notification_template

    tmpl = get_cached_notification_template(template_key)
    if tmpl is None:
        raise ValueError(f"Active notification template '{template_key}' does not exist")

    if recipient_user is None and not (recipient_email or "").strip():
        raise ValueError("An email recipient is required.")
    if recipient_user is not None and not (recipient_email or "").strip():
        recipient_email = recipient_user.email
    recipient_email = (recipient_email or "").strip()

    if tmpl["preference_policy"] == "mandatory_security":
        respect_preferences = False
    preference_key = preference_type or template_key
    if recipient_user is not None and respect_preferences and not is_email_enabled(recipient_user, preference_key):
        audit_log(
            action_type="EMAIL_PREFERENCE_SUPPRESSED",
            event_category="NOTIFICATION",
            target_model="accounts.User",
            target_object_id=recipient_user.id,
            source_app="notifications",
            metadata={
                "template_key": template_key,
                "notification_type": preference_key,
            }
        )
        return None

    # Context schema and safety validation
    from apps.notifications.templates import validate_context_schema
    safe_context = validate_context_schema(tmpl["required_context_schema"], context or {})

    from apps.workflow.services import validate_outbox_payload
    validate_outbox_payload(template_key, safe_context)

    delivery_key = delivery_key or build_email_delivery_key(
        recipient_user=recipient_user,
        template_key=template_key,
        context=safe_context,
        recipient_email=recipient_email,
        notification=notification,
        related_object=related_object,
        purpose=purpose,
    )

    email_subject = subject or tmpl["subject_template"]
    if "{" in email_subject or "[" in email_subject or "%" in email_subject:
        from django.template import Template, Context
        t = Template(email_subject)
        email_subject = t.render(Context(safe_context))

    now = timezone.now()
    defaults = {
        "recipient_user": recipient_user,
        "recipient_email": recipient_email,
        "notification": notification,
        "template_key": template_key,
        "subject": email_subject,
        "context_json": safe_context,
        "status": "pending",
        "delivery_state": "queued",
        "next_retry_at": now,
        "related_object_type": related_object.__class__.__name__ if related_object else None,
        "related_object_id": str(related_object.pk) if related_object else None,
    }
    try:
        delivery, created = EmailDelivery.objects.get_or_create(
            delivery_key=delivery_key,
            defaults=defaults,
        )
    except IntegrityError:
        delivery = EmailDelivery.objects.select_for_update().get(delivery_key=delivery_key)
        created = False

    if not created:
        if delivery.template_key != template_key or delivery.recipient_email != recipient_email:
            raise ValueError("Email delivery key already exists for a different delivery")
        return delivery

    audit_log(
        action_type="EMAIL_QUEUED",
        event_category="NOTIFICATION",
        target_model="notifications.EmailDelivery",
        target_object_id=delivery.id,
        source_app="notifications",
        metadata={
            "template_key": template_key,
            "recipient_id": str(recipient_user.id) if recipient_user is not None else "external",
        }
    )
    return delivery


def send_email_delivery(delivery: EmailDelivery, adapter=None) -> None:
    """Renders the email body from template and context and transmits it via adapter."""
    if delivery.status == "sent":
        return
    if delivery.status in {"dead", "cancelled"}:
        raise ValueError("Dead or cancelled email deliveries cannot be sent")

    if not adapter:
        adapter = DjangoEmailAdapter()

    from apps.notifications.templates import render_email_message
    runtime_context = {}
    if delivery.template_key == "account_recovery":
        from apps.account_security.models import AccountRecoveryRequest
        from apps.account_security.tokens import build_recovery_token, hash_identifier
        from apps.account_security.services import build_recovery_reset_url
        try:
            recovery_request = AccountRecoveryRequest.objects.select_related("user").get(
                pk=delivery.context_json["recovery_request_id"]
            )
        except AccountRecoveryRequest.DoesNotExist:
            recovery_request = None
        now = timezone.now()
        if (
            recovery_request is None
            or recovery_request.status != "pending"
            or recovery_request.expires_at <= now
            or not recovery_request.user
            or not recovery_request.user.is_active
            or hash_identifier((recovery_request.user.email or "").strip().lower())
            != recovery_request.delivery_email_hash
        ):
            # A request can be revoked or become stale after the outbox event
            # was handled.  Never transmit a link that can no longer be used.
            delivery.status = "cancelled"
            delivery.delivery_state = "cancelled"
            delivery.locked_by = None
            delivery.locked_at = None
            delivery.save(update_fields=["status", "delivery_state", "locked_by", "locked_at"])
            audit_log(
                action_type="EMAIL_CANCELLED",
                event_category="NOTIFICATION",
                target_model="notifications.EmailDelivery",
                target_object_id=delivery.id,
                source_app="notifications",
                metadata={"template_key": delivery.template_key, "reason": "recovery_request_not_pending"},
            )
            return
        raw_token = build_recovery_token(recovery_request.id)
        runtime_context.update({
            "action_url": build_recovery_reset_url(raw_token),
            "expires_text": recovery_request.expires_at.strftime("%Y-%m-%d %H:%M UTC"),
        })
    elif delivery.template_key == "student_activation":
        from apps.student_activation.models import StudentActivationInvitation
        from apps.account_security.activation import (
            ActivationPurpose,
            activation_profile,
            activation_url_for_token,
            issue_activation_token,
        )
        from apps.account_security.tokens import hash_identifier

        reference = str(delivery.context_json.get("invitation_id") or "")
        try:
            invitation = StudentActivationInvitation.objects.select_related("user").get(
                token_reference=reference,
            )
        except StudentActivationInvitation.DoesNotExist:
            invitation = None
        now = timezone.now()
        valid = bool(
            invitation
            and invitation.token_version == activation_profile(ActivationPurpose.STUDENT).version
            and invitation.used_at is None
            and invitation.revoked_at is None
            and invitation.expires_at > now
            and invitation.user
            and not invitation.user.is_active
            and invitation.user.role == "STUDENT"
            and invitation.delivery_email_hash == hash_identifier(
                (invitation.user.email or "").strip().lower()
            )
            and invitation.user_id == delivery.recipient_user_id
        )
        if not valid:
            delivery.status = "cancelled"
            delivery.delivery_state = "cancelled"
            delivery.locked_by = None
            delivery.locked_at = None
            delivery.save(update_fields=["status", "delivery_state", "locked_by", "locked_at"])
            audit_log(
                action_type="EMAIL_CANCELLED",
                event_category="NOTIFICATION",
                target_model="notifications.EmailDelivery",
                target_object_id=delivery.id,
                source_app="notifications",
                metadata={"template_key": delivery.template_key, "reason": "activation_not_sendable"},
            )
            return
        raw_token = issue_activation_token(invitation, ActivationPurpose.STUDENT)
        runtime_context.update({
            "action_url": activation_url_for_token(raw_token, ActivationPurpose.STUDENT),
            "expires_text": invitation.expires_at.strftime("%Y-%m-%d %H:%M UTC"),
        })
    elif delivery.template_key == "staff_activation":
        from apps.accounts.models import StaffAccountInvitation
        from apps.account_security.activation import (
            ActivationPurpose,
            activation_url_for_token,
            issue_activation_token,
        )
        reference = str(delivery.context_json.get("invitation_id") or "")
        invitation = StaffAccountInvitation.objects.select_related("user").filter(
            token_reference=reference,
        ).first()
        valid = bool(
            invitation and invitation.used_at is None and invitation.revoked_at is None
            and invitation.expires_at > timezone.now() and invitation.user
            and not invitation.user.is_active and not invitation.user.is_superuser
            and invitation.user.role == invitation.role_snapshot
            and invitation.user_id == delivery.recipient_user_id
        )
        if not valid:
            delivery.status = "cancelled"
            delivery.delivery_state = "cancelled"
            delivery.locked_by = None
            delivery.locked_at = None
            delivery.save(update_fields=["status", "delivery_state", "locked_by", "locked_at"])
            return
        raw_token = issue_activation_token(invitation, ActivationPurpose.STAFF)
        runtime_context.update({
            "action_url": activation_url_for_token(raw_token, ActivationPurpose.STAFF),
            "expires_text": invitation.expires_at.strftime("%Y-%m-%d %H:%M UTC"),
        })
    elif delivery.template_key == "contact_reply":
        # The outbox and EmailDelivery context carry only a reply UUID.  The
        # authenticated body is reconstructed for this single send attempt.
        from apps.content.models import ContactReply, ContactReplyStatus

        reply_id = str(delivery.context_json.get("reply_id") or "")
        reply = (
            ContactReply.objects.select_related("submission")
            .defer("submission__message_body_encrypted")
            .filter(pk=reply_id)
            .first()
        )
        valid = bool(
            reply
            and reply.status in {ContactReplyStatus.APPROVED, ContactReplyStatus.QUEUED}
            and reply.submission.email
            and reply.submission.email == delivery.recipient_email
        )
        if not valid:
            delivery.status = "cancelled"
            delivery.delivery_state = "cancelled"
            delivery.locked_by = None
            delivery.locked_at = None
            delivery.save(update_fields=["status", "delivery_state", "locked_by", "locked_at"])
            sync_contact_reply_delivery_state(delivery)
            return
        runtime_context["reply_body"] = reply.get_body_for_send()
    text_content, html_content = render_email_message(
        delivery.template_key,
        delivery.context_json,
        runtime_context=runtime_context,
    )

    from_email = getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@compass.edu.ph")
    reply_to = getattr(settings, "COMPASS_EMAIL_REPLY_TO", None)
    if reply_to and isinstance(reply_to, str):
        reply_to = [reply_to]

    msg_id = adapter.send_email(
        recipient_email=delivery.recipient_email,
        subject=delivery.subject,
        text_content=text_content,
        html_content=html_content,
        from_email=from_email,
        reply_to=reply_to
    )

    delivery.status = "sent"
    delivery.delivery_state = "sent"
    delivery.sent_at = timezone.now()
    delivery.provider_message_id = msg_id
    delivery.locked_by = None
    delivery.locked_at = None
    delivery.save(update_fields=["status", "delivery_state", "sent_at", "provider_message_id", "locked_by", "locked_at"])

    if delivery.template_key == "contact_reply":
        from apps.content.models import ContactReply, ContactReplyStatus
        ContactReply.objects.filter(pk=delivery.context_json.get("reply_id")).update(
            status=ContactReplyStatus.SENT,
            sent_at=delivery.sent_at,
            delivery_state=delivery.delivery_state,
        )
        sync_contact_reply_delivery_state(delivery)

    audit_log(
        action_type="EMAIL_SENT",
        event_category="NOTIFICATION",
        target_model="notifications.EmailDelivery",
        target_object_id=delivery.id,
        source_app="notifications",
        metadata={
            "template_key": delivery.template_key,
            "provider_message_id": msg_id
        }
    )


def sync_contact_reply_delivery_state(delivery: EmailDelivery) -> None:
    """Generic delivery hook; updates only safe state/evidence fields."""
    if delivery.related_object_type != "ContactReply" and delivery.template_key != "contact_reply":
        return
    from apps.content.models import ContactReply, ContactReplyStatus, PublicContactSubmission, SubmissionStatus

    reply = ContactReply.objects.only("id", "submission_id").filter(
        pk=delivery.related_object_id or delivery.context_json.get("reply_id")
    ).first()
    if not reply:
        return
    status_map = {
        "queued": ContactReplyStatus.QUEUED,
        "sending": ContactReplyStatus.QUEUED,
        "sent": ContactReplyStatus.SENT,
        "delayed": ContactReplyStatus.DELIVERY_FAILED,
        "failed": ContactReplyStatus.DELIVERY_FAILED,
        "retry_exhausted": ContactReplyStatus.DELIVERY_FAILED,
        "bounced": ContactReplyStatus.DELIVERY_FAILED,
        "cancelled": ContactReplyStatus.CANCELLED,
    }
    new_status = status_map.get(delivery.delivery_state)
    if not new_status:
        return
    from apps.content.models import ContactEvidenceScope
    configured_scope = getattr(settings, "COMPASS_EMAIL_EVIDENCE_SCOPE", ContactEvidenceScope.LOCAL_BACKEND)
    if configured_scope not in ContactEvidenceScope.values:
        configured_scope = ContactEvidenceScope.UNKNOWN
    fields = {
        "status": new_status,
        "delivery_state": delivery.delivery_state,
        "evidence_scope": configured_scope,
        "evidence_recorded_at": timezone.now(),
    }
    if new_status == ContactReplyStatus.SENT:
        fields["sent_at"] = delivery.sent_at
    if delivery.last_error_code:
        fields["last_failure_code"] = delivery.last_error_code
    ContactReply.objects.filter(pk=reply.pk).update(**fields)
    if new_status == ContactReplyStatus.SENT:
        PublicContactSubmission.objects.filter(pk=reply.submission_id).exclude(
            status=SubmissionStatus.NO_RESPONSE_REQUIRED
        ).update(status=SubmissionStatus.RESPONDED, privacy_actioned_at=timezone.now())
    elif new_status == ContactReplyStatus.DELIVERY_FAILED:
        # A later provider delay/bounce invalidates an otherwise unsupported
        # Responded claim.  Keep the record unresolved until a retry is
        # accepted again; no response evidence is invented from a send
        # attempt alone.
        PublicContactSubmission.objects.filter(
            pk=reply.submission_id,
            status=SubmissionStatus.RESPONDED,
        ).update(status=SubmissionStatus.RESPONSE_EVIDENCE_MISSING, privacy_actioned_at=timezone.now())


@transaction.atomic
def retry_email_delivery(*, actor, delivery_id, command: EmailDeliveryRetryCommand) -> EmailDelivery:
    """Queue one eligible delivery for retry through the IT boundary."""
    if not isinstance(command, EmailDeliveryRetryCommand):
        raise ValidationError("Delivery retry requires a typed command.")
    if not is_active_nonlegacy_actor(actor):
        raise PermissionDeniedError()
    from apps.notifications.policies import can_view_email_delivery
    if not can_view_email_delivery(actor):
        raise PermissionDeniedError()
    delivery = EmailDelivery.objects.select_for_update().filter(pk=delivery_id).first()
    if delivery is None:
        raise NotFoundError()
    allowed_statuses = {"failed"}
    if command.allow_dead:
        allowed_statuses.add("dead")
    if delivery.status not in allowed_statuses or delivery.delivery_state == "bounced":
        raise LifecycleConflictError()

    now = timezone.now()
    delivery.status = "pending"
    delivery.delivery_state = "queued"
    delivery.attempts = 0
    delivery.next_retry_at = now
    delivery.locked_by = None
    delivery.locked_at = None
    delivery.last_error_code = None
    delivery.last_error_safe_summary = None
    delivery.save(update_fields=[
        "status", "delivery_state", "attempts", "next_retry_at", "locked_by", "locked_at",
        "last_error_code", "last_error_safe_summary",
    ])
    sync_contact_reply_delivery_state(delivery)
    audit_log(
        action_type="EMAIL_MANUAL_RETRY",
        event_category="NOTIFICATION",
        target_model="notifications.EmailDelivery",
        target_object_id=delivery.id,
        actor_user=actor,
        source_app="notifications",
        metadata={"template_key": delivery.template_key}
    )
    return delivery


@transaction.atomic
def mark_email_delivery_dead(*, actor, delivery_id, command: EmailDeliveryDeadLetterCommand) -> EmailDelivery:
    """Dead-letter one delivery with a bounded operational reason."""
    if not isinstance(command, EmailDeliveryDeadLetterCommand):
        raise ValidationError("Dead-lettering requires a typed command.")
    if not is_active_nonlegacy_actor(actor):
        raise PermissionDeniedError()
    from apps.notifications.policies import can_view_email_delivery
    if not can_view_email_delivery(actor):
        raise PermissionDeniedError()
    delivery = EmailDelivery.objects.select_for_update().filter(pk=delivery_id).first()
    if delivery is None:
        raise NotFoundError()
    if delivery.status in {"sent", "cancelled"}:
        raise LifecycleConflictError()
    safe_summaries = {
        DeadLetterReason.PROVIDER_PERMANENT_FAILURE: "Permanent provider failure recorded.",
        DeadLetterReason.RECIPIENT_INVALID: "Recipient address was rejected.",
        DeadLetterReason.MANUAL_OPERATIONAL_REVIEW: "Delivery moved to operational review.",
    }
    delivery.status = "dead"
    delivery.delivery_state = "retry_exhausted"
    delivery.last_error_code = "MANUAL_DEAD_LETTER"
    delivery.last_error_safe_summary = safe_summaries[command.reason]
    delivery.locked_by = None
    delivery.locked_at = None
    delivery.save(update_fields=[
        "status", "delivery_state", "last_error_code", "last_error_safe_summary",
        "locked_by", "locked_at",
    ])
    sync_contact_reply_delivery_state(delivery)
    audit_log(
        action_type="EMAIL_MANUAL_DEAD_LETTER",
        event_category="NOTIFICATION",
        target_model="notifications.EmailDelivery",
        target_object_id=delivery.id,
        actor_user=actor,
        severity="WARNING",
        source_app="notifications",
        metadata={"template_key": delivery.template_key, "reason_code": command.reason.value}
    )
    return delivery


@transaction.atomic
def cancel_email_delivery(*, delivery_id, command: EmailDeliveryCancelCommand, actor=None) -> EmailDelivery | None:
    """Cancel one pending delivery for its owning workflow.

    This is an internal composition primitive, not a public delivery-control
    route. The caller supplies only a stable delivery ID and a bounded reason.
    """
    if not isinstance(command, EmailDeliveryCancelCommand):
        raise ValidationError("Delivery cancellation requires a typed command.")
    delivery = EmailDelivery.objects.select_for_update().filter(pk=delivery_id).first()
    if delivery is None:
        return None
    if delivery.status not in {"sent", "cancelled"}:
        delivery.status = "cancelled"
        delivery.delivery_state = "cancelled"
        delivery.locked_by = None
        delivery.locked_at = None
        delivery.save(update_fields=["status", "delivery_state", "locked_by", "locked_at"])
        sync_contact_reply_delivery_state(delivery)
        audit_log(
            action_type="EMAIL_CANCELLED",
            event_category="NOTIFICATION",
            target_model="notifications.EmailDelivery",
            target_object_id=delivery.id,
            actor_user=actor,
            source_app="notifications",
            metadata={"template_key": delivery.template_key, "reason_code": command.reason},
        )
    return delivery


@transaction.atomic
def cancel_pending_email_deliveries(*, template_key: str, related_object_ids, reason: str = "workflow_cancelled") -> int:
    """Cancel unsent deliveries for stable workflow references."""
    if not isinstance(template_key, str) or not template_key or len(template_key) > 100:
        raise ValidationError("A bounded delivery template key is required.")
    values = tuple(str(value) for value in (related_object_ids or ()) if value is not None)
    if not values:
        return 0
    command = EmailDeliveryCancelCommand(reason=reason)
    queryset = EmailDelivery.objects.select_for_update().filter(
        template_key=template_key,
        related_object_id__in=values,
    ).exclude(delivery_state__in={"sent", "cancelled"})
    count = queryset.update(
        status="cancelled",
        delivery_state="cancelled",
        locked_by=None,
        locked_at=None,
    )
    if count:
        audit_log(
            action_type="EMAIL_DELIVERIES_CANCELLED",
            event_category="NOTIFICATION",
            target_model="notifications.EmailDelivery",
            target_object_id="",
            source_app="notifications",
            metadata={"template_key": template_key, "count": count, "reason_code": command.reason},
        )
    return count


@transaction.atomic
def sync_contact_reply_delivery_state_by_id(delivery_id):
    """Resolve and synchronize contact-reply evidence by stable delivery ID."""
    delivery = EmailDelivery.objects.select_for_update().filter(pk=delivery_id).first()
    if delivery is None:
        raise NotFoundError()
    return sync_contact_reply_delivery_state(delivery)


@transaction.atomic
def claim_email_deliveries(worker_id: str, batch_size: int = 20, lock_timeout_seconds: int = 300) -> list[EmailDelivery]:
    """Claims a lock on pending or retryable email deliveries."""
    now = timezone.now()
    lock_cutoff = now - timedelta(seconds=lock_timeout_seconds)

    db_engine = settings.DATABASES["default"]["ENGINE"]
    is_sqlite = "sqlite" in db_engine

    if is_sqlite:
        qs = EmailDelivery.objects.select_for_update().filter(
            models.Q(status__in=["pending", "failed"], next_retry_at__lte=now) |
            models.Q(status="processing", locked_at__lte=lock_cutoff)
        ).order_by("created_at")[:batch_size]
    else:
        qs = EmailDelivery.objects.select_for_update(skip_locked=True).filter(
            models.Q(status__in=["pending", "failed"], next_retry_at__lte=now) |
            models.Q(status="processing", locked_at__lte=lock_cutoff)
        ).order_by("created_at")[:batch_size]

    claimed = []
    for delivery in qs:
        delivery.status = "processing"
        delivery.delivery_state = "sending"
        delivery.locked_by = worker_id
        delivery.locked_at = now
        delivery.save(update_fields=["status", "delivery_state", "locked_by", "locked_at"])
        claimed.append(delivery)

    return claimed


def process_email_delivery_batch(worker_id: str, batch_size: int = 20, lock_timeout_seconds: int = 300) -> int:
    """Processes a batch of claimed email deliveries with automatic retries and backoff."""
    claimed = claim_email_deliveries(worker_id, batch_size, lock_timeout_seconds)
    processed_count = 0
    adapter = DjangoEmailAdapter()

    for delivery in claimed:
        try:
            send_email_delivery(delivery, adapter)
            processed_count += 1
        except EmailDeliveryError as ede:
            delivery.attempts += 1
            if ede.is_retryable and delivery.attempts < delivery.max_attempts:
                backoff = min(15 * (2 ** delivery.attempts), 3600)
                delivery.status = "failed"
                delivery.delivery_state = "delayed"
                delivery.next_retry_at = timezone.now() + timedelta(seconds=backoff)
                delivery.last_error_code = ede.error_code
                delivery.last_error_safe_summary = "Temporary provider failure; retry scheduled."
                delivery.locked_by = None
                delivery.locked_at = None
                delivery.save(update_fields=["status", "delivery_state", "attempts", "next_retry_at", "last_error_code", "last_error_safe_summary", "locked_by", "locked_at"])

                audit_log(
                    action_type="EMAIL_RETRY_SCHEDULED",
                    event_category="NOTIFICATION",
                    target_model="notifications.EmailDelivery",
                    target_object_id=delivery.id,
                    source_app="notifications",
                    metadata={
                        "template_key": delivery.template_key,
                        "attempt": delivery.attempts,
                        "next_retry_at": delivery.next_retry_at.isoformat()
                    }
                )
            else:
                delivery.status = "dead"
                delivery.delivery_state = "failed" if not ede.is_retryable else "retry_exhausted"
                delivery.last_error_code = ede.error_code
                delivery.last_error_safe_summary = "Permanent provider failure." if not ede.is_retryable else "Retry limit reached."
                delivery.locked_by = None
                delivery.locked_at = None
                delivery.save(update_fields=["status", "delivery_state", "attempts", "last_error_code", "last_error_safe_summary", "locked_by", "locked_at"])

                audit_log(
                    action_type="EMAIL_DEAD_LETTERED",
                    event_category="NOTIFICATION",
                    target_model="notifications.EmailDelivery",
                    target_object_id=delivery.id,
                    severity="WARNING",
                    source_app="notifications",
                    metadata={
                        "template_key": delivery.template_key,
                        "attempts": delivery.attempts,
                        "error_code": ede.error_code,
                    }
                )
        except Exception as e:
            delivery.attempts += 1
            error_msg = "Unexpected notification processing failure."
            if delivery.attempts < delivery.max_attempts:
                backoff = min(15 * (2 ** delivery.attempts), 3600)
                delivery.status = "failed"
                delivery.delivery_state = "delayed"
                delivery.next_retry_at = timezone.now() + timedelta(seconds=backoff)
                delivery.last_error_code = "UNKNOWN_ERROR"
                delivery.last_error_safe_summary = error_msg
                delivery.locked_by = None
                delivery.locked_at = None
                delivery.save(update_fields=["status", "delivery_state", "attempts", "next_retry_at", "last_error_code", "last_error_safe_summary", "locked_by", "locked_at"])
            else:
                delivery.status = "dead"
                delivery.delivery_state = "retry_exhausted"
                delivery.last_error_code = "UNKNOWN_ERROR"
                delivery.last_error_safe_summary = error_msg
                delivery.locked_by = None
                delivery.locked_at = None
                delivery.save(update_fields=["status", "delivery_state", "attempts", "last_error_code", "last_error_safe_summary", "locked_by", "locked_at"])

                audit_log(
                    action_type="EMAIL_DEAD_LETTERED",
                    event_category="NOTIFICATION",
                    target_model="notifications.EmailDelivery",
                    target_object_id=delivery.id,
                    severity="WARNING",
                    source_app="notifications",
                    metadata={
                        "template_key": delivery.template_key,
                        "error_code": "UNKNOWN_ERROR",
                    }
                )
        finally:
            sync_contact_reply_delivery_state(delivery)
    return processed_count


@transaction.atomic
def record_provider_feedback(*, provider_message_id=None, feedback_key=None, state="delayed") -> int:
    """Apply deduplicated provider-neutral delayed/bounce feedback."""
    if state not in {"delayed", "bounced"}:
        raise ValueError("Unsupported provider feedback state")
    marker = str(feedback_key or provider_message_id or "").strip()
    if not marker:
        return 0
    marker_hash = hmac.new(settings.SECRET_KEY.encode("utf-8"), marker.encode("utf-8"), hashlib.sha256).hexdigest()
    qs = EmailDelivery.objects.filter(provider_feedback_hash=marker_hash)
    if qs.exists():
        return 0
    if provider_message_id:
        deliveries = EmailDelivery.objects.filter(provider_message_id=provider_message_id)
    elif feedback_key:
        deliveries = EmailDelivery.objects.filter(delivery_key=feedback_key)
    else:
        deliveries = EmailDelivery.objects.none()
    count = 0
    now = timezone.now()
    for delivery in deliveries.select_for_update():
        delivery.delivery_state = state
        delivery.provider_feedback_hash = marker_hash
        delivery.provider_status_updated_at = now
        delivery.status = "failed" if state in {"delayed", "bounced"} else "sent"
        delivery.save(update_fields=["delivery_state", "provider_feedback_hash", "provider_status_updated_at", "status"])
        sync_contact_reply_delivery_state(delivery)
        count += 1
    return count


def send_transactional_email(
    *, recipient_email: str, template_key: str, context: dict, subject: str = None,
    runtime_context: dict = None, adapter=None,
) -> str:
    """Immediate security/activation send using the same multipart shell."""
    from apps.notifications.templates import render_email_message
    if adapter is None:
        adapter = DjangoEmailAdapter()
    text_content, html_content = render_email_message(
        template_key, context, runtime_context=runtime_context
    )
    from_email = getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@compass.edu.ph")
    reply_to = getattr(settings, "COMPASS_EMAIL_REPLY_TO", None)
    if reply_to and isinstance(reply_to, str):
        reply_to = [reply_to]
    return adapter.send_email(
        recipient_email=recipient_email,
        subject=subject or template_key,
        text_content=text_content,
        html_content=html_content,
        from_email=from_email,
        reply_to=reply_to,
    )
