import uuid
from django.db import models
from django.conf import settings


class IdempotencyKey(models.Model):
    """
    Tracks idempotency keys to prevent duplicate actions on critical workflows.
    Never stores raw keys or sensitive request/response payloads.
    """
    STATUS_CHOICES = [
        ("processing", "Processing"),
        ("succeeded", "Succeeded"),
        ("failed", "Failed"),
        ("expired", "Expired"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    key_hash = models.CharField(max_length=64, db_index=True)
    context_hash = models.CharField(
        max_length=64,
        db_index=True,
        help_text="Deterministic non-sensitive hash of actor/session context."
    )
    actor_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="idempotency_keys",
        help_text="The authenticated user who initiated the action."
    )
    session_key_hash = models.CharField(
        max_length=64,
        null=True,
        blank=True,
        db_index=True,
        help_text="Hashed session key for anonymous actions."
    )
    action_scope = models.CharField(
        max_length=100,
        help_text="Identifies the workflow/action scope, e.g. good_moral.submit"
    )
    request_fingerprint = models.CharField(
        max_length=64,
        db_index=True,
        help_text="Deterministic hash of non-volatile request parameters."
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="processing",
        db_index=True
    )
    related_object_type = models.CharField(
        max_length=100,
        null=True,
        blank=True,
        help_text="Type of the object created/modified by this action."
    )
    related_object_id = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        help_text="ID of the object created/modified by this action."
    )
    safe_response_path = models.TextField(
        null=True,
        blank=True,
        help_text="A safe URL or redirect path representing the completed result."
    )
    error_code = models.CharField(
        max_length=100,
        null=True,
        blank=True,
        help_text="Safe error code if the action failed."
    )
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(db_index=True)
    last_seen_at = models.DateTimeField(auto_now=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    metadata_json = models.JSONField(
        default=dict,
        blank=True,
        help_text="Safe, allowlisted audit metadata only."
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["context_hash", "action_scope", "key_hash"],
                name="uniq_idempotency_context_scope_key"
            )
        ]
        indexes = [
            models.Index(fields=["created_at"]),
            models.Index(fields=["expires_at", "status"]),
        ]

    def __str__(self):
        actor = self.actor_user.email if self.actor_user else "Session"
        return f"{self.action_scope} [{self.status}] by {actor}"


class OutboxEvent(models.Model):
    """
    Transactional outbox for reliable event dispatch and retryable background tasks.
    """
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("processing", "Processing"),
        ("sent", "Sent"),
        ("failed", "Failed"),
        ("dead", "Dead"),
        ("cancelled", "Cancelled"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    event_key = models.CharField(
        max_length=255,
        unique=True,
        help_text="Unique, deterministic key to prevent duplicate enqueuing."
    )
    event_type = models.CharField(
        max_length=100,
        db_index=True,
        help_text="Stable event identifier, e.g. good_moral.request_created"
    )
    payload_json = models.JSONField(
        default=dict,
        help_text="Privacy-safe, allowlisted payload metadata only."
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="pending",
        db_index=True
    )
    attempts = models.IntegerField(default=0)
    max_attempts = models.IntegerField(default=5)
    next_retry_at = models.DateTimeField(db_index=True)
    locked_by = models.CharField(max_length=255, null=True, blank=True)
    locked_at = models.DateTimeField(null=True, blank=True)
    related_object_type = models.CharField(max_length=100, null=True, blank=True)
    related_object_id = models.CharField(max_length=255, null=True, blank=True)
    idempotency_key = models.ForeignKey(
        IdempotencyKey,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="outbox_events"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    available_at = models.DateTimeField(db_index=True)
    processed_at = models.DateTimeField(null=True, blank=True)
    last_error_code = models.CharField(max_length=100, null=True, blank=True)
    last_error_safe_summary = models.TextField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["status", "available_at"]),
            models.Index(fields=["created_at"]),
        ]

    def __str__(self):
        return f"{self.event_type} [{self.status}] (attempts: {self.attempts})"
