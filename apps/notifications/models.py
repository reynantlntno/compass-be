import uuid
from django.db import models
from django.conf import settings


class Notification(models.Model):
    """
    User-facing in-app notification records.
    Never stores sensitive details or personal narrative content.
    """
    STATUS_CHOICES = [
        ("unread", "Unread"),
        ("read", "Read"),
        ("archived", "Archived"),
    ]

    PRIORITY_CHOICES = [
        ("normal", "Normal"),
        ("high", "High"),
        ("urgent", "Urgent"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    dedupe_key = models.CharField(
        max_length=64,
        unique=True,
        null=True,
        blank=True,
        db_index=True,
        help_text="Deterministic non-sensitive key for one event/recipient notification.",
    )
    recipient_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="notifications"
    )
    recipient_role_snapshot = models.CharField(
        max_length=50,
        blank=True,
        help_text="Role of the recipient at time of notification."
    )
    notification_type = models.CharField(
        max_length=100,
        help_text="Identifies the event type of the notification."
    )
    title = models.CharField(max_length=255)
    body_preview = models.CharField(
        max_length=500,
        help_text="Safe preview string. Must NOT contain sensitive details."
    )
    related_object_type = models.CharField(max_length=100, null=True, blank=True)
    related_object_id = models.CharField(max_length=255, null=True, blank=True)
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="unread",
        db_index=True
    )
    priority = models.CharField(
        max_length=20,
        choices=PRIORITY_CHOICES,
        default="normal"
    )
    channel_intent = models.CharField(
        max_length=50,
        default="in_app",
        help_text="Intended delivery channels, e.g. in_app, email, both"
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    read_at = models.DateTimeField(null=True, blank=True)
    archived_at = models.DateTimeField(null=True, blank=True)
    metadata_json = models.JSONField(
        default=dict,
        blank=True,
        help_text="Safe, allowlisted metadata only."
    )

    class Meta:
        indexes = [
            models.Index(fields=["recipient_user", "status", "created_at"]),
        ]
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.title} -> {self.recipient_user.email} [{self.status}]"


class NotificationTemplate(models.Model):
    """
    Defines template paths and schemas for notifications/emails.
    """
    CHANNEL_CHOICES = [
        ("in_app", "In-App Only"),
        ("email", "Email Only"),
        ("both", "Both In-App and Email"),
    ]

    STATUS_CHOICES = [
        ("draft", "Draft"),
        ("active", "Active"),
        ("retired", "Retired"),
    ]

    stable_key = models.CharField(max_length=100, unique=True)
    display_name = models.CharField(max_length=255)
    channel = models.CharField(max_length=20, choices=CHANNEL_CHOICES, default="both")
    subject_template = models.CharField(
        max_length=255,
        help_text="Subject template path or generic text."
    )
    body_template = models.CharField(
        max_length=255,
        help_text="Body template path."
    )
    html_body_template = models.CharField(
        max_length=255,
        default="",
        blank=True,
        help_text="Responsive HTML body template path."
    )
    template_version = models.CharField(max_length=30, default="v1")
    preference_policy = models.CharField(
        max_length=30,
        default="user",
        choices=[("user", "User preference"), ("mandatory_security", "Mandatory security")],
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="active")
    required_context_schema_json = models.JSONField(
        default=dict,
        blank=True,
        help_text="JSON schema validating context keys."
    )
    sensitivity_classification = models.CharField(
        max_length=50,
        default="GENERAL",
        help_text="e.g. GENERAL, CONFIDENTIAL, RESTRICTED"
    )
    audit_category = models.CharField(max_length=100, default="NOTIFICATION")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.display_name} ({self.stable_key})"


class NotificationPreference(models.Model):
    """
    User settings to enable or disable specific notification types.
    """
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="notification_preferences"
    )
    notification_type = models.CharField(max_length=100)
    in_app_enabled = models.BooleanField(default=True)
    email_enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["user", "notification_type"],
                name="uniq_user_notification_type"
            )
        ]

    def __str__(self):
        return f"Prefs for {self.user.email} -> {self.notification_type}"


class EmailDelivery(models.Model):
    """
    Tracks outgoing email delivery state and attempts.
    Never stores rendered sensitive email bodies.
    """
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("processing", "Processing"),
        ("sent", "Sent"),
        ("failed", "Failed"),
        ("dead", "Dead"),
        ("cancelled", "Cancelled"),
    ]

    DELIVERY_STATE_CHOICES = [
        ("queued", "Queued"),
        ("sending", "Sending"),
        ("sent", "Sent (provider accepted)"),
        ("delayed", "Delayed"),
        ("failed", "Failed"),
        ("retry_exhausted", "Retry exhausted"),
        ("bounced", "Bounced"),
        ("cancelled", "Cancelled"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    delivery_key = models.CharField(
        max_length=64,
        unique=True,
        help_text="Deterministic non-sensitive key preventing duplicate delivery enqueue."
    )
    recipient_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="email_deliveries"
    )
    recipient_email = models.CharField(
        max_length=255,
        help_text="Target recipient email address."
    )
    notification = models.ForeignKey(
        Notification,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="email_deliveries"
    )
    template_key = models.CharField(max_length=100)
    subject = models.CharField(
        max_length=255,
        help_text="Safe, generic subject line."
    )
    context_json = models.JSONField(
        default=dict,
        help_text="Safe, privacyallowlisted context variables for rendering on send."
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="pending",
        db_index=True
    )
    delivery_state = models.CharField(
        max_length=30,
        choices=DELIVERY_STATE_CHOICES,
        default="queued",
        db_index=True,
    )
    attempts = models.IntegerField(default=0)
    max_attempts = models.IntegerField(default=3)
    next_retry_at = models.DateTimeField(db_index=True)
    provider_message_id = models.CharField(max_length=255, null=True, blank=True)
    last_error_code = models.CharField(max_length=100, null=True, blank=True)
    last_error_safe_summary = models.TextField(null=True, blank=True)
    related_object_type = models.CharField(max_length=100, null=True, blank=True)
    related_object_id = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    sent_at = models.DateTimeField(null=True, blank=True)
    locked_by = models.CharField(max_length=255, null=True, blank=True)
    locked_at = models.DateTimeField(null=True, blank=True)
    provider_feedback_hash = models.CharField(max_length=64, null=True, blank=True, db_index=True)
    provider_status_updated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["status", "next_retry_at"]),
            models.Index(fields=["created_at"]),
        ]

    def __str__(self):
        value = str(self.recipient_email or "")
        if "@" in value:
            local, domain = value.split("@", 1)
            value = f"{local[:1]}***@{domain[:2]}***"
        else:
            value = "Unavailable"
        return f"Email to {value} via {self.template_key} [{self.delivery_state}]"

    @property
    def normalized_status(self):
        return self.delivery_state
