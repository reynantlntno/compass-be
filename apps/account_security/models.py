import uuid
from django.db import models
from django.conf import settings
from django.utils import timezone
from apps.common.models import TimestampedModel


class AccountRecoveryRequest(TimestampedModel):
    """Model to track password reset / account recovery requests.

    SECURITY: Does not store raw emails, tokens, IPs, or full User-Agents.
    Identifiers are HMAC hashed using settings.ACCOUNT_SECURITY_HASH_SECRET.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="recovery_requests"
    )
    identifier_hash = models.CharField(max_length=64, db_index=True)
    delivery_email_hash = models.CharField(max_length=64, null=True, blank=True, db_index=True)
    token_hash = models.CharField(max_length=64, unique=True)
    token_version = models.CharField(max_length=30, default="recovery-v1")
    token_issued_at = models.DateTimeField(null=True, blank=True)
    request_source = models.CharField(
        max_length=30,
        default="self_service",
        choices=[
            ("self_service", "Self-service"),
            ("staff_assisted", "Staff-assisted"),
        ],
    )
    staff_actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assisted_recovery_requests",
    )
    status = models.CharField(
        max_length=20,
        default="pending",
        choices=[
            ("pending", "Pending"),
            ("used", "Used"),
            ("expired", "Expired"),
            ("revoked", "Revoked"),
            ("locked", "Locked")
        ]
    )
    request_ip_hash = models.CharField(max_length=64, null=True, blank=True)
    request_user_agent_hash = models.CharField(max_length=64, null=True, blank=True)
    failed_attempts = models.IntegerField(default=0)
    captcha_required = models.BooleanField(default=False)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    locked_at = models.DateTimeField(null=True, blank=True)
    metadata_json = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = "account recovery request"
        verbose_name_plural = "account recovery requests"
        indexes = [
            models.Index(fields=["status", "expires_at"]),
        ]

    def __str__(self):
        return f"Recovery Request {self.id} ({self.status})"


class VerifiedEmailEvidence(TimestampedModel):
    """Append-only provenance for the email currently used by an account.

    SECURITY: only an HMAC of the email is persisted.  The evidence becomes
    stale automatically when the account's email changes because selectors
    compare the stored hash with the current address.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="verified_email_evidence",
    )
    email_hash = models.CharField(max_length=64, db_index=True)
    status = models.CharField(
        max_length=20,
        default="verified",
        choices=[("verified", "Verified"), ("revoked", "Revoked")],
    )
    verification_method = models.CharField(
        max_length=40,
        choices=[
        ("activation_invitation", "Activation invitation"),
        ("staff_activation_invitation", "Staff activation invitation"),
            ("staff_out_of_band", "Staff out-of-band verification"),
        ],
    )
    verified_at = models.DateTimeField()
    verified_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="verified_email_evidence_actions",
    )
    source_model = models.CharField(max_length=100, blank=True)
    source_object_id = models.CharField(max_length=255, blank=True)
    reason_category = models.CharField(max_length=60, blank=True)
    metadata_json = models.JSONField(default=dict, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["user", "status", "email_hash"], name="account_sec_user_id_5a2a93_idx"),
            models.Index(fields=["status", "email_hash"], name="account_sec_status_77ab0f_idx"),
        ]

    def __str__(self):
        return f"Verified email evidence {self.id} for account {self.user_id}"

    def save(self, *args, **kwargs):
        if self.pk and VerifiedEmailEvidence.objects.filter(pk=self.pk).exists():
            raise ValueError("VerifiedEmailEvidence is append-only")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("VerifiedEmailEvidence is append-only")


class TwoStepChallenge(TimestampedModel):
    """Model to track email OTP challenges (login/recovery/sensitive action verification).

    SECURITY: Does not store raw OTPs. Stored OTP is hashed.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="twostep_challenges"
    )
    purpose = models.CharField(
        max_length=30,
        choices=[
            ("login", "Login"),
            ("recovery", "Recovery"),
            ("activation", "Activation"),
            ("sensitive_action", "Sensitive Action"),
            ("two_factor_change", "Two-factor change"),
        ]
    )
    otp_hash = models.CharField(max_length=64, db_index=True)
    status = models.CharField(
        max_length=20,
        default="pending",
        choices=[
            ("pending", "Pending"),
            ("verified", "Verified"),
            ("expired", "Expired"),
            ("failed", "Failed"),
            ("locked", "Locked"),
            ("revoked", "Revoked")
        ]
    )
    delivery_channel = models.CharField(max_length=20, default="email")
    delivery_email_hash = models.CharField(max_length=64, null=True, blank=True)
    failed_attempts = models.IntegerField(default=0)
    resend_count = models.IntegerField(default=0)
    last_sent_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()
    verified_at = models.DateTimeField(null=True, blank=True)
    security_stamp = models.UUIDField(default=uuid.uuid4, editable=False)
    assurance_policy_version = models.CharField(max_length=50, blank=True, default="")
    assurance_context = models.CharField(max_length=50, blank=True, default="")
    trusted_device_issued_at = models.DateTimeField(null=True, blank=True)
    request_ip_hash = models.CharField(max_length=64, null=True, blank=True)
    request_user_agent_hash = models.CharField(max_length=64, null=True, blank=True)
    metadata_json = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = "two-step challenge"
        verbose_name_plural = "two-step challenges"
        indexes = [
            models.Index(fields=["status", "expires_at"]),
        ]

    def __str__(self):
        return f"2FA Challenge {self.id} ({self.purpose})"


class TrustedDevice(TimestampedModel):
    """Model to track trusted/remembered user devices.

    Granted only after successful 2FA.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="trusted_devices"
    )
    device_hash = models.CharField(max_length=64, unique=True)
    label = models.CharField(max_length=255)
    status = models.CharField(
        max_length=20,
        default="active",
        choices=[
            ("active", "Active"),
            ("revoked", "Revoked"),
            ("expired", "Expired")
        ]
    )
    trusted_until = models.DateTimeField()
    last_used_at = models.DateTimeField(auto_now=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_reason = models.CharField(max_length=100, blank=True, null=True)
    security_stamp = models.UUIDField(default=uuid.uuid4, editable=False)
    assurance_policy_version = models.CharField(max_length=50, blank=True, default="")
    assurance_context = models.CharField(max_length=50, blank=True, default="")
    request_ip_hash = models.CharField(max_length=64, null=True, blank=True)
    network_class = models.CharField(max_length=32, default="unknown", blank=True)
    metadata_json = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = "trusted device"
        verbose_name_plural = "trusted devices"
        indexes = [
            models.Index(fields=["status", "trusted_until"]),
        ]

    def __str__(self):
        return f"Trusted Device {self.id}"


class StudentTwoFactorEnrollment(TimestampedModel):
    """Self-service two-factor enrollment state for student accounts.

    Staff assurance remains role-governed.  Keeping student enrollment in
    account-security makes the optional student policy explicit and prevents a
    missing row from being treated as an accidental enrollment.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="student_two_factor_enrollment",
    )
    enabled = models.BooleanField(default=False)
    enabled_at = models.DateTimeField(null=True, blank=True)
    disabled_at = models.DateTimeField(null=True, blank=True)
    last_changed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "student two-factor enrollment"
        verbose_name_plural = "student two-factor enrollments"

    def __str__(self):
        return f"Student 2FA enrollment for {self.user_id}"


class ApiSessionStatusChoices(models.TextChoices):
    ACTIVE = "ACTIVE", "Active"
    REVOKED = "REVOKED", "Revoked"
    EXPIRED = "EXPIRED", "Expired"


class ApiSessionAuthenticationMethodChoices(models.TextChoices):
    PASSWORD = "password", "Password"
    OTP = "otp", "OTP"
    TRUSTED_DEVICE = "trusted_device", "Trusted device"
    MIGRATED = "migrated", "Migrated"


class ApiSession(TimestampedModel):
    """One opaque-token family and its bounded security provenance."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="api_sessions",
    )
    status = models.CharField(
        max_length=16,
        choices=ApiSessionStatusChoices.choices,
        default=ApiSessionStatusChoices.ACTIVE,
    )
    device_summary = models.CharField(max_length=120, default="unknown device")
    network_class = models.CharField(max_length=32, default="unknown")
    authentication_method = models.CharField(
        max_length=24,
        choices=ApiSessionAuthenticationMethodChoices.choices,
        default=ApiSessionAuthenticationMethodChoices.PASSWORD,
    )
    security_stamp = models.UUIDField()
    trusted_device = models.ForeignKey(
        "account_security.TrustedDevice",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="api_sessions",
    )
    started_at = models.DateTimeField(default=timezone.now)
    last_activity_at = models.DateTimeField(default=timezone.now)
    absolute_expires_at = models.DateTimeField()
    last_otp_verified_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_reason = models.CharField(max_length=100, blank=True, null=True)

    class Meta:
        verbose_name = "API session"
        verbose_name_plural = "API sessions"
        indexes = [
            models.Index(fields=["user", "status", "absolute_expires_at"]),
            models.Index(fields=["status", "absolute_expires_at"]),
        ]

    def __str__(self):
        return f"API session {self.id} ({self.status.lower()})"


class ApiTokenTypeChoices(models.TextChoices):
    ACCESS = "ACCESS", "Access token"
    REFRESH = "REFRESH", "Refresh token"


class ApiTokenStatusChoices(models.TextChoices):
    ACTIVE = "ACTIVE", "Active"
    USED = "USED", "Used"
    REVOKED = "REVOKED", "Revoked"
    EXPIRED = "EXPIRED", "Expired"


class ApiToken(TimestampedModel):
    """Hash-only opaque API credentials with family-based rotation.

    Raw bearer values are returned once to the client and are never persisted,
    logged, or included in audit metadata. The security stamp and assurance
    fields bind a token to the account security state that issued it.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="api_tokens",
    )
    session = models.ForeignKey(
        "account_security.ApiSession",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="tokens",
    )
    family_id = models.UUIDField(default=uuid.uuid4, db_index=True)
    token_hash = models.CharField(max_length=64, unique=True)
    token_type = models.CharField(
        max_length=16,
        choices=ApiTokenTypeChoices.choices,
    )
    status = models.CharField(
        max_length=16,
        choices=ApiTokenStatusChoices.choices,
        default=ApiTokenStatusChoices.ACTIVE,
    )
    issued_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    security_stamp = models.UUIDField()
    assurance_policy_version = models.CharField(max_length=50, blank=True)
    assurance_context = models.CharField(max_length=50, blank=True)
    request_ip_hash = models.CharField(max_length=64, blank=True)
    request_user_agent_hash = models.CharField(max_length=64, blank=True)

    class Meta:
        verbose_name = "API token"
        verbose_name_plural = "API tokens"
        indexes = [
            models.Index(fields=["user", "status", "expires_at"]),
            models.Index(fields=["family_id", "status"]),
            models.Index(fields=["token_type", "status", "expires_at"]),
        ]

    def __str__(self):
        return f"API {self.token_type.lower()} token {self.id} ({self.status.lower()})"


class SecurityThrottleState(TimestampedModel):
    """Model for durable database-backed rate limiting, lockouts, and CAPTCHA requirements."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    action_scope = models.CharField(max_length=50)  # e.g., login, recovery_request, recovery_verify
    scope_name = models.CharField(max_length=20, default="combined")
    scope_key = models.CharField(max_length=64, default="", db_index=True)
    subject_hash = models.CharField(max_length=64, null=True, blank=True, db_index=True)
    ip_hash = models.CharField(max_length=64, null=True, blank=True, db_index=True)
    session_hash = models.CharField(max_length=64, null=True, blank=True, db_index=True)
    token_hash = models.CharField(max_length=64, null=True, blank=True, db_index=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="security_throttles"
    )
    window_start = models.DateTimeField(default=timezone.now)
    attempts = models.IntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    captcha_required_until = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, default="active")
    metadata_json = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = "security throttle state"
        verbose_name_plural = "security throttle states"
        indexes = [
            models.Index(fields=["action_scope", "status"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["action_scope", "scope_key", "status"],
                name="account_security_throttle_scope_unique",
            ),
        ]

    def __str__(self):
        return f"Throttle state {self.id} ({self.action_scope})"


class CaptchaChallengeState(TimestampedModel):
    """Model to track durable CAPTCHA urgent_support state across sessions/IPs/identifiers."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    action_scope = models.CharField(max_length=50)
    subject_hash = models.CharField(max_length=64, null=True, blank=True, db_index=True)
    session_hash = models.CharField(max_length=64, null=True, blank=True, db_index=True)
    ip_hash = models.CharField(max_length=64, null=True, blank=True, db_index=True)
    captcha_required_until = models.DateTimeField()
    last_provider = models.CharField(max_length=50, blank=True)
    status = models.CharField(
        max_length=20,
        default="pending",
        choices=[
            ("pending", "Pending"),
            ("passed", "Passed"),
            ("failed", "Failed"),
        ]
    )
    failure_count = models.IntegerField(default=0)
    metadata_json = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = "captcha challenge state"
        verbose_name_plural = "captcha challenge states"

    def __str__(self):
        return f"Captcha state {self.id} for {self.action_scope}"
