"""Append-only privacy evidence and metadata-only governance records.

These models deliberately keep sensitive narratives in encrypted fields and
use HMAC-safe references for subjects, tokens, and record identifiers.  They
are governance evidence, not a second copy of any protected workflow record.
"""

import hashlib
import re
import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.db import models
from django.utils import timezone

from apps.common.models import TimestampedModel
from apps.security.fields import EncryptedTextField

from .choices import (
    LegalHoldStatusChoices,
    PrivacyAcceptanceDecisionChoices,
    PrivacyActorTypeChoices,
    PrivacyApprovalStateChoices,
    PrivacyIncidentCategoryChoices,
    PrivacyIncidentNotificationDecisionChoices,
    PrivacyIncidentSeverityChoices,
    PrivacyIncidentStatusChoices,
    PrivacyNoticeStatusChoices,
    PrivacyRequestStatusChoices,
    PrivacyRequestTypeChoices,
    RetentionRuleStateChoices,
    RetentionTriggerChoices,
    ReviewerAuthorizationStatusChoices,
)

SAFE_INCIDENT_METADATA_KEYS = frozenset({
    "containment_code", "affected_count", "system_code", "event_count", "authorization_reference",
})
SAFE_HASH_VALIDATOR = RegexValidator(r"\A[a-f0-9]{64}\Z", "This field must contain a 64-character HMAC reference.")
SAFE_METADATA_VALUE_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}\Z")


class PrivacyNoticeRevision(TimestampedModel):
    """Immutable, content-addressed privacy notice revision."""

    notice_identifier = models.SlugField(max_length=120)
    version = models.CharField(max_length=40)
    revision_hash = models.CharField(max_length=64, editable=False)
    body_markdown = models.TextField()
    source_reference = models.CharField(max_length=500)
    effective_at = models.DateTimeField(null=True, blank=True)
    locale = models.CharField(max_length=20, default="en")
    purpose_workflow = models.CharField(max_length=100)
    status = models.CharField(
        max_length=20,
        choices=PrivacyNoticeStatusChoices.choices,
        default=PrivacyNoticeStatusChoices.PROPOSED,
    )
    approval_state = models.CharField(
        max_length=20,
        choices=PrivacyApprovalStateChoices.choices,
        default=PrivacyApprovalStateChoices.PENDING,
    )
    supersedes = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="superseding_revisions",
    )
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="approved_privacy_notice_revisions",
    )
    approved_at = models.DateTimeField(null=True, blank=True)
    approval_reference = models.CharField(max_length=255, blank=True)
    source_verified_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="created_privacy_notice_revisions",
    )

    class Meta:
        ordering = ["notice_identifier", "purpose_workflow", "locale", "-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["notice_identifier", "version", "locale", "purpose_workflow"],
                name="privacy_notice_revision_identity_unique",
            ),
        ]
        indexes = [
            models.Index(fields=["notice_identifier", "purpose_workflow", "locale", "status"]),
            models.Index(fields=["revision_hash"]),
        ]

    IMMUTABLE_FIELDS = frozenset({
        "notice_identifier", "version", "revision_hash", "body_markdown",
        "source_reference", "effective_at", "locale", "purpose_workflow", "supersedes_id",
    })

    def clean(self):
        super().clean()
        expected = hashlib.sha256((self.body_markdown or "").encode("utf-8")).hexdigest()
        if self.revision_hash and self.revision_hash != expected:
            raise ValidationError({"revision_hash": "The revision hash does not match the notice body."})
        self.revision_hash = expected
        if self.approval_state == PrivacyApprovalStateChoices.APPROVED and not self.approved_at:
            raise ValidationError({"approved_at": "Approved notice revisions require an approval timestamp."})

    def save(self, *args, **kwargs):
        if self.pk:
            persisted = type(self).objects.filter(pk=self.pk).values(*self.IMMUTABLE_FIELDS).first()
            if persisted:
                for field in self.IMMUTABLE_FIELDS:
                    current = persisted[field]
                    incoming = getattr(self, field)
                    if field == "supersedes_id":
                        incoming = self.supersedes_id
                    if current != incoming:
                        raise ValidationError("Privacy notice revisions are immutable after creation.")
        self.full_clean()
        return super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.notice_identifier} {self.version} ({self.locale})"


class PrivacyWorkflowBinding(TimestampedModel):
    """Fail-closed binding between a workflow and its approved notice."""

    purpose_workflow = models.SlugField(max_length=100, unique=True)
    notice_revision = models.ForeignKey(
        PrivacyNoticeRevision,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="workflow_bindings",
    )
    status = models.CharField(
        max_length=20,
        choices=PrivacyNoticeStatusChoices.choices,
        default=PrivacyNoticeStatusChoices.BLOCKED,
    )
    required = models.BooleanField(default=True)
    source_reference = models.CharField(max_length=500, blank=True)
    block_reason = models.CharField(max_length=255, blank=True)

    class Meta:
        indexes = [models.Index(fields=["purpose_workflow", "status"])]

    def clean(self):
        super().clean()
        if self.status == PrivacyNoticeStatusChoices.PUBLISHED and not self.notice_revision_id:
            raise ValidationError("Published workflow bindings require a notice revision.")
        if self.status == PrivacyNoticeStatusChoices.BLOCKED and not self.block_reason:
            raise ValidationError("Blocked workflow bindings require a reason.")


class PrivacyAcceptanceEvent(TimestampedModel):
    """Append-only evidence that a subject made a workflow decision."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    notice_revision = models.ForeignKey(
        PrivacyNoticeRevision,
        on_delete=models.PROTECT,
        related_name="acceptance_events",
    )
    purpose_workflow = models.CharField(max_length=100)
    subject_reference_hash = models.CharField(max_length=64, validators=[SAFE_HASH_VALIDATOR])
    subject_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="privacy_acceptance_events",
    )
    actor_type = models.CharField(max_length=20, choices=PrivacyActorTypeChoices.choices)
    decision = models.CharField(max_length=20, choices=PrivacyAcceptanceDecisionChoices.choices)
    decided_at = models.DateTimeField(default=timezone.now)
    source_route = models.CharField(max_length=255)
    request_correlation_id = models.CharField(max_length=100, blank=True)
    token_session_hash = models.CharField(max_length=64, blank=True, validators=[SAFE_HASH_VALIDATOR])

    class Meta:
        ordering = ["-decided_at", "-created_at"]
        indexes = [
            models.Index(fields=["subject_reference_hash", "purpose_workflow"]),
            models.Index(fields=["notice_revision", "decision"]),
        ]

    def save(self, *args, **kwargs):
        if self.pk and type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError("Privacy acceptance evidence is append-only.")
        self.full_clean()
        return super().save(*args, **kwargs)


class RetentionRule(TimestampedModel):
    """Category-specific retention configuration; no default means active."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    record_category = models.SlugField(max_length=120, unique=True)
    retention_trigger = models.CharField(max_length=30, choices=RetentionTriggerChoices.choices)
    retention_period_days = models.PositiveIntegerField(null=True, blank=True)
    review_due_at = models.DateTimeField(null=True, blank=True)
    source_reference = models.CharField(max_length=500)
    legal_basis = models.CharField(max_length=255, blank=True)
    owner_role = models.CharField(max_length=80)
    approver = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="approved_retention_rules",
    )
    effective_at = models.DateTimeField(null=True, blank=True)
    legal_hold_behavior = models.CharField(max_length=255)
    disposal_method = models.CharField(max_length=255)
    evidence_requirement = models.CharField(max_length=255)
    exception_status = models.CharField(max_length=80, blank=True)
    status = models.CharField(
        max_length=20,
        choices=RetentionRuleStateChoices.choices,
        default=RetentionRuleStateChoices.PROPOSED,
        db_index=True,
    )
    approval_reference = models.CharField(max_length=255, blank=True)
    approved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["record_category"]

    def clean(self):
        super().clean()
        if self.status == RetentionRuleStateChoices.ACTIVE:
            if not self.approver_id or not self.approved_at or not self.effective_at:
                raise ValidationError("An active retention rule requires approval and effective evidence.")
            if not self.retention_period_days and not self.review_due_at:
                raise ValidationError("An active retention rule requires a period or review date.")

    def __str__(self):
        return f"{self.record_category} ({self.status})"


class RetentionRuleTransition(TimestampedModel):
    """Append-only status history for one retention rule."""

    rule = models.ForeignKey(RetentionRule, on_delete=models.PROTECT, related_name="transitions")
    from_status = models.CharField(max_length=20, blank=True)
    to_status = models.CharField(max_length=20, choices=RetentionRuleStateChoices.choices)
    actor_user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    reason_code = models.CharField(max_length=80)
    safe_evidence = models.JSONField(default=dict, blank=True)
    effective_at = models.DateTimeField(default=timezone.now)

    def save(self, *args, **kwargs):
        if self.pk:
            raise ValidationError("Retention rule transitions are append-only.")
        return super().save(*args, **kwargs)


class PrivacyLegalHold(TimestampedModel):
    """Metadata-only legal/institutional hold over a category or safe reference."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    record_category = models.SlugField(max_length=120)
    record_reference_hash = models.CharField(max_length=64, blank=True, validators=[SAFE_HASH_VALIDATOR])
    reason_code = models.CharField(max_length=80)
    status = models.CharField(max_length=20, choices=LegalHoldStatusChoices.choices, default=LegalHoldStatusChoices.ACTIVE)
    placed_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="placed_privacy_holds")
    placed_at = models.DateTimeField(default=timezone.now)
    released_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="released_privacy_holds")
    released_at = models.DateTimeField(null=True, blank=True)
    safe_reference = models.CharField(max_length=255, blank=True)

    class Meta:
        indexes = [models.Index(fields=["record_category", "status"]), models.Index(fields=["record_reference_hash", "status"])]

    def clean(self):
        super().clean()
        if self.safe_reference and not SAFE_METADATA_VALUE_RE.fullmatch(self.safe_reference):
            raise ValidationError({"safe_reference": "Safe hold references must use an allowlisted code."})


class RetentionEvaluation(TimestampedModel):
    """Aggregate, content-blind result of a retention dry-run."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    environment = models.CharField(max_length=40)
    evaluated_at = models.DateTimeField(default=timezone.now)
    record_category = models.SlugField(max_length=120)
    candidate_count = models.PositiveIntegerField(default=0)
    hold_count = models.PositiveIntegerField(default=0)
    result_code = models.CharField(max_length=80)
    safe_metadata = models.JSONField(default=dict, blank=True)


class PrivacyReviewerAuthorization(TimestampedModel):
    """Dated, auditable authorization for designated privacy reviewers."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    authorized_user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="privacy_reviewer_authorizations")
    scopes = models.JSONField(default=list)
    valid_from = models.DateTimeField(default=timezone.now)
    valid_until = models.DateTimeField(null=True, blank=True)
    source_reference = models.CharField(max_length=255)
    authorized_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="issued_privacy_reviewer_authorizations")
    status = models.CharField(max_length=20, choices=ReviewerAuthorizationStatusChoices.choices, default=ReviewerAuthorizationStatusChoices.ACTIVE)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="revoked_privacy_reviewer_authorizations")

    class Meta:
        indexes = [models.Index(fields=["authorized_user", "status", "valid_from", "valid_until"])]

    def clean(self):
        super().clean()
        if self.valid_until and self.valid_until < self.valid_from:
            raise ValidationError("Reviewer authorization expiry must be on or after its start.")
        if not isinstance(self.scopes, (list, dict)) or not self.scopes:
            raise ValidationError("Reviewer authorization requires explicit scopes.")


class DataSubjectRequest(TimestampedModel):
    """Reviewable data-subject request with encrypted free text."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    reference_code = models.CharField(max_length=40, unique=True, editable=False)
    requester = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="privacy_requests")
    subject_reference_hash = models.CharField(max_length=64, validators=[SAFE_HASH_VALIDATOR])
    request_type = models.CharField(max_length=20, choices=PrivacyRequestTypeChoices.choices)
    target_category = models.SlugField(max_length=120, blank=True)
    target_record_reference_hash = models.CharField(max_length=64, blank=True, validators=[SAFE_HASH_VALIDATOR])
    description_encrypted = EncryptedTextField(null=True, blank=True, max_plaintext_bytes=16_384)
    status = models.CharField(max_length=40, choices=PrivacyRequestStatusChoices.choices, default=PrivacyRequestStatusChoices.SUBMITTED, db_index=True)
    submitted_at = models.DateTimeField(default=timezone.now)
    identity_verified_at = models.DateTimeField(null=True, blank=True)
    assigned_reviewer = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="assigned_privacy_requests")
    reviewed_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="reviewed_privacy_requests")
    reviewed_at = models.DateTimeField(null=True, blank=True)
    decision_reason_code = models.CharField(max_length=80, blank=True)
    decision_notes_encrypted = EncryptedTextField(null=True, blank=True, max_plaintext_bytes=16_384)
    fulfilled_at = models.DateTimeField(null=True, blank=True)
    withdrawn_at = models.DateTimeField(null=True, blank=True)
    closed_at = models.DateTimeField(null=True, blank=True)
    staff_assisted = models.BooleanField(default=False)
    source_route = models.CharField(max_length=255)
    request_correlation_id = models.CharField(max_length=100, blank=True)
    protected_fulfillment_file = models.ForeignKey("security.ProtectedFile", null=True, blank=True, on_delete=models.SET_NULL, related_name="privacy_request_fulfillments")

    class Meta:
        ordering = ["-submitted_at"]
        indexes = [models.Index(fields=["subject_reference_hash", "status"]), models.Index(fields=["target_category", "status"])]

    def __str__(self):
        return self.reference_code


class DataSubjectRequestTransition(TimestampedModel):
    request = models.ForeignKey(DataSubjectRequest, on_delete=models.PROTECT, related_name="transitions")
    from_status = models.CharField(max_length=40, blank=True)
    to_status = models.CharField(max_length=40, choices=PrivacyRequestStatusChoices.choices)
    actor_user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    reason_code = models.CharField(max_length=80)
    decision_evidence = models.JSONField(default=dict, blank=True)
    occurred_at = models.DateTimeField(default=timezone.now)

    def save(self, *args, **kwargs):
        if self.pk:
            raise ValidationError("Privacy request transitions are append-only.")
        return super().save(*args, **kwargs)


class PrivacyIncident(TimestampedModel):
    """Metadata-only incident register; never a narrative store."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    incident_code = models.CharField(max_length=40, unique=True, editable=False)
    category = models.CharField(max_length=40, choices=PrivacyIncidentCategoryChoices.choices)
    severity = models.CharField(max_length=20, choices=PrivacyIncidentSeverityChoices.choices)
    affected_workflow = models.CharField(max_length=100, blank=True)
    affected_record_category = models.SlugField(max_length=120, blank=True)
    discovered_at = models.DateTimeField(default=timezone.now)
    reporter = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="reported_privacy_incidents")
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="owned_privacy_incidents")
    status = models.CharField(max_length=20, choices=PrivacyIncidentStatusChoices.choices, default=PrivacyIncidentStatusChoices.OPEN, db_index=True)
    containment_code = models.CharField(max_length=80, blank=True)
    action_metadata = models.JSONField(default=dict, blank=True)
    notification_decision = models.CharField(max_length=20, choices=PrivacyIncidentNotificationDecisionChoices.choices, default=PrivacyIncidentNotificationDecisionChoices.PENDING)
    related_event_ids = models.JSONField(default=list, blank=True)
    safe_summary_code = models.CharField(max_length=100, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-discovered_at"]
        indexes = [models.Index(fields=["category", "status"]), models.Index(fields=["severity", "status"])]

    def __str__(self):
        return self.incident_code

    def clean(self):
        super().clean()
        metadata = self.action_metadata or {}
        if not isinstance(metadata, dict) or set(metadata) - SAFE_INCIDENT_METADATA_KEYS:
            raise ValidationError({"action_metadata": "Incident metadata contains only allowlisted fields."})
        for key in ("affected_count", "event_count"):
            if key in metadata and (not isinstance(metadata[key], int) or metadata[key] < 0):
                raise ValidationError({"action_metadata": "Incident counts must be non-negative integers."})
        for key, value in metadata.items():
            if key not in {"affected_count", "event_count"} and (
                not isinstance(value, str) or not SAFE_METADATA_VALUE_RE.fullmatch(value)
            ):
                raise ValidationError({"action_metadata": "Incident metadata values must be allowlisted codes."})
        if self.containment_code and not SAFE_METADATA_VALUE_RE.fullmatch(self.containment_code):
            raise ValidationError({"containment_code": "Containment must use an allowlisted code."})
        if self.safe_summary_code and not SAFE_METADATA_VALUE_RE.fullmatch(self.safe_summary_code):
            raise ValidationError({"safe_summary_code": "Incident summaries must use an allowlisted code."})
        if not isinstance(self.related_event_ids, list) or any(
            not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value)
            for value in self.related_event_ids
        ):
            raise ValidationError({"related_event_ids": "Related events must be HMAC-safe references."})

    def save(self, *args, **kwargs):
        self.full_clean()
        return super().save(*args, **kwargs)


class PrivacyIncidentTransition(TimestampedModel):
    incident = models.ForeignKey(PrivacyIncident, on_delete=models.PROTECT, related_name="transitions")
    from_status = models.CharField(max_length=20, blank=True)
    to_status = models.CharField(max_length=20, choices=PrivacyIncidentStatusChoices.choices)
    actor_user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    reason_code = models.CharField(max_length=80)
    safe_evidence = models.JSONField(default=dict, blank=True)
    occurred_at = models.DateTimeField(default=timezone.now)

    def clean(self):
        super().clean()
        metadata = self.safe_evidence or {}
        if not isinstance(metadata, dict) or set(metadata) - SAFE_INCIDENT_METADATA_KEYS:
            raise ValidationError({"safe_evidence": "Incident evidence contains only allowlisted fields."})
        for key, value in metadata.items():
            if key in {"affected_count", "event_count"}:
                if not isinstance(value, int) or value < 0:
                    raise ValidationError({"safe_evidence": "Incident counts must be non-negative integers."})
            elif not isinstance(value, str) or not SAFE_METADATA_VALUE_RE.fullmatch(value):
                raise ValidationError({"safe_evidence": "Incident evidence values must be allowlisted codes."})

    def save(self, *args, **kwargs):
        if self.pk:
            raise ValidationError("Privacy incident transitions are append-only.")
        return super().save(*args, **kwargs)
