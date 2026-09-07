import uuid
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.conf import settings
from django.core.exceptions import ValidationError
from apps.common.models import TimestampedModel
from apps.content.validators import (
    validate_safe_slug,
    validate_no_html_or_scripts,
    validate_safe_external_url,
)
from apps.security.fields import EncryptedTextField


class ContentStatus(models.TextChoices):
    DRAFT = "draft", "Draft"
    SCHEDULED = "scheduled", "Scheduled"
    PUBLISHED = "published", "Published"
    ARCHIVED = "archived", "Archived"


class RevisionStatus(models.TextChoices):
    DRAFT = "draft", "Draft"
    REVIEW = "review", "In review"
    PUBLISHED = "published", "Published"
    SCHEDULED = "scheduled", "Scheduled"
    ARCHIVED = "archived", "Archived"


RENDERER_VERSION = "markdown-3.10.3+nh3-0.3.6+fenced_code-v2"


class ContentRevision(TimestampedModel):
    """Immutable, generic snapshot of a governed content object."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    content_type = models.ForeignKey(ContentType, on_delete=models.PROTECT)
    object_id = models.CharField(max_length=64, db_index=True)
    content_object = GenericForeignKey("content_type", "object_id")
    revision_number = models.PositiveIntegerField()
    status = models.CharField(
        max_length=20,
        choices=RevisionStatus.choices,
        default=RevisionStatus.DRAFT,
        db_index=True,
    )
    snapshot = models.JSONField(default=dict)
    body_markdown = models.TextField(blank=True)
    body_html_sanitized = models.TextField(blank=True, editable=False)
    renderer_version = models.CharField(
        max_length=120,
        default=RENDERER_VERSION,
        editable=False,
    )
    supersedes = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="successors",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="content_revisions_created",
    )
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="content_revisions_reviewed",
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    published_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="content_revisions_published",
    )
    published_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-revision_number", "-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["content_type", "object_id", "revision_number"],
                name="content_revision_target_number_uniq",
            ),
        ]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError("Content revisions are immutable; create a new revision.")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Content revisions are immutable and cannot be deleted.")


class AudienceChoices(models.TextChoices):
    PUBLIC = "public", "Public (Guests)"
    STUDENTS = "students", "Students Only"
    STAFF = "staff", "Staff Only"
    COUNSELORS = "counselors", "Counselors Only"
    ALL_AUTHENTICATED = "all_authenticated", "All Authenticated Users"


class TargetScopeChoices(models.TextChoices):
    INSTITUTION_WIDE = "INSTITUTION_WIDE", "Institution-wide"
    ORGANIZATION = "ORGANIZATION", "Organization scope"


class Announcement(TimestampedModel):
    """
    Content-managed announcements.
    Can be featured, scheduled, and configured for authenticated dashboard previews.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    slug = models.CharField(
        max_length=100,
        unique=True,
        validators=[validate_safe_slug],
        db_index=True,
    )
    title = models.CharField(max_length=200, validators=[validate_no_html_or_scripts])
    summary = models.TextField(validators=[validate_no_html_or_scripts])
    body_markdown = models.TextField()
    body_html_sanitized = models.TextField(blank=True, editable=False)
    renderer_version = models.CharField(
        max_length=120,
        default=RENDERER_VERSION,
        editable=False,
    )
    status = models.CharField(
        max_length=20,
        choices=ContentStatus.choices,
        default=ContentStatus.DRAFT,
        db_index=True,
    )
    audience = models.CharField(
        max_length=30,
        choices=AudienceChoices.choices,
        default=AudienceChoices.PUBLIC,
        db_index=True,
    )
    target_scope_mode = models.CharField(
        max_length=30, choices=TargetScopeChoices.choices,
        default=TargetScopeChoices.INSTITUTION_WIDE, db_index=True,
    )
    target_campus = models.CharField(max_length=100, null=True, blank=True)
    target_college = models.CharField(max_length=100, null=True, blank=True)
    target_department = models.CharField(max_length=100, null=True, blank=True)
    target_program = models.CharField(max_length=100, null=True, blank=True)
    featured = models.BooleanField(default=False)
    publish_start = models.DateTimeField(null=True, blank=True, db_index=True)
    publish_end = models.DateTimeField(null=True, blank=True, db_index=True)
    dashboard_preview_enabled = models.BooleanField(default=True)

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="announcements_created",
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="announcements_updated",
    )
    published_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="announcements_published",
    )
    published_at = models.DateTimeField(null=True, blank=True)
    published_revision = models.ForeignKey(
        ContentRevision,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="published_announcements",
        editable=False,
    )

    class Meta:
        ordering = ["-featured", "-published_at", "-created_at"]
        indexes = [
            models.Index(fields=["status", "audience", "publish_start", "publish_end"]),
        ]

    def __str__(self):
        return self.title

    def clean(self):
        super().clean()
        target_values = (self.target_campus, self.target_college, self.target_department, self.target_program)
        if self.target_scope_mode == TargetScopeChoices.ORGANIZATION and not any(target_values):
            raise ValidationError({"target_scope_mode": "Organization content requires at least one target."})
        if self.target_scope_mode == TargetScopeChoices.INSTITUTION_WIDE and any(target_values):
            raise ValidationError({"target_scope_mode": "Institution-wide content cannot carry organization targets."})
        if self.status == ContentStatus.SCHEDULED and not self.publish_start:
            raise ValidationError(
                {"publish_start": "Scheduled announcements must have a publish start time."}
            )
        if self.publish_start and self.publish_end and self.publish_end <= self.publish_start:
            raise ValidationError(
                {"publish_end": "Publish end must be after publish start."}
            )


class ResourceCategory(models.TextChoices):
    GENERAL = "general", "General"
    FORMS = "forms", "Forms and Templates"
    GUIDELINES = "guidelines", "Guidelines and Policies"
    MENTAL_HEALTH = "mental_health", "Mental Health Resources"


class ResourceType(models.TextChoices):
    LINK = "link", "External Link"
    PAGE = "page", "Info Page Content"


class Resource(TimestampedModel):
    """
    Downloadable or linkable public resource pages.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    slug = models.CharField(
        max_length=100,
        unique=True,
        validators=[validate_safe_slug],
        db_index=True,
    )
    title = models.CharField(max_length=200, validators=[validate_no_html_or_scripts])
    summary = models.TextField(validators=[validate_no_html_or_scripts])
    category = models.CharField(
        max_length=30,
        choices=ResourceCategory.choices,
        default=ResourceCategory.GENERAL,
        db_index=True,
    )
    status = models.CharField(
        max_length=20,
        choices=ContentStatus.choices,
        default="draft",
        db_index=True,
    )
    audience = models.CharField(
        max_length=30,
        choices=AudienceChoices.choices,
        default=AudienceChoices.PUBLIC,
        db_index=True,
    )
    target_scope_mode = models.CharField(
        max_length=30, choices=TargetScopeChoices.choices,
        default=TargetScopeChoices.INSTITUTION_WIDE, db_index=True,
    )
    target_campus = models.CharField(max_length=100, null=True, blank=True)
    target_college = models.CharField(max_length=100, null=True, blank=True)
    target_department = models.CharField(max_length=100, null=True, blank=True)
    target_program = models.CharField(max_length=100, null=True, blank=True)
    resource_type = models.CharField(
        max_length=20,
        choices=ResourceType.choices,
        default=ResourceType.LINK,
    )
    external_url = models.URLField(
        null=True,
        blank=True,
        validators=[validate_safe_external_url],
    )
    publish_start = models.DateTimeField(null=True, blank=True, db_index=True)
    publish_end = models.DateTimeField(null=True, blank=True, db_index=True)
    body_markdown = models.TextField(
        null=True,
        blank=True,
    )
    body_html_sanitized = models.TextField(blank=True, editable=False)
    renderer_version = models.CharField(
        max_length=120,
        default=RENDERER_VERSION,
        editable=False,
    )

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="resources_created",
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="resources_updated",
    )
    published_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="resources_published",
    )
    published_at = models.DateTimeField(null=True, blank=True)
    published_revision = models.ForeignKey(
        ContentRevision,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="published_resources",
        editable=False,
    )

    class Meta:
        ordering = ["-published_at", "-created_at"]
        indexes = [
            models.Index(fields=["status", "audience", "category"]),
            models.Index(
                fields=["status", "audience", "publish_start", "publish_end"],
                name="content_res_status_5fb462_idx",
            ),
        ]

    def __str__(self):
        return self.title

    def clean(self):
        super().clean()
        target_values = (self.target_campus, self.target_college, self.target_department, self.target_program)
        if self.target_scope_mode == TargetScopeChoices.ORGANIZATION and not any(target_values):
            raise ValidationError({"target_scope_mode": "Organization content requires at least one target."})
        if self.target_scope_mode == TargetScopeChoices.INSTITUTION_WIDE and any(target_values):
            raise ValidationError({"target_scope_mode": "Institution-wide content cannot carry organization targets."})
        if self.resource_type == ResourceType.LINK and not self.external_url:
            raise ValidationError(
                {"external_url": "Link resource must specify an external URL."}
            )
        if self.resource_type == ResourceType.PAGE and not self.body_markdown:
            raise ValidationError(
                {"body_markdown": "Page resource must specify content body."}
            )
        if self.status == ContentStatus.SCHEDULED and not self.publish_start:
            raise ValidationError(
                {"publish_start": "Scheduled resources must have a publish start time."}
            )
        if self.publish_start and self.publish_end and self.publish_end <= self.publish_start:
            raise ValidationError(
                {"publish_end": "Publish end must be after publish start."}
            )


class ContentPage(TimestampedModel):
    """A governed, route-backed page such as the future About page."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    page_key = models.CharField(max_length=80, unique=True, validators=[validate_safe_slug])
    title = models.CharField(max_length=200, validators=[validate_no_html_or_scripts])
    summary = models.TextField(blank=True, validators=[validate_no_html_or_scripts])
    body_markdown = models.TextField(blank=True)
    body_html_sanitized = models.TextField(blank=True, editable=False)
    renderer_version = models.CharField(
        max_length=120,
        default=RENDERER_VERSION,
        editable=False,
    )
    status = models.CharField(
        max_length=20,
        choices=ContentStatus.choices,
        default=ContentStatus.DRAFT,
        db_index=True,
    )
    audience = models.CharField(
        max_length=30,
        choices=AudienceChoices.choices,
        default=AudienceChoices.PUBLIC,
        db_index=True,
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="content_pages_created",
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="content_pages_updated",
    )
    published_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="content_pages_published",
    )
    published_at = models.DateTimeField(null=True, blank=True)
    published_revision = models.ForeignKey(
        ContentRevision,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="published_pages",
        editable=False,
    )

    class Meta:
        ordering = ["page_key"]

    def __str__(self):
        return self.title

    def clean(self):
        super().clean()
        if self.status == ContentStatus.PUBLISHED and not self.body_markdown:
            raise ValidationError({"body_markdown": "Published pages must specify content."})


class ServiceGuide(TimestampedModel):
    """The single governed public Service Standards / Citizen's Charter guide.

    The registry remains the source of truth for service availability and
    destinations.  ``entries_json`` stores only office-authored copy and
    structured confirmation fields; the public selector combines it with the
    registry and never projects a draft or an out-of-window revision.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    guide_key = models.CharField(
        max_length=80,
        unique=True,
        default="public-service-guide",
        validators=[validate_safe_slug],
        editable=False,
    )
    title = models.CharField(
        max_length=200,
        default="Official Citizen’s Charter / Service Standards",
        validators=[validate_no_html_or_scripts],
    )
    summary = models.TextField(blank=True, validators=[validate_no_html_or_scripts])
    version_label = models.CharField(
        max_length=80,
        help_text="Office-approved revision label, such as 2026.1.",
    )
    effective_date = models.DateField(null=True, blank=True)
    owner_office = models.ForeignKey(
        "organizations.OfficeProfile",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="service_guides",
    )
    status = models.CharField(
        max_length=20,
        choices=ContentStatus.choices,
        default=ContentStatus.DRAFT,
        db_index=True,
    )
    audience = models.CharField(
        max_length=30,
        choices=AudienceChoices.choices,
        default=AudienceChoices.PUBLIC,
        db_index=True,
    )
    publish_start = models.DateTimeField(null=True, blank=True, db_index=True)
    publish_end = models.DateTimeField(null=True, blank=True, db_index=True)
    body_markdown = models.TextField(blank=True)
    body_html_sanitized = models.TextField(blank=True, editable=False)
    renderer_version = models.CharField(
        max_length=120,
        default=RENDERER_VERSION,
        editable=False,
    )
    entries_json = models.JSONField(default=list, blank=True)
    readiness_metadata_json = models.JSONField(
        default=dict,
        blank=True,
        editable=False,
        help_text="Server-generated confirmation/readiness metadata; never office-editable.",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="service_guides_created",
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="service_guides_updated",
    )
    published_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="service_guides_published",
    )
    published_at = models.DateTimeField(null=True, blank=True)
    published_revision = models.ForeignKey(
        ContentRevision,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="published_service_guides",
        editable=False,
    )

    class Meta:
        ordering = ["-effective_date", "-created_at"]
        verbose_name = "service guide"
        verbose_name_plural = "service guides"
        constraints = [
            models.CheckConstraint(
                condition=models.Q(guide_key="public-service-guide"),
                name="content_serviceguide_singleton_key",
            ),
        ]

    def __str__(self):
        return f"{self.title} ({self.version_label})"

    def clean(self):
        super().clean()
        if self.guide_key != "public-service-guide":
            raise ValidationError({"guide_key": "Only the canonical public service guide is supported."})
        if not isinstance(self.entries_json, list):
            raise ValidationError({"entries_json": "Guide entries must be a list."})
        if self.publish_start and self.publish_end and self.publish_end <= self.publish_start:
            raise ValidationError({"publish_end": "Publish end must be after publish start."})
        if self.status in {ContentStatus.PUBLISHED, ContentStatus.SCHEDULED} and not self.version_label:
            raise ValidationError({"version_label": "A published guide requires a version label."})


class SubmissionType(models.TextChoices):
    INQUIRY = "inquiry", "Inquiry / Question"
    SUGGESTION = "suggestion", "Suggestion"
    FEEDBACK = "feedback", "Feedback"
    CONCERN = "concern", "Concern"
    OTHER = "other", "Other"


class AffiliationChoices(models.TextChoices):
    STUDENT = "student", "Student"
    PARENT = "parent", "Parent / Guardian"
    FACULTY = "faculty", "Faculty Member"
    STAFF = "staff", "Staff Member"
    VISITOR = "visitor", "Visitor / Guest"
    OTHER = "other", "Other"


class SubmissionStatus(models.TextChoices):
    NEW = "new", "New"
    TRIAGED = "triaged", "Triaged"
    ASSIGNED = "assigned", "Assigned"
    RESPONDED = "responded", "Responded"
    NO_RESPONSE_REQUIRED = "no_response_required", "No response required"
    RESPONSE_EVIDENCE_MISSING = "response_evidence_missing", "Response evidence missing"
    ARCHIVED = "archived", "Archived"
    SPAM = "spam", "Spam / Ignored"
    DUPLICATE = "duplicate", "Duplicate"


class SubmissionPriority(models.TextChoices):
    NORMAL = "normal", "Normal"
    HIGH = "high", "High"


class PublicContactSubmission(TimestampedModel):
    """
    Operational record for inquiries and suggestions submitted on the public page.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    reference_code = models.CharField(
        max_length=50,
        unique=True,
        db_index=True,
        help_text="Canonical CNT reference code.",
    )
    submission_type = models.CharField(
        max_length=30,
        choices=SubmissionType.choices,
        default=SubmissionType.INQUIRY,
        db_index=True,
    )
    name = models.CharField(max_length=150, blank=True, null=True)
    email = models.EmailField(blank=True, null=True)
    phone = models.CharField(max_length=50, blank=True, null=True)
    affiliation = models.CharField(
        max_length=30,
        choices=AffiliationChoices.choices,
        default=AffiliationChoices.VISITOR,
        db_index=True,
    )
    subject = models.CharField(max_length=200)
    # ``message_body`` is retained only as a staged legacy migration source.
    # New submissions write an empty source value and authenticated ciphertext.
    message_body = models.TextField(blank=True)
    message_body_encrypted = EncryptedTextField(
        null=True,
        blank=True,
        default=None,
        max_plaintext_bytes=32_768,
        help_text="Authenticated encrypted intake message; legacy plaintext is source-only.",
    )
    privacy_acknowledged = models.BooleanField(default=False)
    urgent_support_disclaimer_acknowledged = models.BooleanField(default=False)

    status = models.CharField(
        max_length=30,
        choices=SubmissionStatus.choices,
        default=SubmissionStatus.NEW,
        db_index=True,
    )
    # New terminal transitions carry explicit action evidence. Legacy rows are
    # intentionally left NULL rather than assigning an inferred trigger.
    privacy_actioned_at = models.DateTimeField(null=True, blank=True)
    priority = models.CharField(
        max_length=20,
        choices=SubmissionPriority.choices,
        default=SubmissionPriority.NORMAL,
    )
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_contact_submissions",
    )
    source_ip_hash = models.CharField(max_length=64, blank=True, null=True)
    user_agent_hash = models.CharField(max_length=64, blank=True, null=True)
    duplicate_fingerprint = models.CharField(max_length=64, blank=True, null=True, db_index=True)
    idempotency_key_hash = models.CharField(max_length=64, blank=True, null=True, unique=True, db_index=True)

    submitted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="contact_submissions_made",
    )
    metadata_json = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.subject} ({self.submission_type}) - {self.status}"

    def clean(self):
        super().clean()
        if not self.privacy_acknowledged:
            raise ValidationError(
                {"privacy_acknowledged": "You must acknowledge the privacy notice to submit."}
            )

    @property
    def reply_required(self):
        return self.submission_type in {
            SubmissionType.INQUIRY,
            SubmissionType.CONCERN,
            SubmissionType.OTHER,
        }

    @property
    def reply_channel_available(self):
        return bool(self.email and self.email.strip())

    def get_message_body_for_staff(self):
        """Prefer authenticated ciphertext; use plaintext only for legacy rows."""
        if self.message_body_encrypted is not None:
            return self.message_body_encrypted
        return self.message_body or ""

    def save(self, *args, **kwargs):
        # The field-operation framework marks its own authorized staged
        # backfill/rotation writes explicitly. Ordinary callers cannot use
        # update_fields to bypass immutable intake provenance.
        authorized_field_operation = getattr(self, "_allow_immutable_field_operation", False)
        if not self._state.adding and not authorized_field_operation:
            immutable_fields = (
                "reference_code", "submission_type", "name", "email", "phone",
                "affiliation", "subject", "message_body", "privacy_acknowledged",
                "urgent_support_disclaimer_acknowledged", "submitted_by_id",
            )
            current = type(self).objects.get(pk=self.pk)
            changed = [
                field for field in immutable_fields
                if getattr(current, field) != getattr(self, field)
            ]
            if current.message_body_encrypted != self.message_body_encrypted:
                changed.append("message_body_encrypted")
            if changed:
                raise ValidationError("Contact intake fields are immutable after creation.")
        return super().save(*args, **kwargs)


class ContactReplyStatus(models.TextChoices):
    DRAFT = "draft", "Draft"
    PENDING_APPROVAL = "pending_approval", "Pending approval"
    APPROVED = "approved", "Approved"
    QUEUED = "queued", "Queued"
    SENT = "sent", "Sent"
    DELIVERY_FAILED = "delivery_failed", "Delivery failed"
    REJECTED = "rejected", "Rejected"
    CANCELLED = "cancelled", "Cancelled"


class ContactEvidenceScope(models.TextChoices):
    LOCAL_BACKEND = "local_backend", "Local mail backend acceptance"
    STAGING_PROVIDER = "staging_provider", "Staging/provider acceptance"
    PRODUCTION_PROVIDER = "production_provider", "Production/provider acceptance"
    UNKNOWN = "unknown", "Evidence scope unknown"


class ContactReply(TimestampedModel):
    """Tracked, encrypted correspondence attached to one contact intake."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    submission = models.ForeignKey(
        PublicContactSubmission,
        on_delete=models.PROTECT,
        related_name="replies",
    )
    reply_body_encrypted = EncryptedTextField(
        null=True,
        blank=True,
        default=None,
        max_plaintext_bytes=32_768,
    )
    subject = models.CharField(
        max_length=120,
        default="COMPASS contact response",
        editable=False,
    )
    channel = models.CharField(max_length=20, default="email", editable=False)
    recipient_channel_hash = models.CharField(max_length=64, editable=False)
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="contact_replies_authored",
    )
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="contact_replies_approved",
    )
    approved_at = models.DateTimeField(null=True, blank=True)
    approval_evidence_json = models.JSONField(default=dict, blank=True)
    status = models.CharField(
        max_length=30,
        choices=ContactReplyStatus.choices,
        default=ContactReplyStatus.DRAFT,
        db_index=True,
    )
    delivery = models.ForeignKey(
        "notifications.EmailDelivery",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="contact_replies",
    )
    delivery_state = models.CharField(max_length=30, blank=True)
    evidence_scope = models.CharField(
        max_length=30,
        choices=ContactEvidenceScope.choices,
        default=ContactEvidenceScope.LOCAL_BACKEND,
    )
    evidence_recorded_at = models.DateTimeField(null=True, blank=True)
    last_failure_code = models.CharField(max_length=80, blank=True)
    sent_at = models.DateTimeField(null=True, blank=True)
    frozen_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Contact reply for {self.submission.reference_code} ({self.status})"

    def clean(self):
        super().clean()
        if self.channel != "email":
            raise ValidationError({"channel": "Email is the only supported reply channel."})
        if self.status in {
            ContactReplyStatus.PENDING_APPROVAL,
            ContactReplyStatus.APPROVED,
            ContactReplyStatus.QUEUED,
            ContactReplyStatus.SENT,
        } and not self.reply_body_encrypted:
            raise ValidationError({"reply_body_encrypted": "A reply body is required before approval."})

    def get_body_for_send(self):
        return self.reply_body_encrypted or ""

    def save(self, *args, **kwargs):
        if not self._state.adding:
            current = type(self).objects.get(pk=self.pk)
            frozen = current.status not in {
                ContactReplyStatus.DRAFT,
                ContactReplyStatus.PENDING_APPROVAL,
            } or current.frozen_at is not None
            if frozen and any(
                getattr(current, field) != getattr(self, field)
                for field in (
                    "submission_id", "reply_body_encrypted", "subject", "channel",
                    "recipient_channel_hash", "author_id",
                )
            ):
                raise ValidationError("Approved contact replies are immutable.")
        return super().save(*args, **kwargs)


class ContactNoResponseReason(models.TextChoices):
    INFORMATIONAL_ONLY = "informational_only", "Informational only"
    ANONYMOUS_NO_CONTACT = "anonymous_no_contact", "No reply channel provided"
    SENDER_DECLINED = "sender_declined", "Sender declined a response"
    DUPLICATE = "duplicate", "Duplicate"
    SPAM = "spam", "Spam"
    OTHER = "other", "Other approved reason"


class ContactNoResponseDisposition(TimestampedModel):
    """Audited, allowlisted closure for a contact needing no reply."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    submission = models.OneToOneField(
        PublicContactSubmission,
        on_delete=models.PROTECT,
        related_name="no_response_disposition",
    )
    reason_code = models.CharField(max_length=40, choices=ContactNoResponseReason.choices)
    detail_encrypted = EncryptedTextField(null=True, blank=True, default=None, max_plaintext_bytes=8_192)
    recorded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="contact_no_response_dispositions",
    )

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError("No-response dispositions are immutable.")
        return super().save(*args, **kwargs)
