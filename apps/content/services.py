import hashlib
import hmac
import re
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone
from django.db import IntegrityError, transaction
from django.contrib.contenttypes.models import ContentType
from apps.audit.services import audit_log
from apps.common.exceptions import PermissionDeniedError as PermissionDenied, NotFoundError, ValidationError
from apps.common.rich_text import RichTextValidationError, render_rich_text
from apps.common.request_dedup import RequestKeyPolicy, validate_and_lock_request_key
from apps.content.models import (
    Announcement,
    Resource,
    PublicContactSubmission,
    ServiceGuide,
    ContentStatus,
    ContentPage,
    ContentRevision,
    RevisionStatus,
    RENDERER_VERSION,
    SubmissionStatus,
    SubmissionType,
    ContactReply,
    ContactReplyStatus,
    ContactNoResponseDisposition,
    ContactNoResponseReason,
)
from apps.content.commands import (
    AnnouncementCreateCommand,
    AnnouncementUpdateCommand,
    ContactAssignmentCommand,
    ContactNoResponseCommand,
    ContactReplyCommand,
    ContactStatusCommand,
    ContactSubmissionCommand,
    ContentPageCreateCommand,
    ContentPageUpdateCommand,
    ContentSeedCommand,
    ResourceCreateCommand,
    ResourceUpdateCommand,
    ServiceGuideCreateCommand,
    ServiceGuideUpdateCommand,
)
from apps.content.policies import (
    can_manage_contact_submissions,
    can_manage_contact_admin,
    can_manage_contact_reply,
    can_transition_contact_reply,
    can_manage_content,
    can_prepare_content,
    can_publish_content,
    can_schedule_content,
    can_archive_content,
)
from apps.access_control.rules import is_active_nonlegacy_actor, is_counselor
from apps.content.validators import validate_model

CONTACT_MESSAGE_MAX_PLAINTEXT_BYTES = 32_768

def _can_prepare_model(user, model, obj=None) -> bool:
    """Keep governed ContentPage authoring Head Guidance-only."""
    if model in {ContentPage, ServiceGuide}:
        return can_manage_content(user)
    return can_prepare_content(user, obj)


def render_markdown(body_markdown: str | None) -> str:
    """Compatibility wrapper for the canonical public-content renderer."""
    try:
        return render_rich_text(body_markdown)
    except RichTextValidationError as exc:
        # Preserve the existing domain error boundary without echoing source
        # content or renderer details to an API caller.
        raise ValidationError() from exc


def _contact_hmac(value: str) -> str | None:
    """Return a deterministic HMAC-SHA256 for public-contact abuse controls."""
    if not value:
        return None
    secret = getattr(settings, "AUDIT_HASH_SECRET", "")
    if not secret:
        raise ImproperlyConfigured("AUDIT_HASH_SECRET is required for contact hashing.")
    return hmac.new(
        secret.encode("utf-8"),
        value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _normalize_identifier(value: str | None, *, max_length: int | None = None) -> str:
    if not value:
        return ""
    normalized = re.sub(r"\s+", " ", value.strip())
    if max_length is not None:
        normalized = normalized[:max_length]
    return normalized


def _duplicate_fingerprint(command: ContactSubmissionCommand) -> str:
    parts = [
        _normalize_identifier(command.email).lower(),
        _normalize_identifier(command.subject).lower(),
        _normalize_identifier(command.message_body).lower(),
    ]
    return _contact_hmac("\n".join(parts))


def _snapshot(obj):
    fields = {
        "slug": getattr(obj, "slug", None),
        "page_key": getattr(obj, "page_key", None),
        "title": obj.title,
        "summary": obj.summary,
        "body_markdown": obj.body_markdown or "",
        "audience": obj.audience,
        "target_scope_mode": getattr(obj, "target_scope_mode", "INSTITUTION_WIDE"),
        "target_campus": getattr(obj, "target_campus", None),
        "target_college": getattr(obj, "target_college", None),
        "target_department": getattr(obj, "target_department", None),
        "target_program": getattr(obj, "target_program", None),
    }
    for name in ("featured", "publish_start", "publish_end", "dashboard_preview_enabled", "category", "resource_type", "external_url"):
        if hasattr(obj, name):
            value = getattr(obj, name)
            fields[name] = value.isoformat() if hasattr(value, "isoformat") else value
    for name in ("guide_key", "version_label", "effective_date", "entries_json", "readiness_metadata_json"):
        if hasattr(obj, name):
            value = getattr(obj, name)
            if name == "effective_date" and value:
                value = value.isoformat()
            fields[name] = value
    if hasattr(obj, "owner_office_id"):
        fields["owner_office_id"] = str(obj.owner_office_id) if obj.owner_office_id else None
    return fields


def _target_content_type(obj):
    return ContentType.objects.get_for_model(obj, for_concrete_model=False)


def _next_revision_number(obj):
    return (ContentRevision.objects.filter(
        content_type=_target_content_type(obj), object_id=str(obj.pk)
    ).order_by("-revision_number").values_list("revision_number", flat=True).first() or 0) + 1


def _create_revision(obj, user, *, status, supersedes=None, reviewed=False, published=False):
    body_markdown = obj.body_markdown or ""
    revision = ContentRevision.objects.create(
        content_type=_target_content_type(obj),
        object_id=str(obj.pk),
        revision_number=_next_revision_number(obj),
        status=status,
        snapshot=_snapshot(obj),
        body_markdown=body_markdown,
        body_html_sanitized=render_markdown(body_markdown),
        renderer_version=RENDERER_VERSION,
        supersedes=supersedes,
        created_by=user,
        reviewed_by=user if reviewed else None,
        reviewed_at=timezone.now() if reviewed else None,
        published_by=user if published else None,
        published_at=timezone.now() if published else None,
    )
    return revision


def _apply_snapshot(obj, snapshot, html_output, user):
    for name in ("slug", "page_key", "title", "summary", "body_markdown", "audience", "target_scope_mode", "target_campus", "target_college", "target_department", "target_program", "featured", "publish_start", "publish_end", "dashboard_preview_enabled", "category", "resource_type", "external_url"):
        if name not in snapshot or not hasattr(obj, name):
            continue
        value = snapshot[name]
        if name in {"publish_start", "publish_end"} and value:
            value = timezone.datetime.fromisoformat(value)
        setattr(obj, name, value)
    for name in ("guide_key", "version_label", "entries_json", "readiness_metadata_json"):
        if name in snapshot and hasattr(obj, name):
            setattr(obj, name, snapshot[name])
    if "effective_date" in snapshot and hasattr(obj, "effective_date"):
        value = snapshot["effective_date"]
        if value:
            value = timezone.datetime.fromisoformat(value).date()
        setattr(obj, "effective_date", value)
    if "owner_office_id" in snapshot and hasattr(obj, "owner_office_id"):
        setattr(obj, "owner_office_id", snapshot["owner_office_id"] or None)
    obj.body_html_sanitized = html_output
    obj.renderer_version = RENDERER_VERSION
    obj.updated_by = user


def _save_new_or_draft(obj, user, *, status=None):
    if isinstance(obj, ServiceGuide):
        from apps.content.service_guide import compute_service_guide_readiness
        obj.readiness_metadata_json = compute_service_guide_readiness(obj.entries_json, obj)
    validate_model(obj)
    obj.save()
    revision_status = {
        ContentStatus.SCHEDULED: RevisionStatus.SCHEDULED,
        ContentStatus.ARCHIVED: RevisionStatus.ARCHIVED,
    }.get(status or obj.status, RevisionStatus.DRAFT)
    revision = _create_revision(obj, user, status=revision_status)
    if status == ContentStatus.PUBLISHED or obj.status == ContentStatus.PUBLISHED:
        revision.status = RevisionStatus.PUBLISHED
        revision.published_by = user
        revision.published_at = timezone.now()
        # ContentRevision is immutable; create the published snapshot directly
        # by making the initial revision published in the first place.
        raise AssertionError("published creation must use _publish_object")
    return revision


def _apply_values(obj, values: dict):
    for name in ("slug", "title", "summary", "body_markdown", "audience", "target_scope_mode", "target_campus", "target_college", "target_department", "target_program", "featured", "publish_start", "publish_end", "dashboard_preview_enabled", "category", "resource_type", "external_url", "page_key", "version_label", "effective_date", "owner_office", "owner_office_id", "entries_json"):
        if name in values and hasattr(obj, name):
            setattr(obj, name, values[name])
    return obj


def _candidate(obj, command):
    return _apply_values(obj, command.to_fields())


def _locked_content(model, object_id):
    obj = model.objects.select_for_update().filter(pk=object_id).first()
    if obj is None:
        raise NotFoundError()
    return obj


def _require_active_actor(user):
    if not is_active_nonlegacy_actor(user):
        raise PermissionDenied()
    return user


def _publish_object(obj, user, *, supersedes=None):
    if isinstance(obj, ServiceGuide):
        from apps.content.service_guide import compute_service_guide_readiness
        obj.readiness_metadata_json = compute_service_guide_readiness(obj.entries_json, obj)
    obj.body_html_sanitized = render_markdown(obj.body_markdown)
    obj.renderer_version = RENDERER_VERSION
    obj.status = ContentStatus.PUBLISHED
    obj.published_by = user
    obj.published_at = timezone.now()
    obj.updated_by = user
    validate_model(obj)
    obj.save()
    revision = _create_revision(
        obj,
        user,
        status=RevisionStatus.PUBLISHED,
        supersedes=supersedes,
        reviewed=can_publish_content(user, obj),
        published=True,
    )
    obj.published_revision = revision
    obj.save(update_fields=["published_revision", "updated_at"])
    return revision


def _create_content(user, model, command, *, action_type):
    values = command.to_fields()
    if model in {ContentPage, ServiceGuide} and not _can_prepare_model(user, model):
        raise PermissionDenied("You do not have permission to manage content.")
    if model is ServiceGuide and ServiceGuide.objects.filter(guide_key="public-service-guide").exists():
        raise ValidationError("The public service guide is a singleton; edit its existing draft.")
    model_field_names = {
        name
        for field in model._meta.fields
        for name in (field.name, field.attname)
    }
    defaults = {name: value for name, value in values.items() if name in model_field_names}
    defaults.pop("status", None)
    defaults["body_markdown"] = command.get("body_markdown", "")
    defaults.update(created_by=user, updated_by=user)
    obj = model(**defaults)
    if not _can_prepare_model(user, model, obj):
        raise PermissionDenied("You do not have permission to manage content.")
    requested_status = command.get("status", ContentStatus.DRAFT)
    if requested_status == ContentStatus.PUBLISHED:
        if not can_publish_content(user, obj):
            raise PermissionDenied("You do not have publication authority for this target.")
        validate_model(obj)
        obj.save()
        _publish_object(obj, user)
    elif requested_status == ContentStatus.SCHEDULED:
        if not can_schedule_content(user, obj):
            raise PermissionDenied("You do not have scheduling authority for this target.")
        obj.status = requested_status
        _schedule_object(obj, user)
    else:
        obj.status = requested_status
        _save_new_or_draft(obj, user, status=requested_status)
    audit_log(
        action_type=action_type,
        event_category="CONTENT",
        target_model=f"content.{model.__name__}",
        target_object_id=str(obj.pk),
        actor_user=user,
        source_app="content",
        metadata={"status": obj.status, "revision_safe": True},
    )
    return obj


@transaction.atomic
def seed_demo_content(model, command: ContentSeedCommand):
    """Insert controlled demo content without bypassing publication safety.

    This is intentionally not a user-facing authorization path.  New demo
    rows receive the same sanitized derivative and immutable published
    snapshot as normal publication.  Existing published rows are never
    silently overwritten: changed seed values become a review revision while
    the current public version remains intact.
    """
    if model not in {Announcement, Resource, ContentPage}:
        raise ValueError("Demo seeding is limited to public page, announcement, and resource content.")
    if not isinstance(command, ContentSeedCommand):
        raise ValidationError("Content seeding requires a ContentSeedCommand.")
    values = command.to_fields()
    lookup_field = "page_key" if model is ContentPage else "slug"
    lookup_value = command.get(lookup_field)
    if not lookup_value:
        raise ValidationError(f"Seeded {model.__name__} content requires a {lookup_field}.")

    current = model.objects.select_for_update().filter(**{lookup_field: lookup_value}).first()
    model_field_names = {
        name
        for field in model._meta.fields
        for name in (field.name, field.attname)
    }
    defaults = {
        name: value
        for name, value in values.items()
        if name in model_field_names
    }
    defaults.pop("status", None)
    defaults["body_markdown"] = command.get("body_markdown", "")

    if current is None:
        obj = model(**defaults)
        obj.status = ContentStatus.PUBLISHED
        obj.body_html_sanitized = render_markdown(obj.body_markdown)
        obj.renderer_version = RENDERER_VERSION
        obj.published_at = timezone.now()
        validate_model(obj)
        obj.save()
        revision = _create_revision(obj, None, status=RevisionStatus.PUBLISHED, published=True)
        obj.published_revision = revision
        obj.save(update_fields=["published_revision", "updated_at"])
        audit_log(
            action_type="DEMO_CONTENT_PUBLISHED",
            event_category="CONTENT",
            target_model=f"content.{model.__name__}",
            target_object_id=str(obj.pk),
            actor_user=None,
            source_app="content",
            metadata={"status": obj.status, "revision_id": str(revision.pk), "seeded_demo": True},
        )
        return obj, True

    candidate = model.objects.get(pk=current.pk)
    _apply_values(candidate, defaults)
    candidate.status = ContentStatus.PUBLISHED
    candidate.body_html_sanitized = render_markdown(candidate.body_markdown)
    candidate.renderer_version = RENDERER_VERSION
    candidate.published_at = current.published_at or timezone.now()
    validate_model(candidate)
    candidate_snapshot = _snapshot(candidate)
    published_revision = current.published_revision
    revision_matches = bool(
        published_revision
        and published_revision.status == RevisionStatus.PUBLISHED
        and published_revision.body_markdown == candidate.body_markdown
        and published_revision.snapshot == candidate_snapshot
    )

    if current.status == ContentStatus.PUBLISHED and revision_matches:
        if (
            current.body_html_sanitized != candidate.body_html_sanitized
            or current.renderer_version != RENDERER_VERSION
        ):
            current.body_html_sanitized = candidate.body_html_sanitized
            current.renderer_version = RENDERER_VERSION
            current.save(update_fields=["body_html_sanitized", "renderer_version", "updated_at"])
        return current, False

    if current.status == ContentStatus.PUBLISHED:
        existing_review = ContentRevision.objects.filter(
            content_type=_target_content_type(current),
            object_id=str(current.pk),
            status=RevisionStatus.REVIEW,
            body_markdown=candidate.body_markdown,
            snapshot=candidate_snapshot,
        ).first()
        if existing_review is None:
            revision = _create_revision(
                candidate,
                None,
                status=RevisionStatus.REVIEW,
                supersedes=current.published_revision,
            )
            audit_log(
                action_type="DEMO_CONTENT_REVIEW_QUEUED",
                event_category="CONTENT",
                target_model=f"content.{model.__name__}",
                target_object_id=str(current.pk),
                actor_user=None,
                source_app="content",
                metadata={"revision_id": str(revision.pk), "seeded_demo": True},
            )
        return current, False

    # Do not turn a pre-existing operator draft into an implicit publication.
    # Keep it untouched and record the seeded candidate for explicit review.
    existing_review = ContentRevision.objects.filter(
        content_type=_target_content_type(current),
        object_id=str(current.pk),
        status=RevisionStatus.REVIEW,
        body_markdown=candidate.body_markdown,
        snapshot=candidate_snapshot,
    ).first()
    if existing_review is None:
        _create_revision(candidate, None, status=RevisionStatus.REVIEW, supersedes=current.published_revision)
    return current, False


@transaction.atomic
def create_announcement(user, command: AnnouncementCreateCommand):
    _require_active_actor(user)
    if not isinstance(command, AnnouncementCreateCommand):
        raise ValidationError("Announcements require an AnnouncementCreateCommand.")
    return _create_content(user, Announcement, command, action_type="ANNOUNCEMENT_CREATED")


@transaction.atomic
def update_announcement(user, announcement_id, command: AnnouncementUpdateCommand):
    if not isinstance(command, AnnouncementUpdateCommand):
        raise ValidationError("Announcements require an AnnouncementUpdateCommand.")
    return _update_content(user, announcement_id, command, model=Announcement, action_type="ANNOUNCEMENT_UPDATED")


@transaction.atomic
def publish_announcement(user, announcement_id):
    return _publish_existing(user, announcement_id, model=Announcement, action_type="ANNOUNCEMENT_PUBLISHED")


@transaction.atomic
def archive_announcement(user, announcement_id):
    return _archive_existing(user, announcement_id, model=Announcement, action_type="ANNOUNCEMENT_ARCHIVED")


@transaction.atomic
def create_resource(user, command: ResourceCreateCommand):
    _require_active_actor(user)
    if not isinstance(command, ResourceCreateCommand):
        raise ValidationError("Resources require a ResourceCreateCommand.")
    return _create_content(user, Resource, command, action_type="RESOURCE_CREATED")


@transaction.atomic
def update_resource(user, resource_id, command: ResourceUpdateCommand):
    if not isinstance(command, ResourceUpdateCommand):
        raise ValidationError("Resources require a ResourceUpdateCommand.")
    return _update_content(user, resource_id, command, model=Resource, action_type="RESOURCE_UPDATED")


@transaction.atomic
def publish_resource(user, resource_id):
    return _publish_existing(user, resource_id, model=Resource, action_type="RESOURCE_PUBLISHED")


@transaction.atomic
def archive_resource(user, resource_id):
    return _archive_existing(user, resource_id, model=Resource, action_type="RESOURCE_ARCHIVED")


def _update_content(user, object_id, command, *, model, action_type):
    _require_active_actor(user)
    current = _locked_content(model, object_id)
    candidate = model.objects.get(pk=current.pk)
    _candidate(candidate, command)
    if not _can_prepare_model(user, model, candidate):
        raise PermissionDenied("You do not have permission to manage content.")
    if isinstance(candidate, ServiceGuide):
        from apps.content.service_guide import compute_service_guide_readiness
        candidate.readiness_metadata_json = compute_service_guide_readiness(candidate.entries_json, candidate)
    if current.status == ContentStatus.PUBLISHED:
        validate_model(candidate)
        revision = _create_revision(candidate, user, status=RevisionStatus.REVIEW, supersedes=current.published_revision)
        current.updated_by = user
        current.save(update_fields=["updated_by", "updated_at"])
        audit_log(action_type=action_type, event_category="CONTENT", target_model=f"content.{model.__name__}", target_object_id=str(current.pk), actor_user=user, source_app="content", metadata={"status": current.status, "revision_status": revision.status, "published_immutable": True})
        return current
    candidate.status = command.get("status", current.status)
    if candidate.status == ContentStatus.PUBLISHED and not can_publish_content(user, candidate):
        raise PermissionDenied("You do not have publication authority for this target.")
    if candidate.status == ContentStatus.SCHEDULED and not can_schedule_content(user, candidate):
        raise PermissionDenied("You do not have scheduling authority for this target.")
    candidate.body_html_sanitized = render_markdown(candidate.body_markdown)
    candidate.renderer_version = RENDERER_VERSION
    candidate.updated_by = user
    validate_model(candidate)
    candidate.save()
    _create_revision(candidate, user, status=RevisionStatus.SCHEDULED if candidate.status == ContentStatus.SCHEDULED else RevisionStatus.DRAFT)
    audit_log(action_type=action_type, event_category="CONTENT", target_model=f"content.{model.__name__}", target_object_id=str(candidate.pk), actor_user=user, source_app="content", metadata={"status": candidate.status, "revision_safe": True})
    return candidate


def _publish_existing(user, object_id, *, model, action_type):
    _require_active_actor(user)
    current = _locked_content(model, object_id)
    if not can_publish_content(user, current):
        raise PermissionDenied("You do not have publication authority for this target.")
    latest = ContentRevision.objects.filter(content_type=_target_content_type(current), object_id=str(current.pk), status__in=[RevisionStatus.DRAFT, RevisionStatus.REVIEW, RevisionStatus.SCHEDULED]).order_by("-revision_number").first()
    supersedes = current.published_revision
    if latest:
        # Re-render the canonical Markdown even though the revision stores a
        # derived snapshot. This keeps publication safe if a legacy/admin path
        # ever tampered with the derived HTML column.
        _apply_snapshot(current, latest.snapshot, render_markdown(latest.body_markdown), user)
    revision = _publish_object(current, user, supersedes=supersedes)
    audit_log(action_type=action_type, event_category="CONTENT", target_model=f"content.{model.__name__}", target_object_id=str(current.pk), actor_user=user, source_app="content", metadata={"revision_id": str(revision.pk), "published_revision": True})
    return current


def _archive_existing(user, object_id, *, model, action_type):
    _require_active_actor(user)
    current = _locked_content(model, object_id)
    if not can_archive_content(user, current):
        raise PermissionDenied("You do not have archive authority for this target.")
    current.status = ContentStatus.ARCHIVED
    current.updated_by = user
    validate_model(current)
    current.save()
    _create_revision(current, user, status=RevisionStatus.ARCHIVED, supersedes=current.published_revision)
    audit_log(action_type=action_type, event_category="CONTENT", target_model=f"content.{model.__name__}", target_object_id=str(current.pk), actor_user=user, source_app="content", metadata={"status": current.status, "revision_safe": True})
    return current


@transaction.atomic
def create_content_page(user, command: ContentPageCreateCommand):
    _require_active_actor(user)
    if not isinstance(command, ContentPageCreateCommand):
        raise ValidationError("Content pages require a ContentPageCreateCommand.")
    return _create_content(user, ContentPage, command, action_type="CONTENT_PAGE_CREATED")


@transaction.atomic
def update_content_page(user, page_id, command: ContentPageUpdateCommand):
    if not isinstance(command, ContentPageUpdateCommand):
        raise ValidationError("Content pages require a ContentPageUpdateCommand.")
    return _update_content(user, page_id, command, model=ContentPage, action_type="CONTENT_PAGE_UPDATED")


@transaction.atomic
def publish_content_page(user, page_id):
    return _publish_existing(user, page_id, model=ContentPage, action_type="CONTENT_PAGE_PUBLISHED")


@transaction.atomic
def archive_content_page(user, page_id):
    return _archive_existing(user, page_id, model=ContentPage, action_type="CONTENT_PAGE_ARCHIVED")


@transaction.atomic
def create_service_guide(user, command: ServiceGuideCreateCommand):
    """Create the singleton guide draft through the governed authoring gate."""
    _require_active_actor(user)
    if not isinstance(command, ServiceGuideCreateCommand):
        raise ValidationError("Service guides require a ServiceGuideCreateCommand.")
    return _create_content(user, ServiceGuide, command, action_type="SERVICE_GUIDE_CREATED")


@transaction.atomic
def update_service_guide(user, guide_id, command: ServiceGuideUpdateCommand):
    if not isinstance(command, ServiceGuideUpdateCommand):
        raise ValidationError("Service guides require a ServiceGuideUpdateCommand.")
    return _update_content(user, guide_id, command, model=ServiceGuide, action_type="SERVICE_GUIDE_UPDATED")


@transaction.atomic
def publish_service_guide(user, guide_id):
    return _publish_existing(user, guide_id, model=ServiceGuide, action_type="SERVICE_GUIDE_PUBLISHED")


@transaction.atomic
def archive_service_guide(user, guide_id):
    return _archive_existing(user, guide_id, model=ServiceGuide, action_type="SERVICE_GUIDE_ARCHIVED")


@transaction.atomic
def schedule_service_guide(user, guide_id, command: ServiceGuideUpdateCommand | None = None):
    _require_active_actor(user)
    if command is not None and not isinstance(command, ServiceGuideUpdateCommand):
        raise ValidationError("Service guides require a ServiceGuideUpdateCommand.")
    current = _locked_content(ServiceGuide, guide_id)
    if not can_schedule_content(user, current):
        raise PermissionDenied("You do not have scheduling authority for this content.")
    candidate = ServiceGuide.objects.get(pk=current.pk)
    if command is not None:
        _candidate(candidate, command)
    return _schedule_object(candidate, user, supersedes=current.published_revision)


@transaction.atomic
def submit_content_for_review(user, content_type, object_id, command=None):
    """Save a candidate and create an immutable review revision."""
    _require_active_actor(user)
    model = {
        "announcement": Announcement,
        "resource": Resource,
        "page": ContentPage,
        "service_guide": ServiceGuide,
    }.get(str(content_type))
    if model is None:
        raise ValidationError("Unsupported content type.")
    expected_commands = {
        Announcement: AnnouncementUpdateCommand,
        Resource: ResourceUpdateCommand,
        ContentPage: ContentPageUpdateCommand,
        ServiceGuide: ServiceGuideUpdateCommand,
    }
    if command is not None and not isinstance(command, expected_commands[model]):
        raise ValidationError("The submitted command does not match the content type.")
    current = _locked_content(model, object_id)
    if not _can_prepare_model(user, model, current):
        raise PermissionDenied("You do not have permission to manage content.")
    candidate = model.objects.get(pk=current.pk)
    if command is not None:
        _candidate(candidate, command)
    if isinstance(candidate, ServiceGuide):
        from apps.content.service_guide import compute_service_guide_readiness
        candidate.readiness_metadata_json = compute_service_guide_readiness(candidate.entries_json, candidate)
    candidate.status = current.status if current.status != ContentStatus.PUBLISHED else current.status
    candidate.body_html_sanitized = render_markdown(candidate.body_markdown)
    candidate.renderer_version = RENDERER_VERSION
    candidate.updated_by = user
    if current.status != ContentStatus.PUBLISHED:
        validate_model(candidate)
        candidate.save()
    revision = _create_revision(candidate, user, status=RevisionStatus.REVIEW, supersedes=current.published_revision)
    audit_log(action_type="CONTENT_SUBMITTED_FOR_REVIEW", event_category="CONTENT", target_model=f"content.{model.__name__}", target_object_id=str(current.pk), actor_user=user, source_app="content", metadata={"revision_id": str(revision.pk), "status": revision.status})
    return current if current.status == ContentStatus.PUBLISHED else candidate


def _schedule_object(obj, user, *, supersedes=None):
    """Move a candidate to a future scheduled state with an immutable revision."""
    if not obj.publish_start or obj.publish_start <= timezone.now():
        raise ValidationError({"publish_start": "Scheduled content must start in the future."})
    obj.status = ContentStatus.SCHEDULED
    if isinstance(obj, ServiceGuide):
        from apps.content.service_guide import compute_service_guide_readiness
        obj.readiness_metadata_json = compute_service_guide_readiness(obj.entries_json, obj)
    obj.body_html_sanitized = render_markdown(obj.body_markdown)
    obj.renderer_version = RENDERER_VERSION
    obj.updated_by = user
    validate_model(obj)
    obj.save()
    revision = _create_revision(
        obj,
        user,
        status=RevisionStatus.SCHEDULED,
        supersedes=supersedes,
        reviewed=True,
    )
    audit_log(
        action_type="CONTENT_SCHEDULED",
        event_category="CONTENT",
        target_model=f"content.{obj.__class__.__name__}",
        target_object_id=str(obj.pk),
        actor_user=user,
        source_app="content",
        metadata={"revision_id": str(revision.pk), "status": obj.status, "reviewed": True},
    )
    return obj


@transaction.atomic
def schedule_announcement(user, announcement_id, command: AnnouncementUpdateCommand | None = None):
    _require_active_actor(user)
    current = _locked_content(Announcement, announcement_id)
    candidate = Announcement.objects.get(pk=current.pk)
    if command is not None:
        _candidate(candidate, command)
    if not can_schedule_content(user, candidate):
        raise PermissionDenied("You do not have scheduling authority for this target.")
    return _schedule_object(candidate, user, supersedes=current.published_revision)


@transaction.atomic
def schedule_resource(user, resource_id, command: ResourceUpdateCommand | None = None):
    _require_active_actor(user)
    current = _locked_content(Resource, resource_id)
    candidate = Resource.objects.get(pk=current.pk)
    if command is not None:
        _candidate(candidate, command)
    if not can_schedule_content(user, candidate):
        raise PermissionDenied("You do not have scheduling authority for this target.")
    return _schedule_object(candidate, user, supersedes=current.published_revision)


def _notify_staff_of_submission(submission):
    """Register one transactional event for the current Head Guidance queue."""
    from apps.notifications.dispatch import enqueue_notification_event

    enqueue_notification_event(
        "content.contact_submission",
        {
            "submission_id": str(submission.pk),
            "action": "submitted",
            "status": "Received",
        },
        related_object=submission,
        event_key=f"content:contact_submission:{submission.pk}",
    )


def get_contact_submission_for_idempotency(command: ContactSubmissionCommand, idempotency_key):
    """Return an exact immutable retry or raise a safe content conflict.

    This lookup is intentionally separate from the create transaction so a
    client retry can be recognized before abuse evaluation.  It never returns
    or persists the raw idempotency value; callers receive only the existing
    submission reference through the normal success flow.
    """
    if not idempotency_key:
        return None
    idempotency_hash = _contact_hmac(
        _normalize_identifier(idempotency_key, max_length=512)
    )
    existing = PublicContactSubmission.objects.filter(
        idempotency_key_hash=idempotency_hash,
    ).first()
    if not existing:
        return None
    if existing.duplicate_fingerprint != _duplicate_fingerprint(command):
        raise ValidationError("This submission could not be retried safely.")
    existing._contact_idempotency_reused = True
    return existing


@transaction.atomic
def create_contact_submission(
    command: ContactSubmissionCommand,
    submitted_by=None,
    source_ip=None,
    user_agent=None,
    idempotency_key=None,
):
    """Process a public contact submission, including hashing PII, duplicate checks, and alerting."""
    if not isinstance(command, ContactSubmissionCommand):
        raise ValidationError("Contact submissions require a ContactSubmissionCommand.")
    # 1. Enforce privacy acknowledgement early
    if not command.privacy_acknowledged:
        raise ValidationError(
            {"privacy_acknowledged": "You must acknowledge the privacy notice to submit."}
        )
    if not command.urgent_support_disclaimer_acknowledged:
        raise ValidationError(
            {
                "urgent_support_disclaimer_acknowledged": (
                    "You must acknowledge that this form is not for urgent or emergency support."
                )
            }
        )

    submission_type = command.submission_type or SubmissionType.INQUIRY
    if not isinstance(command.message_body, str):
        raise ValidationError({"message_body": "Message must be text."})
    try:
        message_body_size = len(command.message_body.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise ValidationError({"message_body": "Message contains invalid text."}) from error
    if message_body_size > CONTACT_MESSAGE_MAX_PLAINTEXT_BYTES:
        raise ValidationError({"message_body": "Message is too long."})
    if idempotency_key:
        idempotency_key = validate_and_lock_request_key(
            RequestKeyPolicy("content.public_contact", max_length=512),
            idempotency_key,
        )
    email = (command.email or "").strip()
    if command.email is not None and submission_type in {
        SubmissionType.INQUIRY,
        SubmissionType.CONCERN,
        SubmissionType.OTHER,
    } and not email:
        raise ValidationError({
            "email": "An email address is required for this type of message so the office can reply."
        })

    # 2. Hash sensitive technical details
    ip_hash = _contact_hmac(_normalize_identifier(source_ip)) if source_ip else None
    ua_hash = _contact_hmac(_normalize_identifier(user_agent, max_length=512)) if user_agent else None

    # 3. Compute duplicate fingerprint (subject + message_body + email + affiliation)
    fingerprint = _duplicate_fingerprint(command)

    idempotency_hash = _contact_hmac(_normalize_identifier(idempotency_key, max_length=512)) if idempotency_key else None
    existing_idempotent = get_contact_submission_for_idempotency(command, idempotency_key)
    if existing_idempotent:
        return existing_idempotent

    # 4. Check for duplicate within 5 minutes
    now = timezone.now()
    window_start = now - timezone.timedelta(minutes=5)
    existing_duplicate = PublicContactSubmission.objects.filter(
        duplicate_fingerprint=fingerprint,
        created_at__gte=window_start,
    ).first()

    status = SubmissionStatus.NEW
    if existing_duplicate:
        status = SubmissionStatus.DUPLICATE

    # 5. Generate an immutable, non-PII CNT reference code for every submission.
    from apps.content.reference_codes import generate_contact_reference_code
    from apps.organizations.academic_year import resolve_current_academic_year

    try:
        academic_year = resolve_current_academic_year()
    except Exception as exc:
        raise ValidationError("The current academic year is not configured.") from exc
    try:
        ref_code = generate_contact_reference_code(academic_year)
    except Exception as exc:
        raise ValidationError(
            f"Could not generate contact reference code: {exc}"
        ) from exc

    # 6. Save record
    submission = PublicContactSubmission(
        reference_code=ref_code,
        submission_type=submission_type,
        name=command.name,
        email=email or None,
        phone=command.phone,
        affiliation=command.affiliation or "visitor",
        subject=command.subject,
        # The legacy plaintext column is a staged migration source only.
        # New intake is written to the authenticated field below.
        message_body="",
        message_body_encrypted=command.message_body,
        privacy_acknowledged=True,
        urgent_support_disclaimer_acknowledged=command.urgent_support_disclaimer_acknowledged,
        status=status,
        source_ip_hash=ip_hash,
        user_agent_hash=ua_hash,
        duplicate_fingerprint=fingerprint,
        idempotency_key_hash=idempotency_hash,
        submitted_by=submitted_by,
    )
    validate_model(submission)
    try:
        with transaction.atomic():
            submission.save()
    except IntegrityError:
        # A concurrent retry may win the unique HMAC key race.  Reuse only
        # the immutable row whose fingerprint matches; never expose details.
        if not idempotency_hash:
            raise
        existing_idempotent = PublicContactSubmission.objects.filter(
            idempotency_key_hash=idempotency_hash,
        ).first()
        if not existing_idempotent or existing_idempotent.duplicate_fingerprint != fingerprint:
            raise ValidationError("This submission could not be retried safely.")
        existing_idempotent._contact_idempotency_reused = True
        return existing_idempotent

    # privacy.boundary records the exact public-contact notice revision in the same
    # transaction as the submission.  The event stores only HMAC-safe
    # references; the message, email, and request body never enter governance
    # metadata.
    from apps.orchestration.commands import PrivacyAcceptanceCommand
    from apps.orchestration.use_cases import record_privacy_acceptance_for_composition

    record_privacy_acceptance_for_composition(
        submitted_by,
        PrivacyAcceptanceCommand(
            notice_identifier="compass-gco-privacy",
            purpose_workflow="compass_public",
            subject_reference=f"contact:{submission.pk}",
            source_route="api",
        ),
    )

    # 7. Write a privacy-safe audit log (exclude message body, email, raw IP, etc.)
    audit_log(
        action_type="CONTACT_SUBMISSION_RECEIVED",
        event_category="WORKFLOW",
        target_model="content.PublicContactSubmission",
        target_object_id=str(submission.pk),
        actor_user=submitted_by,
        reference_code=submission.reference_code or "",
        source_app="content",
        metadata={
            "submission_type": submission.submission_type,
            "status": submission.status,
        },
    )

    # 8. Notify staff if it's not a duplicate
    if submission.status != SubmissionStatus.DUPLICATE:
        _notify_staff_of_submission(submission)

    return submission


def _locked_submission(submission_id):
    submission = PublicContactSubmission.objects.select_for_update().filter(pk=submission_id).first()
    if submission is None:
        raise NotFoundError()
    return submission


def _locked_reply(reply_id):
    reply = ContactReply.objects.select_for_update().select_related("submission").filter(pk=reply_id).first()
    if reply is None:
        raise NotFoundError()
    return reply


@transaction.atomic
def assign_submission(user, submission_id, command: ContactAssignmentCommand):
    """Assign one contact submission using a stable target ID."""
    _require_active_actor(user)
    if not isinstance(command, ContactAssignmentCommand):
        raise ValidationError("Assignments require a ContactAssignmentCommand.")
    submission = _locked_submission(submission_id)
    if not can_manage_contact_admin(user, submission):
        raise PermissionDenied("You do not have permission to manage contact submissions.")

    assignee = None
    if command.assignee_id is not None:
        from apps.accounts.models import User
        assignee = User.objects.filter(pk=command.assignee_id).first()
        if not assignee or not getattr(assignee, "is_active", False) or not is_counselor(assignee):
            raise ValidationError("Contact submissions may only be assigned to an active counselor.")

    submission.assigned_to = assignee
    submission.status = SubmissionStatus.ASSIGNED
    validate_model(submission)
    submission.save()

    audit_log(
        action_type="CONTACT_SUBMISSION_ASSIGNED",
        event_category="WORKFLOW",
        target_model="content.PublicContactSubmission",
        target_object_id=str(submission.pk),
        actor_user=user,
        reference_code=submission.reference_code or "",
        source_app="content",
        metadata={
            "assigned_to_id": str(assignee.id) if assignee else None,
        },
    )
    return submission


@transaction.atomic
def update_submission_status(user, submission_id, command: ContactStatusCommand):
    """Change one contact submission status using a stable target ID."""
    _require_active_actor(user)
    if not isinstance(command, ContactStatusCommand):
        raise ValidationError("Status changes require a ContactStatusCommand.")
    submission = _locked_submission(submission_id)
    new_status = command.status
    if not can_manage_contact_admin(user, submission):
        raise PermissionDenied("You do not have permission to manage contact submissions.")

    if new_status not in SubmissionStatus.values:
        raise ValidationError("Invalid status value.")

    if new_status in {
        SubmissionStatus.RESPONDED,
        SubmissionStatus.NO_RESPONSE_REQUIRED,
        SubmissionStatus.RESPONSE_EVIDENCE_MISSING,
    }:
        raise ValidationError("Use the correspondence or no-response action for this state.")

    old_status = submission.status
    submission.status = new_status
    if new_status in {
        SubmissionStatus.ARCHIVED,
        SubmissionStatus.RESPONSE_EVIDENCE_MISSING,
    }:
        submission.privacy_actioned_at = timezone.now()
    validate_model(submission)
    submission.save()

    audit_log(
        action_type="CONTACT_SUBMISSION_STATUS_CHANGED",
        event_category="WORKFLOW",
        target_model="content.PublicContactSubmission",
        target_object_id=str(submission.pk),
        actor_user=user,
        reference_code=submission.reference_code or "",
        source_app="content",
        metadata={
            "old_status": old_status,
            "new_status": new_status,
        },
    )
    return submission


def _reply_recipient_hash(email: str) -> str:
    return _contact_hmac((email or "").strip().lower()) or ""


@transaction.atomic
def create_contact_reply(user, submission_id, command: ContactReplyCommand):
    """Create a draft reply within assignment scope."""
    _require_active_actor(user)
    if not isinstance(command, ContactReplyCommand):
        raise ValidationError("Replies require a ContactReplyCommand.")
    submission = _locked_submission(submission_id)
    if not can_manage_contact_submissions(user, submission):
        raise PermissionDenied("You do not have permission to draft this correspondence.")
    if not submission.email:
        raise ValidationError("This submission has no email reply channel.")
    body = str(command.body or "")
    if not body.strip() or len(body) > 20_000:
        raise ValidationError("Reply text is required and must be within the safe limit.")
    reply = ContactReply.objects.create(
        submission=submission,
        reply_body_encrypted=body,
        subject="COMPASS contact response",
        channel="email",
        recipient_channel_hash=_reply_recipient_hash(submission.email),
        author=user,
        status=ContactReplyStatus.DRAFT,
    )
    audit_log(
        action_type="CONTACT_REPLY_DRAFTED",
        event_category="WORKFLOW",
        target_model="content.ContactReply",
        target_object_id=str(reply.pk),
        actor_user=user,
        reference_code=submission.reference_code or "",
        source_app="content",
        metadata={"status": reply.status, "channel": "email"},
    )
    return reply


@transaction.atomic
def update_contact_reply_draft(user, reply_id, command: ContactReplyCommand):
    """Edit an existing draft without changing its author or recipient hash."""
    _require_active_actor(user)
    if not isinstance(command, ContactReplyCommand):
        raise ValidationError("Replies require a ContactReplyCommand.")
    reply = _locked_reply(reply_id)
    if not can_manage_contact_reply(user, reply):
        raise PermissionDenied("You do not have permission to edit this correspondence.")
    if reply.status != ContactReplyStatus.DRAFT or reply.frozen_at is not None:
        raise ValidationError("Only an unfrozen draft can be edited.")
    body = str(command.body or "")
    if not body.strip() or len(body) > 20_000:
        raise ValidationError("Reply text is required and must be within the safe limit.")
    reply.reply_body_encrypted = body
    reply.save(update_fields=["reply_body_encrypted", "updated_at"])
    audit_log(
        action_type="CONTACT_REPLY_DRAFT_UPDATED",
        event_category="WORKFLOW",
        target_model="content.ContactReply",
        target_object_id=str(reply.pk),
        actor_user=user,
        reference_code=reply.submission.reference_code or "",
        source_app="content",
        metadata={"status": reply.status, "channel": "email"},
    )
    return reply


@transaction.atomic
def submit_contact_reply_for_approval(user, reply_id, command: ContactReplyCommand | None = None):
    _require_active_actor(user)
    reply = _locked_reply(reply_id)
    if not can_manage_contact_reply(user, reply):
        raise PermissionDenied("You do not have permission to submit this correspondence.")
    if reply.status not in {ContactReplyStatus.DRAFT, ContactReplyStatus.PENDING_APPROVAL}:
        raise ValidationError("This reply is no longer editable.")
    if command is not None:
        if not isinstance(command, ContactReplyCommand):
            raise ValidationError("Replies require a ContactReplyCommand.")
        body = str(command.body or "")
        if not body.strip():
            raise ValidationError("Reply text is required.")
        reply.reply_body_encrypted = body
    if not reply.submission.email:
        raise ValidationError("The immutable submission has no email reply channel.")
    reply.recipient_channel_hash = _reply_recipient_hash(reply.submission.email)
    reply.status = ContactReplyStatus.PENDING_APPROVAL
    reply.save(update_fields=["reply_body_encrypted", "recipient_channel_hash", "status", "updated_at"])
    audit_log(
        action_type="CONTACT_REPLY_SUBMITTED_FOR_APPROVAL",
        event_category="WORKFLOW",
        target_model="content.ContactReply",
        target_object_id=str(reply.pk),
        actor_user=user,
        reference_code=reply.submission.reference_code or "",
        source_app="content",
        metadata={"status": reply.status},
    )
    return reply


@transaction.atomic
def approve_contact_reply(user, reply_id):
    _require_active_actor(user)
    reply = _locked_reply(reply_id)
    if not can_transition_contact_reply(user, reply, ContactReplyStatus.APPROVED):
        raise PermissionDenied("Only Head Guidance may approve correspondence.")
    if reply.status not in {ContactReplyStatus.PENDING_APPROVAL, ContactReplyStatus.DRAFT}:
        raise ValidationError("Only a draft or pending reply can be approved.")
    if not reply.submission.email:
        raise ValidationError("The immutable submission email is no longer available.")
    reply.recipient_channel_hash = _reply_recipient_hash(reply.submission.email)
    reply.approved_by = user
    reply.approved_at = timezone.now()
    reply.frozen_at = timezone.now()
    reply.approval_evidence_json = {
        "self_approved": bool(reply.author_id == user.id),
        "channel": "email",
        "recipient_revalidated": True,
    }
    reply.status = ContactReplyStatus.APPROVED
    reply.save(update_fields=[
        "recipient_channel_hash", "approved_by", "approved_at", "frozen_at",
        "approval_evidence_json", "status", "updated_at",
    ])
    from apps.workflow.services import enqueue_outbox_event
    enqueue_outbox_event(
        event_type="content.contact_reply",
        payload={"reply_id": str(reply.pk)},
        related_object=reply,
        event_key=f"content:contact_reply:{reply.pk}",
    )
    audit_log(
        action_type="CONTACT_REPLY_APPROVED",
        event_category="WORKFLOW",
        target_model="content.ContactReply",
        target_object_id=str(reply.pk),
        actor_user=user,
        reference_code=reply.submission.reference_code or "",
        source_app="content",
        metadata={"status": reply.status, "self_approved": reply.author_id == user.id},
    )
    return reply


@transaction.atomic
def reject_contact_reply(user, reply_id):
    _require_active_actor(user)
    reply = _locked_reply(reply_id)
    if not can_transition_contact_reply(user, reply, ContactReplyStatus.REJECTED):
        raise PermissionDenied("You do not have permission to reject correspondence.")
    if reply.status not in {ContactReplyStatus.DRAFT, ContactReplyStatus.PENDING_APPROVAL}:
        raise ValidationError("This reply cannot be rejected in its current state.")
    reply.status = ContactReplyStatus.REJECTED
    reply.save(update_fields=["status", "updated_at"])
    return reply


@transaction.atomic
def cancel_contact_reply(user, reply_id):
    _require_active_actor(user)
    reply = _locked_reply(reply_id)
    if not can_transition_contact_reply(user, reply, ContactReplyStatus.CANCELLED):
        raise PermissionDenied("Only Head Guidance may cancel correspondence.")
    if reply.status in {ContactReplyStatus.SENT, ContactReplyStatus.CANCELLED}:
        raise ValidationError("A sent or cancelled reply cannot be cancelled again.")
    reply.status = ContactReplyStatus.CANCELLED
    reply.save(update_fields=["status", "updated_at"])
    if reply.delivery_id:
        from apps.orchestration.commands import ContactReplyDeliveryCancellationCommand
        from apps.orchestration.use_cases import cancel_contact_reply_delivery_for_composition

        cancel_contact_reply_delivery_for_composition(
            actor=user,
            command=ContactReplyDeliveryCancellationCommand(delivery_id=reply.delivery_id),
        )
    return reply


@transaction.atomic
def retry_contact_reply(user, reply_id):
    _require_active_actor(user)
    reply = _locked_reply(reply_id)
    if not can_manage_contact_reply(user, reply):
        raise PermissionDenied("You do not have permission to retry correspondence.")
    if reply.status != ContactReplyStatus.DELIVERY_FAILED or not reply.delivery_id:
        raise ValidationError("Only a delivery-failed reply can be retried.")
    from apps.orchestration.commands import ContactReplyDeliveryCommand
    from apps.orchestration.use_cases import retry_contact_reply_delivery
    delivery = retry_contact_reply_delivery(
        user,
        ContactReplyDeliveryCommand(str(reply.delivery_id)),
    )
    reply.status = ContactReplyStatus.QUEUED
    reply.delivery_state = delivery.delivery_state
    reply.save(update_fields=["status", "delivery_state", "updated_at"])
    return reply


@transaction.atomic
def record_contact_no_response(user, submission_id, command: ContactNoResponseCommand):
    _require_active_actor(user)
    if not isinstance(command, ContactNoResponseCommand):
        raise ValidationError("No-response closure requires a ContactNoResponseCommand.")
    submission = _locked_submission(submission_id)
    reason_code = command.reason_code
    detail = command.detail
    if not can_manage_contact_admin(user, submission):
        raise PermissionDenied("You do not have permission to close this contact submission.")
    if reason_code not in ContactNoResponseReason.values:
        raise ValidationError("Unsupported no-response reason.")
    if submission.replies.filter(status=ContactReplyStatus.SENT).exists():
        raise ValidationError("A sent reply cannot be closed as No response required.")
    disposition = ContactNoResponseDisposition.objects.create(
        submission=submission,
        reason_code=reason_code,
        detail_encrypted=detail or None,
        recorded_by=user,
    )
    submission.status = SubmissionStatus.NO_RESPONSE_REQUIRED
    submission.privacy_actioned_at = timezone.now()
    submission.save(update_fields=["status", "privacy_actioned_at", "updated_at"])
    audit_log(
        action_type="CONTACT_NO_RESPONSE_RECORDED",
        event_category="WORKFLOW",
        target_model="content.ContactNoResponseDisposition",
        target_object_id=str(disposition.pk),
        actor_user=user,
        reference_code=submission.reference_code or "",
        source_app="content",
        metadata={"reason_code": reason_code},
    )
    return disposition
