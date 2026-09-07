from django.utils import timezone
from django.db.models import Q
from django.contrib.contenttypes.models import ContentType
from apps.common.rich_text import RichTextValidationError, render_rich_text
from apps.common.exceptions import PermissionDeniedError as PermissionDenied
from apps.access_control.rules import is_active_nonlegacy_actor, is_counselor, is_gco_staff, is_student
from apps.access_control.capabilities import Capability
from apps.access_control.scopes import build_geographic_scope_q, build_workflow_authority_scope_q, get_live_counselor_coverages
from apps.content.models import (
    Announcement,
    ContentPage,
    Resource,
    ServiceGuide,
    PublicContactSubmission,
    ContentStatus,
    ContentRevision,
    AudienceChoices, TargetScopeChoices,
    RENDERER_VERSION,
    RevisionStatus,
)
from apps.content.policies import (
    can_manage_content,
    can_manage_contact_submissions,
    can_view_content_workspace,
    _target_visible,
)


def get_contact_alert_recipients():
    """Return the active Head Guidance recipients for public-contact alerts."""
    from apps.accounts.models import RoleChoices, User

    return User.objects.filter(
        role=RoleChoices.COUNSELOR,
        counselor_profile__is_head_guidance=True,
        is_active=True,
    )


def _content_target_q(user) -> Q:
    """Return target containment for a model queryset."""
    institution = Q(target_scope_mode=TargetScopeChoices.INSTITUTION_WIDE)
    if is_student(user):
        profile = getattr(user, "student_profile", None)
        if not profile:
            return institution
        local = Q(target_scope_mode=TargetScopeChoices.ORGANIZATION)
        for field in ("campus", "college", "department", "program"):
            value = getattr(profile, field, None)
            if value:
                local &= Q(**{f"target_{field}__in": [value, None, ""]})
        return institution | local
    if is_counselor(user):
        scopes = get_live_counselor_coverages(user)
        local = None
        for scope in scopes:
            item = Q(target_scope_mode=TargetScopeChoices.ORGANIZATION)
            for field in ("campus", "college", "department", "program"):
                value = getattr(scope, field, None)
                if value:
                    item &= Q(**{f"target_{field}__in": [value, None, ""]})
            local = item if local is None else local | item
        return institution | (local or Q(pk__in=[]))
    if is_gco_staff(user):
        return institution | build_workflow_authority_scope_q(
            user, capability=Capability.CONTENT_LOCAL_VIEW,
            field_map={
                "campus": "target_campus", "college": "target_college",
                "department": "target_department", "program": "target_program",
            },
        )
    return institution if not user or not getattr(user, "is_authenticated", False) else Q(pk__in=[])


def get_published_announcements():
    """Return public announcements that are currently active and published."""
    now = timezone.now()
    queryset = Announcement.objects.select_related("published_revision").filter(
        status__in=[ContentStatus.PUBLISHED, ContentStatus.SCHEDULED],
        audience=AudienceChoices.PUBLIC,
    ).filter(target_scope_mode=TargetScopeChoices.INSTITUTION_WIDE).filter(
        Q(publish_start__isnull=True) | Q(publish_start__lte=now)
    ).filter(
        Q(publish_end__isnull=True) | Q(publish_end__gt=now)
    )
    return queryset


def get_published_resources():
    """Return public resources that are currently published and in-window."""
    now = timezone.now()
    queryset = Resource.objects.select_related("published_revision").filter(
        status__in=[ContentStatus.PUBLISHED, ContentStatus.SCHEDULED],
        audience=AudienceChoices.PUBLIC,
    ).filter(target_scope_mode=TargetScopeChoices.INSTITUTION_WIDE).filter(
        Q(publish_start__isnull=True) | Q(publish_start__lte=now)
    ).filter(
        Q(publish_end__isnull=True) | Q(publish_end__gt=now)
    )
    return queryset


def _populate_public_html(instance):
    """Project only freshly rendered HTML into a public response object.

    Stored derived HTML is deliberately not trusted at this boundary.  The
    canonical Markdown source is rendered through the single audited service
    on every public projection, including legacy/demo rows and rows whose
    derived field was modified outside the service layer.
    """
    published_revision = getattr(instance, "published_revision", None)
    source = instance.body_markdown or ""
    if (
        published_revision
        and published_revision.status == RevisionStatus.PUBLISHED
        and isinstance(published_revision.body_markdown, str)
    ):
        source = published_revision.body_markdown
    try:
        instance.body_html_sanitized = render_rich_text(source)
    except RichTextValidationError:
        # Approved status does not make malformed source safe to expose.
        return None
    instance.renderer_version = RENDERER_VERSION
    return instance


def get_published_content_page(page_key):
    """Return an approved public page, or ``None`` when unavailable."""
    page = ContentPage.objects.select_related("published_revision").filter(
        page_key=page_key,
        status=ContentStatus.PUBLISHED,
        audience=AudienceChoices.PUBLIC,
    ).first()
    if page is None:
        return None
    return _populate_public_html(page)


def get_content_page_by_key(page_key, user=None):
    if can_manage_content(user):
        return ContentPage.objects.filter(page_key=page_key).first()
    from apps.content.cache import get_cached_public_page

    return get_cached_public_page(page_key)


def get_visible_announcements_for_user(user):
    """Return all announcements visible to the given user based on their roles."""
    if can_manage_content(user):
        return Announcement.objects.all()

    now = timezone.now()
    # Build audience filter based on user roles
    audiences = [AudienceChoices.PUBLIC]
    if user and user.is_authenticated:
        audiences.append(AudienceChoices.ALL_AUTHENTICATED)
        if is_student(user):
            audiences.append(AudienceChoices.STUDENTS)
        if is_gco_staff(user) or is_counselor(user):
            audiences.append(AudienceChoices.STAFF)
        if is_counselor(user):
            audiences.append(AudienceChoices.COUNSELORS)

    return Announcement.objects.filter(
        status__in=[ContentStatus.PUBLISHED, ContentStatus.SCHEDULED],
        audience__in=audiences,
    ).filter(_content_target_q(user)).filter(
        Q(publish_start__isnull=True) | Q(publish_start__lte=now)
    ).filter(
        Q(publish_end__isnull=True) | Q(publish_end__gt=now)
    )


def get_visible_published_announcements_for_user(user):
    """Return only currently visible published content for a signed-in actor."""
    if not is_active_nonlegacy_actor(user):
        return Announcement.objects.none()
    now = timezone.now()
    audiences = [AudienceChoices.PUBLIC, AudienceChoices.ALL_AUTHENTICATED]
    if is_student(user):
        audiences.append(AudienceChoices.STUDENTS)
    if is_gco_staff(user) or is_counselor(user):
        audiences.append(AudienceChoices.STAFF)
    if is_counselor(user):
        audiences.append(AudienceChoices.COUNSELORS)
    return Announcement.objects.select_related("published_revision").filter(
        status__in=[ContentStatus.PUBLISHED, ContentStatus.SCHEDULED],
        audience__in=audiences,
    ).filter(_content_target_q(user)).filter(
        Q(publish_start__isnull=True) | Q(publish_start__lte=now)
    ).filter(
        Q(publish_end__isnull=True) | Q(publish_end__gt=now)
    )


def get_visible_resources_for_user(user):
    """Return all resources visible to the given user based on their roles."""
    if can_manage_content(user):
        return Resource.objects.all()

    now = timezone.now()
    # Build audience filter based on user roles
    audiences = [AudienceChoices.PUBLIC]
    if user and user.is_authenticated:
        audiences.append(AudienceChoices.ALL_AUTHENTICATED)
        if is_student(user):
            audiences.append(AudienceChoices.STUDENTS)
        if is_gco_staff(user) or is_counselor(user):
            audiences.append(AudienceChoices.STAFF)
        if is_counselor(user):
            audiences.append(AudienceChoices.COUNSELORS)

    return Resource.objects.filter(
        status__in=[ContentStatus.PUBLISHED, ContentStatus.SCHEDULED],
        audience__in=audiences,
    ).filter(_content_target_q(user)).filter(
        Q(publish_start__isnull=True) | Q(publish_start__lte=now)
    ).filter(
        Q(publish_end__isnull=True) | Q(publish_end__gt=now)
    )


def get_visible_published_resources_for_user(user):
    """Return only currently visible published resources for a signed-in actor."""
    if not is_active_nonlegacy_actor(user):
        return Resource.objects.none()
    now = timezone.now()
    audiences = [AudienceChoices.PUBLIC, AudienceChoices.ALL_AUTHENTICATED]
    if is_student(user):
        audiences.append(AudienceChoices.STUDENTS)
    if is_gco_staff(user) or is_counselor(user):
        audiences.append(AudienceChoices.STAFF)
    if is_counselor(user):
        audiences.append(AudienceChoices.COUNSELORS)
    return Resource.objects.select_related("published_revision").filter(
        status__in=[ContentStatus.PUBLISHED, ContentStatus.SCHEDULED],
        audience__in=audiences,
    ).filter(_content_target_q(user)).filter(
        Q(publish_start__isnull=True) | Q(publish_start__lte=now)
    ).filter(
        Q(publish_end__isnull=True) | Q(publish_end__gt=now)
    )


def get_announcement_by_slug(slug, user=None):
    """Fetch an announcement visible to the given user, or ``None``."""
    return get_visible_announcements_for_user(user).filter(slug=slug).first()


def get_public_announcement_by_slug(slug):
    """Fetch a model-free publicly visible announcement, or ``None``."""
    from apps.content.cache import get_cached_public_announcement_by_slug

    return get_cached_public_announcement_by_slug(slug)


def get_resource_by_slug(slug, user=None):
    """Fetch a resource visible to the given user, or ``None``."""
    return get_visible_resources_for_user(user).filter(slug=slug).first()


def get_public_resource_by_slug(slug):
    """Fetch a model-free publicly visible resource, or ``None``."""
    from apps.content.cache import get_cached_public_resource_by_slug

    return get_cached_public_resource_by_slug(slug)


def get_dashboard_announcements_preview(user, limit=3):
    """Return a preview list of featured/latest announcements visible to the user for the dashboard."""
    # Filter by user audience
    qs = get_visible_announcements_for_user(user).filter(dashboard_preview_enabled=True)
    return qs[:limit]


def get_dashboard_resources_preview(user, limit=3):
    """Return a preview list of resources visible to the user for the dashboard."""
    qs = get_visible_resources_for_user(user)
    return qs[:limit]


CONTENT_WORKSPACE_TYPES = {
    "announcement": Announcement,
    "resource": Resource,
    "page": ContentPage,
    "service_guide": ServiceGuide,
}


def get_content_workspace_items(user, status_key="all"):
    """Return a privacy-safe, role-scoped projection for the content workspace."""
    if not can_view_content_workspace(user):
        raise PermissionDenied("You do not have permission to view the content workspace.")

    now = timezone.now()
    rows = []
    for content_type, model in CONTENT_WORKSPACE_TYPES.items():
        queryset = model.objects.select_related("created_by", "updated_by", "published_by").all()
        for item in queryset:
            if not can_manage_content(user):
                if model in {Announcement, Resource}:
                    if not _target_visible(user, item):
                        continue
                else:
                    # Institution-wide pages/guides remain governed content;
                    # local grants never turn them into delegated workspaces.
                    continue
            # Resolve the generic revision target without exposing identifiers.
            content_type_obj = ContentType.objects.get_for_model(model, for_concrete_model=False)
            revisions = ContentRevision.objects.filter(
                content_type=content_type_obj,
                object_id=str(item.pk),
            )
            latest_revision = revisions.order_by("-revision_number").first()
            latest_review = latest_revision if latest_revision and latest_revision.status == RevisionStatus.REVIEW else None
            latest_scheduled = latest_revision if latest_revision and latest_revision.status == RevisionStatus.SCHEDULED else None
            if latest_review:
                effective_status = "review"
            elif latest_scheduled and latest_scheduled.snapshot.get("publish_end") and now >= timezone.datetime.fromisoformat(latest_scheduled.snapshot["publish_end"]):
                effective_status = "expired"
            elif latest_scheduled and latest_scheduled.snapshot.get("publish_start") and now >= timezone.datetime.fromisoformat(latest_scheduled.snapshot["publish_start"]):
                effective_status = "published"
            elif latest_scheduled:
                effective_status = "scheduled"
            elif item.status in {ContentStatus.PUBLISHED, ContentStatus.SCHEDULED} and item.publish_end and now >= item.publish_end:
                effective_status = "expired"
            elif item.status == ContentStatus.SCHEDULED and item.publish_start and now >= item.publish_start:
                effective_status = "published"
            elif item.status == ContentStatus.SCHEDULED:
                effective_status = "scheduled"
            else:
                effective_status = item.status
            if status_key != "all" and effective_status != status_key:
                continue
            rows.append({
                "content_type": content_type,
                "object": item,
                "latest_review": latest_review,
                "effective_status": effective_status,
                "status_label": dict(
                    [(value, label) for value, label in ContentStatus.choices]
                    + [("review", "For review"), ("expired", "Expired")]
                ).get(effective_status, effective_status.title()),
            })
    return sorted(rows, key=lambda row: (
        row["effective_status"],
        -(row["object"].updated_at.timestamp() if row["object"].updated_at else 0),
    ))


def get_content_workspace_item(user, content_type, object_id):
    """Fetch one authorized governed content item for staff workflows."""
    if not can_view_content_workspace(user):
        raise PermissionDenied("You do not have permission to view the content workspace.")
    model = CONTENT_WORKSPACE_TYPES.get(content_type)
    if model is None:
        raise PermissionDenied("Unknown content type.")
    item = model.objects.filter(pk=object_id).first()
    if item is None:
        return None
    if not can_manage_content(user):
        if model not in {Announcement, Resource} or not _target_visible(user, item):
            raise PermissionDenied("You do not have permission to view this content item.")
    return item


def get_latest_content_revision(obj, *, statuses=None):
    content_type = ContentType.objects.get_for_model(obj, for_concrete_model=False)
    queryset = ContentRevision.objects.filter(content_type=content_type, object_id=str(obj.pk))
    if statuses:
        queryset = queryset.filter(status__in=statuses)
    return queryset.order_by("-revision_number").first()


def get_contact_submissions_queue(user):
    """Return all contact submissions for authorized staff handlers."""
    from apps.content.policies import can_view_contact_queue
    if can_view_contact_queue(user) and can_manage_contact_submissions(user):
        return PublicContactSubmission.objects.all().order_by("-created_at")
    if can_view_contact_queue(user) and is_gco_staff(user):
        # Front-desk staff see queue-safe metadata only.  Full fields are
        # fetched after Head Guidance assigns an individual submission.
        return PublicContactSubmission.objects.only(
            "id", "reference_code", "created_at", "updated_at", "status", "priority",
            "assigned_to_id", "submission_type", "affiliation",
        ).order_by("-created_at")
    from apps.content.policies import can_view_contact_submission_metadata
    if can_view_contact_submission_metadata(user):
        # IT receives metadata-only operational rows.  Do not select email,
        # subject, plaintext source, or encrypted body into this projection.
        return PublicContactSubmission.objects.only(
            "id", "reference_code", "created_at", "updated_at", "status", "priority",
            "assigned_to_id", "submission_type", "affiliation",
        ).order_by("-created_at")
    raise PermissionDenied("You do not have permission to view contact submissions.")


def get_contact_delivery_metadata(user, *, offset=0, limit=100):
    """Return aggregate delivery-health evidence without recipient content."""
    from apps.content.policies import can_view_contact_delivery_metadata
    from apps.notifications.models import EmailDelivery
    if not can_view_contact_delivery_metadata(user):
        raise PermissionDenied("You do not have permission to view delivery metadata.")
    rows = EmailDelivery.objects.filter(template_key="contact_reply").values(
        "delivery_state", "status", "created_at", "sent_at", "provider_status_updated_at",
    ).order_by("-created_at")
    from django.db.models import Count

    counts = {
        row["delivery_state"] or "unknown": row["total"]
        for row in EmailDelivery.objects.filter(template_key="contact_reply")
        .values("delivery_state")
        .annotate(total=Count("id"))
    }
    return {
        "counts": counts,
        "total": rows.count(),
        "rows": list(rows[offset:offset + limit]),
    }


def get_contact_submission_by_id(submission_id, user):
    """Fetch a specific contact submission by ID for authorized staff."""
    # Defer ciphertext until the full-detail policy has granted access. This
    # keeps IT metadata lookups from invoking authenticated body decryption.
    submission = PublicContactSubmission.objects.defer("message_body_encrypted").filter(
        id=submission_id,
    ).first()
    if submission is None:
        return None
    if not can_manage_contact_submissions(user, submission):
        raise PermissionDenied("You do not have permission to view contact submissions.")
    return submission


def get_contact_submission_metadata_by_id(submission_id, user):
    """Fetch only operational metadata for technical or queue projections."""
    from apps.content.policies import can_view_contact_submission_metadata

    if not can_view_contact_submission_metadata(user):
        raise PermissionDenied("You do not have permission to view contact metadata.")
    return PublicContactSubmission.objects.only(
        "id", "reference_code", "created_at", "updated_at", "status", "priority",
        "assigned_to_id", "submission_type", "affiliation",
    ).filter(pk=submission_id).first()


def get_contact_submission_by_reference(user, reference_code):
    """Fetch a single contact submission by reference code for authorized staff.

    Fails closed with the same generic message whether the submission does not
    exist or the actor lacks permission, so existence is never leaked. Records
    a sensitive-view audit entry for staff detail access, mirroring the other
    workflow detail selectors.
    """
    from apps.audit.services import audit_sensitive_view
    from apps.content.policies import can_view_contact_submission_full

    try:
        submission = PublicContactSubmission.objects.defer("message_body_encrypted").get(
            reference_code=reference_code,
        )
    except (PublicContactSubmission.DoesNotExist, ValueError):
        raise PermissionDenied("Contact submission not found.")
    if not can_view_contact_submission_full(user, submission):
        raise PermissionDenied("Contact submission not found.")

    audit_sensitive_view(
        actor_user=user,
        target_model="content.PublicContactSubmission",
        target_object_id=str(submission.id),
        reference_code=submission.reference_code,
        metadata={"action": "view_detail"},
    )
    return submission
