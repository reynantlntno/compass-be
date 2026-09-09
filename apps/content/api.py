"""Django Ninja adapter for public and staff content workflows."""

from __future__ import annotations

from datetime import date, datetime
from typing import Literal
from uuid import UUID

from ninja import Field, Query, Router, Schema

from apps.account_security.network import get_client_ip_from_headers
from apps.access_control.authority import has_fixed_capability
from apps.access_control.capabilities import Capability
from apps.common.api.idempotency import ApiMutationOutcome, run_api_mutation
from apps.common.api.constants import API_MAX_CAPTCHA_RESPONSE_LENGTH
from apps.common.api.operations import prepare_api_operation
from apps.common.api.pagination import PageQuery, PageSizeQuery, page_request_from_values
from apps.common.api.schemas import PageResultSchema
from apps.common.contracts import ContractValidationError
from apps.common.exceptions import NotFoundError, ValidationError
from apps.common.request_dedup import normalize_request_key
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
    ResourceCreateCommand,
    ResourceUpdateCommand,
    ServiceGuideCreateCommand,
    ServiceGuideUpdateCommand,
)
from apps.content.models import (
    Announcement,
    ContactNoResponseDisposition,
    ContactReply,
    PublicContactSubmission,
)
from apps.content.projections import (
    project_contact_reply,
)
from apps.content.queries import (
    contact_delivery_metadata,
    contact_queue,
    contact_reply_projection,
    contact_submission_by_reference,
    contact_submission_detail,
    content_workspace,
    content_workspace_detail,
    no_response_projection,
    public_announcement,
    public_announcements,
    public_contact_result,
    public_page,
    public_resource,
    public_resources,
    public_service_guide,
    visible_announcements,
    visible_resources,
)
from apps.content.services import (
    approve_contact_reply,
    archive_announcement,
    archive_content_page,
    archive_resource,
    archive_service_guide,
    assign_submission,
    cancel_contact_reply,
    create_announcement,
    create_contact_reply,
    create_contact_submission,
    create_content_page,
    create_resource,
    create_service_guide,
    record_contact_no_response,
    reject_contact_reply,
    publish_announcement,
    publish_content_page,
    publish_resource,
    publish_service_guide,
    retry_contact_reply,
    schedule_announcement,
    schedule_resource,
    schedule_service_guide,
    submit_contact_reply_for_approval,
    submit_content_for_review,
    update_announcement,
    update_contact_reply_draft,
    update_content_page,
    update_resource,
    update_service_guide,
    update_submission_status,
)


router = Router(tags=["content"])


class PublicContentSchema(Schema):
    id: str
    slug: str
    title: str
    summary: str
    body_html: str
    status: str
    audience: str
    target_scope_mode: str
    publish_start: str | None = None
    publish_end: str | None = None
    published_at: str | None = None
    content_type: str | None = None
    featured: bool | None = None
    category: str | None = None
    resource_type: str | None = None
    external_url: str | None = None


class PublicPageSchema(Schema):
    id: str
    page_key: str
    title: str
    summary: str
    body_html: str
    status: str
    audience: str
    published_at: str | None = None


class ServiceGuideConfirmationFieldSchema(Schema):
    label: str
    value: str
    confirmed: bool
    owner: str


class ServiceGuideFieldsSchema(Schema):
    requirements: ServiceGuideConfirmationFieldSchema
    fees: ServiceGuideConfirmationFieldSchema
    timelines: ServiceGuideConfirmationFieldSchema
    receipt_rules: ServiceGuideConfirmationFieldSchema
    claim_rules: ServiceGuideConfirmationFieldSchema
    proxy_claims: ServiceGuideConfirmationFieldSchema
    office_hours: ServiceGuideConfirmationFieldSchema
    contact: ServiceGuideConfirmationFieldSchema


class ServiceGuideStepSchema(Schema):
    key: str
    label: str
    description: str
    boundary: str


class ServiceGuideMissingFieldSchema(Schema):
    entry_key: str
    field: str
    label: str
    owner: str


class ServiceGuideReadinessSchema(Schema):
    state: str
    official: bool
    missing_fields: list[ServiceGuideMissingFieldSchema]
    document_readiness: str
    document_official: bool
    display_state: str
    pending_notice: str


class ServiceGuideEntrySchema(Schema):
    key: str
    anchor: str
    label: str
    summary: str
    description: str
    available: bool
    privacy_level: str
    availability_label: str
    fields: ServiceGuideFieldsSchema
    steps: list[ServiceGuideStepSchema]


class PublicServiceGuideSchema(Schema):
    guide_key: str
    title: str
    summary: str
    version_label: str
    effective_date: str | None = None
    owner_office: str
    publication_state: str
    has_approved_revision: bool
    readiness: ServiceGuideReadinessSchema
    entries: list[ServiceGuideEntrySchema]


class ContentPageResultSchema(PageResultSchema):
    items: list[PublicContentSchema]


class ContentWorkspaceTargetSchema(Schema):
    """Output-only target scope for governed content."""

    target_scope_mode: str
    target_campus: str | None = None
    target_college: str | None = None
    target_department: str | None = None
    target_program: str | None = None


class ContentRevisionProjectionSchema(Schema):
    """Output-only metadata for the latest review revision."""

    id: str
    revision_number: int
    status: str
    created_at: str | None = None
    reviewed_at: str | None = None
    published_at: str | None = None
    body_markdown: str | None = None


class ContentEditorFieldSchema(Schema):
    """Bounded office-authored Service Guide confirmation field."""

    label: str | None = None
    value: str | None = None
    confirmed: bool | None = None
    owner: str | None = None


class ContentEditorFieldsSchema(Schema):
    """Known Service Guide editor fields; unknown JSON keys are not exposed."""

    requirements: ContentEditorFieldSchema | None = None
    fees: ContentEditorFieldSchema | None = None
    timelines: ContentEditorFieldSchema | None = None
    receipt_rules: ContentEditorFieldSchema | None = None
    claim_rules: ContentEditorFieldSchema | None = None
    proxy_claims: ContentEditorFieldSchema | None = None
    office_hours: ContentEditorFieldSchema | None = None
    contact: ContentEditorFieldSchema | None = None


class ContentEditorStepSchema(Schema):
    """Bounded Service Guide editor step."""

    key: str | None = None
    label: str | None = None
    description: str | None = None
    boundary: str | None = None


class ContentEditorEntrySchema(Schema):
    """Bounded Service Guide editor entry used by staff workspace views."""

    key: str | None = None
    summary: str | None = None
    description: str | None = None
    owner: str | None = None
    fields: ContentEditorFieldsSchema | None = None
    steps: list[ContentEditorStepSchema] = Field(default_factory=list)


class ContentWorkspaceProjectionSchema(Schema):
    """Output-only full projection for the governed content workspace."""

    id: str
    content_type: str
    title: str
    summary: str
    status: str
    effective_status: str
    audience: str
    publish_start: str | None = None
    publish_end: str | None = None
    published_at: str | None = None
    updated_at: str | None = None
    created_at: str | None = None
    featured: bool
    target: ContentWorkspaceTargetSchema | None = None
    slug: str | None = None
    page_key: str | None = None
    guide_key: str | None = None
    category: str | None = None
    resource_type: str | None = None
    external_url: str | None = None
    body_markdown: str | None = None
    version_label: str | None = None
    effective_date: str | None = None
    owner_office_id: int | None = None
    entries_json: list[ContentEditorEntrySchema] = Field(default_factory=list)
    latest_review: ContentRevisionProjectionSchema | None = None


class ContentWorkspaceReplaySchema(Schema):
    """Output-only replay-safe subset returned by content mutations."""

    id: str
    content_type: str
    title: str
    status: str
    slug: str | None = None
    page_key: str | None = None
    guide_key: str | None = None
    updated_at: str


class ContentWorkspacePageSchema(PageResultSchema):
    items: list[ContentWorkspaceProjectionSchema]


class ContactSubmissionSchema(Schema):
    id: str
    reference_code: str
    status: str
    created_at: str


class ContactMetadataSchema(Schema):
    id: str
    reference_code: str
    created_at: str
    updated_at: str
    status: str
    priority: str
    submission_type: str
    affiliation: str
    assigned_to_id: int | None = None


class ContactDetailSchema(ContactMetadataSchema):
    name: str | None = None
    email: str | None = None
    phone: str | None = None
    subject: str | None = None
    message_body: str | None = None
    privacy_acknowledged: bool | None = None
    urgent_support_disclaimer_acknowledged: bool | None = None
    privacy_actioned_at: str | None = None


class ContactMetadataPageSchema(PageResultSchema):
    items: list[ContactMetadataSchema]


class ContactReplySchema(Schema):
    id: str
    submission_id: str
    status: str
    created_at: str
    updated_at: str
    approved_at: str | None = None
    delivery_state: str
    evidence_scope: str
    evidence_recorded_at: str | None = None
    sent_at: str | None = None
    last_failure_code: str
    body: str | None = None


class ContactReplyPageSchema(PageResultSchema):
    items: list[ContactReplySchema]


class ContactNoResponseProjectionSchema(Schema):
    id: str
    submission_id: str
    reason_code: str
    created_at: str


class ContactDeliveryMetadataItemSchema(Schema):
    delivery_state: str
    status: str
    created_at: str | None = None
    sent_at: str | None = None
    provider_status_updated_at: str | None = None


class ContactDeliveryCountsSchema(Schema):
    queued: int | None = None
    sending: int | None = None
    sent: int | None = None
    delayed: int | None = None
    failed: int | None = None
    retry_exhausted: int | None = None
    bounced: int | None = None
    cancelled: int | None = None
    unknown: int | None = None


class ContactDeliveryMetadataResultSchema(Schema):
    counts: ContactDeliveryCountsSchema
    items: list[ContactDeliveryMetadataItemSchema]
    page: int
    page_size: int
    total: int


class AnnouncementCreateSchema(Schema):
    slug: str
    title: str
    summary: str
    body_markdown: str
    audience: str = "public"
    target_scope_mode: str = "INSTITUTION_WIDE"
    target_campus: str | None = None
    target_college: str | None = None
    target_department: str | None = None
    target_program: str | None = None
    featured: bool = False
    publish_start: datetime | None = None
    publish_end: datetime | None = None
    dashboard_preview_enabled: bool = True
    status: str = "draft"


class AnnouncementUpdateSchema(Schema):
    slug: str | None = None
    title: str | None = None
    summary: str | None = None
    body_markdown: str | None = None
    audience: str | None = None
    target_scope_mode: str | None = None
    target_campus: str | None = None
    target_college: str | None = None
    target_department: str | None = None
    target_program: str | None = None
    featured: bool | None = None
    publish_start: datetime | None = None
    publish_end: datetime | None = None
    dashboard_preview_enabled: bool | None = None
    status: str | None = None


class ResourceCreateSchema(Schema):
    slug: str
    title: str
    summary: str
    category: str
    resource_type: str
    body_markdown: str | None = None
    external_url: str | None = None
    audience: str = "public"
    target_scope_mode: str = "INSTITUTION_WIDE"
    target_campus: str | None = None
    target_college: str | None = None
    target_department: str | None = None
    target_program: str | None = None
    publish_start: datetime | None = None
    publish_end: datetime | None = None
    status: str = "draft"


class ResourceUpdateSchema(Schema):
    slug: str | None = None
    title: str | None = None
    summary: str | None = None
    category: str | None = None
    resource_type: str | None = None
    body_markdown: str | None = None
    external_url: str | None = None
    audience: str | None = None
    target_scope_mode: str | None = None
    target_campus: str | None = None
    target_college: str | None = None
    target_department: str | None = None
    target_program: str | None = None
    publish_start: datetime | None = None
    publish_end: datetime | None = None
    status: str | None = None


class ContentPageCreateSchema(Schema):
    page_key: str
    title: str
    summary: str = ""
    body_markdown: str = ""
    audience: str = "public"
    status: str = "draft"


class ContentPageUpdateSchema(Schema):
    title: str | None = None
    summary: str | None = None
    body_markdown: str | None = None
    audience: str | None = None
    status: str | None = None


class ServiceGuideCreateSchema(Schema):
    version_label: str
    title: str = "Official Citizen’s Charter / Service Standards"
    summary: str = ""
    effective_date: date | None = None
    publish_start: datetime | None = None
    publish_end: datetime | None = None
    body_markdown: str = ""
    entries_json: list[ContentEditorEntrySchema] = Field(default_factory=list)
    owner_office_id: int | None = None
    audience: str = "public"
    status: str = "draft"


class ServiceGuideUpdateSchema(Schema):
    version_label: str | None = None
    title: str | None = None
    summary: str | None = None
    effective_date: date | None = None
    publish_start: datetime | None = None
    publish_end: datetime | None = None
    body_markdown: str | None = None
    entries_json: list[ContentEditorEntrySchema] | None = None
    owner_office_id: int | None = None
    audience: str | None = None
    status: str | None = None


class ContactSubmissionCreateSchema(Schema):
    submission_type: Literal[
        "inquiry",
        "suggestion",
        "feedback",
        "concern",
        "other",
    ] = "inquiry"
    name: str = Field(default="", max_length=150)
    email: str = Field(default="", max_length=254)
    phone: str = Field(default="", max_length=50)
    affiliation: Literal[
        "student",
        "parent",
        "faculty",
        "staff",
        "visitor",
        "other",
    ] = "visitor"
    subject: str = Field(..., min_length=1, max_length=200)
    message_body: str = Field(default="", max_length=32_768)
    privacy_acknowledged: bool
    urgent_support_disclaimer_acknowledged: bool
    captcha_response: str | None = Field(default=None, max_length=API_MAX_CAPTCHA_RESPONSE_LENGTH)


class ContactAssignmentSchema(Schema):
    assignee_id: int | None = None


class ContactStatusSchema(Schema):
    status: str


class ContactReplyCommandSchema(Schema):
    body: str


class ContactReplyOptionalSchema(Schema):
    body: str | None = None


class ContactNoResponseSchema(Schema):
    reason_code: str
    detail: str = ""


def _actor(request):
    return request.auth.user


def _page(page: PageQuery, page_size: PageSizeQuery):
    try:
        return page_request_from_values(page, page_size)
    except ContractValidationError as error:
        raise ValidationError() from error


def _payload(payload):
    return payload.dict(exclude_unset=True)


def _replay_content(key):
    action = str(key.action_scope)
    object_id = key.related_object_id
    if not object_id:
        return None
    if "announcement" in action:
        from apps.content.models import Announcement
        item = Announcement.objects.filter(pk=object_id).first()
        return project_workspace_replay(item, "announcement")
    if "resource" in action:
        from apps.content.models import Resource
        item = Resource.objects.filter(pk=object_id).first()
        return project_workspace_replay(item, "resource")
    if "page" in action:
        from apps.content.models import ContentPage
        item = ContentPage.objects.filter(pk=object_id).first()
        return project_workspace_replay(item, "page")
    if "service_guide" in action:
        from apps.content.models import ServiceGuide
        item = ServiceGuide.objects.filter(pk=object_id).first()
        return project_workspace_replay(item, "service_guide")
    if "contact_reply" in action:
        reply = ContactReply.objects.select_related("submission").filter(pk=object_id).first()
        return project_contact_reply(reply, include_body=True) if reply else None
    if "contact_no_response" in action:
        disposition = ContactNoResponseDisposition.objects.filter(pk=object_id).first()
        return no_response_projection(disposition) if disposition else None
    if "contact" in action:
        submission = PublicContactSubmission.objects.filter(pk=object_id).first()
        return public_contact_result(submission) if submission else None
    return None


def project_workspace_replay(item, content_type):
    if item is None:
        return None
    return {
        "id": str(item.pk),
        "content_type": content_type,
        "title": item.title,
        "status": item.status,
        "slug": getattr(item, "slug", None),
        "page_key": getattr(item, "page_key", None),
        "guide_key": getattr(item, "guide_key", None),
        "updated_at": item.updated_at.isoformat(),
    }


def _outcome(value, *, related_object, path):
    return ApiMutationOutcome(value=value, related_object=related_object, safe_response_path=path)


def _run(request, operation_id, payload, operation):
    prepared = prepare_api_operation(request, operation_id)
    return run_api_mutation(
        request,
        operation_id,
        payload,
        operation,
        _replay_content,
        prepared_operation=prepared,
    )


@router.get("/announcements/", auth=None, response=ContentPageResultSchema, operation_id="content_public_announcements")
def list_public_announcements(request, page: PageQuery, page_size: PageSizeQuery):
    return public_announcements(_page(page, page_size)).as_dict()


@router.get("/announcements/{slug}/", auth=None, response=PublicContentSchema, operation_id="content_public_announcement")
def get_public_announcement(request, slug: str):
    value = public_announcement(slug)
    if value is None:
        raise NotFoundError()
    return value


@router.get("/resources/", auth=None, response=ContentPageResultSchema, operation_id="content_public_resources")
def list_public_resources(request, page: PageQuery, page_size: PageSizeQuery):
    return public_resources(_page(page, page_size)).as_dict()


@router.get("/resources/{slug}/", auth=None, response=PublicContentSchema, operation_id="content_public_resource")
def get_public_resource(request, slug: str):
    value = public_resource(slug)
    if value is None:
        raise NotFoundError()
    return value


@router.get("/pages/{page_key}/", auth=None, response=PublicPageSchema, operation_id="content_public_page")
def get_public_page(request, page_key: str):
    value = public_page(page_key)
    if value is None:
        raise NotFoundError()
    return value


@router.get("/service-guide/", auth=None, response=PublicServiceGuideSchema, operation_id="content_public_service_guide")
def get_public_service_guide(request):
    value = public_service_guide()
    if value is None:
        raise NotFoundError()
    return value


@router.get("/feed/announcements/", response=ContentPageResultSchema, operation_id="content_visible_announcements")
def list_visible_announcements(request, page: PageQuery, page_size: PageSizeQuery):
    return visible_announcements(_actor(request), _page(page, page_size)).as_dict()


@router.get("/feed/resources/", response=ContentPageResultSchema, operation_id="content_visible_resources")
def list_visible_resources(request, page: PageQuery, page_size: PageSizeQuery):
    return visible_resources(_actor(request), _page(page, page_size)).as_dict()


@router.get(
    "/workspace/",
    response=ContentWorkspacePageSchema,
    exclude_unset=True,
    operation_id="content_workspace",
)
def workspace(
    request,
    page: PageQuery,
    page_size: PageSizeQuery,
    status: str = Query(default="all"),
):
    status_key = status or "all"
    return content_workspace(_actor(request), status_key, _page(page, page_size)).as_dict()


@router.get(
    "/workspace/{content_type}/{object_id}/",
    response=ContentWorkspaceProjectionSchema,
    exclude_unset=True,
    operation_id="content_workspace_detail",
)
def workspace_detail(request, content_type: str, object_id: UUID):
    return content_workspace_detail(_actor(request), content_type, object_id)


@router.post(
    "/announcements/",
    response=ContentWorkspaceReplaySchema,
    exclude_unset=True,
    operation_id="content_announcement_create",
)
def create_announcement_api(request, payload: AnnouncementCreateSchema):
    actor = _actor(request)
    command = AnnouncementCreateCommand(**payload.dict())
    def operation():
        item = create_announcement(actor, command)
        return _outcome(project_workspace_replay(item, "announcement"), related_object=item, path=f"/api/v1/content/workspace/announcement/{item.pk}/")
    return _run(
        request, "content_announcement_create", _payload(payload),
        operation,
    )


def _announcement_outcome(actor, announcement_id, command, action):
    item = action(actor, announcement_id, command) if command is not None else action(actor, announcement_id)
    return _outcome(project_workspace_replay(item, "announcement"), related_object=item, path=f"/api/v1/content/workspace/announcement/{item.pk}/")


@router.put(
    "/announcements/{announcement_id}/",
    response=ContentWorkspaceReplaySchema,
    exclude_unset=True,
    operation_id="content_announcement_update",
)
def update_announcement_api(request, announcement_id: UUID, payload: AnnouncementUpdateSchema):
    actor = _actor(request)
    command = AnnouncementUpdateCommand(**_payload(payload))
    return _run(request, "content_announcement_update", {"announcement_id": str(announcement_id), **_payload(payload)}, lambda: _announcement_outcome(actor, announcement_id, command, update_announcement))


@router.post(
    "/announcements/{announcement_id}/submit-review/",
    response=ContentWorkspaceReplaySchema,
    exclude_unset=True,
    operation_id="content_announcement_submit_review",
)
def submit_announcement_api(request, announcement_id: UUID):
    actor = _actor(request)
    return _run(request, "content_announcement_submit_review", {"announcement_id": str(announcement_id)}, lambda: _announcement_outcome(actor, announcement_id, None, lambda user, object_id: submit_content_for_review(user, "announcement", object_id)))


@router.post(
    "/announcements/{announcement_id}/publish/",
    response=ContentWorkspaceReplaySchema,
    exclude_unset=True,
    operation_id="content_announcement_publish",
)
def publish_announcement_api(request, announcement_id: UUID):
    actor = _actor(request)
    return _run(request, "content_announcement_publish", {"announcement_id": str(announcement_id)}, lambda: _announcement_outcome(actor, announcement_id, None, publish_announcement))


@router.post(
    "/announcements/{announcement_id}/schedule/",
    response=ContentWorkspaceReplaySchema,
    exclude_unset=True,
    operation_id="content_announcement_schedule",
)
def schedule_announcement_api(request, announcement_id: UUID, payload: AnnouncementUpdateSchema | None = None):
    actor = _actor(request)
    command = AnnouncementUpdateCommand(**_payload(payload)) if payload else None
    return _run(request, "content_announcement_schedule", {"announcement_id": str(announcement_id), **(_payload(payload) if payload else {})}, lambda: _announcement_outcome(actor, announcement_id, command, schedule_announcement))


@router.post(
    "/announcements/{announcement_id}/archive/",
    response=ContentWorkspaceReplaySchema,
    exclude_unset=True,
    operation_id="content_announcement_archive",
)
def archive_announcement_api(request, announcement_id: UUID):
    actor = _actor(request)
    return _run(request, "content_announcement_archive", {"announcement_id": str(announcement_id)}, lambda: _announcement_outcome(actor, announcement_id, None, archive_announcement))


@router.post(
    "/resources/",
    response=ContentWorkspaceReplaySchema,
    exclude_unset=True,
    operation_id="content_resource_create",
)
def create_resource_api(request, payload: ResourceCreateSchema):
    actor = _actor(request)
    command = ResourceCreateCommand(**payload.dict())
    def operation():
        item = create_resource(actor, command)
        return _outcome(project_workspace_replay(item, "resource"), related_object=item, path=f"/api/v1/content/workspace/resource/{item.pk}/")
    return _run(request, "content_resource_create", _payload(payload), operation)


def _resource_outcome(actor, resource_id, command, action):
    item = action(actor, resource_id, command) if command is not None else action(actor, resource_id)
    return _outcome(project_workspace_replay(item, "resource"), related_object=item, path=f"/api/v1/content/workspace/resource/{item.pk}/")


@router.put(
    "/resources/{resource_id}/",
    response=ContentWorkspaceReplaySchema,
    exclude_unset=True,
    operation_id="content_resource_update",
)
def update_resource_api(request, resource_id: UUID, payload: ResourceUpdateSchema):
    actor = _actor(request)
    command = ResourceUpdateCommand(**_payload(payload))
    return _run(request, "content_resource_update", {"resource_id": str(resource_id), **_payload(payload)}, lambda: _resource_outcome(actor, resource_id, command, update_resource))


@router.post(
    "/resources/{resource_id}/submit-review/",
    response=ContentWorkspaceReplaySchema,
    exclude_unset=True,
    operation_id="content_resource_submit_review",
)
def submit_resource_api(request, resource_id: UUID):
    actor = _actor(request)
    return _run(request, "content_resource_submit_review", {"resource_id": str(resource_id)}, lambda: _resource_outcome(actor, resource_id, None, lambda user, object_id: submit_content_for_review(user, "resource", object_id)))


@router.post(
    "/resources/{resource_id}/publish/",
    response=ContentWorkspaceReplaySchema,
    exclude_unset=True,
    operation_id="content_resource_publish",
)
def publish_resource_api(request, resource_id: UUID):
    actor = _actor(request)
    return _run(request, "content_resource_publish", {"resource_id": str(resource_id)}, lambda: _resource_outcome(actor, resource_id, None, publish_resource))


@router.post(
    "/resources/{resource_id}/schedule/",
    response=ContentWorkspaceReplaySchema,
    exclude_unset=True,
    operation_id="content_resource_schedule",
)
def schedule_resource_api(request, resource_id: UUID, payload: ResourceUpdateSchema | None = None):
    actor = _actor(request)
    command = ResourceUpdateCommand(**_payload(payload)) if payload else None
    return _run(request, "content_resource_schedule", {"resource_id": str(resource_id), **(_payload(payload) if payload else {})}, lambda: _resource_outcome(actor, resource_id, command, schedule_resource))


@router.post(
    "/resources/{resource_id}/archive/",
    response=ContentWorkspaceReplaySchema,
    exclude_unset=True,
    operation_id="content_resource_archive",
)
def archive_resource_api(request, resource_id: UUID):
    actor = _actor(request)
    return _run(request, "content_resource_archive", {"resource_id": str(resource_id)}, lambda: _resource_outcome(actor, resource_id, None, archive_resource))


def _page_outcome(actor, page_id, command, action):
    item = action(actor, page_id, command) if command is not None else action(actor, page_id)
    return _outcome(project_workspace_replay(item, "page"), related_object=item, path=f"/api/v1/content/workspace/page/{item.pk}/")


@router.post(
    "/pages/",
    response=ContentWorkspaceReplaySchema,
    exclude_unset=True,
    operation_id="content_page_create",
)
def create_page_api(request, payload: ContentPageCreateSchema):
    actor = _actor(request)
    command = ContentPageCreateCommand(**payload.dict())
    def operation():
        item = create_content_page(actor, command)
        return _outcome(project_workspace_replay(item, "page"), related_object=item, path=f"/api/v1/content/workspace/page/{item.pk}/")
    return _run(request, "content_page_create", _payload(payload), operation)


@router.put(
    "/pages/{page_id}/",
    response=ContentWorkspaceReplaySchema,
    exclude_unset=True,
    operation_id="content_page_update",
)
def update_page_api(request, page_id: UUID, payload: ContentPageUpdateSchema):
    actor = _actor(request)
    command = ContentPageUpdateCommand(**_payload(payload))
    return _run(request, "content_page_update", {"page_id": str(page_id), **_payload(payload)}, lambda: _page_outcome(actor, page_id, command, update_content_page))


@router.post(
    "/pages/{page_id}/submit-review/",
    response=ContentWorkspaceReplaySchema,
    exclude_unset=True,
    operation_id="content_page_submit_review",
)
def submit_page_api(request, page_id: UUID):
    actor = _actor(request)
    return _run(request, "content_page_submit_review", {"page_id": str(page_id)}, lambda: _page_outcome(actor, page_id, None, lambda user, object_id: submit_content_for_review(user, "page", object_id)))


@router.post(
    "/pages/{page_id}/publish/",
    response=ContentWorkspaceReplaySchema,
    exclude_unset=True,
    operation_id="content_page_publish",
)
def publish_page_api(request, page_id: UUID):
    actor = _actor(request)
    return _run(request, "content_page_publish", {"page_id": str(page_id)}, lambda: _page_outcome(actor, page_id, None, publish_content_page))


@router.post(
    "/pages/{page_id}/archive/",
    response=ContentWorkspaceReplaySchema,
    exclude_unset=True,
    operation_id="content_page_archive",
)
def archive_page_api(request, page_id: UUID):
    actor = _actor(request)
    return _run(request, "content_page_archive", {"page_id": str(page_id)}, lambda: _page_outcome(actor, page_id, None, archive_content_page))


def _guide_outcome(actor, guide_id, command, action):
    item = action(actor, guide_id, command) if command is not None else action(actor, guide_id)
    return _outcome(project_workspace_replay(item, "service_guide"), related_object=item, path=f"/api/v1/content/workspace/service_guide/{item.pk}/")


@router.post(
    "/service-guide/",
    response=ContentWorkspaceReplaySchema,
    exclude_unset=True,
    operation_id="content_service_guide_create",
)
def create_service_guide_api(request, payload: ServiceGuideCreateSchema):
    actor = _actor(request)
    command = ServiceGuideCreateCommand(**payload.dict())
    def operation():
        item = create_service_guide(actor, command)
        return _outcome(project_workspace_replay(item, "service_guide"), related_object=item, path=f"/api/v1/content/workspace/service_guide/{item.pk}/")
    return _run(request, "content_service_guide_create", _payload(payload), operation)


@router.put(
    "/service-guide/{guide_id}/",
    response=ContentWorkspaceReplaySchema,
    exclude_unset=True,
    operation_id="content_service_guide_update",
)
def update_service_guide_api(request, guide_id: UUID, payload: ServiceGuideUpdateSchema):
    actor = _actor(request)
    command = ServiceGuideUpdateCommand(**_payload(payload))
    return _run(request, "content_service_guide_update", {"guide_id": str(guide_id), **_payload(payload)}, lambda: _guide_outcome(actor, guide_id, command, update_service_guide))


@router.post(
    "/service-guide/{guide_id}/submit-review/",
    response=ContentWorkspaceReplaySchema,
    exclude_unset=True,
    operation_id="content_service_guide_submit_review",
)
def submit_service_guide_api(request, guide_id: UUID):
    actor = _actor(request)
    return _run(request, "content_service_guide_submit_review", {"guide_id": str(guide_id)}, lambda: _guide_outcome(actor, guide_id, None, lambda user, object_id: submit_content_for_review(user, "service_guide", object_id)))


@router.post(
    "/service-guide/{guide_id}/publish/",
    response=ContentWorkspaceReplaySchema,
    exclude_unset=True,
    operation_id="content_service_guide_publish",
)
def publish_service_guide_api(request, guide_id: UUID):
    actor = _actor(request)
    return _run(request, "content_service_guide_publish", {"guide_id": str(guide_id)}, lambda: _guide_outcome(actor, guide_id, None, publish_service_guide))


@router.post(
    "/service-guide/{guide_id}/schedule/",
    response=ContentWorkspaceReplaySchema,
    exclude_unset=True,
    operation_id="content_service_guide_schedule",
)
def schedule_service_guide_api(request, guide_id: UUID, payload: ServiceGuideUpdateSchema | None = None):
    actor = _actor(request)
    command = ServiceGuideUpdateCommand(**_payload(payload)) if payload else None
    return _run(request, "content_service_guide_schedule", {"guide_id": str(guide_id), **(_payload(payload) if payload else {})}, lambda: _guide_outcome(actor, guide_id, command, schedule_service_guide))


@router.post(
    "/service-guide/{guide_id}/archive/",
    response=ContentWorkspaceReplaySchema,
    exclude_unset=True,
    operation_id="content_service_guide_archive",
)
def archive_service_guide_api(request, guide_id: UUID):
    actor = _actor(request)
    return _run(request, "content_service_guide_archive", {"guide_id": str(guide_id)}, lambda: _guide_outcome(actor, guide_id, None, archive_service_guide))


@router.post("/contact-submissions/", auth=None, response=ContactSubmissionSchema, operation_id="content_contact_create")
def create_contact_submission_api(request, payload: ContactSubmissionCreateSchema):
    # The contact domain keeps its own request-key replay record; the shared
    # preparation still supplies the central abuse-control decision.
    prepare_api_operation(
        request,
        "content_contact_create",
        captcha_response=payload.captcha_response,
    )
    raw_key = str((request.META or {}).get("HTTP_IDEMPOTENCY_KEY", "") or "").strip()
    idempotency_key = normalize_request_key(raw_key, max_length=128) if raw_key else None
    command = ContactSubmissionCommand(**payload.dict(exclude={"captcha_response"}))
    submission = create_contact_submission(
        command,
        submitted_by=getattr(getattr(request, "auth", None), "user", None),
        source_ip=get_client_ip_from_headers(request.META),
        user_agent=str(request.META.get("HTTP_USER_AGENT", "") or ""),
        idempotency_key=idempotency_key,
    )
    return public_contact_result(submission)


@router.get(
    "/contact-submissions/",
    response=ContactMetadataPageSchema,
    exclude_unset=True,
    operation_id="content_contact_queue",
)
def list_contact_submissions(request, page: PageQuery, page_size: PageSizeQuery):
    return contact_queue(_actor(request), _page(page, page_size)).as_dict()


@router.get(
    "/contact-submissions/reference/{reference_code}/",
    response=ContactDetailSchema,
    exclude_unset=True,
    operation_id="content_contact_reference_detail",
)
def get_contact_submission_by_reference_api(request, reference_code: str):
    return contact_submission_by_reference(_actor(request), reference_code)


@router.get(
    "/contact-submissions/{submission_id}/",
    response=ContactDetailSchema,
    exclude_unset=True,
    operation_id="content_contact_detail",
)
def get_contact_submission_api(request, submission_id: UUID):
    actor = _actor(request)
    return contact_submission_detail(
        actor,
        submission_id,
        full=not has_fixed_capability(actor, Capability.CONTENT_DELIVERY_METADATA_VIEW),
    )


@router.get(
    "/contact-delivery/metadata/",
    response=ContactDeliveryMetadataResultSchema,
    exclude_unset=True,
    operation_id="content_contact_delivery_metadata",
)
def get_contact_delivery_metadata_api(request, page: PageQuery, page_size: PageSizeQuery):
    return contact_delivery_metadata(_actor(request), _page(page, page_size))


def _submission_outcome(item):
    return _outcome(project_public_contact_result(item), related_object=item, path=f"/api/v1/content/contact-submissions/{item.pk}/")


@router.post(
    "/contact-submissions/{submission_id}/assign/",
    response=ContactSubmissionSchema,
    exclude_unset=True,
    operation_id="content_contact_assign",
)
def assign_contact_submission_api(request, submission_id: UUID, payload: ContactAssignmentSchema):
    actor = _actor(request)
    command = ContactAssignmentCommand(**payload.dict())
    return _run(request, "content_contact_assign", {"submission_id": str(submission_id), **_payload(payload)}, lambda: _submission_outcome(assign_submission(actor, submission_id, command)))


@router.post(
    "/contact-submissions/{submission_id}/status/",
    response=ContactSubmissionSchema,
    exclude_unset=True,
    operation_id="content_contact_status",
)
def update_contact_status_api(request, submission_id: UUID, payload: ContactStatusSchema):
    actor = _actor(request)
    command = ContactStatusCommand(**payload.dict())
    return _run(request, "content_contact_status", {"submission_id": str(submission_id), **_payload(payload)}, lambda: _submission_outcome(update_submission_status(actor, submission_id, command)))


@router.post(
    "/contact-submissions/{submission_id}/no-response/",
    response=ContactNoResponseProjectionSchema,
    exclude_unset=True,
    operation_id="content_contact_no_response",
)
def record_no_response_api(request, submission_id: UUID, payload: ContactNoResponseSchema):
    actor = _actor(request)
    command = ContactNoResponseCommand(**payload.dict())
    def operation():
        disposition = record_contact_no_response(actor, submission_id, command)
        return _outcome(
            no_response_projection(disposition),
            related_object=disposition,
            path=f"/api/v1/content/contact-submissions/{submission_id}/",
        )
    return _run(
        request,
        "content_contact_no_response",
        {"submission_id": str(submission_id), **_payload(payload)},
        operation,
    )


@router.get(
    "/contact-submissions/{submission_id}/replies/",
    response=ContactReplyPageSchema,
    exclude_unset=True,
    operation_id="content_contact_replies",
)
def list_contact_replies(request, submission_id: UUID, page: PageQuery, page_size: PageSizeQuery):
    from apps.content.queries import contact_replies
    return contact_replies(_actor(request), submission_id, _page(page, page_size)).as_dict()


def _reply_outcome(reply):
    return _outcome(project_contact_reply(reply, include_body=True), related_object=reply, path=f"/api/v1/content/contact-replies/{reply.pk}/")


@router.post(
    "/contact-submissions/{submission_id}/replies/",
    response=ContactReplySchema,
    exclude_unset=True,
    operation_id="content_contact_reply_create",
)
def create_reply_api(request, submission_id: UUID, payload: ContactReplyCommandSchema):
    actor = _actor(request)
    command = ContactReplyCommand(**payload.dict())
    return _run(request, "content_contact_reply_create", {"submission_id": str(submission_id), **_payload(payload)}, lambda: _reply_outcome(create_contact_reply(actor, submission_id, command)))


@router.put(
    "/contact-replies/{reply_id}/",
    response=ContactReplySchema,
    exclude_unset=True,
    operation_id="content_contact_reply_update",
)
def update_reply_api(request, reply_id: UUID, payload: ContactReplyCommandSchema):
    actor = _actor(request)
    command = ContactReplyCommand(**payload.dict())
    return _run(request, "content_contact_reply_update", {"reply_id": str(reply_id), **_payload(payload)}, lambda: _reply_outcome(update_contact_reply_draft(actor, reply_id, command)))


@router.post(
    "/contact-replies/{reply_id}/submit/",
    response=ContactReplySchema,
    exclude_unset=True,
    operation_id="content_contact_reply_submit",
)
def submit_reply_api(request, reply_id: UUID, payload: ContactReplyOptionalSchema | None = None):
    actor = _actor(request)
    command = ContactReplyCommand(**_payload(payload)) if payload and payload.body is not None else None
    return _run(request, "content_contact_reply_submit", {"reply_id": str(reply_id), **(_payload(payload) if payload else {})}, lambda: _reply_outcome(submit_contact_reply_for_approval(actor, reply_id, command)))


@router.post(
    "/contact-replies/{reply_id}/approve/",
    response=ContactReplySchema,
    exclude_unset=True,
    operation_id="content_contact_reply_approve",
)
def approve_reply_api(request, reply_id: UUID):
    actor = _actor(request)
    return _run(request, "content_contact_reply_approve", {"reply_id": str(reply_id)}, lambda: _reply_outcome(approve_contact_reply(actor, reply_id)))


@router.post(
    "/contact-replies/{reply_id}/reject/",
    response=ContactReplySchema,
    exclude_unset=True,
    operation_id="content_contact_reply_reject",
)
def reject_reply_api(request, reply_id: UUID):
    actor = _actor(request)
    return _run(request, "content_contact_reply_reject", {"reply_id": str(reply_id)}, lambda: _reply_outcome(reject_contact_reply(actor, reply_id)))


@router.post(
    "/contact-replies/{reply_id}/cancel/",
    response=ContactReplySchema,
    exclude_unset=True,
    operation_id="content_contact_reply_cancel",
)
def cancel_reply_api(request, reply_id: UUID):
    actor = _actor(request)
    return _run(request, "content_contact_reply_cancel", {"reply_id": str(reply_id)}, lambda: _reply_outcome(cancel_contact_reply(actor, reply_id)))


@router.post(
    "/contact-replies/{reply_id}/retry/",
    response=ContactReplySchema,
    exclude_unset=True,
    operation_id="content_contact_reply_retry",
)
def retry_reply_api(request, reply_id: UUID):
    actor = _actor(request)
    return _run(request, "content_contact_reply_retry", {"reply_id": str(reply_id)}, lambda: _reply_outcome(retry_contact_reply(actor, reply_id)))
