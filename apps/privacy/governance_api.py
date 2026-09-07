"""Privacy-owned administrative policy routes.

The generic lifecycle remains in Governance; these aggregates and their v1
HTTP surface belong to the privacy domain.
"""

from datetime import datetime
from uuid import UUID

from ninja import Router, Schema

from apps.common.api.idempotency import ApiMutationOutcome, run_api_mutation
from apps.common.api.operations import prepare_api_operation
from apps.common.api.pagination import PageQuery, PageSizeQuery, page_request_from_values
from apps.common.exceptions import NotFoundError, ValidationError
from apps.privacy.commands import PrivacyReviewerAuthorizationCommand
from apps.privacy.models import PrivacyNoticeRevision, PrivacyReviewerAuthorization, PrivacyWorkflowBinding
from apps.privacy.projections import (
    notice_revision_projection,
    reviewer_authorization_projection,
    workflow_binding_projection,
)


router = Router(tags=["privacy"])


class PrivacyReviewerAuthorizationCreateSchema(Schema):
    authorized_user_id: int
    scopes: list[str]
    categories: list[str]
    valid_from: datetime
    valid_until: datetime | None = None
    source_reference: str


class PrivacyReviewerAuthorizationSchema(Schema):
    id: str
    authorized_user_id: int
    scopes: list[str]
    categories: list[str]
    valid_from: str
    valid_until: str | None = None
    source_reference: str
    status: str
    authorized_at: str
    revoked_at: str | None = None


class PrivacyReviewerAuthorizationPageSchema(Schema):
    items: list[PrivacyReviewerAuthorizationSchema]
    page: int
    page_size: int
    total: int


class GovernanceReasonSchema(Schema):
    reason_code: str = ""


class PrivacyNoticeRevisionCreateSchema(Schema):
    notice_identifier: str
    version: str
    body_markdown: str
    source_reference: str
    effective_at: datetime | None = None
    locale: str = "en"
    purpose_workflow: str
    supersedes_id: int | None = None


class PrivacyNoticeRevisionApprovalSchema(Schema):
    approval_reference: str


class PrivacyNoticeRevisionSchema(Schema):
    id: str
    notice_identifier: str
    version: str
    body_markdown: str
    revision_hash: str
    source_reference: str
    effective_at: str | None = None
    locale: str
    purpose_workflow: str
    status: str
    approval_state: str
    approval_reference: str
    approved_at: str | None = None
    created_at: str


class PrivacyNoticeRevisionPageSchema(Schema):
    items: list[PrivacyNoticeRevisionSchema]
    page: int
    page_size: int
    total: int


class PrivacyWorkflowBindingSetSchema(Schema):
    purpose_workflow: str
    notice_revision_id: int | None = None
    status: str = "BLOCKED"
    required: bool = True
    source_reference: str = ""
    block_reason: str = ""


class PrivacyWorkflowBindingSchema(Schema):
    id: str
    purpose_workflow: str
    notice_revision_id: str | None = None
    status: str
    required: bool
    source_reference: str
    block_reason: str
    created_at: str
    updated_at: str


class PrivacyWorkflowBindingPageSchema(Schema):
    items: list[PrivacyWorkflowBindingSchema]
    page: int
    page_size: int
    total: int


def _actor(request):
    return request.auth.user


def _page_request(page: PageQuery, page_size: PageSizeQuery):
    try:
        return page_request_from_values(page, page_size)
    except ValueError as error:
        raise ValidationError() from error


def _current_dpo_actor(actor):
    from apps.governance.dpo_services import is_current_dpo

    return bool(is_current_dpo(actor))


def _reviewer_replay(key):
    authorization = PrivacyReviewerAuthorization.objects.filter(pk=key.related_object_id).first()
    return reviewer_authorization_projection(authorization)


def _notice_revision_replay(key):
    revision = PrivacyNoticeRevision.objects.filter(pk=key.related_object_id).first()
    return notice_revision_projection(revision)


def _notice_binding_replay(key):
    binding = PrivacyWorkflowBinding.objects.filter(pk=key.related_object_id).first()
    return workflow_binding_projection(binding)


def _governance_outcome(value, projector, path):
    return ApiMutationOutcome(value=projector(value), related_object=value, safe_response_path=path)


@router.get("/reviewer-authorizations/", response=PrivacyReviewerAuthorizationPageSchema, operation_id="privacy_reviewer_authorizations")
def privacy_reviewer_authorizations(request, page: PageQuery, page_size: PageSizeQuery):
    actor = _actor(request)
    if not _current_dpo_actor(actor):
        raise NotFoundError()
    page = _page_request(page, page_size)
    queryset = PrivacyReviewerAuthorization.objects.all().order_by("-created_at")
    total = queryset.count()
    items = [
        reviewer_authorization_projection(row)
        for row in queryset[page.offset:page.offset + page.page_size]
    ]
    return {"items": items, "page": page.page, "page_size": page.page_size, "total": total}


@router.post(
    "/reviewer-authorizations/",
    response=PrivacyReviewerAuthorizationSchema,
    exclude_unset=True,
    operation_id="privacy_reviewer_authorization_create",
)
def privacy_reviewer_authorization_create(request, payload: PrivacyReviewerAuthorizationCreateSchema):
    actor = _actor(request)
    from apps.privacy.services import create_privacy_reviewer_authorization_command

    command = PrivacyReviewerAuthorizationCommand(
        authorized_user_id=str(payload.authorized_user_id),
        scopes=tuple(payload.scopes),
        categories=tuple(payload.categories),
        valid_from=payload.valid_from,
        valid_until=payload.valid_until,
        source_reference=payload.source_reference,
    )
    prepared = prepare_api_operation(request, "privacy_reviewer_authorization_create")
    return run_api_mutation(
        request,
        "privacy_reviewer_authorization_create",
        {
            "authorized_user_id": command.authorized_user_id,
            "scopes": list(command.scopes),
            "categories": list(command.categories),
            "source_reference": command.source_reference,
        },
        lambda: _governance_outcome(
            create_privacy_reviewer_authorization_command(actor=actor, command=command),
            reviewer_authorization_projection,
            "/api/v1/privacy/reviewer-authorizations/",
        ),
        _reviewer_replay,
        prepared_operation=prepared,
    )


@router.post(
    "/reviewer-authorizations/{authorization_id}/revoke/",
    response=PrivacyReviewerAuthorizationSchema,
    exclude_unset=True,
    operation_id="privacy_reviewer_authorization_revoke",
)
def privacy_reviewer_authorization_revoke(request, authorization_id: UUID, payload: GovernanceReasonSchema | None = None):
    actor = _actor(request)
    from apps.privacy.services import revoke_privacy_reviewer_authorization_by_id

    reason_code = (payload.reason_code if payload else "REVOKED_BY_DPO")[:80]
    prepared = prepare_api_operation(request, "privacy_reviewer_authorization_revoke")
    return run_api_mutation(
        request,
        "privacy_reviewer_authorization_revoke",
        {"authorization_id": str(authorization_id), "reason_code": reason_code},
        lambda: _governance_outcome(
            revoke_privacy_reviewer_authorization_by_id(
                actor=actor,
                authorization_id=authorization_id,
                reason_code=reason_code,
            ),
            reviewer_authorization_projection,
            "/api/v1/privacy/reviewer-authorizations/",
        ),
        _reviewer_replay,
        prepared_operation=prepared,
    )


@router.get(
    "/notice-revisions/",
    response=PrivacyNoticeRevisionPageSchema,
    operation_id="privacy_notice_revisions",
)
def privacy_notice_revisions(request, page: PageQuery, page_size: PageSizeQuery):
    if not _current_dpo_actor(_actor(request)):
        raise NotFoundError()
    page = _page_request(page, page_size)
    queryset = PrivacyNoticeRevision.objects.all().order_by("-created_at", "-pk")
    total = queryset.count()
    items = [
        notice_revision_projection(row)
        for row in queryset[page.offset:page.offset + page.page_size]
    ]
    return {"items": items, "page": page.page, "page_size": page.page_size, "total": total}


@router.post(
    "/notice-revisions/",
    response=PrivacyNoticeRevisionSchema,
    operation_id="privacy_notice_revision_create",
)
def privacy_notice_revision_create(request, payload: PrivacyNoticeRevisionCreateSchema):
    actor = _actor(request)
    from apps.privacy.commands import PrivacyNoticeRevisionCommand
    from apps.privacy.services import create_privacy_notice_revision_command

    command = PrivacyNoticeRevisionCommand(
        notice_identifier=payload.notice_identifier,
        version=payload.version,
        body_markdown=payload.body_markdown,
        source_reference=payload.source_reference,
        effective_at=payload.effective_at,
        locale=payload.locale,
        purpose_workflow=payload.purpose_workflow,
        supersedes_id=str(payload.supersedes_id) if payload.supersedes_id else "",
    )
    prepared = prepare_api_operation(request, "privacy_notice_revision_create")
    return run_api_mutation(
        request,
        "privacy_notice_revision_create",
        {
            "notice_identifier": command.notice_identifier,
            "version": command.version,
            "purpose_workflow": command.purpose_workflow,
            "locale": command.locale,
        },
        lambda: _governance_outcome(
            create_privacy_notice_revision_command(actor=actor, command=command),
            notice_revision_projection,
            "/api/v1/privacy/notice-revisions/",
        ),
        _notice_revision_replay,
        prepared_operation=prepared,
    )


@router.post(
    "/notice-revisions/{revision_id}/approve/",
    response=PrivacyNoticeRevisionSchema,
    operation_id="privacy_notice_revision_approve",
)
def privacy_notice_revision_approve(request, revision_id: int, payload: PrivacyNoticeRevisionApprovalSchema):
    actor = _actor(request)
    from apps.privacy.commands import PrivacyNoticeRevisionApprovalCommand
    from apps.privacy.services import approve_privacy_notice_revision_command

    command = PrivacyNoticeRevisionApprovalCommand(approval_reference=payload.approval_reference)
    prepared = prepare_api_operation(request, "privacy_notice_revision_approve")
    return run_api_mutation(
        request,
        "privacy_notice_revision_approve",
        {"revision_id": str(revision_id), "approval_reference": command.approval_reference},
        lambda: _governance_outcome(
            approve_privacy_notice_revision_command(actor=actor, revision_id=revision_id, command=command),
            notice_revision_projection,
            f"/api/v1/privacy/notice-revisions/{revision_id}/",
        ),
        _notice_revision_replay,
        prepared_operation=prepared,
    )


@router.post(
    "/notice-revisions/{revision_id}/retire/",
    response=PrivacyNoticeRevisionSchema,
    operation_id="privacy_notice_revision_retire",
)
def privacy_notice_revision_retire(request, revision_id: int, payload: GovernanceReasonSchema):
    actor = _actor(request)
    from apps.privacy.commands import PrivacyNoticeRevisionRetirementCommand
    from apps.privacy.services import retire_privacy_notice_revision_command

    command = PrivacyNoticeRevisionRetirementCommand(reason_code=payload.reason_code)
    prepared = prepare_api_operation(request, "privacy_notice_revision_retire")
    return run_api_mutation(
        request,
        "privacy_notice_revision_retire",
        {"revision_id": str(revision_id), "reason_code": command.reason_code},
        lambda: _governance_outcome(
            retire_privacy_notice_revision_command(actor=actor, revision_id=revision_id, command=command),
            notice_revision_projection,
            f"/api/v1/privacy/notice-revisions/{revision_id}/",
        ),
        _notice_revision_replay,
        prepared_operation=prepared,
    )


@router.get(
    "/notice-bindings/",
    response=PrivacyWorkflowBindingPageSchema,
    operation_id="privacy_notice_bindings",
)
def privacy_notice_bindings(request, page: PageQuery, page_size: PageSizeQuery):
    if not _current_dpo_actor(_actor(request)):
        raise NotFoundError()
    page = _page_request(page, page_size)
    queryset = PrivacyWorkflowBinding.objects.all().order_by("purpose_workflow")
    total = queryset.count()
    items = [
        workflow_binding_projection(row)
        for row in queryset[page.offset:page.offset + page.page_size]
    ]
    return {"items": items, "page": page.page, "page_size": page.page_size, "total": total}


@router.post(
    "/notice-bindings/",
    response=PrivacyWorkflowBindingSchema,
    operation_id="privacy_notice_binding_set",
)
def privacy_notice_binding_set(request, payload: PrivacyWorkflowBindingSetSchema):
    actor = _actor(request)
    from apps.privacy.commands import PrivacyWorkflowBindingCommand
    from apps.privacy.services import bind_privacy_notice_command

    command = PrivacyWorkflowBindingCommand(
        purpose_workflow=payload.purpose_workflow,
        notice_revision_id=str(payload.notice_revision_id) if payload.notice_revision_id else "",
        status=payload.status,
        required=payload.required,
        source_reference=payload.source_reference,
        block_reason=payload.block_reason,
    )
    prepared = prepare_api_operation(request, "privacy_notice_binding_set")
    return run_api_mutation(
        request,
        "privacy_notice_binding_set",
        {
            "purpose_workflow": command.purpose_workflow,
            "notice_revision_id": command.notice_revision_id,
            "status": command.status,
            "required": command.required,
        },
        lambda: _governance_outcome(
            bind_privacy_notice_command(actor=actor, command=command),
            workflow_binding_projection,
            "/api/v1/privacy/notice-bindings/",
        ),
        _notice_binding_replay,
        prepared_operation=prepared,
    )
