"""Authenticated, metadata-only Policy Center API."""

from datetime import datetime
from uuid import UUID

from ninja import Router, Schema

from apps.common.api.idempotency import ApiMutationOutcome, run_api_mutation
from apps.common.api.operations import prepare_api_operation
from apps.common.api.pagination import (
    PageQuery,
    PageSizeQuery,
    page_request_from_values,
    page_result,
)
from apps.common.exceptions import NotFoundError, ValidationError
from apps.common.policy import PolicyChangeRequest
from apps.governance.projections import project_policy
from apps.governance.registry import POLICY_SPECS, get_policy_spec
from apps.governance.selectors import effective_policies_visible_to, policies_visible_to
from apps.governance.policy_lifecycle import (
    activate_policy,
    approve_policy,
    can_manage_policy,
    create_policy_draft,
    reject_policy,
    retire_policy,
    submit_policy,
    update_policy_draft,
)
from apps.governance.models import PolicyRecord


router = Router(tags=["policies"])


class PolicyProjectionSchema(Schema):
    id: str
    key: str
    schema_version: str
    owner_plane: str
    target_type: str
    target_reference: str
    sensitivity: str
    status: str
    effectiveness: str
    effective_from: str | None = None
    effective_until: str | None = None
    source_reference: str
    configuration: dict
    created_at: str
    updated_at: str
    approved_at: str | None = None
    activated_at: str | None = None
    retired_at: str | None = None
    approval_evidence: dict


class PolicySpecSchema(Schema):
    key: str
    owner_plane: str
    sensitivity: str
    lifecycle_actions: list[str]
    approval_required: bool
    requires_effective_dates: bool
    projection_fields: list[str]
    configuration_fields: list[str]
    target_type: str
    target_required: bool
    runtime_reader: str
    runtime_consumer: str
    stricter_only: bool


class PolicyPageSchema(Schema):
    items: list[PolicyProjectionSchema]
    page: int
    page_size: int
    total: int


class PolicySpecPageSchema(Schema):
    items: list[PolicySpecSchema]
    page: int
    page_size: int
    total: int


class PolicyDraftSchema(Schema):
    """Generic policy envelope validated by the registered domain contract."""

    key: str
    effective_from: datetime | None = None
    effective_until: datetime | None = None
    source_reference: str
    configuration: dict | None = None
    target_type: str = ""
    target_reference: str = ""


class PolicyRejectionSchema(Schema):
    reason_code: str


def _actor(request):
    return request.auth.user


def _page_request(page: PageQuery, page_size: PageSizeQuery):
    try:
        return page_request_from_values(page, page_size)
    except ValueError as error:
        raise ValidationError() from error


def _command(payload: PolicyDraftSchema):
    spec = get_policy_spec(payload.key)
    if spec is None:
        raise ValidationError()
    return PolicyChangeRequest(
        key=payload.key,
        configuration=dict(payload.configuration or {}),
        effective_from=payload.effective_from,
        effective_until=payload.effective_until,
        source_reference=payload.source_reference,
        target_type=payload.target_type,
        target_reference=payload.target_reference,
    )


def _load_owned(actor, policy_id: UUID):
    policy = PolicyRecord.objects.filter(pk=policy_id).first()
    if policy is None or not can_manage_policy(actor, policy.key):
        raise NotFoundError()
    return policy


@router.get("/catalog/", response=PolicySpecPageSchema, operation_id="policies_catalog")
def catalog(request, page: PageQuery, page_size: PageSizeQuery):
    actor = _actor(request)
    page = _page_request(page, page_size)
    visible = [spec for spec in POLICY_SPECS if can_manage_policy(actor, spec.key)]
    rows = [{
        "key": spec.key,
        "owner_plane": getattr(spec.owner_plane, "value", spec.owner_plane),
        "sensitivity": spec.sensitivity,
        "lifecycle_actions": list(spec.lifecycle_actions),
        "approval_required": spec.approval_required,
        "requires_effective_dates": spec.requires_effective_dates,
        "projection_fields": list(spec.projection_fields),
        "configuration_fields": list(spec.configuration_fields),
        "target_type": spec.target_type,
        "target_required": spec.target_required,
        "runtime_reader": spec.runtime_reader,
        "runtime_consumer": spec.runtime_consumer,
        "stricter_only": spec.stricter_only,
    } for spec in visible]
    return page_result(rows, page)


@router.get("/effective/", response=PolicyPageSchema, operation_id="policies_effective")
def effective(request, page: PageQuery, page_size: PageSizeQuery):
    actor = _actor(request)
    page = _page_request(page, page_size)
    target_type = str(request.GET.get("target_type", "") or "").strip()
    target_reference = str(request.GET.get("target_reference", "") or "").strip()
    policy_key = str(request.GET.get("key", "") or "").strip()
    rows = effective_policies_visible_to(actor)
    if target_type:
        rows = rows.filter(target_type=target_type)
    if target_reference:
        rows = rows.filter(target_reference=target_reference)
    if policy_key:
        rows = rows.filter(key=policy_key)
    total = rows.count()
    items = [project_policy(policy) for policy in rows[page.offset: page.offset + page.page_size]]
    return {"items": items, "page": page.page, "page_size": page.page_size, "total": total}


@router.get("/{policy_key}/", response=PolicyProjectionSchema, operation_id="policies_view")
def view(request, policy_key: str, target_type: str = "", target_reference: str = ""):
    actor = _actor(request)
    if not can_manage_policy(actor, policy_key):
        raise NotFoundError()
    spec = next((item for item in POLICY_SPECS if item.key == policy_key), None)
    if spec is None:
        raise NotFoundError()
    if spec.target_required and (not target_type or not target_reference):
        raise NotFoundError()
    if not spec.target_required and (target_type or target_reference):
        raise NotFoundError()
    policy = policies_visible_to(actor).filter(
        key=policy_key,
        target_type=target_type,
        target_reference=target_reference,
    ).first()
    if policy is None:
        raise NotFoundError()
    return project_policy(policy)


def _policy_replay(key):
    policy = PolicyRecord.objects.filter(pk=key.related_object_id).first()
    return project_policy(policy) if policy else None


def _policy_outcome(policy):
    return ApiMutationOutcome(
        value=project_policy(policy),
        related_object=policy,
        safe_response_path=f"/api/v1/policies/{policy.pk}/",
    )


@router.post("/drafts/", response=PolicyProjectionSchema, operation_id="policies_draft_create")
def draft_create(request, payload: PolicyDraftSchema):
    actor = _actor(request)
    prepared = prepare_api_operation(request, "policies_draft_create")
    command = _command(payload)
    return run_api_mutation(
        request,
        "policies_draft_create",
        payload.dict(),
        lambda: _policy_outcome(create_policy_draft(actor, command)),
        _policy_replay,
        prepared_operation=prepared,
    )


@router.put("/drafts/{policy_id}/", response=PolicyProjectionSchema, operation_id="policies_draft_update")
def draft_update(request, policy_id: UUID, payload: PolicyDraftSchema):
    actor = _actor(request)
    policy = _load_owned(actor, policy_id)
    prepared = prepare_api_operation(request, "policies_draft_update")
    command = _command(payload)
    return run_api_mutation(
        request,
        "policies_draft_update",
        {"policy_id": str(policy_id), **payload.dict()},
        lambda: _policy_outcome(update_policy_draft(actor, policy, command)),
        _policy_replay,
        prepared_operation=prepared,
    )


@router.post("/{policy_id}/submit/", response=PolicyProjectionSchema, operation_id="policies_submit")
def submit(request, policy_id: UUID):
    actor = _actor(request)
    policy = _load_owned(actor, policy_id)
    prepared = prepare_api_operation(request, "policies_submit")
    return run_api_mutation(
        request,
        "policies_submit",
        {"policy_id": str(policy_id)},
        lambda: _policy_outcome(submit_policy(actor, policy)),
        _policy_replay,
        prepared_operation=prepared,
    )


@router.post("/{policy_id}/approve/", response=PolicyProjectionSchema, operation_id="policies_approve")
def approve(request, policy_id: UUID):
    actor = _actor(request)
    policy = _load_owned(actor, policy_id)
    prepared = prepare_api_operation(request, "policies_approve")
    return run_api_mutation(
        request,
        "policies_approve",
        {"policy_id": str(policy_id)},
        lambda: _policy_outcome(approve_policy(actor, policy)),
        _policy_replay,
        prepared_operation=prepared,
    )


@router.post("/{policy_id}/reject/", response=PolicyProjectionSchema, operation_id="policies_reject")
def reject(request, policy_id: UUID, payload: PolicyRejectionSchema):
    actor = _actor(request)
    policy = _load_owned(actor, policy_id)
    prepared = prepare_api_operation(request, "policies_reject")
    return run_api_mutation(
        request,
        "policies_reject",
        {"policy_id": str(policy_id), **payload.dict()},
        lambda: _policy_outcome(reject_policy(actor, policy, reason_code=payload.reason_code)),
        _policy_replay,
        prepared_operation=prepared,
    )


@router.post("/{policy_id}/activate/", response=PolicyProjectionSchema, operation_id="policies_activate")
def activate(request, policy_id: UUID):
    actor = _actor(request)
    policy = _load_owned(actor, policy_id)
    prepared = prepare_api_operation(request, "policies_activate")
    return run_api_mutation(
        request,
        "policies_activate",
        {"policy_id": str(policy_id)},
        lambda: _policy_outcome(activate_policy(actor, policy)),
        _policy_replay,
        prepared_operation=prepared,
    )


@router.post("/{policy_id}/retire/", response=PolicyProjectionSchema, operation_id="policies_retire")
def retire(request, policy_id: UUID):
    actor = _actor(request)
    policy = _load_owned(actor, policy_id)
    prepared = prepare_api_operation(request, "policies_retire")
    return run_api_mutation(
        request,
        "policies_retire",
        {"policy_id": str(policy_id)},
        lambda: _policy_outcome(retire_policy(actor, policy)),
        _policy_replay,
        prepared_operation=prepared,
    )
