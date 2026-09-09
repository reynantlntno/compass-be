"""Safe, internal account-authority management API."""

from datetime import date

from django.db import transaction
from ninja import Router, Schema

from apps.access_control.authority import (
    build_authority_context,
    create_authority_grant,
    matching_grants,
    resolve_capability,
    revoke_authority_grant,
)
from apps.access_control.capabilities import CAPABILITY_SPECS, Capability
from apps.access_control.choices import GrantReasonCode, GrantSourceType, RevocationReasonCode, ScopeMode
from apps.access_control.models import WorkflowAuthorityGrant
from apps.access_control.projections import project_counselor_coverage
from apps.access_control.rules import is_active_nonlegacy_actor, is_counselor
from apps.access_control.scopes import get_live_counselor_coverages
from apps.accounts.models import RoleChoices, User
from apps.common.api.idempotency import ApiMutationOutcome, run_api_mutation
from apps.common.api.operations import prepare_api_operation
from apps.common.api.pagination import (
    PageQuery,
    PageSizeQuery,
    page_request_from_values,
    page_result,
)
from apps.common.exceptions import (
    NotFoundError,
    PermissionDeniedError as PermissionDenied,
    ValidationError,
)


router = Router(tags=["authority"])


class OrganizationScopeSchema(Schema):
    campus: str | None = None
    college: str | None = None
    department: str | None = None
    program: str | None = None


class GrantCreateSchema(Schema):
    grantee_id: int
    capability: str
    scope_mode: str
    valid_from: date
    valid_until: date | None = None
    organization: OrganizationScopeSchema | None = None
    grant_reason_code: str = GrantReasonCode.LOCAL_WORKFLOW
    grant_reason_note: str = ""
    source_reference: str = ""


class BulkGrantSchema(Schema):
    grants: list[GrantCreateSchema]


class CapabilityProjectionSchema(Schema):
    capability: str
    authority_sources: list[str]
    grant_eligible_roles: list[str]
    grant_scope_modes: list[str]
    office_wide_grant_allowed: bool
    expiry_required: bool
    sensitivity: str
    impact_scope: str
    ui_bundle: str


class ScopeOptionSchema(Schema):
    value: str
    label: str


class GranteeProjectionSchema(Schema):
    id: int
    display_label: str
    role: str


class OrganizationProjectionSchema(Schema):
    campus: str | None = None
    college: str | None = None
    department: str | None = None
    program: str | None = None


class GrantProjectionSchema(Schema):
    id: int
    grantee_id: int
    capability: str
    scope_mode: str
    organization: OrganizationProjectionSchema
    valid_from: str
    valid_until: str | None = None
    status: str
    grant_reason_code: str
    grant_reason_note: str
    source_type: str
    source_reference: str
    created_at: str
    updated_at: str
    revoked_at: str | None = None


class EffectiveCapabilityProjectionSchema(Schema):
    capability: str
    source: str
    reason_code: str


class EffectiveAuthorityProjectionSchema(Schema):
    account_id: int
    role: str
    is_head_guidance: bool
    effective_capabilities: list[EffectiveCapabilityProjectionSchema]
    grants: list[GrantProjectionSchema]


class CounselorCoverageProjectionSchema(Schema):
    scope_label: str
    campus: str | None = None
    college: str | None = None
    department: str | None = None
    program: str | None = None
    is_primary: bool


class CounselorCoveragePageSchema(Schema):
    items: list[CounselorCoverageProjectionSchema]
    page: int
    page_size: int
    total: int


class CapabilityPageSchema(Schema):
    items: list[CapabilityProjectionSchema]
    page: int
    page_size: int
    total: int


class ScopeOptionPageSchema(Schema):
    items: list[ScopeOptionSchema]
    page: int
    page_size: int
    total: int


class GranteePageSchema(Schema):
    items: list[GranteeProjectionSchema]
    page: int
    page_size: int
    total: int


class GrantPageSchema(Schema):
    items: list[GrantProjectionSchema]
    page: int
    page_size: int
    total: int


class BulkGrantResultSchema(Schema):
    items: list[GrantProjectionSchema]
    count: int


def _actor(request):
    return request.auth.user


def _require_manager(request):
    actor = _actor(request)
    if not resolve_capability(actor, Capability.WORKFLOW_AUTHORITY_MANAGE):
        raise PermissionDenied()
    return actor


def _project(grant):
    return {
        "id": grant.pk,
        "grantee_id": grant.grantee_id,
        "capability": grant.capability,
        "scope_mode": grant.scope_mode,
        "organization": {
            field: getattr(grant, field, None)
            for field in ("campus", "college", "department", "program")
        },
        "valid_from": grant.valid_from.isoformat(),
        "valid_until": grant.valid_until.isoformat() if grant.valid_until else None,
        "status": grant.status,
        "grant_reason_code": grant.grant_reason_code,
        "grant_reason_note": grant.grant_reason_note,
        "source_type": grant.source_type,
        "source_reference": grant.source_reference,
        "created_at": grant.created_at.isoformat(),
        "updated_at": grant.updated_at.isoformat(),
        "revoked_at": grant.revoked_at.isoformat() if grant.revoked_at else None,
    }


def _effective_projection(context):
    """Expose only effective capabilities and their source, never ORM objects."""
    from apps.access_control.authority import evaluate_capability

    rows = []
    for capability in Capability:
        decision = evaluate_capability(context, capability)
        if decision.allowed:
            rows.append({
                "capability": capability.value,
                "source": decision.source,
                "reason_code": decision.reason_code,
            })
    return rows


@router.get("/capabilities/", response=CapabilityPageSchema, operation_id="authority_capabilities")
def capabilities(request, page: PageQuery, page_size: PageSizeQuery):
    _require_manager(request)
    page_request = page_request_from_values(page, page_size)
    rows = [{
        "capability": cap.value,
        "authority_sources": sorted(source.value for source in spec.authority_sources),
        "grant_eligible_roles": sorted(spec.grant_eligible_roles),
        "grant_scope_modes": sorted(mode.value for mode in spec.grant_scope_modes),
        "office_wide_grant_allowed": spec.office_wide_grant_allowed,
        "expiry_required": spec.expiry_required,
        "sensitivity": spec.sensitivity,
        "impact_scope": spec.impact_scope,
        "ui_bundle": spec.ui_bundle,
    } for cap, spec in CAPABILITY_SPECS.items()]
    return page_result(rows, page_request)


@router.get("/scope-options/", response=ScopeOptionPageSchema, operation_id="authority_scope_options")
def scope_options(request, page: PageQuery, page_size: PageSizeQuery):
    _require_manager(request)
    page_request = page_request_from_values(page, page_size)
    return page_result([{"value": mode.value, "label": mode.label} for mode in ScopeMode], page_request)


@router.get("/grantees/", response=GranteePageSchema, operation_id="authority_grantees")
def grantees(request, page: PageQuery, page_size: PageSizeQuery):
    _require_manager(request)
    page_request = page_request_from_values(page, page_size)
    qs = User.objects.filter(
        is_active=True, is_superuser=False, role__in=[RoleChoices.COUNSELOR, RoleChoices.GCO_STAFF],
    ).order_by("last_name", "first_name", "id")
    total = qs.count()
    rows = list(qs[page_request.offset:page_request.offset + page_request.page_size])
    return {
        "items": [{"id": user.pk, "display_label": user.get_full_name(), "role": user.role} for user in rows],
        "page": page_request.page,
        "page_size": page_request.page_size,
        "total": total,
    }


@router.get("/accounts/{user_id}/grants/", response=GrantPageSchema, operation_id="authority_account_grants")
def account_grants(request, user_id: int, page: PageQuery, page_size: PageSizeQuery):
    _require_manager(request)
    if not User.objects.filter(pk=user_id).exists():
        raise NotFoundError()
    page_request = page_request_from_values(page, page_size)
    queryset = WorkflowAuthorityGrant.objects.filter(grantee_id=user_id).order_by("-created_at")
    return {
        "items": [_project(grant) for grant in queryset[page_request.offset:page_request.offset + page_request.page_size]],
        "page": page_request.page,
        "page_size": page_request.page_size,
        "total": queryset.count(),
    }


@router.get("/accounts/{user_id}/effective/", response=EffectiveAuthorityProjectionSchema, operation_id="authority_account_effective")
def account_effective(request, user_id: int):
    _require_manager(request)
    user = User.objects.filter(pk=user_id).first()
    if user is None:
        raise NotFoundError()
    context = build_authority_context(user)
    return {
        "account_id": user.pk,
        "role": user.role,
        "is_head_guidance": context.is_head_guidance,
        "effective_capabilities": _effective_projection(context),
        "grants": [_project(grant) for grant in context.grants[:100]],
    }


@router.get("/me/", response=EffectiveAuthorityProjectionSchema, operation_id="authority_me")
def me(request):
    user = _actor(request)
    context = build_authority_context(user)
    return {
        "account_id": user.pk,
        "role": user.role,
        "is_head_guidance": context.is_head_guidance,
        "effective_capabilities": _effective_projection(context),
        "grants": [_project(grant) for grant in context.grants[:100]],
    }


@router.get(
    "/me/coverage/",
    response=CounselorCoveragePageSchema,
    operation_id="authority_me_coverage",
)
def me_coverage(request, page: PageQuery, page_size: PageSizeQuery):
    actor = _actor(request)
    page_request = page_request_from_values(page, page_size)
    if not is_active_nonlegacy_actor(actor) or not is_counselor(actor):
        return page_result([], page_request)

    coverages = get_live_counselor_coverages(actor).order_by(
        "-is_primary", "campus", "college", "department", "program", "pk",
    )
    projected = [project_counselor_coverage(coverage) for coverage in coverages]
    return page_result(projected, page_request)


@router.post("/grants/", response=GrantProjectionSchema, operation_id="authority_grant_create")
def grant_create(request, payload: GrantCreateSchema):
    actor = _require_manager(request)
    prepared = prepare_api_operation(request, "authority_grant_create")
    grantee = User.objects.filter(pk=payload.grantee_id).first()
    if grantee is None:
        raise NotFoundError()
    return run_api_mutation(
        request,
        "authority_grant_create",
        payload.dict(),
        lambda: _create_grant_outcome(actor, grantee, payload),
        _grant_replay,
        prepared_operation=prepared,
    )


def _create_grant_outcome(actor, grantee, payload):
    grant = create_authority_grant(
            actor, grantee=grantee, capability=payload.capability, scope_mode=payload.scope_mode,
            valid_from=payload.valid_from, valid_until=payload.valid_until,
            organization=payload.organization.dict() if payload.organization else {},
            grant_reason_code=payload.grant_reason_code,
            grant_reason_note=payload.grant_reason_note, source_type=GrantSourceType.MANUAL,
            source_reference=payload.source_reference,
        )
    return ApiMutationOutcome(
        value=_project(grant),
        related_object=grant,
        safe_response_path=f"/api/v1/authority/accounts/{grant.grantee_id}/grants/",
    )


def _grant_replay(key):
    grant = WorkflowAuthorityGrant.objects.filter(pk=key.related_object_id).first()
    return _project(grant) if grant else None


@router.post("/grants/bulk/", response=BulkGrantResultSchema, operation_id="authority_grant_bulk_create")
@transaction.atomic
def grant_bulk_create(request, payload: BulkGrantSchema):
    actor = _require_manager(request)
    if not payload.grants or len(payload.grants) > 100:
        raise ValidationError()
    prepared = prepare_api_operation(request, "authority_grant_bulk_create")
    return run_api_mutation(
        request,
        "authority_grant_bulk_create",
        payload.dict(),
        lambda: _create_bulk_grant_outcome(actor, payload),
        _bulk_grant_replay,
        prepared_operation=prepared,
    )


def _create_bulk_grant_outcome(actor, payload):
    created = []
    for item in payload.grants:
        grantee = User.objects.filter(pk=item.grantee_id).first()
        if grantee is None:
            raise NotFoundError()
        created.append(create_authority_grant(
                actor, grantee=grantee, capability=item.capability, scope_mode=item.scope_mode,
                valid_from=item.valid_from, valid_until=item.valid_until,
                organization=item.organization.dict() if item.organization else {},
                grant_reason_code=item.grant_reason_code, grant_reason_note=item.grant_reason_note,
                source_type=GrantSourceType.BULK, source_reference=item.source_reference,
            ))
    return ApiMutationOutcome(
        value={"items": [_project(grant) for grant in created], "count": len(created)},
        related_object_ids=tuple(str(grant.pk) for grant in created),
        safe_response_path="/api/v1/authority/grants/bulk/",
    )


def _bulk_grant_replay(key):
    ids = (key.metadata_json or {}).get("related_object_ids", [])
    grants = WorkflowAuthorityGrant.objects.filter(pk__in=ids)
    by_id = {str(grant.pk): grant for grant in grants}
    items = [_project(by_id[item]) for item in ids if item in by_id]
    return {"items": items, "count": len(items)}


@router.post("/grants/{grant_id}/revoke/", response=GrantProjectionSchema, operation_id="authority_grant_revoke")
def grant_revoke(request, grant_id: int, reason_code: str = RevocationReasonCode.NO_LONGER_NEEDED):
    actor = _require_manager(request)
    grant = WorkflowAuthorityGrant.objects.filter(pk=grant_id).first()
    if grant is None:
        raise NotFoundError()
    prepared = prepare_api_operation(request, "authority_grant_revoke")
    return run_api_mutation(
        request,
        "authority_grant_revoke",
        {"grant_id": grant_id, "reason_code": reason_code},
        lambda: _revoke_grant_outcome(actor, grant, reason_code),
        _grant_replay,
        prepared_operation=prepared,
    )


def _revoke_grant_outcome(actor, grant, reason_code):
    grant = revoke_authority_grant(actor, grant, reason_code=reason_code)
    return ApiMutationOutcome(
        value=_project(grant),
        related_object=grant,
        safe_response_path=f"/api/v1/authority/accounts/{grant.grantee_id}/grants/",
    )
