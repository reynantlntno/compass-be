"""Authenticated administration API for controlled staff onboarding."""

from uuid import UUID

from ninja import Router, Schema

from apps.accounts.commands import StaffAccountCreateCommand, StaffInvitationActivationCommand
from apps.accounts.models import RoleChoices
from apps.accounts.projections import project_staff_account, project_head_designation
from apps.accounts.queries import (
    head_designation_visible_to,
    staff_account_visible_to,
    staff_accounts_page_visible_to,
    staff_accounts_visible_to,
)
from apps.accounts.services import (
    assign_head_guidance,
    deactivate_staff_account,
    provision_staff_account,
    reissue_staff_invitation,
    revoke_head_guidance,
)
from apps.common.api.idempotency import ApiMutationOutcome, run_api_mutation
from apps.common.api.operations import prepare_api_operation
from apps.common.api.pagination import PageQuery, PageSizeQuery, page_request_from_values
from apps.common.exceptions import NotFoundError, PermissionDeniedError
from apps.profiles.models import CounselorProfile


router = Router(tags=["staff-accounts"])


class StaffAccountCreateSchema(Schema):
    email: str
    first_name: str
    last_name: str
    role: str
    license_number: str = ""
    designation: str = ""
    validity_days: int | None = None
    source_reference: str = ""


class InvitationStateSchema(Schema):
    state: str
    expires_at: str | None = None
    created_at: str | None = None
    used_at: str | None = None
    revoked_at: str | None = None


class StaffAccountSchema(Schema):
    id: int
    email: str
    first_name: str
    last_name: str
    role: str
    is_active: bool
    profile_type: str | None = None
    designation: str
    license_present: bool
    employee_number_present: bool
    is_head_guidance: bool
    invitation: InvitationStateSchema


class HeadGuidanceSchema(Schema):
    user_id: int


class HeadGuidanceProjectionSchema(Schema):
    user_id: int
    is_head_guidance: bool
    designated_at: str | None = None


class StaffAccountPageSchema(Schema):
    items: list[StaffAccountSchema]
    page: int
    page_size: int
    total: int


def _actor(request):
    return request.auth.user


def _require_head(actor):
    from apps.accounts.policies import can_manage_staff_accounts
    if not can_manage_staff_accounts(actor, RoleChoices.COUNSELOR):
        raise PermissionDeniedError()


def _staff_replay(key):
    from apps.accounts.selectors import get_pending_staff_invitation, get_staff_account_by_id
    user = get_staff_account_by_id(key.related_object_id)
    return project_staff_account(user, get_pending_staff_invitation(user)) if user else None


def _head_replay(key):
    profile = CounselorProfile.objects.filter(pk=key.related_object_id).select_related("user").first()
    return project_head_designation(profile)


@router.get("/", response=StaffAccountPageSchema, operation_id="staff_accounts_list")
def list_staff_accounts(request, page: PageQuery, page_size: PageSizeQuery):
    actor = _actor(request)
    _require_head(actor)
    return staff_accounts_page_visible_to(actor, page_request_from_values(page, page_size))


@router.post("/", response=StaffAccountSchema, operation_id="staff_accounts_create")
def create_staff_account(request, payload: StaffAccountCreateSchema):
    actor = _actor(request)
    _require_head(actor)
    prepared = prepare_api_operation(request, "staff_accounts_create")
    command = StaffAccountCreateCommand(**payload.dict())
    return run_api_mutation(
        request,
        "staff_accounts_create",
        payload.dict(),
        lambda: _provision_staff_outcome(actor, command),
        _staff_replay,
        prepared_operation=prepared,
    )


def _provision_staff_outcome(actor, command):
    user, invitation = provision_staff_account(actor, command)
    return ApiMutationOutcome(
        value=project_staff_account(user, invitation),
        related_object=user,
        safe_response_path=f"/api/v1/staff-accounts/{user.pk}/",
    )


@router.get("/{user_id}/", response=StaffAccountSchema, operation_id="staff_accounts_view")
def view_staff_account(request, user_id: int):
    result = staff_account_visible_to(_actor(request), user_id)
    if result is None:
        raise NotFoundError()
    return result


@router.post("/{user_id}/reinvite/", response=StaffAccountSchema, operation_id="staff_accounts_reinvite")
def reinvite_staff_account(request, user_id: int):
    actor = _actor(request)
    from apps.accounts.selectors import get_staff_account_by_id
    user = get_staff_account_by_id(user_id)
    if user is None:
        raise NotFoundError()
    _require_head(actor)
    prepared = prepare_api_operation(request, "staff_accounts_reinvite")
    return run_api_mutation(
        request,
        "staff_accounts_reinvite",
        {"user_id": user_id},
        lambda: _reinvite_staff_outcome(actor, user),
        _staff_replay,
        prepared_operation=prepared,
    )


def _reinvite_staff_outcome(actor, user):
    invitation = reissue_staff_invitation(actor, user)
    return ApiMutationOutcome(
        value=project_staff_account(user, invitation),
        related_object=user,
        safe_response_path=f"/api/v1/staff-accounts/{user.pk}/",
    )


@router.post("/{user_id}/deactivate/", response=StaffAccountSchema, operation_id="staff_accounts_deactivate")
def deactivate_staff_account_api(request, user_id: int):
    actor = _actor(request)
    from apps.accounts.selectors import get_staff_account_by_id
    user = get_staff_account_by_id(user_id)
    if user is None:
        raise NotFoundError()
    _require_head(actor)
    prepared = prepare_api_operation(request, "staff_accounts_deactivate")
    return run_api_mutation(
        request,
        "staff_accounts_deactivate",
        {"user_id": user_id},
        lambda: _deactivate_staff_outcome(actor, user),
        _staff_replay,
        prepared_operation=prepared,
    )


def _deactivate_staff_outcome(actor, user):
    user = deactivate_staff_account(actor, user)
    return ApiMutationOutcome(
        value=project_staff_account(user),
        related_object=user,
        safe_response_path=f"/api/v1/staff-accounts/{user.pk}/",
    )


@router.post(
    "/head-guidance/assign/",
    response=HeadGuidanceProjectionSchema,
    exclude_unset=True,
    operation_id="staff_accounts_head_guidance_assign",
)
def assign_head(request, payload: HeadGuidanceSchema):
    actor = _actor(request)
    from apps.accounts.selectors import get_staff_account_by_id
    target = get_staff_account_by_id(payload.user_id)
    if target is None:
        raise NotFoundError()
    _require_head(actor)
    prepared = prepare_api_operation(request, "staff_accounts_head_guidance_assign")
    return run_api_mutation(
        request,
        "staff_accounts_head_guidance_assign",
        payload.dict(),
        lambda: _head_assign_outcome(actor, target),
        _head_replay,
        prepared_operation=prepared,
    )


def _head_assign_outcome(actor, target):
    profile = assign_head_guidance(actor, target)
    return ApiMutationOutcome(
        value=project_head_designation(profile),
        related_object=profile,
        safe_response_path="/api/v1/staff-accounts/head-guidance/",
    )


@router.post(
    "/head-guidance/revoke/",
    response=HeadGuidanceProjectionSchema,
    exclude_unset=True,
    operation_id="staff_accounts_head_guidance_revoke",
)
def revoke_head(request, payload: HeadGuidanceSchema):
    actor = _actor(request)
    from apps.accounts.selectors import get_staff_account_by_id
    target = get_staff_account_by_id(payload.user_id)
    if target is None:
        raise NotFoundError()
    _require_head(actor)
    prepared = prepare_api_operation(request, "staff_accounts_head_guidance_revoke")
    return run_api_mutation(
        request,
        "staff_accounts_head_guidance_revoke",
        payload.dict(),
        lambda: _head_revoke_outcome(actor, target),
        _head_replay,
        prepared_operation=prepared,
    )


def _head_revoke_outcome(actor, target):
    profile = revoke_head_guidance(actor, target)
    return ApiMutationOutcome(
        value=project_head_designation(profile),
        related_object=profile,
        safe_response_path="/api/v1/staff-accounts/head-guidance/",
    )
