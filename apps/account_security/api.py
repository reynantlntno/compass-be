"""Authentication and current-user operations for API v1."""

from __future__ import annotations

import json
from uuid import UUID

from django.http import HttpResponse
from django.middleware.csrf import get_token
from ninja import Query, Router, Status

from apps.account_security.api_tokens import (
    ApiRateLimited,
    ApiSecurityUnavailable,
    ApiTokenError,
    InvalidApiCredentials,
    begin_password_login,
    complete_password_login,
    revoke_form_invitation_family,
    revoke_session_for_raw_credential,
    rotate_refresh_token,
)
from apps.account_security.network import get_client_ip_from_headers
from apps.account_security.api_auth import extract_bearer_token
from apps.account_security.session_cookies import (
    authorization_header,
    clear_session_cookies,
    clear_trusted_device_cookie,
    session_access_cookie,
    session_refresh_cookie,
    session_response,
    session_transport_requested,
    set_session_cookies,
    trusted_device_cookie,
)
from apps.common.contracts import RequestMetadata
from apps.account_security.schemas import (
    ActivityPageSchema,
    AuthSessionReceiptSchema,
    CsrfTokenSchema,
    ErrorSchema,
    LoginChallengeSchema,
    LoginRequestSchema,
    LoginVerifyRequestSchema,
    LogoutRequestSchema,
    MeSchema,
    RefreshTokenRequestSchema,
    TokenPairSchema,
    StaffActivationRequestSchema,
    StudentActivationRequestSchema,
    StaffActivationResponseSchema,
    PasswordChangeRequestSchema,
    RecoveryRequestSchema,
    RecoveryResetRequestSchema,
    RecoveryResponseSchema,
    OtpResendRequestSchema,
    OtpResendResponseSchema,
    PasswordChangedResponseSchema,
    RecoveryResetResponseSchema,
    StaffAssistedRecoveryRequestSchema,
    StaffAssistedRecoveryResponseSchema,
    RevocationResponseSchema,
    SessionPageSchema,
    TrustedDevicePageSchema,
    TwoFactorStatusSchema,
    TwoFactorChangeRequestSchema,
    TwoFactorChangeVerifyRequestSchema,
    AssuranceChallengeSchema,
    AssuranceVerifyRequestSchema,
    AssuranceVerifyResponseSchema,
    TwoFactorChangeResponseSchema,
)
from apps.common.exceptions import (
    CompassError,
    DependencyFailureError,
    InvalidCredentialsError,
    RateLimitError,
)
from apps.common.api.operations import prepare_api_operation
from apps.common.api.correlation import request_id, trace_id
from apps.common.api.idempotency import ApiMutationOutcome, run_api_mutation
from apps.common.api.pagination import PageQuery, PageSizeQuery, page_request_from_values
from apps.common.contracts import ContractValidationError
from apps.access_control.rules import is_active_nonlegacy_actor
from apps.account_security.application_services import (
    change_password,
    request_staff_account_recovery,
    request_password_recovery,
    resend_login_otp,
    reset_password,
)
from apps.account_security.commands import (
    ActivityQueryCommand,
    OtpResendCommand,
    PasswordChangeCommand,
    RecoveryRequestCommand,
    RecoveryResetCommand,
    StaffAssistedRecoveryCommand,
    SessionRevokeCommand,
    SessionRevokeOthersCommand,
    TrustedDeviceRevokeAllCommand,
    TrustedDeviceRevokeCommand,
)
from apps.account_security.queries import (
    get_activity_page,
    get_session_page,
    get_trusted_device_page,
)
from apps.student_activation.commands import StudentActivationCommand
from apps.student_activation.services import activate_student_account


router = Router(tags=["authentication"])
me_router = Router(tags=["account-security"])


def _request_context(request) -> RequestMetadata:
    """Translate Django request facts at the API boundary only."""
    session = getattr(request, "session", None)
    return RequestMetadata(
        ip_address=get_client_ip_from_headers(request.META),
        user_agent=str(request.META.get("HTTP_USER_AGENT", "") or ""),
        session_key=str(getattr(session, "session_key", "") or ""),
    )


def _raise_auth_error(error: ApiTokenError, *, default_detail: str) -> None:
    if isinstance(error, ApiRateLimited):
        raise RateLimitError(retry_after=error.retry_after)
    if isinstance(error, ApiSecurityUnavailable):
        raise DependencyFailureError(retry_after=60)
    if isinstance(error, InvalidApiCredentials):
        raise InvalidCredentialsError()
    raise InvalidCredentialsError()


def _reject_conflicting_session_credentials(request) -> None:
    if session_transport_requested(request) and authorization_header(request):
        raise InvalidCredentialsError()


def _auth_success_response(request, pair, *, receipt_data=None):
    if not session_transport_requested(request):
        result = pair.as_dict()
        if receipt_data:
            result.update(receipt_data)
        return result
    response = session_response({"authenticated": True, **(receipt_data or {})})
    set_session_cookies(response, pair)
    return response


@router.get(
    "/csrf/",
    auth=None,
    response={200: CsrfTokenSchema},
    operation_id="auth_csrf",
)
def csrf(request):
    """Issue Django's canonical CSRF token for the same-origin BFF."""

    return {"csrf_token": get_token(request)}


@router.post(
    "/staff-activation/",
    auth=None,
    response={200: StaffActivationResponseSchema, 422: ErrorSchema},
    operation_id="auth_staff_activation",
)
def staff_activation(request, payload: StaffActivationRequestSchema):
    _reject_conflicting_session_credentials(request)
    prepare_api_operation(
        request,
        "auth_staff_activation",
        captcha_response=payload.captcha_response,
    )
    from apps.accounts.commands import StaffInvitationActivationCommand
    from apps.accounts.services import activate_staff_invitation
    try:
        user = activate_staff_invitation(
            StaffInvitationActivationCommand(
                token=payload.token,
                password=payload.password,
                password_confirmation=payload.password_confirmation,
            ),
            ip_address=_request_context(request).ip_address,
            user_agent=_request_context(request).user_agent,
        )
    except CompassError as error:
        raise error
    return {"activated": True, "role": user.role}


@router.post(
    "/staff-recovery/request/",
    response={
        200: StaffAssistedRecoveryResponseSchema,
        401: ErrorSchema,
        403: ErrorSchema,
        409: ErrorSchema,
        422: ErrorSchema,
        429: ErrorSchema,
        503: ErrorSchema,
    },
    operation_id="auth_staff_recovery_request",
)
def staff_recovery_request(request, payload: StaffAssistedRecoveryRequestSchema):
    """Queue a recovery email for an active staff account, including Head Guidance."""
    _reject_conflicting_session_credentials(request)
    actor = _active_actor(request)
    prepared = prepare_api_operation(request, "auth_staff_recovery_request")
    context = _request_context(request)
    command = StaffAssistedRecoveryCommand(
        target_account_id=payload.target_account_id,
        reason_category=payload.reason_category,
        email_ownership_attested=payload.email_ownership_attested,
    )
    assurance_token = getattr(getattr(request, "auth", None), "token", None)
    safe_result = {
        "accepted": True,
        "detail": "Recovery instructions were queued for the selected staff account.",
    }

    def operation():
        value = request_staff_account_recovery(
            actor=actor,
            command=command,
            ip=context.ip_address,
            user_agent=context.user_agent,
            assurance_token=assurance_token,
        )
        return ApiMutationOutcome(
            value=value,
            metadata={"operation": "staff_recovery_request", "outcome": "accepted"},
        )

    return run_api_mutation(
        request,
        "auth_staff_recovery_request",
        {
            "target_account_id": command.target_account_id,
            "reason_category": command.reason_category,
            "email_ownership_attested": command.email_ownership_attested,
        },
        operation,
        _replay(safe_result),
        prepared_operation=prepared,
    )


@router.post(
    "/student-activation/",
    auth=None,
    response={200: StaffActivationResponseSchema, 422: ErrorSchema, 429: ErrorSchema, 503: ErrorSchema},
    operation_id="auth_student_activation",
)
def student_activation(request, payload: StudentActivationRequestSchema):
    """Activate only an inactive STUDENT through the single-use invitation flow."""
    _reject_conflicting_session_credentials(request)
    prepare_api_operation(
        request,
        "auth_student_activation",
        captcha_response=payload.captcha_response,
    )
    context = _request_context(request)
    user = activate_student_account(
        StudentActivationCommand(
            token=payload.token,
            password=payload.password,
            password_confirmation=payload.password_confirmation,
        ),
        ip_address=context.ip_address,
        user_agent=context.user_agent,
        request_id=request_id(request),
        trace_id=trace_id(request),
        source_view="api_student_activation",
    )
    return {"activated": True, "role": user.role}


@router.post(
    "/login/",
    auth=None,
    response={
        200: TokenPairSchema | AuthSessionReceiptSchema,
        202: LoginChallengeSchema,
        401: ErrorSchema,
        429: ErrorSchema,
        503: ErrorSchema,
    },
    operation_id="auth_login",
)
def login(request, payload: LoginRequestSchema):
    _reject_conflicting_session_credentials(request)
    trusted_token = payload.trusted_device_token
    if session_transport_requested(request):
        if trusted_token is not None:
            raise InvalidCredentialsError()
        trusted_token = trusted_device_cookie(request)
    try:
        outcome = begin_password_login(
            payload.email,
            payload.password,
            _request_context(request),
            trusted_device_token=trusted_token,
            captcha_response=payload.captcha_response,
        )
    except ApiTokenError as error:
        _raise_auth_error(error, default_detail="Invalid credentials.")
    if hasattr(outcome, "pending_nonce"):
        if session_transport_requested(request):
            return session_response(outcome.as_dict(), status=202)
        return Status(202, outcome.as_dict())
    return _auth_success_response(request, outcome)


@router.post(
    "/login/verify/",
    auth=None,
    response={200: TokenPairSchema | AuthSessionReceiptSchema, 401: ErrorSchema, 429: ErrorSchema, 503: ErrorSchema},
    operation_id="auth_login_verify",
)
def login_verify(request, payload: LoginVerifyRequestSchema):
    _reject_conflicting_session_credentials(request)
    try:
        pair = complete_password_login(
            payload.challenge_id,
            payload.pending_nonce,
            payload.otp,
            _request_context(request),
            trust_device=payload.trust_device,
        )
    except ApiTokenError as error:
        _raise_auth_error(error, default_detail="Verification could not be completed.")
    return _auth_success_response(request, pair)


@router.post(
    "/token/refresh/",
    auth=None,
    response={200: TokenPairSchema | AuthSessionReceiptSchema, 401: ErrorSchema},
    operation_id="auth_token_refresh",
)
def token_refresh(request, payload: RefreshTokenRequestSchema):
    _reject_conflicting_session_credentials(request)
    if session_transport_requested(request):
        if payload.refresh_token is not None:
            raise InvalidCredentialsError()
        raw_refresh_token = session_refresh_cookie(request)
    else:
        raw_refresh_token = payload.refresh_token
    try:
        pair = rotate_refresh_token(
            raw_refresh_token,
            ip=_request_context(request).ip_address,
            user_agent=_request_context(request).user_agent,
        )
    except ApiTokenError as error:
        _raise_auth_error(error, default_detail="Refresh token is invalid.")
    return _auth_success_response(request, pair)


@router.post(
    "/logout/",
    auth=None,
    response={204: None},
    operation_id="auth_logout",
)
def logout(request):
    context = _request_context(request)
    refresh_body = None
    if not session_transport_requested(request) and getattr(request, "body", b""):
        try:
            parsed = json.loads(request.body.decode("utf-8"))
            if isinstance(parsed, dict):
                refresh_body = parsed.get("refresh_token")
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
            refresh_body = None
    credentials = []
    if session_transport_requested(request):
        credentials.extend([session_access_cookie(request), session_refresh_cookie(request)])
    else:
        credentials.extend([extract_bearer_token(request), refresh_body])
    for raw_credential in credentials:
        revoke_session_for_raw_credential(
            raw_credential,
            ip=context.ip_address,
            user_agent=context.user_agent,
            reason="logout",
        )
    response = HttpResponse(status=204)
    # Logout is deliberately idempotent at the transport boundary.  Clear
    # both cookie credentials even when the caller used bearer auth or sent
    # an already-expired/revoked credential.
    clear_session_cookies(response)
    return response


@router.get(
    "/me/",
    response={200: MeSchema, 401: ErrorSchema},
    operation_id="auth_me",
)
def me(request):
    user = request.auth.user
    return {
        "id": user.id,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "role": user.role,
    }


@me_router.get(
    "/two-factor/",
    response={200: TwoFactorStatusSchema, 403: ErrorSchema},
    operation_id="me_two_factor_status",
)
def two_factor_status(request):
    actor = _active_actor(request)
    prepare_api_operation(request, "me_two_factor_status")
    from apps.account_security.two_factor import two_factor_status as get_status

    return get_status(actor)


@me_router.post(
    "/two-factor/change/request/",
    response={200: AssuranceChallengeSchema, 403: ErrorSchema, 422: ErrorSchema},
    operation_id="me_two_factor_change_request",
)
def two_factor_change_request(request, payload: TwoFactorChangeRequestSchema):
    actor = _active_actor(request)
    prepare_api_operation(request, "me_two_factor_change_request")
    context = _request_context(request)
    from apps.account_security.two_factor import request_student_two_factor_change

    return request_student_two_factor_change(
        actor,
        current_password=payload.current_password,
        enabled=payload.enabled,
        ip=context.ip_address,
        user_agent=context.user_agent,
    )


@me_router.post(
    "/two-factor/change/verify/",
    response={
        200: TokenPairSchema | AuthSessionReceiptSchema | TwoFactorChangeResponseSchema,
        401: ErrorSchema,
        403: ErrorSchema,
    },
    operation_id="me_two_factor_change_verify",
)
def two_factor_change_verify(request, payload: TwoFactorChangeVerifyRequestSchema):
    actor = _active_actor(request)
    prepare_api_operation(request, "me_two_factor_change_verify")
    context = _request_context(request)
    from apps.account_security.two_factor import verify_student_two_factor_change

    enabled, pair = verify_student_two_factor_change(
        actor,
        challenge_id=payload.challenge_id,
        pending_nonce=payload.pending_nonce,
        otp=payload.otp,
        ip=context.ip_address,
        user_agent=context.user_agent,
    )
    response = _auth_success_response(request, pair, receipt_data={"enabled": enabled})
    if session_transport_requested(request):
        clear_trusted_device_cookie(response)
    return response


@me_router.post(
    "/two-factor/change/resend/",
    response={200: OtpResendResponseSchema, 401: ErrorSchema},
    operation_id="me_two_factor_change_resend",
)
def two_factor_change_resend(request, payload: OtpResendRequestSchema):
    actor = _active_actor(request)
    prepare_api_operation(request, "me_two_factor_change_resend")
    context = _request_context(request)
    from apps.account_security.two_factor import resend_student_two_factor_change

    return resend_student_two_factor_change(
        actor,
        challenge_id=payload.challenge_id,
        pending_nonce=payload.pending_nonce,
        ip=context.ip_address,
        user_agent=context.user_agent,
    )


@me_router.post(
    "/assurance/challenge/",
    response={200: AssuranceChallengeSchema, 403: ErrorSchema, 422: ErrorSchema},
    operation_id="me_assurance_challenge",
)
def assurance_challenge(request):
    actor = _active_actor(request)
    prepare_api_operation(request, "me_assurance_challenge")
    context = _request_context(request)
    from apps.account_security.two_factor import request_assurance_challenge

    return request_assurance_challenge(
        actor,
        session_id=request.auth.token.session_id or request.auth.token.family_id,
        ip=context.ip_address,
        user_agent=context.user_agent,
    )


@me_router.post(
    "/assurance/verify/",
    response={200: AssuranceVerifyResponseSchema, 401: ErrorSchema},
    operation_id="me_assurance_verify",
)
def assurance_verify(request, payload: AssuranceVerifyRequestSchema):
    actor = _active_actor(request)
    prepare_api_operation(request, "me_assurance_verify")
    context = _request_context(request)
    from apps.account_security.two_factor import verify_assurance_challenge

    return verify_assurance_challenge(
        actor,
        session_id=request.auth.token.session_id or request.auth.token.family_id,
        challenge_id=payload.challenge_id,
        pending_nonce=payload.pending_nonce,
        otp=payload.otp,
        ip=context.ip_address,
        user_agent=context.user_agent,
    )


@me_router.post(
    "/assurance/resend/",
    response={200: OtpResendResponseSchema, 401: ErrorSchema},
    operation_id="me_assurance_resend",
)
def assurance_resend(request, payload: OtpResendRequestSchema):
    actor = _active_actor(request)
    prepare_api_operation(request, "me_assurance_resend")
    context = _request_context(request)
    from apps.account_security.two_factor import resend_assurance_challenge

    return resend_assurance_challenge(
        actor,
        challenge_id=payload.challenge_id,
        pending_nonce=payload.pending_nonce,
        ip=context.ip_address,
        user_agent=context.user_agent,
    )


def _active_actor(request):
    actor = request.auth.user
    if not is_active_nonlegacy_actor(actor):
        from apps.common.exceptions import PermissionDeniedError
        raise PermissionDeniedError()
    return actor


def _page(page: PageQuery, page_size: PageSizeQuery):
    try:
        return page_request_from_values(page, page_size)
    except ContractValidationError as exc:
        from apps.common.exceptions import ValidationError
        raise ValidationError() from exc


def _replay(value):
    return lambda _key: dict(value)


@me_router.get(
    "/activity/",
    response=ActivityPageSchema,
    exclude_unset=True,
    operation_id="me_activity_list",
)
def activity(
    request,
    page: PageQuery,
    page_size: PageSizeQuery,
    category: str = Query(default="all"),
):
    actor = _active_actor(request)
    prepare_api_operation(request, "me_activity_list")
    command = ActivityQueryCommand(category=category or "all")
    return get_activity_page(actor, _page(page, page_size), category=command.category).as_dict()


@me_router.get(
    "/sessions/",
    response=SessionPageSchema,
    exclude_unset=True,
    operation_id="me_sessions_list",
)
def sessions(request, page: PageQuery, page_size: PageSizeQuery):
    actor = _active_actor(request)
    prepare_api_operation(request, "me_sessions_list")
    return get_session_page(
        actor,
        _page(page, page_size),
        current_session_id=str(request.auth.token.session_id or request.auth.token.family_id),
    )


@me_router.post(
    "/sessions/revoke-others/",
    response={200: RevocationResponseSchema, 422: ErrorSchema},
    operation_id="me_sessions_revoke_others",
)
def revoke_other_sessions(request):
    actor = _active_actor(request)
    prepared = prepare_api_operation(request, "me_sessions_revoke_others")
    command = SessionRevokeOthersCommand()
    context = _request_context(request)
    safe_result = {"revoked": True}

    def operation():
        from apps.account_security.services import terminate_other_sessions
        count = terminate_other_sessions(
            str(request.auth.token.session_id or request.auth.token.family_id),
            actor,
            ip=context.ip_address,
            user_agent=context.user_agent,
        )
        return ApiMutationOutcome(
            value={"revoked": True},
            metadata={"operation": "sessions_revoke_others"},
        )

    # The command is intentionally constructed even though it has no fields;
    # this keeps the mutation boundary typed and immutable.
    if not isinstance(command, SessionRevokeOthersCommand):
        raise TypeError("Invalid session command")
    return run_api_mutation(
        request,
        "me_sessions_revoke_others",
        {"operation": "sessions_revoke_others"},
        operation,
        _replay(safe_result),
        prepared_operation=prepared,
    )


@me_router.post(
    "/sessions/{session_token}/revoke/",
    response={200: RevocationResponseSchema, 422: ErrorSchema},
    operation_id="me_session_revoke",
)
def revoke_session(request, session_token: str):
    actor = _active_actor(request)
    prepared = prepare_api_operation(request, "me_session_revoke")
    command = SessionRevokeCommand(session_token=session_token)
    context = _request_context(request)

    def operation():
        from apps.account_security.services import terminate_session
        revoked = terminate_session(
            command.session_token,
            actor,
            ip=context.ip_address,
            user_agent=context.user_agent,
            current_session_key=str(request.auth.token.session_id or request.auth.token.family_id),
        )
        if not revoked:
            from apps.common.exceptions import NotFoundError
            raise NotFoundError()
        return ApiMutationOutcome(
            value={"revoked": True},
            metadata={"operation": "session_revoke"},
        )

    return run_api_mutation(
        request,
        "me_session_revoke",
        {"operation": "session_revoke"},
        operation,
        _replay({"revoked": True}),
        prepared_operation=prepared,
    )


@me_router.get(
    "/trusted-devices/",
    response=TrustedDevicePageSchema,
    exclude_unset=True,
    operation_id="me_trusted_devices_list",
)
def trusted_devices(request, page: PageQuery, page_size: PageSizeQuery):
    actor = _active_actor(request)
    prepare_api_operation(request, "me_trusted_devices_list")
    current_device_id = getattr(request.auth.token.session, "trusted_device_id", None)
    return get_trusted_device_page(
        actor,
        _page(page, page_size),
        current_device_id=current_device_id,
    ).as_dict()


@me_router.post(
    "/trusted-devices/revoke-all/",
    response={200: RevocationResponseSchema, 422: ErrorSchema},
    operation_id="me_trusted_devices_revoke_all",
)
def revoke_all_trusted_devices(request):
    actor = _active_actor(request)
    prepared = prepare_api_operation(request, "me_trusted_devices_revoke_all")
    command = TrustedDeviceRevokeAllCommand()
    context = _request_context(request)

    def operation():
        from apps.account_security.services import revoke_all_trusted_devices_for_user
        count = revoke_all_trusted_devices_for_user(
            actor,
            reason="user_revoked_all",
            ip=context.ip_address,
            audit_when_empty=True,
        )
        return ApiMutationOutcome(
            value={"revoked": True},
            metadata={"operation": "trusted_devices_revoke_all"},
        )

    if not isinstance(command, TrustedDeviceRevokeAllCommand):
        raise TypeError("Invalid trusted-device command")
    return run_api_mutation(
        request,
        "me_trusted_devices_revoke_all",
        {"operation": "trusted_devices_revoke_all"},
        operation,
        _replay({"revoked": True}),
        prepared_operation=prepared,
    )


@me_router.post(
    "/trusted-devices/{device_id}/revoke/",
    response={200: RevocationResponseSchema, 422: ErrorSchema},
    operation_id="me_trusted_device_revoke",
)
def revoke_trusted_device(request, device_id: UUID):
    actor = _active_actor(request)
    prepared = prepare_api_operation(request, "me_trusted_device_revoke")
    command = TrustedDeviceRevokeCommand(device_id=device_id)
    context = _request_context(request)

    def operation():
        from apps.account_security.services import revoke_trusted_device
        revoked = revoke_trusted_device(
            actor,
            str(command.device_id),
            ip=context.ip_address,
            user_agent=context.user_agent,
        )
        if not revoked:
            from apps.common.exceptions import NotFoundError
            raise NotFoundError()
        return ApiMutationOutcome(
            value={"revoked": True},
            metadata={"operation": "trusted_device_revoke"},
        )

    return run_api_mutation(
        request,
        "me_trusted_device_revoke",
        {"operation": "trusted_device_revoke"},
        operation,
        _replay({"revoked": True}),
        prepared_operation=prepared,
    )


@me_router.post(
    "/password/change/",
    response={200: PasswordChangedResponseSchema, 422: ErrorSchema},
    operation_id="me_password_change",
)
def password_change(request, payload: PasswordChangeRequestSchema):
    actor = _active_actor(request)
    prepared = prepare_api_operation(request, "me_password_change")
    command = PasswordChangeCommand(
        current_password=payload.current_password,
        new_password=payload.new_password,
        password_confirmation=payload.password_confirmation,
    )
    context = _request_context(request)

    def operation():
        value = change_password(
            actor=actor,
            command=command,
            ip=context.ip_address,
            user_agent=context.user_agent,
        )
        return ApiMutationOutcome(value=value, metadata={"operation": "password_change"})

    return run_api_mutation(
        request,
        "me_password_change",
        {"operation": "password_change"},
        operation,
        _replay({"changed": True}),
        prepared_operation=prepared,
    )


@router.post(
    "/recovery/request/",
    auth=None,
    response={200: RecoveryResponseSchema, 422: ErrorSchema, 429: ErrorSchema},
    operation_id="auth_recovery_request",
)
def recovery_request(request, payload: RecoveryRequestSchema):
    _reject_conflicting_session_credentials(request)
    prepared = prepare_api_operation(
        request,
        "auth_recovery_request",
        captcha_response=payload.captcha_response,
    )
    del prepared
    context = _request_context(request)
    return request_password_recovery(
        command=RecoveryRequestCommand(email=payload.email),
        ip=context.ip_address,
        user_agent=context.user_agent,
    )


@router.post(
    "/recovery/reset/",
    auth=None,
    response={200: RecoveryResetResponseSchema, 401: ErrorSchema, 422: ErrorSchema, 429: ErrorSchema, 503: ErrorSchema},
    operation_id="auth_recovery_reset",
)
def recovery_reset(request, payload: RecoveryResetRequestSchema):
    _reject_conflicting_session_credentials(request)
    prepared = prepare_api_operation(
        request,
        "auth_recovery_reset",
        captcha_response=payload.captcha_response,
    )
    del prepared
    context = _request_context(request)
    command = RecoveryResetCommand(
        token=payload.token,
        new_password=payload.new_password,
        password_confirmation=payload.password_confirmation,
    )
    return reset_password(
        command=command,
        ip=context.ip_address,
        user_agent=context.user_agent,
        session=context.session_key,
    )


@router.post(
    "/login/verify/resend/",
    auth=None,
    response={200: OtpResendResponseSchema, 401: ErrorSchema, 422: ErrorSchema, 429: ErrorSchema},
    operation_id="auth_login_otp_resend",
)
def login_otp_resend(request, payload: OtpResendRequestSchema):
    _reject_conflicting_session_credentials(request)
    prepared = prepare_api_operation(request, "auth_login_otp_resend")
    del prepared
    context = _request_context(request)
    command = OtpResendCommand(
        challenge_id=payload.challenge_id,
        pending_nonce=payload.pending_nonce,
    )
    return resend_login_otp(
        command=command,
        ip=context.ip_address,
        user_agent=context.user_agent,
    )
