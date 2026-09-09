"""Explicit request and response schemas for account API operations."""

from uuid import UUID
from typing import Literal

from ninja import Schema
from pydantic import Field

from apps.common.api.constants import API_MAX_CAPTCHA_RESPONSE_LENGTH


ChallengeAction = Literal["login", "recovery", "activation", "contact"]


class ErrorSchema(Schema):
    detail: str
    code: str
    request_id: str
    error_id: str | None = None
    field_errors: dict[str, list[str]] = Field(default_factory=dict)
    challenge_required: bool = False
    challenge_action: ChallengeAction | None = None


class LoginRequestSchema(Schema):
    email: str
    password: str
    trusted_device_token: str | None = None
    captcha_response: str | None = Field(default=None, max_length=API_MAX_CAPTCHA_RESPONSE_LENGTH)


class LoginVerifyRequestSchema(Schema):
    challenge_id: UUID
    pending_nonce: str
    otp: str
    trust_device: bool = False


class RefreshTokenRequestSchema(Schema):
    # Bearer clients send this value in the JSON body.  Cookie-profile
    # clients deliberately send an empty object and authenticate with the
    # HttpOnly refresh cookie instead.
    refresh_token: str | None = None


class LogoutRequestSchema(Schema):
    refresh_token: str | None = None


class TrustedDeviceReceiptSchema(Schema):
    token: str
    expires_in: int


class TokenPairSchema(Schema):
    token_type: str
    access_token: str
    expires_in: int
    refresh_token: str
    refresh_expires_in: int
    trusted_device: TrustedDeviceReceiptSchema | None = None


class AuthSessionReceiptSchema(Schema):
    """Safe success projection for the explicit browser session profile."""

    authenticated: bool


class CsrfTokenSchema(Schema):
    """Django's CSRF token for the same-origin BFF bootstrap boundary."""

    csrf_token: str


class LoginChallengeSchema(Schema):
    challenge_id: UUID
    pending_nonce: str
    expires_in: int
    requires_verification: bool


class MeSchema(Schema):
    id: int
    email: str
    first_name: str
    last_name: str
    role: str


class StaffActivationRequestSchema(Schema):
    token: str
    password: str
    password_confirmation: str
    captcha_response: str | None = Field(default=None, max_length=API_MAX_CAPTCHA_RESPONSE_LENGTH)


class StudentActivationRequestSchema(Schema):
    """Request-local credentials for the student-only activation boundary."""

    token: str
    password: str
    password_confirmation: str
    captcha_response: str | None = Field(default=None, max_length=API_MAX_CAPTCHA_RESPONSE_LENGTH)


class StaffActivationResponseSchema(Schema):
    activated: bool
    role: str


class AccountSecurityDisplayStateSchema(Schema):
    state: str
    label: str


class ActivityEntrySchema(Schema):
    activity_type: str
    category: str
    label: str
    created_at: str
    status_label: str
    status_tone: str
    reference_code: str | None = None
    device: AccountSecurityDisplayStateSchema | None = None
    network: AccountSecurityDisplayStateSchema | None = None


class ActivityPageSchema(Schema):
    items: list[ActivityEntrySchema]
    page: int
    page_size: int
    total: int


class ActiveSessionProjectionSchema(Schema):
    session_token: str
    is_current: bool
    device: AccountSecurityDisplayStateSchema
    network: AccountSecurityDisplayStateSchema
    started_at: str | None
    last_activity_at: str | None
    expires_at: str | None
    authentication_method: str


class SessionPageSchema(Schema):
    items: list[ActiveSessionProjectionSchema]
    page: int
    page_size: int
    total: int


class TrustedDeviceProjectionSchema(Schema):
    id: str
    device: AccountSecurityDisplayStateSchema
    status: str
    trusted_until: str | None
    last_used_at: str | None
    revoked_at: str | None
    is_current: bool = False


class TrustedDevicePageSchema(Schema):
    items: list[TrustedDeviceProjectionSchema]
    page: int
    page_size: int
    total: int


class PasswordChangeRequestSchema(Schema):
    current_password: str
    new_password: str
    password_confirmation: str


class RecoveryRequestSchema(Schema):
    email: str
    captcha_response: str | None = Field(default=None, max_length=API_MAX_CAPTCHA_RESPONSE_LENGTH)


class RecoveryResetRequestSchema(Schema):
    token: str
    new_password: str
    password_confirmation: str
    captcha_response: str | None = Field(default=None, max_length=API_MAX_CAPTCHA_RESPONSE_LENGTH)


class RecoveryResponseSchema(Schema):
    detail: str


class OtpResendRequestSchema(Schema):
    challenge_id: UUID
    pending_nonce: str


class RevocationResponseSchema(Schema):
    revoked: bool


class PasswordChangedResponseSchema(Schema):
    changed: bool


class RecoveryResetResponseSchema(Schema):
    reset: bool


class StaffAssistedRecoveryRequestSchema(Schema):
    target_account_id: int = Field(gt=0)
    reason_category: str
    email_ownership_attested: bool = False


class StaffAssistedRecoveryResponseSchema(Schema):
    accepted: bool
    detail: str


class OtpResendResponseSchema(Schema):
    resent: bool
    detail: str


class TwoFactorStatusSchema(Schema):
    enabled: bool
    required: bool
    can_change: bool


class TwoFactorChangeRequestSchema(Schema):
    current_password: str
    enabled: bool


class TwoFactorChangeVerifyRequestSchema(Schema):
    challenge_id: UUID
    pending_nonce: str
    otp: str


class AssuranceChallengeSchema(Schema):
    challenge_id: UUID
    pending_nonce: str
    expires_in: int
    requires_verification: bool


class AssuranceVerifyRequestSchema(Schema):
    challenge_id: UUID
    pending_nonce: str
    otp: str


class TwoFactorChangeResponseSchema(Schema):
    enabled: bool
    token_type: str | None = None
    access_token: str | None = None
    expires_in: int | None = None
    refresh_token: str | None = None
    refresh_expires_in: int | None = None
    trusted_device: TrustedDeviceReceiptSchema | None = None


class AssuranceVerifyResponseSchema(Schema):
    verified: bool
