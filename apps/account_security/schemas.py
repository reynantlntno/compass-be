"""Explicit request and response schemas for account API operations."""

from uuid import UUID

from ninja import Schema
from pydantic import Field


class ErrorSchema(Schema):
    detail: str
    code: str
    request_id: str
    error_id: str | None = None
    field_errors: dict[str, list[str]] = Field(default_factory=dict)


class LoginRequestSchema(Schema):
    email: str
    password: str


class LoginVerifyRequestSchema(Schema):
    challenge_id: UUID
    pending_nonce: str
    otp: str


class RefreshTokenRequestSchema(Schema):
    # Bearer clients send this value in the JSON body.  Cookie-profile
    # clients deliberately send an empty object and authenticate with the
    # HttpOnly refresh cookie instead.
    refresh_token: str | None = None


class TokenPairSchema(Schema):
    token_type: str
    access_token: str
    expires_in: int
    refresh_token: str
    refresh_expires_in: int


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


class StudentActivationRequestSchema(Schema):
    """Request-local credentials for the student-only activation boundary."""

    token: str
    password: str
    password_confirmation: str


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
    first_seen: str
    last_activity: str
    expire_date: str


class SessionDecodeStateSchema(Schema):
    state: str
    reason_code: str
    display_label: str


class SessionPageSchema(Schema):
    items: list[ActiveSessionProjectionSchema]
    page: int
    page_size: int
    total: int
    decode: SessionDecodeStateSchema


class TrustedDeviceProjectionSchema(Schema):
    id: str
    device: AccountSecurityDisplayStateSchema
    status: str
    trusted_until: str
    last_used_at: str
    revoked_at: str


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


class RecoveryResetRequestSchema(Schema):
    token: str
    new_password: str
    password_confirmation: str


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
