"""Opaque bearer-token lifecycle for the versioned COMPASS API."""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass
from datetime import timedelta

from django.contrib.auth import authenticate, get_user_model
from django.db import transaction
from django.utils import timezone

from apps.account_security.abuse_controls import (
    AbuseAction,
    evaluate,
    record_failure,
    record_success,
)
from apps.account_security.assurance import ASSURANCE_CONTEXT, ASSURANCE_POLICY_VERSION
from apps.account_security.audit import log_security_event
from apps.account_security.models import (
    ApiToken,
    ApiTokenStatusChoices,
    ApiTokenTypeChoices,
    TwoStepChallenge,
)
from apps.account_security.policies import is_2fa_required_for_user
from apps.account_security.services import create_twostep_challenge, verify_otp
from apps.account_security.tokens import hash_identifier, hash_token
from apps.common.contracts import RequestMetadata
from apps.governance.runtime_config import resolve_runtime_setting


User = get_user_model()

API_TOKEN_VERSION = "opaque-v1"


class ApiTokenError(Exception):
    """Base class for safe, non-secret API token failures."""


class InvalidApiCredentials(ApiTokenError):
    """Raised when a login or token credential cannot be accepted."""


class ApiRateLimited(ApiTokenError):
    """Raised when the existing abuse policy blocks an authentication action."""

    def __init__(self, retry_after: int | None = None):
        self.retry_after = retry_after
        super().__init__("Authentication is temporarily unavailable.")


class ApiSecurityUnavailable(ApiTokenError):
    """Raised when the fail-closed abuse boundary is unavailable."""


@dataclass(frozen=True)
class ApiTokenPrincipal:
    """The authenticated API subject attached to ``request.auth``."""

    user: object
    token: ApiToken


@dataclass(frozen=True)
class ApiTokenPair:
    access_token: str
    refresh_token: str
    access_expires_at: object
    refresh_expires_at: object

    def as_dict(self) -> dict[str, object]:
        now = timezone.now()
        return {
            "token_type": "Bearer",
            "access_token": self.access_token,
            "expires_in": max(0, int((self.access_expires_at - now).total_seconds())),
            "refresh_token": self.refresh_token,
            "refresh_expires_in": max(0, int((self.refresh_expires_at - now).total_seconds())),
        }


@dataclass(frozen=True)
class LoginChallenge:
    challenge_id: uuid.UUID
    pending_nonce: str
    expires_at: object

    def as_dict(self) -> dict[str, object]:
        return {
            "challenge_id": self.challenge_id,
            "pending_nonce": self.pending_nonce,
            "expires_in": max(0, int((self.expires_at - timezone.now()).total_seconds())),
            "requires_verification": True,
        }


def _positive_setting(name: str) -> int:
    value = int(resolve_runtime_setting("security.account_security_controls", name))
    if value <= 0:
        raise ApiSecurityUnavailable(f"{name} must be positive.")
    return value


def access_token_ttl() -> timedelta:
    return timedelta(
        seconds=_positive_setting(
            "API_ACCESS_TOKEN_TTL_SECONDS",
        )
    )


def refresh_token_ttl() -> timedelta:
    return timedelta(
        seconds=_positive_setting(
            "API_REFRESH_TOKEN_TTL_SECONDS",
        )
    )


def _request_hashes(ip: str | None, user_agent: str | None) -> tuple[str, str]:
    return hash_identifier(ip or ""), hash_identifier(user_agent or "")


def _user_can_receive_api_tokens(user) -> bool:
    return bool(
        user
        and getattr(user, "is_authenticated", False)
        and getattr(user, "is_active", False)
        and not getattr(user, "is_superuser", False)
    )


def _assurance_values(user, *, assurance_verified: bool) -> tuple[str, str]:
    if not is_2fa_required_for_user(user):
        return "", ""
    if not assurance_verified:
        raise InvalidApiCredentials("Additional verification is required.")
    return ASSURANCE_POLICY_VERSION, ASSURANCE_CONTEXT


def _new_raw_token() -> str:
    return secrets.token_urlsafe(48)


def _create_token_record(
    *,
    user,
    family_id: uuid.UUID,
    raw_token: str,
    token_type: str,
    expires_at,
    security_stamp,
    assurance_policy_version: str,
    assurance_context: str,
    request_ip_hash: str,
    request_user_agent_hash: str,
) -> ApiToken:
    return ApiToken.objects.create(
        user=user,
        family_id=family_id,
        token_hash=hash_token(raw_token),
        token_type=token_type,
        status=ApiTokenStatusChoices.ACTIVE,
        issued_at=timezone.now(),
        expires_at=expires_at,
        security_stamp=security_stamp,
        assurance_policy_version=assurance_policy_version,
        assurance_context=assurance_context,
        request_ip_hash=request_ip_hash,
        request_user_agent_hash=request_user_agent_hash,
    )


def _issue_token_pair_in_transaction(
    user,
    *,
    family_id: uuid.UUID | None,
    ip: str | None,
    user_agent: str | None,
    assurance_verified: bool,
    now=None,
) -> ApiTokenPair:
    if not _user_can_receive_api_tokens(user):
        raise InvalidApiCredentials("Authentication is not available for this account.")

    assurance_policy_version, assurance_context = _assurance_values(
        user,
        assurance_verified=assurance_verified,
    )
    now = now or timezone.now()
    family_id = family_id or uuid.uuid4()
    access_expires_at = now + access_token_ttl()
    refresh_expires_at = now + refresh_token_ttl()
    access_token = _new_raw_token()
    refresh_token = _new_raw_token()
    request_ip_hash, request_user_agent_hash = _request_hashes(ip, user_agent)

    _create_token_record(
        user=user,
        family_id=family_id,
        raw_token=access_token,
        token_type=ApiTokenTypeChoices.ACCESS,
        expires_at=access_expires_at,
        security_stamp=user.auth_security_stamp,
        assurance_policy_version=assurance_policy_version,
        assurance_context=assurance_context,
        request_ip_hash=request_ip_hash,
        request_user_agent_hash=request_user_agent_hash,
    )
    _create_token_record(
        user=user,
        family_id=family_id,
        raw_token=refresh_token,
        token_type=ApiTokenTypeChoices.REFRESH,
        expires_at=refresh_expires_at,
        security_stamp=user.auth_security_stamp,
        assurance_policy_version=assurance_policy_version,
        assurance_context=assurance_context,
        request_ip_hash=request_ip_hash,
        request_user_agent_hash=request_user_agent_hash,
    )
    return ApiTokenPair(
        access_token=access_token,
        refresh_token=refresh_token,
        access_expires_at=access_expires_at,
        refresh_expires_at=refresh_expires_at,
    )


@transaction.atomic
def issue_token_pair(
    user,
    *,
    ip: str | None = None,
    user_agent: str | None = None,
    assurance_verified: bool = False,
    family_id: uuid.UUID | None = None,
) -> ApiTokenPair:
    """Issue a pair while storing only HMAC hashes of the raw credentials."""

    family_id = family_id or uuid.uuid4()
    pair = _issue_token_pair_in_transaction(
        user,
        family_id=family_id,
        ip=ip,
        user_agent=user_agent,
        assurance_verified=assurance_verified,
    )
    log_security_event(
        action_type="api_token_issued",
        target_model="account_security.ApiToken",
        target_object_id=str(family_id),
        actor_user=user,
        ip_address=ip,
        user_agent=user_agent,
        metadata={
            "token_version": API_TOKEN_VERSION,
            "assurance_context": (
                ASSURANCE_CONTEXT if assurance_verified and is_2fa_required_for_user(user) else ""
            ),
            "status": "active",
        },
    )
    return pair


def _token_user_is_current(token: ApiToken) -> bool:
    user = token.user
    if not _user_can_receive_api_tokens(user):
        return False
    if token.security_stamp != user.auth_security_stamp:
        return False
    if is_2fa_required_for_user(user):
        return (
            token.assurance_policy_version == ASSURANCE_POLICY_VERSION
            and token.assurance_context == ASSURANCE_CONTEXT
        )
    return True


def _expire_if_needed(token: ApiToken, now) -> bool:
    if token.expires_at > now:
        return False
    ApiToken.objects.filter(
        pk=token.pk,
        status=ApiTokenStatusChoices.ACTIVE,
    ).update(
        status=ApiTokenStatusChoices.EXPIRED,
        updated_at=now,
    )
    return True


def resolve_access_token(raw_token: str | None) -> ApiTokenPrincipal | None:
    """Resolve an access bearer without revealing why a credential failed."""

    if not raw_token or len(raw_token) > 512:
        return None
    token = (
        ApiToken.objects.select_related("user")
        .filter(
            token_hash=hash_token(raw_token),
            token_type=ApiTokenTypeChoices.ACCESS,
        )
        .first()
    )
    if token is None or token.status != ApiTokenStatusChoices.ACTIVE:
        return None
    now = timezone.now()
    if _expire_if_needed(token, now) or not _token_user_is_current(token):
        return None
    ApiToken.objects.filter(pk=token.pk).update(last_used_at=now, updated_at=now)
    return ApiTokenPrincipal(user=token.user, token=token)


@transaction.atomic
def revoke_form_invitation_family(
    family_id: uuid.UUID,
    *,
    actor_user=None,
    ip: str | None = None,
    user_agent: str | None = None,
    reason: str = "logout",
) -> int:
    now = timezone.now()
    updated = ApiToken.objects.filter(
        family_id=family_id,
        status=ApiTokenStatusChoices.ACTIVE,
    ).update(
        status=ApiTokenStatusChoices.REVOKED,
        revoked_at=now,
        updated_at=now,
    )
    log_security_event(
        action_type="api_token_family_revoked",
        target_model="account_security.ApiToken",
        target_object_id=str(family_id),
        actor_user=actor_user,
        ip_address=ip,
        user_agent=user_agent,
        metadata={"reason": reason, "status": "revoked"},
    )
    return updated


@transaction.atomic
def revoke_all_api_tokens_for_user(
    user,
    *,
    ip: str | None = None,
    user_agent: str | None = None,
    reason: str = "security_state_changed",
) -> int:
    now = timezone.now()
    updated = ApiToken.objects.filter(
        user=user,
        status=ApiTokenStatusChoices.ACTIVE,
    ).update(
        status=ApiTokenStatusChoices.REVOKED,
        revoked_at=now,
        updated_at=now,
    )
    log_security_event(
        action_type="api_tokens_revoked_for_user",
        target_model="accounts.User",
        target_object_id=str(user.pk),
        actor_user=user,
        ip_address=ip,
        user_agent=user_agent,
        metadata={"reason": reason, "attempts": updated},
    )
    return updated


def rotate_refresh_token(
    raw_refresh_token: str,
    *,
    ip: str | None = None,
    user_agent: str | None = None,
) -> ApiTokenPair:
    if not raw_refresh_token or len(raw_refresh_token) > 512:
        raise InvalidApiCredentials("Refresh token is invalid.")

    token = None
    pair = None
    family_to_revoke = None
    invalid_user = None
    invalid_reason = "refresh_invalidated"
    with transaction.atomic():
        token = (
            ApiToken.objects.select_for_update()
            .select_related("user")
            .filter(
                token_hash=hash_token(raw_refresh_token),
                token_type=ApiTokenTypeChoices.REFRESH,
            )
            .first()
        )
        if token is None:
            raise InvalidApiCredentials("Refresh token is invalid.")

        now = timezone.now()
        if token.status != ApiTokenStatusChoices.ACTIVE:
            family_to_revoke = token.family_id
            invalid_user = token.user
            invalid_reason = "refresh_reuse"
        elif _expire_if_needed(token, now) or not _token_user_is_current(token):
            family_to_revoke = token.family_id
            invalid_user = token.user
        else:
            token.status = ApiTokenStatusChoices.USED
            token.used_at = now
            token.last_used_at = now
            token.save(update_fields=["status", "used_at", "last_used_at", "updated_at"])
            pair = _issue_token_pair_in_transaction(
                token.user,
                family_id=token.family_id,
                ip=ip,
                user_agent=user_agent,
                assurance_verified=bool(token.assurance_context),
                now=now,
            )

    if family_to_revoke is not None:
        revoke_form_invitation_family(
            family_to_revoke,
            actor_user=invalid_user,
            reason=invalid_reason,
        )
        raise InvalidApiCredentials("Refresh token is invalid.")

    if token is None or pair is None:
        raise InvalidApiCredentials("Refresh token is invalid.")

    log_security_event(
        action_type="api_refresh_rotated",
        target_model="account_security.ApiToken",
        target_object_id=str(token.family_id),
        actor_user=token.user,
        ip_address=ip,
        user_agent=user_agent,
        metadata={"token_version": API_TOKEN_VERSION, "status": "active"},
    )
    return pair


def _login_decision(email: str, request_context: RequestMetadata):
    ip = request_context.ip_address
    decision = evaluate(AbuseAction.LOGIN, subject=email, ip=ip)
    if decision.reason_code == "ABUSE_CONTROL_UNAVAILABLE":
        raise ApiSecurityUnavailable("Authentication is temporarily unavailable.")
    if not decision.allowed or decision.challenge_required:
        raise ApiRateLimited(decision.retry_after)
    return ip


def _record_login_failure(email: str, request_context: RequestMetadata, *, reason: str) -> None:
    ip = request_context.ip_address
    record_failure(AbuseAction.LOGIN, subject=email, ip=ip, reason_code=reason)
    log_security_event(
        action_type="login_failure",
        target_model="accounts.User",
        target_object_id="",
        severity="WARNING",
        ip_address=ip,
        user_agent=request_context.user_agent,
        metadata={"reason": reason},
    )


def begin_password_login(email: str, password: str, request_context: RequestMetadata):
    normalized_email = str(email or "").strip().lower()
    ip = _login_decision(normalized_email, request_context)
    user_agent = request_context.user_agent
    user = authenticate(request=None, username=normalized_email, password=password)
    if not _user_can_receive_api_tokens(user):
        _record_login_failure(normalized_email, request_context, reason="invalid_credentials")
        raise InvalidApiCredentials("Invalid credentials.")

    if is_2fa_required_for_user(user):
        pending_nonce = secrets.token_urlsafe(32)
        challenge, _ = create_twostep_challenge(
            user,
            purpose="login",
            ip=ip,
            user_agent=user_agent,
            pending_nonce=pending_nonce,
        )
        if challenge is None:
            _record_login_failure(normalized_email, request_context, reason="assurance_unavailable")
            raise ApiSecurityUnavailable("Authentication is temporarily unavailable.")
        return LoginChallenge(
            challenge_id=challenge.id,
            pending_nonce=pending_nonce,
            expires_at=challenge.expires_at,
        )

    pair = issue_token_pair(
        user,
        ip=ip,
        user_agent=user_agent,
        assurance_verified=False,
    )
    record_success(AbuseAction.LOGIN, subject=normalized_email, ip=ip)
    log_security_event(
        action_type="login_success",
        target_model="accounts.User",
        target_object_id=str(user.pk),
        actor_user=user,
        ip_address=ip,
        user_agent=user_agent,
        metadata={"assurance_context": ""},
    )
    return pair


def complete_password_login(
    challenge_id: uuid.UUID,
    pending_nonce: str,
    otp: str,
    request_context: RequestMetadata,
) -> ApiTokenPair:
    challenge = (
        TwoStepChallenge.objects.select_related("user")
        .filter(id=challenge_id, purpose="login")
        .first()
    )
    if challenge is None or not _user_can_receive_api_tokens(challenge.user):
        _record_login_failure("", request_context, reason="invalid_challenge")
        raise InvalidApiCredentials("Verification could not be completed.")

    if not verify_otp(
        str(challenge.id),
        otp,
        expected_user_id=challenge.user_id,
        purpose="login",
        pending_nonce=pending_nonce,
        ip=request_context.ip_address,
        user_agent=request_context.user_agent,
    ):
        _record_login_failure(challenge.user.email, request_context, reason="invalid_otp")
        raise InvalidApiCredentials("Verification could not be completed.")

    ip = request_context.ip_address
    user_agent = request_context.user_agent
    pair = issue_token_pair(
        challenge.user,
        ip=ip,
        user_agent=user_agent,
        assurance_verified=True,
    )
    record_success(AbuseAction.LOGIN, subject=challenge.user.email, ip=ip)
    log_security_event(
        action_type="login_success",
        target_model="accounts.User",
        target_object_id=str(challenge.user.pk),
        actor_user=challenge.user,
        ip_address=ip,
        user_agent=user_agent,
        metadata={"assurance_context": ASSURANCE_CONTEXT},
    )
    return pair
