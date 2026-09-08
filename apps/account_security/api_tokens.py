"""Opaque bearer-token and token-family session lifecycle for the API."""

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
    ApiSession,
    ApiSessionAuthenticationMethodChoices,
    ApiSessionStatusChoices,
    ApiToken,
    ApiTokenStatusChoices,
    ApiTokenTypeChoices,
    TwoStepChallenge,
)
from apps.account_security.network import classify_network_class
from apps.account_security.policies import is_2fa_required_for_user
from apps.account_security.services import create_twostep_challenge, verify_otp
from apps.account_security.tokens import get_safe_user_agent_summary, hash_identifier, hash_token
from apps.common.contracts import RequestMetadata
from apps.governance.runtime_config import resolve_runtime_setting


User = get_user_model()

API_TOKEN_VERSION = "opaque-v1"
API_SESSION_MAX_AGE = timedelta(days=30)


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
    user: object
    token: ApiToken


@dataclass(frozen=True)
class ApiTokenPair:
    access_token: str
    refresh_token: str
    access_expires_at: object
    refresh_expires_at: object
    session_id: uuid.UUID
    trusted_device_token: str | None = None
    trusted_device_expires_at: object | None = None

    def as_dict(self) -> dict[str, object]:
        now = timezone.now()
        result = {
            "token_type": "Bearer",
            "access_token": self.access_token,
            "expires_in": max(0, int((self.access_expires_at - now).total_seconds())),
            "refresh_token": self.refresh_token,
            "refresh_expires_in": max(0, int((self.refresh_expires_at - now).total_seconds())),
        }
        if self.trusted_device_token and self.trusted_device_expires_at:
            result["trusted_device"] = {
                "token": self.trusted_device_token,
                "expires_in": max(
                    0,
                    int((self.trusted_device_expires_at - now).total_seconds()),
                ),
            }
        return result


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
    return timedelta(seconds=_positive_setting("API_ACCESS_TOKEN_TTL_SECONDS"))


def refresh_token_ttl() -> timedelta:
    return timedelta(seconds=_positive_setting("API_REFRESH_TOKEN_TTL_SECONDS"))


def _request_hashes(ip: str | None, user_agent: str | None) -> tuple[str, str]:
    return hash_identifier(ip or ""), hash_identifier(user_agent or "")


def _user_can_receive_api_tokens(user) -> bool:
    return bool(
        user
        and getattr(user, "is_authenticated", False)
        and getattr(user, "is_active", False)
        and not getattr(user, "is_superuser", False)
    )


def _assurance_values(user, *, assurance_verified: bool, authentication_method: str) -> tuple[str, str]:
    if not is_2fa_required_for_user(user):
        return "", ""
    if not assurance_verified and authentication_method != ApiSessionAuthenticationMethodChoices.TRUSTED_DEVICE:
        raise InvalidApiCredentials("Additional verification is required.")
    return ASSURANCE_POLICY_VERSION, ASSURANCE_CONTEXT


def _new_raw_token() -> str:
    return secrets.token_urlsafe(48)


def _device_summary(user_agent: str | None) -> str:
    return get_safe_user_agent_summary(user_agent or "").strip().lower()


def _create_session(
    user,
    *,
    session_id: uuid.UUID,
    ip: str | None,
    user_agent: str | None,
    authentication_method: str,
    otp_verified_at,
    now,
) -> ApiSession:
    return ApiSession.objects.create(
        id=session_id,
        user=user,
        status=ApiSessionStatusChoices.ACTIVE,
        device_summary=_device_summary(user_agent),
        network_class=classify_network_class(ip),
        authentication_method=authentication_method,
        security_stamp=user.auth_security_stamp,
        started_at=now,
        last_activity_at=now,
        absolute_expires_at=now + API_SESSION_MAX_AGE,
        last_otp_verified_at=otp_verified_at,
    )


def _create_token_record(
    *,
    user,
    session: ApiSession,
    raw_token: str,
    token_type: str,
    expires_at,
    security_stamp,
    assurance_policy_version: str,
    assurance_context: str,
    request_ip_hash: str,
    request_user_agent_hash: str,
    issued_at,
) -> ApiToken:
    return ApiToken.objects.create(
        user=user,
        session=session,
        family_id=session.id,
        token_hash=hash_token(raw_token),
        token_type=token_type,
        status=ApiTokenStatusChoices.ACTIVE,
        issued_at=issued_at,
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
    authentication_method: str | None = None,
    otp_verified_at=None,
    session: ApiSession | None = None,
    now=None,
    trusted_device_token: str | None = None,
    trusted_device_expires_at=None,
    trusted_device_id=None,
) -> ApiTokenPair:
    if not _user_can_receive_api_tokens(user):
        raise InvalidApiCredentials("Authentication is not available for this account.")

    now = now or timezone.now()
    authentication_method = authentication_method or (
        ApiSessionAuthenticationMethodChoices.OTP
        if assurance_verified
        else ApiSessionAuthenticationMethodChoices.PASSWORD
    )
    assurance_policy_version, assurance_context = _assurance_values(
        user,
        assurance_verified=assurance_verified,
        authentication_method=authentication_method,
    )
    session_id = (session.id if session is not None else None) or family_id or uuid.uuid4()
    session_was_created = False
    if session is None:
        session = ApiSession.objects.select_for_update().filter(pk=session_id).first()
    if session is None:
        session = _create_session(
            user,
            session_id=session_id,
            ip=ip,
            user_agent=user_agent,
            authentication_method=authentication_method,
            otp_verified_at=otp_verified_at if assurance_verified else None,
            now=now,
        )
        session_was_created = True
    if session.user_id != user.pk or session.status != ApiSessionStatusChoices.ACTIVE:
        raise InvalidApiCredentials("Authentication is not available for this account.")
    if session.security_stamp != user.auth_security_stamp:
        raise InvalidApiCredentials("Authentication is not available for this account.")
    if trusted_device_id is not None:
        session.trusted_device_id = trusted_device_id
        session.save(update_fields=["trusted_device", "updated_at"])
    if session.absolute_expires_at <= now:
        session.status = ApiSessionStatusChoices.EXPIRED
        session.updated_at = now
        session.save(update_fields=["status", "updated_at"])
        raise InvalidApiCredentials("Authentication is not available for this account.")

    if (
        session_was_created
        and assurance_verified
        and authentication_method == ApiSessionAuthenticationMethodChoices.OTP
    ):
        session.last_otp_verified_at = otp_verified_at or now
    session.last_activity_at = now
    session.save(update_fields=["last_activity_at", "last_otp_verified_at", "updated_at"])

    access_expires_at = min(now + access_token_ttl(), session.absolute_expires_at)
    refresh_expires_at = min(now + refresh_token_ttl(), session.absolute_expires_at)
    if access_expires_at <= now or refresh_expires_at <= now:
        raise InvalidApiCredentials("Authentication is not available for this account.")
    access_token = _new_raw_token()
    refresh_token = _new_raw_token()
    request_ip_hash, request_user_agent_hash = _request_hashes(ip, user_agent)
    for raw_token, token_type, expires_at in (
        (access_token, ApiTokenTypeChoices.ACCESS, access_expires_at),
        (refresh_token, ApiTokenTypeChoices.REFRESH, refresh_expires_at),
    ):
        _create_token_record(
            user=user,
            session=session,
            raw_token=raw_token,
            token_type=token_type,
            expires_at=expires_at,
            security_stamp=user.auth_security_stamp,
            assurance_policy_version=assurance_policy_version,
            assurance_context=assurance_context,
            request_ip_hash=request_ip_hash,
            request_user_agent_hash=request_user_agent_hash,
            issued_at=now,
        )
    return ApiTokenPair(
        access_token=access_token,
        refresh_token=refresh_token,
        access_expires_at=access_expires_at,
        refresh_expires_at=refresh_expires_at,
        session_id=session.id,
        trusted_device_token=trusted_device_token,
        trusted_device_expires_at=trusted_device_expires_at,
    )


@transaction.atomic
def issue_token_pair(
    user,
    *,
    ip: str | None = None,
    user_agent: str | None = None,
    assurance_verified: bool = False,
    family_id: uuid.UUID | None = None,
    authentication_method: str | None = None,
    otp_verified_at=None,
    trusted_device_token: str | None = None,
    trusted_device_expires_at=None,
    trusted_device_id=None,
) -> ApiTokenPair:
    """Issue a pair and its API session while storing only token HMACs."""

    pair = _issue_token_pair_in_transaction(
        user,
        family_id=family_id,
        ip=ip,
        user_agent=user_agent,
        assurance_verified=assurance_verified,
        authentication_method=authentication_method,
        otp_verified_at=otp_verified_at,
        trusted_device_token=trusted_device_token,
        trusted_device_expires_at=trusted_device_expires_at,
        trusted_device_id=trusted_device_id,
    )
    log_security_event(
        action_type="api_token_issued",
        target_model="account_security.ApiSession",
        target_object_id=str(pair.session_id),
        actor_user=user,
        ip_address=ip,
        user_agent=user_agent,
        metadata={
            "token_version": API_TOKEN_VERSION,
            "authentication_method": authentication_method
            or ("otp" if assurance_verified else "password"),
            "status": "active",
        },
    )
    return pair


def _session_is_current(session: ApiSession | None, now=None) -> bool:
    if session is None:
        return False
    now = now or timezone.now()
    if session.status != ApiSessionStatusChoices.ACTIVE:
        return False
    if session.absolute_expires_at <= now:
        ApiSession.objects.filter(
            pk=session.pk,
            status=ApiSessionStatusChoices.ACTIVE,
        ).update(status=ApiSessionStatusChoices.EXPIRED, updated_at=now)
        return False
    return True


def _token_user_is_current(token: ApiToken) -> bool:
    user = token.user
    session = getattr(token, "session", None)
    if not _user_can_receive_api_tokens(user) or not _session_is_current(session):
        return False
    if token.security_stamp != user.auth_security_stamp or session.security_stamp != user.auth_security_stamp:
        return False
    if is_2fa_required_for_user(user):
        if token.assurance_policy_version != ASSURANCE_POLICY_VERSION:
            return False
        if token.assurance_context != ASSURANCE_CONTEXT:
            return False
        if session.authentication_method not in {
            ApiSessionAuthenticationMethodChoices.OTP,
            ApiSessionAuthenticationMethodChoices.TRUSTED_DEVICE,
            ApiSessionAuthenticationMethodChoices.MIGRATED,
        }:
            return False
    return True


def _expire_if_needed(token: ApiToken, now) -> bool:
    if token.expires_at > now and _session_is_current(getattr(token, "session", None), now):
        return False
    ApiToken.objects.filter(
        pk=token.pk,
        status=ApiTokenStatusChoices.ACTIVE,
    ).update(status=ApiTokenStatusChoices.EXPIRED, updated_at=now)
    return True


def resolve_access_token(raw_token: str | None) -> ApiTokenPrincipal | None:
    """Resolve an access bearer without revealing why a credential failed."""

    if not raw_token or len(raw_token) > 512:
        return None
    token = (
        ApiToken.objects.select_related("user", "session")
        .filter(token_hash=hash_token(raw_token), token_type=ApiTokenTypeChoices.ACCESS)
        .first()
    )
    if token is None or token.status != ApiTokenStatusChoices.ACTIVE:
        return None
    now = timezone.now()
    if _expire_if_needed(token, now) or not _token_user_is_current(token):
        return None
    ApiToken.objects.filter(pk=token.pk).update(last_used_at=now, updated_at=now)
    ApiSession.objects.filter(pk=token.session_id, status=ApiSessionStatusChoices.ACTIVE).update(
        last_activity_at=now,
        updated_at=now,
    )
    return ApiTokenPrincipal(user=token.user, token=token)


@transaction.atomic
def revoke_api_session(
    session_id: uuid.UUID | str,
    *,
    actor_user=None,
    ip: str | None = None,
    user_agent: str | None = None,
    reason: str = "logout",
) -> int:
    """Revoke one token-family session and every active credential in it."""

    now = timezone.now()
    session = ApiSession.objects.select_for_update().filter(pk=session_id).first()
    if session is None:
        return 0
    updated = ApiToken.objects.filter(session=session).exclude(
        status=ApiTokenStatusChoices.REVOKED,
    ).update(
        status=ApiTokenStatusChoices.REVOKED,
        revoked_at=now,
        updated_at=now,
    )
    if session.status == ApiSessionStatusChoices.ACTIVE:
        session.status = ApiSessionStatusChoices.REVOKED
        session.revoked_at = now
        session.revoked_reason = reason
        session.updated_at = now
        session.save(update_fields=["status", "revoked_at", "revoked_reason", "updated_at"])
    log_security_event(
        action_type="api_token_family_revoked",
        target_model="account_security.ApiSession",
        target_object_id=str(session.id),
        actor_user=actor_user,
        ip_address=ip,
        user_agent=user_agent,
        metadata={"reason": reason, "status": "revoked"},
    )
    return updated


@transaction.atomic
def revoke_form_invitation_family(
    family_id: uuid.UUID,
    *,
    actor_user=None,
    ip: str | None = None,
    user_agent: str | None = None,
    reason: str = "logout",
) -> int:
    """Compatibility name for older callers; families are now ApiSessions."""

    count = revoke_api_session(
        family_id,
        actor_user=actor_user,
        ip=ip,
        user_agent=user_agent,
        reason=reason,
    )
    if count:
        return count
    now = timezone.now()
    return ApiToken.objects.filter(
        family_id=family_id,
        status=ApiTokenStatusChoices.ACTIVE,
    ).update(status=ApiTokenStatusChoices.REVOKED, revoked_at=now, updated_at=now)


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
    ).update(status=ApiTokenStatusChoices.REVOKED, revoked_at=now, updated_at=now)
    ApiSession.objects.filter(
        user=user,
        status=ApiSessionStatusChoices.ACTIVE,
    ).update(
        status=ApiSessionStatusChoices.REVOKED,
        revoked_at=now,
        revoked_reason=reason,
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


def revoke_session_for_raw_credential(
    raw_credential: str | None,
    *,
    actor_user=None,
    ip: str | None = None,
    user_agent: str | None = None,
    reason: str = "logout",
) -> bool:
    """Find a credential even when expired/revoked and revoke its session."""

    if not raw_credential or len(raw_credential) > 512:
        return False
    token = (
        ApiToken.objects.select_related("user", "session")
        .filter(token_hash=hash_token(raw_credential))
        .first()
    )
    if token is None:
        return False
    revoke_api_session(
        token.session_id or token.family_id,
        actor_user=actor_user or token.user,
        ip=ip,
        user_agent=user_agent,
        reason=reason,
    )
    return True


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
    session_to_revoke = None
    invalid_user = None
    invalid_reason = "refresh_invalidated"
    with transaction.atomic():
        token = (
            ApiToken.objects.select_for_update()
            .select_related("user", "session")
            .filter(token_hash=hash_token(raw_refresh_token), token_type=ApiTokenTypeChoices.REFRESH)
            .first()
        )
        if token is None:
            raise InvalidApiCredentials("Refresh token is invalid.")
        now = timezone.now()
        session = token.session
        if token.status != ApiTokenStatusChoices.ACTIVE:
            session_to_revoke = token.session_id or token.family_id
            invalid_user = token.user
            invalid_reason = "refresh_reuse"
        elif _expire_if_needed(token, now) or not _token_user_is_current(token):
            session_to_revoke = token.session_id or token.family_id
            invalid_user = token.user
        else:
            token.status = ApiTokenStatusChoices.USED
            token.used_at = now
            token.last_used_at = now
            token.save(update_fields=["status", "used_at", "last_used_at", "updated_at"])
            pair = _issue_token_pair_in_transaction(
                token.user,
                family_id=token.family_id,
                session=session,
                ip=ip,
                user_agent=user_agent,
                assurance_verified=session.authentication_method in {
                    ApiSessionAuthenticationMethodChoices.OTP,
                    ApiSessionAuthenticationMethodChoices.MIGRATED,
                },
                authentication_method=session.authentication_method,
                otp_verified_at=None,
                now=now,
            )

    if session_to_revoke is not None:
        revoke_api_session(
            session_to_revoke,
            actor_user=invalid_user,
            reason=invalid_reason,
        )
        raise InvalidApiCredentials("Refresh token is invalid.")
    if token is None or pair is None:
        raise InvalidApiCredentials("Refresh token is invalid.")
    log_security_event(
        action_type="api_refresh_rotated",
        target_model="account_security.ApiSession",
        target_object_id=str(token.session_id or token.family_id),
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


def begin_password_login(
    email: str,
    password: str,
    request_context: RequestMetadata,
    *,
    trusted_device_token: str | None = None,
):
    normalized_email = str(email or "").strip().lower()
    ip = _login_decision(normalized_email, request_context)
    user_agent = request_context.user_agent
    user = authenticate(request=None, username=normalized_email, password=password)
    if not _user_can_receive_api_tokens(user):
        _record_login_failure(normalized_email, request_context, reason="invalid_credentials")
        raise InvalidApiCredentials("Invalid credentials.")

    if is_2fa_required_for_user(user):
        if trusted_device_token:
            from apps.account_security.services import consume_trusted_device_for_login

            device_receipt = consume_trusted_device_for_login(
                user,
                trusted_device_token,
                ip=ip,
                user_agent=user_agent,
            )
            if device_receipt is not None:
                raw_device_token, expiry, device_id = device_receipt
                pair = issue_token_pair(
                    user,
                    ip=ip,
                    user_agent=user_agent,
                    authentication_method=ApiSessionAuthenticationMethodChoices.TRUSTED_DEVICE,
                    trusted_device_token=raw_device_token,
                    trusted_device_expires_at=expiry,
                    trusted_device_id=device_id,
                )
                record_success(AbuseAction.LOGIN, subject=normalized_email, ip=ip)
                return pair
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

    pair = issue_token_pair(user, ip=ip, user_agent=user_agent, assurance_verified=False)
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
    *,
    trust_device: bool = False,
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

    challenge.refresh_from_db(fields=["verified_at"])

    raw_device_token = None
    device_expiry = None
    device_id = None
    if trust_device:
        from apps.account_security.services import issue_trusted_device_after_otp

        raw_device_token, device_expiry, device_id = issue_trusted_device_after_otp(
            challenge,
            user_agent=request_context.user_agent,
            ip=request_context.ip_address,
        )
    pair = issue_token_pair(
        challenge.user,
        ip=request_context.ip_address,
        user_agent=request_context.user_agent,
        assurance_verified=True,
        authentication_method=ApiSessionAuthenticationMethodChoices.OTP,
        otp_verified_at=challenge.verified_at or timezone.now(),
        trusted_device_token=raw_device_token,
        trusted_device_expires_at=device_expiry,
        trusted_device_id=device_id,
    )
    record_success(AbuseAction.LOGIN, subject=challenge.user.email, ip=request_context.ip_address)
    log_security_event(
        action_type="login_success",
        target_model="accounts.User",
        target_object_id=str(challenge.user.pk),
        actor_user=challenge.user,
        ip_address=request_context.ip_address,
        user_agent=request_context.user_agent,
        metadata={"assurance_context": ASSURANCE_CONTEXT},
    )
    return pair
