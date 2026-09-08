"""Student enrollment and authenticated OTP step-up services."""

from __future__ import annotations

import secrets
import uuid
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from django.db import transaction
from django.utils import timezone

from apps.account_security.assurance import validate_api_session_assurance
from apps.account_security.models import (
    ApiSession,
    ApiSessionAuthenticationMethodChoices,
    ApiSessionStatusChoices,
    StudentTwoFactorEnrollment,
    TwoStepChallenge,
)
from apps.account_security.policies import (
    is_2fa_required_for_user,
    is_student_two_factor_enabled,
)
from apps.account_security.services import (
    create_twostep_challenge,
    resend_otp,
    revoke_all_trusted_devices_for_user,
    verify_otp,
)
from apps.common.exceptions import AssuranceRequiredError, InvalidCredentialsError, PermissionDeniedError, ValidationError


User = get_user_model()


def _challenge_projection(challenge, pending_nonce: str) -> dict:
    return {
        "challenge_id": challenge.id,
        "pending_nonce": pending_nonce,
        "expires_in": max(0, int((challenge.expires_at - timezone.now()).total_seconds())),
        "requires_verification": True,
    }


def two_factor_status(user) -> dict:
    if getattr(user, "role", None) != "STUDENT":
        return {
            "enabled": bool(is_2fa_required_for_user(user)),
            "required": bool(is_2fa_required_for_user(user)),
            "can_change": False,
        }
    return {
        "enabled": is_student_two_factor_enabled(user),
        "required": False,
        "can_change": True,
    }


def request_student_two_factor_change(
    user,
    *,
    current_password: str,
    enabled: bool,
    ip: str | None = None,
    user_agent: str | None = None,
) -> dict:
    if getattr(user, "role", None) != "STUDENT" or not getattr(user, "is_active", False):
        raise PermissionDeniedError()
    if type(enabled) is not bool:
        raise ValidationError()
    current = StudentTwoFactorEnrollment.objects.filter(user=user).first()
    if current is not None and current.enabled == enabled:
        raise ValidationError(field_errors={"enabled": ["The requested state is already active."]})
    if not check_password(current_password, user.password):
        raise InvalidCredentialsError()
    pending_nonce = secrets.token_urlsafe(32)
    challenge, _ = create_twostep_challenge(
        user,
        purpose="two_factor_change",
        ip=ip,
        user_agent=user_agent,
        pending_nonce=pending_nonce,
    )
    if challenge is None:
        raise ValidationError()
    challenge.metadata_json = {
        **dict(challenge.metadata_json or {}),
        "desired_enabled": enabled,
    }
    challenge.save(update_fields=["metadata_json", "updated_at"])
    return _challenge_projection(challenge, pending_nonce)


@transaction.atomic
def verify_student_two_factor_change(
    user,
    *,
    challenge_id: uuid.UUID,
    pending_nonce: str,
    otp: str,
    ip: str | None = None,
    user_agent: str | None = None,
):
    if getattr(user, "role", None) != "STUDENT":
        raise PermissionDeniedError()
    challenge = TwoStepChallenge.objects.select_for_update().filter(
        id=challenge_id,
        user=user,
        purpose="two_factor_change",
        status="pending",
    ).first()
    if challenge is None or not verify_otp(
        str(challenge_id),
        otp,
        expected_user_id=user.pk,
        purpose="two_factor_change",
        pending_nonce=pending_nonce,
        ip=ip,
        user_agent=user_agent,
    ):
        raise InvalidCredentialsError()
    challenge.refresh_from_db(fields=["verified_at"])
    desired = bool((challenge.metadata_json or {}).get("desired_enabled"))
    current_user = User.objects.select_for_update().get(pk=user.pk, is_active=True)
    enrollment, _ = StudentTwoFactorEnrollment.objects.select_for_update().get_or_create(
        user=current_user,
    )
    now = timezone.now()
    enrollment.enabled = desired
    enrollment.enabled_at = now if desired else enrollment.enabled_at
    enrollment.disabled_at = now if not desired else None
    enrollment.last_changed_at = now
    enrollment.save(update_fields=["enabled", "enabled_at", "disabled_at", "last_changed_at", "updated_at"])

    # Changing the enrollment is an authentication-state change. Rotate the
    # account stamp first so old sessions/devices cannot survive the change.
    current_user.auth_security_stamp = uuid.uuid4()
    current_user.save(update_fields=["auth_security_stamp", "updated_at"])
    revoke_all_trusted_devices_for_user(
        current_user,
        reason="student_two_factor_changed",
        ip=ip,
        audit_when_empty=True,
    )
    from apps.account_security.api_tokens import issue_token_pair

    pair = issue_token_pair(
        current_user,
        ip=ip,
        user_agent=user_agent,
        assurance_verified=True,
        authentication_method=ApiSessionAuthenticationMethodChoices.OTP,
        otp_verified_at=challenge.verified_at or now,
    )
    return desired, pair


def resend_student_two_factor_change(
    user,
    *,
    challenge_id: uuid.UUID,
    pending_nonce: str,
    ip: str | None = None,
    user_agent: str | None = None,
) -> dict:
    challenge = TwoStepChallenge.objects.filter(
        id=challenge_id,
        user=user,
        purpose="two_factor_change",
        status="pending",
    ).first()
    if challenge is None:
        raise InvalidCredentialsError()
    delivered, message = resend_otp(
        str(challenge_id),
        expected_user_id=user.pk,
        pending_nonce=pending_nonce,
        ip=ip,
        user_agent=user_agent,
    )
    if not delivered:
        raise InvalidCredentialsError()
    return {"resent": True, "detail": message}


def request_assurance_challenge(
    user,
    *,
    session_id,
    ip: str | None = None,
    user_agent: str | None = None,
) -> dict:
    session = ApiSession.objects.filter(
        id=session_id,
        user=user,
        status=ApiSessionStatusChoices.ACTIVE,
    ).first()
    if session is None:
        raise PermissionDeniedError()
    pending_nonce = secrets.token_urlsafe(32)
    challenge, _ = create_twostep_challenge(
        user,
        purpose="sensitive_action",
        ip=ip,
        user_agent=user_agent,
        pending_nonce=pending_nonce,
    )
    if challenge is None:
        raise ValidationError()
    return _challenge_projection(challenge, pending_nonce)


@transaction.atomic
def verify_assurance_challenge(
    user,
    *,
    session_id,
    challenge_id: uuid.UUID,
    pending_nonce: str,
    otp: str,
    ip: str | None = None,
    user_agent: str | None = None,
) -> dict:
    session = ApiSession.objects.select_for_update().filter(
        id=session_id,
        user=user,
        status=ApiSessionStatusChoices.ACTIVE,
    ).first()
    challenge = TwoStepChallenge.objects.filter(
        id=challenge_id,
        user=user,
        purpose="sensitive_action",
        status="pending",
    ).first()
    if session is None or challenge is None or not verify_otp(
        str(challenge_id),
        otp,
        expected_user_id=user.pk,
        purpose="sensitive_action",
        pending_nonce=pending_nonce,
        ip=ip,
        user_agent=user_agent,
    ):
        raise InvalidCredentialsError()
    challenge.refresh_from_db(fields=["verified_at"])
    session.last_otp_verified_at = challenge.verified_at or timezone.now()
    session.authentication_method = ApiSessionAuthenticationMethodChoices.OTP
    session.last_activity_at = timezone.now()
    session.save(update_fields=["last_otp_verified_at", "authentication_method", "last_activity_at", "updated_at"])
    return {"verified": True}


def resend_assurance_challenge(
    user,
    *,
    challenge_id: uuid.UUID,
    pending_nonce: str,
    ip: str | None = None,
    user_agent: str | None = None,
) -> dict:
    challenge = TwoStepChallenge.objects.filter(
        id=challenge_id,
        user=user,
        purpose="sensitive_action",
        status="pending",
    ).first()
    if challenge is None:
        raise InvalidCredentialsError()
    delivered, message = resend_otp(
        str(challenge_id),
        expected_user_id=user.pk,
        pending_nonce=pending_nonce,
        ip=ip,
        user_agent=user_agent,
    )
    if not delivered:
        raise InvalidCredentialsError()
    return {"resent": True, "detail": message}


def require_fresh_otp(user, session) -> None:
    valid, _ = validate_api_session_assurance(user, session)
    if not valid:
        raise AssuranceRequiredError()
