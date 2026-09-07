"""Shared, purpose-bound activation mechanics for account onboarding.

This module owns only security mechanics.  Student eligibility, staff
provisioning, profile validation, invitation authorization, auditing, and
notification policy remain in their respective domains.
"""

from __future__ import annotations

import hashlib
import hmac
import uuid
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Mapping, Protocol
from urllib.parse import quote, urlsplit

from django.conf import settings
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core import signing
from django.utils import timezone

from apps.common.exceptions import ValidationError


class ActivationPurpose(StrEnum):
    STUDENT = "student"
    STAFF = "staff"


@dataclass(frozen=True)
class ActivationTokenProfile:
    purpose: ActivationPurpose
    version: str
    signer_salt: str
    client_path: str


ACTIVATION_TOKEN_PROFILES: Mapping[ActivationPurpose, ActivationTokenProfile] = MappingProxyType({
    ActivationPurpose.STUDENT: ActivationTokenProfile(
        purpose=ActivationPurpose.STUDENT,
        version="account-activation-student-v1",
        signer_salt="compass.account-activation.student.v1",
        client_path="/activate/",
    ),
    ActivationPurpose.STAFF: ActivationTokenProfile(
        purpose=ActivationPurpose.STAFF,
        version="account-activation-staff-v1",
        signer_salt="compass.account-activation.staff.v1",
        client_path="/staff-activate/",
    ),
})


class ActivationInvitationState(Protocol):
    """The common state surface implemented by both invitation models."""

    used_at: object
    revoked_at: object
    expires_at: object


def activation_profile(purpose: ActivationPurpose) -> ActivationTokenProfile:
    try:
        return ACTIVATION_TOKEN_PROFILES[ActivationPurpose(purpose)]
    except (KeyError, ValueError, TypeError) as exc:
        raise ValidationError("The activation purpose is invalid.") from exc


def _activation_secret() -> bytes:
    value = str(getattr(settings, "ACCOUNT_ACTIVATION_TOKEN_SECRET", "") or "")
    if not value:
        raise ValidationError("Account activation security is not configured.")
    return value.encode("utf-8")


def hash_activation_token(raw_token: str) -> str:
    """Return the persisted HMAC digest; never persist the bearer token."""
    if not isinstance(raw_token, str) or not raw_token or len(raw_token) > 512:
        raise ValidationError("The activation token is invalid.")
    return hmac.new(
        _activation_secret(),
        raw_token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def issue_activation_token(reference, purpose: ActivationPurpose) -> str:
    """Build a purpose- and version-bound token from an opaque reference."""
    profile = activation_profile(purpose)
    reference = getattr(reference, "token_reference", reference)
    reference = uuid.UUID(str(reference))
    payload = f"{profile.version}:{profile.purpose.value}:{reference}"
    return signing.Signer(salt=profile.signer_salt).sign(payload)


def decode_activation_reference(raw_token: str, purpose: ActivationPurpose):
    """Return the UUID reference only when the requested purpose matches."""
    profile = activation_profile(purpose)
    if not isinstance(raw_token, str) or not raw_token or len(raw_token) > 512:
        return None
    try:
        value = signing.Signer(salt=profile.signer_salt).unsign(raw_token)
        version, token_purpose, reference = value.split(":", 2)
        if version != profile.version or token_purpose != profile.purpose.value:
            return None
        return uuid.UUID(reference)
    except (signing.BadSignature, ValueError, TypeError, AttributeError):
        return None


def activation_url_for_token(raw_token: str, purpose: ActivationPurpose) -> str:
    """Build a client activation URL using the purpose-specific path."""
    profile = activation_profile(purpose)
    base = str(getattr(settings, "COMPASS_CLIENT_BASE_URL", "") or "").strip().rstrip("/")
    if not base:
        raise ValidationError("The canonical client URL is not configured.")
    parsed = urlsplit(base)
    environment = str(getattr(settings, "COMPASS_ENVIRONMENT", "development") or "").lower()
    if (
        not parsed.scheme
        or not parsed.netloc
        or parsed.scheme not in {"http", "https"}
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or (environment in {"staging", "production"} and parsed.scheme != "https")
    ):
        raise ValidationError("The canonical client URL is invalid.")
    return f"{base}{profile.client_path}?token={quote(raw_token, safe='')}"


def invitation_state_reason(invitation: ActivationInvitationState | None, *, now=None) -> str | None:
    """Return a safe state code, or ``None`` when an invitation is usable."""
    if invitation is None:
        return "not_found"
    now = now or timezone.now()
    if invitation.used_at is not None:
        return "used"
    if invitation.revoked_at is not None:
        return "revoked"
    if invitation.expires_at <= now:
        return "expired"
    return None


def validate_activation_password(password: str, confirmation: str, user) -> None:
    if password != confirmation:
        raise ValidationError("Passwords do not match.")
    try:
        validate_password(password, user=user)
    except DjangoValidationError as exc:
        raise ValidationError("The password does not meet the account requirements.") from exc


def consume_activation_invitation(user, invitation: ActivationInvitationState, password: str, *, now=None):
    """Activate a locked invitation after its domain has validated its purpose.

    Callers must hold the invitation row lock and must perform the
    student/staff role and profile checks before calling this primitive.
    """
    reason = invitation_state_reason(invitation, now=now)
    if reason is not None or user.is_active:
        raise ValidationError("The activation invitation is invalid or no longer available.")
    now = now or timezone.now()
    user.set_password(password)
    user.is_active = True
    user.save(update_fields=["password", "is_active", "updated_at"])
    invitation.__class__.objects.filter(pk=invitation.pk).update(used_at=now)
    return now
