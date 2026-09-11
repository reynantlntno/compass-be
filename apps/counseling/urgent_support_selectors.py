"""Opaque, request-scoped selectors for urgent-support operations.

Selection tokens are encrypted rather than merely signed because their
payload contains an internal user or grant key.  A token is still only a
short-lived selector: every resolver checks the current actor, request, and
policy again before returning an object.
"""

from __future__ import annotations

import base64
import hashlib
import json

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings

from apps.counseling.models import (
    TemporarySupportAccessGrant,
    TemporarySupportAccessStatus,
    UrgentSupportRequest,
)


TOKEN_MAX_AGE = 10 * 60
TOKEN_SALT = "compass.urgent-support-selector.v1"


def _fernet() -> Fernet:
    material = hashlib.sha256(
        f"{settings.SECRET_KEY}:{TOKEN_SALT}".encode("utf-8")
    ).digest()
    return Fernet(base64.urlsafe_b64encode(material))


def _issue(actor, *, reference_code: str, purpose: str, value: int) -> str:
    payload = json.dumps(
        {
            "actor": actor.pk,
            "reference_code": str(reference_code),
            "purpose": purpose,
            "value": int(value),
        },
        separators=(",", ":"),
    ).encode("utf-8")
    return _fernet().encrypt(payload).decode("ascii")


def issue_counselor_selection_token(actor, urgent_support, counselor) -> str:
    return _issue(
        actor,
        reference_code=urgent_support.reference_code,
        purpose="counselor",
        value=counselor.pk,
    )


def issue_grant_selection_token(actor, grant) -> str:
    return _issue(
        actor,
        reference_code=grant.urgent_support.reference_code,
        purpose="grant",
        value=grant.pk,
    )


def _decode(actor, *, reference_code: str, purpose: str, token: object) -> int | None:
    if not isinstance(token, str) or not token or not getattr(actor, "pk", None):
        return None
    try:
        payload = json.loads(
            _fernet().decrypt(token.encode("ascii"), ttl=TOKEN_MAX_AGE).decode("utf-8")
        )
    except (InvalidToken, UnicodeError, ValueError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None
    if (
        payload.get("actor") != actor.pk
        or payload.get("reference_code") != str(reference_code)
        or payload.get("purpose") != purpose
        or not isinstance(payload.get("value"), int)
    ):
        return None
    return payload["value"]


def resolve_counselor_selection_token(actor, urgent_support, token: object):
    counselor_pk = _decode(
        actor,
        reference_code=urgent_support.reference_code,
        purpose="counselor",
        token=token,
    )
    if counselor_pk is None:
        return None
    from apps.access_control.rules import is_counselor
    from apps.accounts.models import RoleChoices, User

    counselor = User.objects.filter(
        pk=counselor_pk,
        is_active=True,
        role=RoleChoices.COUNSELOR,
    ).first()
    return counselor if counselor is not None and is_counselor(counselor) else None


def resolve_grant_selection_token(actor, urgent_support, token: object):
    grant_pk = _decode(
        actor,
        reference_code=urgent_support.reference_code,
        purpose="grant",
        token=token,
    )
    if grant_pk is None:
        return None
    return TemporarySupportAccessGrant.objects.filter(
        pk=grant_pk,
        urgent_support=urgent_support,
        status=TemporarySupportAccessStatus.ACTIVE,
        revoked_at__isnull=True,
    ).first()
