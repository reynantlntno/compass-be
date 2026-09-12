"""Short-lived opaque selectors for staff workflow choices.

The encrypted payload is intentionally request-local.  It is bound to the
actor, workflow, and record reference, and every resolver still relies on the
target domain policy before a mutation is allowed.
"""

from __future__ import annotations

import base64
import hashlib
import json

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings


TOKEN_MAX_AGE = 10 * 60
TOKEN_SALT = "compass.workflow-selector.v1"
COUNSELOR_WORKFLOWS = frozenset({"referral", "call_slip"})


def _fernet() -> Fernet:
    material = hashlib.sha256(
        f"{settings.SECRET_KEY}:{TOKEN_SALT}".encode("utf-8")
    ).digest()
    return Fernet(base64.urlsafe_b64encode(material))


def issue_counselor_selection_token(actor, workflow: str, reference_code: str, counselor) -> str:
    if workflow not in COUNSELOR_WORKFLOWS:
        raise ValueError("Unsupported counselor selection workflow.")
    payload = json.dumps(
        {
            "actor": actor.pk,
            "workflow": workflow,
            "reference_code": str(reference_code).strip(),
            "purpose": "counselor",
            "value": int(counselor.pk),
        },
        separators=(",", ":"),
    ).encode("utf-8")
    return _fernet().encrypt(payload).decode("ascii")


def resolve_counselor_selection_token(
    actor,
    workflow: str,
    reference_code: str,
    token: object,
):
    if workflow not in COUNSELOR_WORKFLOWS or not isinstance(token, str) or not token:
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
        payload.get("actor") != getattr(actor, "pk", None)
        or payload.get("workflow") != workflow
        or payload.get("reference_code") != str(reference_code).strip()
        or payload.get("purpose") != "counselor"
        or isinstance(payload.get("value"), bool)
        or not isinstance(payload.get("value"), int)
    ):
        return None

    from apps.accounts.models import RoleChoices, User

    return User.objects.filter(
        pk=payload["value"],
        is_active=True,
        is_superuser=False,
        role=RoleChoices.COUNSELOR,
    ).first()
