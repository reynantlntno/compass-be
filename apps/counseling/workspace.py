"""Small, signed state helpers for the live e-counseling workspace.

The token carries no raw database identifiers or counseling content.  It binds
an editable panel to the current actor, opaque session reference, purpose, and
the record timestamp observed when the panel was rendered.
"""

import hashlib
import hmac

from django.core import signing
from apps.common.exceptions import StaleStateError, ValidationError


WORKSPACE_TOKEN_SALT = "compass.counseling.workspace.v1"
WORKSPACE_TOKEN_MAX_AGE = 12 * 60 * 60


class WorkspaceStateError(ValidationError):
    """Base class for invalid or stale workspace panel state."""


class WorkspaceStateInvalid(WorkspaceStateError):
    pass


class WorkspaceStateStale(WorkspaceStateError, StaleStateError):
    code = StaleStateError.code
    public_message = StaleStateError.public_message
    pass


def _digest(value) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def issue_workspace_state_token(user, session, panel: str, updated_at) -> str:
    payload = {
        "actor": _digest(user.pk),
        "session": _digest(session.reference_code),
        "panel": panel,
        "purpose": "workspace-panel-save",
        "updated_at": updated_at.isoformat() if updated_at else "",
    }
    return signing.dumps(payload, salt=WORKSPACE_TOKEN_SALT, compress=True)


def validate_workspace_state_token(token, user, session, panel: str, updated_at) -> None:
    if not token:
        raise WorkspaceStateInvalid("Missing workspace state.")
    try:
        payload = signing.loads(
            token,
            salt=WORKSPACE_TOKEN_SALT,
            max_age=WORKSPACE_TOKEN_MAX_AGE,
        )
    except signing.BadSignature as exc:
        raise WorkspaceStateInvalid("Invalid workspace state.") from exc
    if payload.get("panel") != panel or payload.get("purpose") != "workspace-panel-save":
        raise WorkspaceStateInvalid("Invalid workspace purpose.")
    if not hmac.compare_digest(payload.get("actor", ""), _digest(user.pk)):
        raise WorkspaceStateInvalid("Invalid workspace actor.")
    if not hmac.compare_digest(payload.get("session", ""), _digest(session.reference_code)):
        raise WorkspaceStateInvalid("Invalid workspace session.")
    expected = updated_at.isoformat() if updated_at else ""
    if not hmac.compare_digest(payload.get("updated_at", ""), expected):
        raise WorkspaceStateStale("This panel is out of date. Refresh it before saving again.")
