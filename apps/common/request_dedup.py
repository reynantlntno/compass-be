"""Shared request-key and command-deduplication mechanics.

This module deliberately owns mechanics only.  Domain applications retain the
records that express their business idempotency and uniqueness rules; this
module supplies one bounded key contract, one hashing primitive, one safe
fingerprint builder, and one transaction-bound lock helper.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass

from django.conf import settings
from django.db import connection

from apps.common.contracts import to_json_value
from apps.common.exceptions import ValidationError


DEFAULT_MAX_REQUEST_KEY_LENGTH = 128
MAX_ALLOWED_REQUEST_KEY_LENGTH = 512
_SAFE_REQUEST_KEY_RE = re.compile(r"\A[\x21-\x7e]+\Z")
_VOLATILE_OR_SENSITIVE_FIELDS = frozenset({
    "csrfmiddlewaretoken",
    "password",
    "secret",
    "token",
    "otp",
    "jwt",
    "session_key",
    "ip_address",
    "user_agent",
    "request_id",
    "trace_id",
})


@dataclass(frozen=True, slots=True)
class RequestKeyPolicy:
    """Bounded, purpose-specific validation settings for a request key."""

    namespace: str
    max_length: int = DEFAULT_MAX_REQUEST_KEY_LENGTH

    def __post_init__(self) -> None:
        if not self.namespace or not _SAFE_REQUEST_KEY_RE.fullmatch(self.namespace):
            raise ValueError("Request-key namespace must be a safe non-empty string.")
        if isinstance(self.max_length, bool) or not isinstance(self.max_length, int):
            raise ValueError("Request-key maximum length must be an integer.")
        if self.max_length < 1 or self.max_length > MAX_ALLOWED_REQUEST_KEY_LENGTH:
            raise ValueError(
                f"Request-key maximum length must be between 1 and {MAX_ALLOWED_REQUEST_KEY_LENGTH}."
            )


def normalize_request_key(value: str, *, max_length: int | None = DEFAULT_MAX_REQUEST_KEY_LENGTH) -> str:
    """Validate and return one bounded opaque request key.

    Raw keys are accepted only in memory.  Callers must persist the returned
    value only when their domain record intentionally preserves request-key
    history; generic API replay storage uses ``hash_request_key`` instead.
    """

    if type(value) is not str:
        raise ValidationError("A request key is required.")
    normalized = value.strip()
    if not normalized or (max_length is not None and len(normalized) > max_length) or not _SAFE_REQUEST_KEY_RE.fullmatch(normalized):
        raise ValidationError("The request key is malformed or exceeds its allowed length.")
    return normalized


def _secret_value(*, secret_setting: str, secret: str | None) -> str:
    value = secret if secret is not None else getattr(settings, secret_setting, "")
    if not value:
        raise RuntimeError(f"{secret_setting} is required for request-key hashing.")
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return str(value)


def hash_request_key(
    value: str,
    *,
    purpose: str = "",
    secret_setting: str = "SECRET_KEY",
    secret: str | None = None,
    max_length: int | None = DEFAULT_MAX_REQUEST_KEY_LENGTH,
) -> str:
    """Return a deterministic HMAC-SHA256 digest without persisting the key."""

    normalized = normalize_request_key(value, max_length=max_length)
    secret_value = _secret_value(secret_setting=secret_setting, secret=secret)
    message = f"{purpose}:{normalized}" if purpose else normalized
    return hmac.new(
        secret_value.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def build_command_fingerprint(payload: dict) -> str:
    """Hash a bounded JSON-safe command projection for domain deduplication."""

    try:
        serialized = json.dumps(
            to_json_value(payload or {}),
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise ValidationError("The command cannot be fingerprinted safely.") from exc
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def build_request_fingerprint(
    method: str,
    path: str,
    payload: dict,
    actor_user=None,
    session_key: str | None = None,
) -> str:
    """Build the canonical API request fingerprint used by workflow replay."""

    clean_payload = {}
    for key, value in (payload or {}).items():
        key_lower = str(key).lower()
        if not any(marker in key_lower for marker in _VOLATILE_OR_SENSITIVE_FIELDS):
            clean_payload[key] = value

    try:
        serialized_payload = json.dumps(
            to_json_value(clean_payload),
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise ValidationError("The request cannot be fingerprinted safely.") from exc

    actor_id = str(actor_user.id) if actor_user and hasattr(actor_user, "id") else ""
    session_context = (
        hash_request_key(session_key, purpose="fingerprint-session")
        if session_key
        else ""
    )
    fingerprint_input = (
        f"{method.upper()}:{path.lower()}:{actor_id}:{session_context}:{serialized_payload}"
    )
    return hashlib.sha256(fingerprint_input.encode("utf-8")).hexdigest()


def lock_request_key(
    policy: RequestKeyPolicy,
    value: str,
) -> str:
    """Acquire a transaction-scoped lock using only a keyed digest.

    PostgreSQL is the production database and receives the advisory lock.  A
    non-PostgreSQL development backend still receives the same validation and
    digest; its domain uniqueness constraint remains the safety backstop.
    """

    digest = hash_request_key(
        value,
        purpose=f"request-lock:{policy.namespace}",
        max_length=policy.max_length,
    )
    if connection.vendor == "postgresql":
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))",
                [f"{policy.namespace}:{digest}"],
            )
    return digest


def validate_and_lock_request_key(policy: RequestKeyPolicy, value: str) -> str:
    """Validate one domain key, lock its digest, and return the normalized key.

    Domain records intentionally retain their existing request-key history;
    only the lock path uses the digest.
    """
    normalized = normalize_request_key(value, max_length=policy.max_length)
    lock_request_key(policy, normalized)
    return normalized
