"""Fixed safe projections for Audit Viewer responses."""

from __future__ import annotations

import hashlib
import hmac
import re

from django.conf import settings


_SAFE_CODE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}\Z")
_SAFE_REFERENCE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}\Z")
_SAFE_CONTEXT_KEYS = frozenset({
    "status",
    "from_status",
    "to_status",
    "decision",
    "decision_code",
    "reason_code",
    "result_code",
    "operation",
    "outcome",
    "scope",
    "policy_key",
    "success",
    "has_notes",
    "count",
})


def _safe_code(value, *, fallback: str = "") -> str:
    candidate = str(value or "").strip()
    return candidate[:100] if _SAFE_CODE.fullmatch(candidate) else fallback


def _safe_correlation(value) -> str | None:
    candidate = str(value or "").strip()
    return candidate[:100] if _SAFE_CODE.fullmatch(candidate) else None


def _opaque(namespace: str, value: str | int | None) -> str | None:
    if value is None or value == "":
        return None
    secret = str(getattr(settings, "AUDIT_HASH_SECRET", "")).encode("utf-8")
    if not secret:
        return None
    material = f"{namespace}:v1:{value}".encode("utf-8")
    return hmac.new(secret, material, hashlib.sha256).hexdigest()


def _safe_context(metadata) -> dict:
    if not isinstance(metadata, dict):
        return {}
    result = {}
    for key in _SAFE_CONTEXT_KEYS:
        value = metadata.get(key)
        if isinstance(value, bool):
            result[key] = value
        elif isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 1000000:
            result[key] = value
        elif isinstance(value, str):
            safe_value = _safe_code(value)
            if safe_value:
                result[key] = safe_value
    return result


def audit_entry_projection(entry) -> dict:
    """Project one row without exposing raw audit metadata or object IDs."""

    target_model = _safe_code(entry.target_model, fallback="unknown")
    reference = entry.reference_code.strip() if isinstance(entry.reference_code, str) else ""
    return {
        "id": entry.id,
        "created_at": entry.created_at,
        "action_type": _safe_code(entry.action_type, fallback="unknown"),
        "event_category": _safe_code(entry.event_category, fallback="unknown"),
        "severity": _safe_code(entry.severity, fallback="unknown"),
        "source_app": _safe_code(entry.source_app, fallback="unknown"),
        "actor_role": _safe_code(entry.actor_role, fallback="unknown"),
        "actor_fingerprint": _opaque("audit-actor", entry.actor_user_id),
        "target_model": target_model,
        "target_reference": (
            reference[:100]
            if _SAFE_REFERENCE.fullmatch(reference)
            else None
        ),
        "target_fingerprint": _opaque(
            "audit-target",
            f"{target_model}:{entry.target_object_id}",
        ),
        "request_id": _safe_correlation(entry.request_id),
        "trace_id": _safe_correlation(entry.trace_id),
        "safe_context": _safe_context(entry.safe_metadata),
    }
