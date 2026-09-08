"""Bounded output boundary for account-activity and active-session data.

The session selectors in :mod:`apps.account_security.selectors` are internal
query sources.  Consumers must use the projection helpers in this module
rather than serializing model rows or raw session metadata directly.  This
module is the single privacy and presentation contract: it never exposes a raw
IP, raw User-Agent, or session key, and it distinguishes the bounded display
states instead of collapsing them into one "Protected" label.

Distinguishable states (exported constants):
- ``available``     — authoritative, present value (e.g. a real device summary).
- ``approximate``   — coarse, intentionally imprecise value (network class only).
- ``not_captured``  — absent, or an old hash-only record we will not reconstruct.
- ``unavailable``   — present but invalid / undecodable / sanitation failed.
"""

import re

from django.utils import timezone
from django.utils.dateparse import parse_datetime

from apps.account_security.network import (
    CLASS_CAMPUS,
    CLASS_PRIVATE,
    CLASS_PUBLIC,
)
from apps.account_security.tokens import get_session_action_token


STATE_AVAILABLE = "available"
STATE_APPROXIMATE = "approximate"
STATE_NOT_CAPTURED = "not_captured"
STATE_UNAVAILABLE = "unavailable"

# A stored device summary matching these is treated as "we never captured a
# real browser/OS" and is presented as not_captured — never reconstructed.
NOT_CAPTURED_DEVICE_VALUES = frozenset(
    {"unknown device", "unknown browser on unknown os"}
)

# Bounded browser/OS names emitted by ``get_safe_user_agent_summary``. A stored
# summary is only ``available`` when it combines a real browser with a real OS;
# any other arbitrary non-empty string is an invalid present value and becomes
# ``unavailable`` (never ``available``).
BROWSER_NAMES = frozenset({"edge", "opera", "chrome", "safari", "firefox"})
OS_NAMES = frozenset({"windows", "macos", "ios", "android", "linux"})

# Valid bounded network-class values that project as ``approximate``.
APPROXIMATE_NETWORK_CLASSES = frozenset(
    {CLASS_CAMPUS, CLASS_PRIVATE, CLASS_PUBLIC}
)

# The bounded "not captured / unclassifiable" network class from
# ``classify_network_class`` (missing or unparseable IP metadata). It is
# presented as ``not_captured``, never as a decoder failure.
NOT_CAPTURED_NETWORK_CLASSES = frozenset({"unknown"})

ACTIVITY_LABELS = {
    "login_success": "Sign-in completed",
    "login_failure": "Sign-in attempt blocked",
    "password_changed": "Password changed",
    "twostep_challenge_created": "Two-step verification requested",
    "twostep_challenge_email_failed": "Two-step verification could not be sent",
    "twostep_challenge_failed": "Two-step verification failed",
    "twostep_challenge_verify_failed": "Two-step verification failed",
    "twostep_challenge_locked": "Two-step verification locked",
    "twostep_challenge_resend_denied": "Two-step verification resend blocked",
    "twostep_challenge_resend_failed": "Two-step verification resend failed",
    "twostep_challenge_resent": "Two-step verification code resent",
    "twostep_challenge_verified": "Two-step verification completed",
    "twostep_setup_unavailable": "Two-step verification unavailable",
    "internal_assurance_established": "Additional sign-in verification completed",
    "internal_assurance_rejected": "Additional sign-in verification blocked",
    "trusted_device_created": "Trusted device added",
    "trusted_device_rejected": "Trusted device rejected",
    "trusted_device_revoked": "Trusted device revoked",
    "trusted_device_used": "Trusted device used",
    "trusted_devices_bulk_revoked": "All trusted devices revoked",
    "recovery_request_policy_denied": "Account recovery request blocked",
    "recovery_requested": "Account recovery requested",
    "recovery_request_email_failed": "Account recovery message could not be sent",
    "recovery_verify_failed": "Account recovery verification failed",
    "recovery_verify_success": "Account recovery completed",
    "recovery_locked": "Account recovery locked",
    "verified_email_recorded": "Email ownership verification recorded",
    "staff_assisted_recovery_requested": "Assisted account recovery requested",
    "staff_assisted_recovery_denied": "Assisted account recovery blocked",
    "session_terminated": "Session signed out",
    "sessions_terminated_bulk": "Other sessions signed out",
}

ACTIVITY_FAILURE_ACTIONS = frozenset(
    {
        "login_failure",
        "twostep_challenge_email_failed",
        "twostep_challenge_failed",
        "twostep_challenge_verify_failed",
        "twostep_challenge_locked",
        "twostep_challenge_resend_denied",
        "twostep_challenge_resend_failed",
        "twostep_setup_unavailable",
        "internal_assurance_rejected",
        "trusted_device_rejected",
        "recovery_request_policy_denied",
        "recovery_request_email_failed",
        "recovery_verify_failed",
        "recovery_locked",
        "staff_assisted_recovery_denied",
    }
)


def project_timestamp(value) -> str | None:
    """Return one consistent ISO-8601 timestamp representation.

    Accepts a datetime or an ISO-8601/date-time string and normalizes both to
    ``localtime(...).isoformat()``.  Missing values remain ``None`` so API
    timestamp fields never mix presentation copy with machine-readable data.
    """
    if value is None or value == "":
        return None
    if isinstance(value, str):
        parsed = parse_datetime(value)
        if parsed is None:
            return None
        value = parsed
    if not isinstance(value, timezone.datetime):
        return None
    if timezone.is_naive(value):
        value = timezone.make_aware(value, timezone.get_current_timezone())
    return timezone.localtime(value).isoformat()


def _is_valid_device_summary(label: str) -> bool:
    """Return whether ``label`` is a bounded browser/OS summary.

    Only summaries of the form ``"{browser} on {os}"`` with a real browser and
    a real OS (as emitted by ``get_safe_user_agent_summary``) are ``available``.
    """
    if " on " not in label:
        return False
    browser, os_part = label.lower().split(" on ", 1)
    return browser in BROWSER_NAMES and os_part in OS_NAMES


def project_device(raw) -> dict:
    """Project a stored device summary into a bounded display state.

    - Missing / absent          → ``not_captured``.
    - Present-but-invalid type  → ``unavailable``.
    - "Unknown Device" / "Unknown Browser on Unknown OS" → ``not_captured``.
    - A real summarised browser/OS → ``available`` (truncated to 80 chars).
    - Any other arbitrary non-empty string → ``unavailable`` (rejected, never
      presented as ``available``).
    """
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return {"state": STATE_NOT_CAPTURED, "label": "Device information not captured"}
    if not isinstance(raw, str):
        return {"state": STATE_UNAVAILABLE, "label": "Device information unavailable"}
    label = raw.strip()[:80]
    if label.lower() in NOT_CAPTURED_DEVICE_VALUES:
        return {"state": STATE_NOT_CAPTURED, "label": "Device information not captured"}
    if not _is_valid_device_summary(label):
        return {"state": STATE_UNAVAILABLE, "label": "Device information unavailable"}
    return {"state": STATE_AVAILABLE, "label": label}


def project_network(network_class) -> dict:
    """Project a bounded network class into an approximate display state.

    Only coarse classes are ever shown.  Missing → ``not_captured``; the
    bounded ``unknown`` class (missing/unparseable IP metadata) → ``not_captured``
    (a capture gap, not a decoder failure); a distinctly invalid present value
    → ``unavailable``.
    """
    if network_class is None or (
        isinstance(network_class, str) and not network_class.strip()
    ):
        return {"state": STATE_NOT_CAPTURED, "label": "Network information not captured"}
    normalized = str(network_class).strip().lower()
    if normalized in APPROXIMATE_NETWORK_CLASSES:
        return {"state": STATE_APPROXIMATE, "label": "Approximate network location"}
    if normalized in NOT_CAPTURED_NETWORK_CLASSES:
        return {"state": STATE_NOT_CAPTURED, "label": "Network information not captured"}
    return {"state": STATE_UNAVAILABLE, "label": "Network information unavailable"}


def _metadata_states(metadata) -> dict | None:
    """Return unavailable states when audit sanitization degraded the record."""
    if not isinstance(metadata, dict):
        return None
    degraded = metadata.get("redacted") is True or metadata.get("reason_code") == (
        "metadata_sanitization_failed"
    )
    if not degraded:
        return None
    return {
        "device": {"state": STATE_UNAVAILABLE, "label": "Device information unavailable"},
        "network": {"state": STATE_UNAVAILABLE, "label": "Network information unavailable"},
    }


def project_activity_log(log) -> dict:
    """Project one audit row into the bounded account-activity contract."""
    metadata = log.safe_metadata if isinstance(log.safe_metadata, dict) else {}
    states = _metadata_states(metadata)
    if states is None:
        states = {
            "device": project_device(metadata.get("device_label")),
            "network": project_network(metadata.get("network_class")),
        }
    blocked = log.action_type in ACTIVITY_FAILURE_ACTIONS or log.severity in {
        "ERROR",
        "CRITICAL",
    }
    return {
        "label": ACTIVITY_LABELS.get(log.action_type, "Security activity"),
        "created_at": project_timestamp(log.created_at),
        "device": states["device"],
        "network": states["network"],
        "status_label": "Blocked" if blocked else "Completed",
        "status_tone": "danger" if blocked else "success",
    }


def _activity_category(event_category: str) -> str:
    category = str(event_category or "").upper()
    if category == "SECURITY":
        return "security"
    if category in {"SYSTEM", "AUTHORIZATION", "TOKEN_BATCH"}:
        return "technical"
    if category in {"PRIVACY", "PRIVACY_GOVERNANCE", "DATA_ACCESS"}:
        return "privacy"
    return "work"


def project_user_activity_entry(log) -> dict:
    """Project one actor-owned activity event without exposing its target."""
    category = _activity_category(log.event_category)
    action = str(log.action_type or "").strip()
    safe_action = action[:100] if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}", action) else "activity"
    label = ACTIVITY_LABELS.get(action, safe_action.replace("_", " ").title())
    reference = log.reference_code if isinstance(log.reference_code, str) else ""
    reference = reference.strip()[:50] if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,49}", reference.strip()) else None
    blocked = str(log.severity or "").upper() in {"ERROR", "CRITICAL"}
    result = {
        "activity_type": safe_action,
        "category": category,
        "label": label,
        "created_at": project_timestamp(log.created_at),
        "status_label": "Blocked" if blocked else "Completed",
        "status_tone": "danger" if blocked else "success",
        "reference_code": reference,
    }
    if category == "security":
        security = project_activity_log(log)
        result["device"] = security["device"]
        result["network"] = security["network"]
    return result


def project_trusted_device(device, *, current_device_id=None) -> dict:
    """Project a trusted device without exposing its verifier or network hash."""
    return {
        "id": str(device.id),
        "device": project_device(device.label),
        "status": str(device.status),
        "trusted_until": project_timestamp(device.trusted_until),
        "last_used_at": project_timestamp(device.last_used_at),
        "revoked_at": project_timestamp(device.revoked_at),
        "is_current": str(device.id) == str(current_device_id or ""),
    }


def project_session_row(session, current_session_id=None) -> dict:
    """Project one real opaque-token family into the bounded contract."""
    return {
        "session_token": get_session_action_token(str(session.id)),
        "is_current": str(session.id) == str(current_session_id or ""),
        "device": project_device(session.device_summary),
        "network": project_network(session.network_class),
        "started_at": project_timestamp(session.started_at),
        "last_activity_at": project_timestamp(session.last_activity_at),
        "expires_at": project_timestamp(session.absolute_expires_at),
        "authentication_method": str(session.authentication_method),
    }
