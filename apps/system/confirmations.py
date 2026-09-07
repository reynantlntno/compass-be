# Project: COMPASS
# File: apps/system/confirmations.py
# Module: apps.system
# Purpose: Reusable signed confirmation/reversal helper foundation
# Domain boundary and service policy.
# Notes:
#   - Prefer stateless signed short-lived payloads before DB token tables.
#   - Confirmation payload is bound to actor, action key, target type,
#     target ID/reference, and expiry.
#   - Policy is re-checked at execution time.
#   - UI confirmation does not replace backend service/policy checks.

import json
import logging
from datetime import timedelta
from typing import Any, Dict, Optional, Tuple

from django.conf import settings
from django.core.signing import BadSignature, SignatureExpired, TimestampSigner
from django.utils import timezone

from apps.access_control.rules import is_it_admin
from apps.common.django_adapters import DjangoPermissionDenied
from apps.common.exceptions import PermissionDeniedError as PermissionDenied, ValidationError

logger = logging.getLogger("apps.system.confirmations")

# ---------------------------------------------------------------------------
# Sensitive action reason denylist
# ---------------------------------------------------------------------------
SENSITIVE_REASON_BLOCKLIST = {
    "password",
    "secret",
    "token",
    "otp",
    "jwt",
    "api_key",
    "private_key",
    "encryption_key",
    "credential",
    "counseling_notes",
    "counseling notes",
    "counseling note",
    "referral_reason",
    "referral reason",
    "referral reasons",
    "assessment_interpretation",
    "assessment interpretation",
    "support_message",
    "support message",
    "health_narrative",
    "health narrative",
    "family_narrative",
    "family narrative",
    "financial_narrative",
    "financial narrative",
    "student_number",
    "student number",
    "control_number",
    "control number",
    "email",
    "vault",
    "storage_key",
    "storage key",
    "private_url",
    "private url",
    "signed_url",
    "signed url",
    "reset_link",
    "reset link",
}

# Default confirmation expiry in seconds.
DEFAULT_CONFIRMATION_EXPIRY_SECONDS = 300  # 5 minutes

# Signer key prefix for confirmation payloads.
SIGNER_SALT = "compass.confirmation.v1"


def _get_signer() -> TimestampSigner:
    """Return a TimestampSigner for confirmation payloads."""
    return TimestampSigner(salt=SIGNER_SALT)


def clean_action_reason(reason: str, max_length: int = 255) -> str:
    """Sanitize and validate an action reason.

    Redacts obvious sensitive/private content. Returns a bounded safe string.
    """
    if not reason or not isinstance(reason, str):
        return ""
    cleaned = reason.strip()[:max_length]
    lower = cleaned.lower()
    for blocked in SENSITIVE_REASON_BLOCKLIST:
        if blocked in lower:
            return "[REASON REDACTED]"
    return cleaned


def normalize_safe_feedback_message(
    action_label: str,
    target_reference: str,
    consequence: str,
    reversibility: str = "",
) -> str:
    """Build a privacy-safe feedback message for confirmation UI.

    Never echoes sensitive submitted content.
    """
    parts = [f"Are you sure you want to {action_label}"]
    if target_reference:
        parts.append(f"for {target_reference}")
    if consequence:
        parts.append(f"? This will {consequence}.")
    else:
        parts.append("?")
    if reversibility:
        parts.append(f" This action is {reversibility}.")
    return " ".join(parts)


def create_confirmation_context(
    *,
    action_key: str,
    action_label: str,
    actor,
    target_type: str,
    target_id: str,
    target_reference: str = "",
    consequence: str = "",
    reversibility: str = "",
    required_reason: bool = False,
    required_typed_phrase: bool = False,
    expiry_seconds: int = DEFAULT_CONFIRMATION_EXPIRY_SECONDS,
) -> Dict:
    """Build a confirmation context dict for rendering and signing.

    Returns a dict with safe metadata for the confirmation page/partial
    and a signed payload for server-side validation.
    """
    now = timezone.now()
    expires_at = now + timedelta(seconds=expiry_seconds)

    payload = {
        "action_key": action_key,
        "actor_id": str(getattr(actor, "id", "")),
        "target_type": target_type,
        "target_id": str(target_id),
        "target_reference": target_reference,
        "issued_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
        "required_reason": required_reason,
        "required_typed_phrase": required_typed_phrase,
    }

    signer = _get_signer()
    signed_payload = signer.sign(json.dumps(payload, default=str))

    return {
        "signed_payload": signed_payload,
        "action_key": action_key,
        "action_label": action_label,
        "target_type": target_type,
        "target_id": str(target_id),
        "target_reference": target_reference,
        "consequence": consequence,
        "reversibility": reversibility,
        "required_reason": required_reason,
        "required_typed_phrase": required_typed_phrase,
        "expires_at": expires_at,
    }


def sign_confirmation_payload(
    *,
    action_key: str,
    actor_id: str,
    target_type: str,
    target_id: str,
    target_reference: str = "",
    expiry_seconds: int = DEFAULT_CONFIRMATION_EXPIRY_SECONDS,
) -> str:
    """Sign a confirmation payload and return the signed string.

    Lower-level helper for programmatic use.
    """
    now = timezone.now()
    expires_at = now + timedelta(seconds=expiry_seconds)

    payload = {
        "action_key": action_key,
        "actor_id": str(actor_id),
        "target_type": target_type,
        "target_id": str(target_id),
        "target_reference": target_reference,
        "issued_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
    }

    signer = _get_signer()
    return signer.sign(json.dumps(payload, default=str))


def validate_confirmation_payload(
    *,
    signed_payload: str,
    actor,
    expected_action_key: str,
    expected_target_type: str,
    expected_target_id: str,
) -> Tuple[bool, str, Dict]:
    """Validate a signed confirmation payload.

    Checks:
    - Signature validity and expiry.
    - Actor binding.
    - Action key match.
    - Target type/ID match.

    Returns (is_valid, error_message, payload_dict).
    """
    if not signed_payload:
        return False, "Missing confirmation payload.", {}

    signer = _get_signer()
    try:
        unsigned = signer.unsign(signed_payload, max_age=DEFAULT_CONFIRMATION_EXPIRY_SECONDS)
    except SignatureExpired:
        return False, "Confirmation has expired. Please try again.", {}
    except BadSignature:
        return False, "Invalid confirmation signature.", {}

    try:
        payload = json.loads(unsigned)
    except (json.JSONDecodeError, ValueError):
        return False, "Invalid confirmation payload.", {}

    # Also check the payload's own expires_at field.
    expires_at_str = payload.get("expires_at")
    if expires_at_str:
        try:
            from datetime import datetime
            expires_at = datetime.fromisoformat(expires_at_str)
            if timezone.now() > expires_at:
                return False, "Confirmation has expired. Please try again.", payload
        except (ValueError, TypeError):
            pass

    # Actor binding
    actor_id = str(getattr(actor, "id", ""))
    if payload.get("actor_id") != actor_id:
        return False, "This confirmation was issued for a different user.", payload

    # Action key
    if payload.get("action_key") != expected_action_key:
        return False, "Confirmation action mismatch.", payload

    # Target type
    if payload.get("target_type") != expected_target_type:
        return False, "Confirmation target type mismatch.", payload

    # Target ID
    if payload.get("target_id") != str(expected_target_id):
        return False, "Confirmation target mismatch.", payload

    return True, "", payload


def execute_confirmed_action(
    *,
    signed_payload: str,
    actor,
    expected_action_key: str,
    expected_target_type: str,
    expected_target_id: str,
    domain_service_callable,
    reason: str = "",
    **service_kwargs,
) -> Tuple[bool, str, Any]:
    """Execute a domain service after validating the confirmation payload.

    Policy is re-checked at execution time by the domain service.
    Returns (success, message, result).
    """
    is_valid, error_msg, payload = validate_confirmation_payload(
        signed_payload=signed_payload,
        actor=actor,
        expected_action_key=expected_action_key,
        expected_target_type=expected_target_type,
        expected_target_id=expected_target_id,
    )
    if not is_valid:
        return False, error_msg, None

    # Re-check policy at execution time.
    try:
        result = domain_service_callable(actor=actor, **service_kwargs)
        return True, "Action completed successfully.", result
    except PermissionDenied as e:
        return False, str(e), None
    except ValidationError as e:
        return False, str(e), None
    except Exception:
        logger.warning(
            "confirmed_action_execution_failed",
            extra={
                "reason_code": "execution_exception",
                "action_key": expected_action_key,
            },
        )
        return False, "The action could not be completed.", None


def record_reversal_audit_entry(
    *,
    actor,
    target_model: str,
    target_object_id: str,
    reference_code: str = "",
    action_type: str = "REVERSAL",
    metadata: Optional[Dict] = None,
):
    """Record a reversal audit entry with safe metadata.

    Import is deferred to avoid circular imports at module level.
    """
    from apps.audit.services import audit_log

    audit_log(
        action_type=action_type,
        event_category="WORKFLOW",
        target_model=target_model,
        target_object_id=str(target_object_id),
        actor_user=actor,
        source_app="system",
        reference_code=reference_code,
        metadata=metadata or {},
    )
