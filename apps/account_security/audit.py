from typing import Dict, Any, Optional
from django.conf import settings
from apps.audit.services import audit_log
from apps.account_security.network import classify_network_class
from apps.account_security.tokens import get_safe_user_agent_summary

# Strict allowlist of metadata keys for security events to prevent any leak of PII or secrets.
ALLOWLISTED_METADATA_KEYS = {
    "action",
    "scope",
    "purpose",
    "challenge_id",
    "device_id",
    "device_label",
    "network_class",
    "recovery_request_id",
    "reason",
    "attempts",
    "max_attempts",
    "lockout_duration_seconds",
    "delivery_channel",
    "email_delivery_id",
    "resend_count",
    "success",
    "status",
    "request_ip_hash",
    "request_user_agent_hash",
    "assurance_method",
    "assurance_version",
    "assurance_context",
    "route_class",
    "target_role",
    "reason_category",
    "outcome",
    "verification_method",
    "token_version",
}


def log_security_event(
    action_type: str,
    target_model: str,
    target_object_id: str,
    severity: str = "INFO",
    actor_user=None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    request_id: Optional[str] = None,
    trace_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
):
    """Log an account security event, enforcing the metadata allowlist.

    ``device_label`` and ``network_class`` are derived ONLY from the transient
    ``user_agent`` and ``ip_address`` arguments at this event boundary.  Any
    caller-supplied values under those keys are ignored and overwritten so a
    caller can never inject an unbounded device or network value.
    """
    clean_metadata = {}
    if metadata:
        for k, v in metadata.items():
            if k in ALLOWLISTED_METADATA_KEYS and k not in ("device_label", "network_class"):
                clean_metadata[k] = v

    # Bounded, transient-derived values only. Raw IP / User-Agent are never
    # persisted here; audit_log stores only their HMAC hashes.
    clean_metadata["device_label"] = get_safe_user_agent_summary(user_agent or "")
    clean_metadata["network_class"] = classify_network_class(ip_address)

    return audit_log(
        action_type=action_type,
        event_category="SECURITY",
        target_model=target_model,
        target_object_id=str(target_object_id) if target_object_id else "",
        severity=severity,
        actor_user=actor_user,
        ip_address=ip_address,
        user_agent=user_agent,
        request_id=request_id,
        trace_id=trace_id,
        source_app="apps.account_security",
        metadata=clean_metadata
    )
