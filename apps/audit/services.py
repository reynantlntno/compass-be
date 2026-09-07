# Project: COMPASS
# File: apps/audit/services.py
# Module: apps.audit
# Purpose: Services for audit logging and metadata sanitization
# Domain boundary and service policy.
# Notes: Ensure sensitive data is never serialized raw into the DB.

import json
import hashlib
import hmac
import re
from copy import deepcopy
from typing import Any, Dict, Optional
from django.db import transaction
from django.db.models import Model
from django.conf import settings
from .models import AuditLogEntry

SENSITIVE_KEYS = {
    "password", "secret", "token", "api_key", "private_key", "encryption_key",
    "otp", "jwt", "credential", "smtp_password", "daily", "request_body",
    "counseling_notes", "referral_reason", "assessment_interpretation",
    "session_key", "authorization", "auth", "cookie", "signature", "salt",
    "pin", "current_pin", "new_pin", "confirmation", "kek", "jcek",
    "journal_key", "derived_key", "nonce", "wrap", "wrapped_key",
    "ciphertext", "envelope", "title", "content", "body", "shared_payload",
    "raw_request", "raw request", "exception", "content_hash",
}

SENSITIVE_VALUE_KEYWORDS = {
    "password", "secret", "token", "api_key", "private_key", "encryption_key",
    "otp", "jwt", "credential", "smtp_password", "session_key", "authorization", 
    "auth", "cookie", "signature", "salt",
    "counseling_notes", "counseling notes", "counseling note",
    "referral_reason", "referral reason", "referral reasons",
    "assessment_interpretation", "assessment interpretation",
    "health_narrative", "health narrative",
    "family_narrative", "family narrative",
    "financial_narrative", "financial narrative",
    "request_body", "request body",
    "daily", "csrfmiddlewaretoken", "pin", "current_pin", "new_pin",
    "confirmation", "kek", "jcek", "journal_key", "journal key",
    "derived_key", "derived key", "nonce", "wrapped_key", "wrapped key",
    "ciphertext", "envelope", "shared_payload", "shared payload",
    "raw request", "request material", "content_hash", "content hash",
}

JWT_REGEX = re.compile(r"ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+")

MAX_STRING_LENGTH = 1024
MAX_METADATA_SIZE_BYTES = 65536 # 64KB max JSON size
NON_SERIALIZABLE_METADATA_PLACEHOLDER = "[REDACTED_NON_SERIALIZABLE_METADATA]"

def _hash_value(value: str) -> Optional[str]:
    """Helper to consistently hash privacy-sensitive values like IP and User-Agent using HMAC-SHA256."""
    if not value:
        return None
    key = settings.AUDIT_HASH_SECRET.encode('utf-8')
    return hmac.new(key, value.encode('utf-8'), hashlib.sha256).hexdigest()

def sanitize_audit_metadata(metadata: Any) -> Any:
    """
    Sanitizes metadata recursively.
    Redacts sensitive keys, truncates long strings, redacts sensitive string values, and ensures serializability.
    """
    if isinstance(metadata, dict):
        sanitized = {}
        for k, v in metadata.items():
            k_lower = str(k).lower()
            normalized_key = re.sub(r"[^a-z0-9]+", "_", k_lower).strip("_")
            compact_key = normalized_key.replace("_", "")
            if any(
                sensitive.replace(" ", "_") in normalized_key
                or sensitive.replace("_", "").replace(" ", "") in compact_key
                for sensitive in SENSITIVE_KEYS
            ):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = sanitize_audit_metadata(v)
        return sanitized
    elif isinstance(metadata, list) or isinstance(metadata, tuple):
        return [sanitize_audit_metadata(item) for item in metadata]
    elif isinstance(metadata, str):
        val_lower = metadata.lower()
        # Check if the string matches JWT regex
        if JWT_REGEX.search(metadata):
            return "[REDACTED]"
        # Check for HTTP URLs with sensitive parameters
        if "http" in val_lower:
            if any(param in val_lower for param in ["signature", "awsaccesskeyid", "expires", "token", "jwt", "secret", "key"]):
                return "[REDACTED]"
        # Check for Daily meeting JWTs or Daily link with credentials
        if "daily" in val_lower and any(kw in val_lower for kw in ["jwt", "token", "secret", "room"]):
            return "[REDACTED]"
        # Check for request bodies or general credentials
        if any(term in val_lower for term in ["csrfmiddlewaretoken", "password=", "password\"", "secret\"", "token\""]):
            return "[REDACTED]"
        # Check general sensitive value keywords
        if any(keyword in val_lower for keyword in SENSITIVE_VALUE_KEYWORDS):
            return "[REDACTED]"
        
        if len(metadata) > MAX_STRING_LENGTH:
            return metadata[:MAX_STRING_LENGTH] + "...[TRUNCATED]"
        return metadata
    elif isinstance(metadata, (int, float, bool, type(None))):
        return metadata
    else:
        return NON_SERIALIZABLE_METADATA_PLACEHOLDER

def _prepare_safe_metadata(metadata: Optional[Dict]) -> Dict:
    if not metadata:
        return {}
    
    try:
        sanitized = sanitize_audit_metadata(metadata)
        # Verify size limit
        json_str = json.dumps(sanitized)
        if len(json_str.encode('utf-8')) > MAX_METADATA_SIZE_BYTES:
            return {"error": "Metadata exceeded maximum allowed size", "truncated": True}
        return sanitized
    except Exception:
        return {
            "redacted": True,
            "reason_code": "metadata_sanitization_failed",
        }

def audit_log(
    action_type: str,
    event_category: str,
    target_model: str,
    target_object_id: str,
    severity: str = "INFO",
    actor_user=None,
    reference_code: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    request_id: Optional[str] = None,
    trace_id: Optional[str] = None,
    source_app: Optional[str] = None,
    source_view: Optional[str] = None,
    metadata: Optional[Dict] = None
) -> Optional[AuditLogEntry]:
    """
    Core function to create an AuditLogEntry.
    Will gracefully handle failures by catching exceptions and printing to standard logging,
    unless it's a strict database error that breaks the transaction, in which case we might rely on the caller's transaction handling.
    """
    try:
        actor_role = ""
        if actor_user and hasattr(actor_user, "role"):
            actor_role = actor_user.role

        safe_metadata = _prepare_safe_metadata(metadata)

        entry = AuditLogEntry.objects.create(
            actor_user=actor_user,
            actor_role=actor_role,
            action_type=action_type,
            event_category=event_category,
            severity=severity,
            target_model=target_model,
            target_object_id=str(target_object_id),
            reference_code=reference_code,
            actor_ip_hash=_hash_value(ip_address),
            user_agent_hash=_hash_value(user_agent),
            request_id=request_id,
            trace_id=trace_id,
            source_app=source_app,
            source_view=source_view,
            safe_metadata=safe_metadata
        )
        return entry
    except Exception:
        # Audit log failures must not crash the main request.
        # Use safe logging without raw exception text.
        import logging
        logging.getLogger("apps.audit.services").warning(
            "audit_log_creation_failed",
            extra={"reason_code": "audit_log_exception"},
        )
        return None

def audit_sensitive_view(
    actor_user,
    target_model: str,
    target_object_id: str,
    reference_code: Optional[str] = None,
    metadata: Optional[Dict] = None,
    **kwargs
) -> Optional[AuditLogEntry]:
    """Helper for logging when a user views sensitive data."""
    return audit_log(
        action_type="SENSITIVE_VIEW",
        event_category="DATA_ACCESS",
        severity="INFO",
        target_model=target_model,
        target_object_id=target_object_id,
        actor_user=actor_user,
        reference_code=reference_code,
        metadata=metadata,
        **kwargs
    )

def audit_assignment_change(
    actor_user,
    target_model: str,
    target_object_id: str,
    reference_code: Optional[str] = None,
    metadata: Optional[Dict] = None,
    **kwargs
) -> Optional[AuditLogEntry]:
    """Helper for logging assignment and reassignment of records."""
    return audit_log(
        action_type="ASSIGNMENT_CHANGE",
        event_category="WORKFLOW",
        severity="INFO",
        target_model=target_model,
        target_object_id=target_object_id,
        actor_user=actor_user,
        reference_code=reference_code,
        metadata=metadata,
        **kwargs
    )

def audit_status_transition(
    actor_user,
    target_model: str,
    target_object_id: str,
    reference_code: Optional[str] = None,
    metadata: Optional[Dict] = None,
    **kwargs
) -> Optional[AuditLogEntry]:
    """Helper for logging workflow status transitions."""
    return audit_log(
        action_type="STATUS_TRANSITION",
        event_category="WORKFLOW",
        severity="INFO",
        target_model=target_model,
        target_object_id=target_object_id,
        actor_user=actor_user,
        reference_code=reference_code,
        metadata=metadata,
        **kwargs
    )

def audit_form_invitation(
    actor_user,
    target_model: str,
    target_object_id: str,
    reference_code: Optional[str] = None,
    metadata: Optional[Dict] = None,
    **kwargs
) -> Optional[AuditLogEntry]:
    """Helper for logging token-based access."""
    return audit_log(
        action_type="FORM_INVITATION_ACCESS",
        event_category="SECURITY",
        severity="WARNING", # Token access generally warrants higher visibility
        target_model=target_model,
        target_object_id=target_object_id,
        actor_user=actor_user,
        reference_code=reference_code,
        metadata=metadata,
        **kwargs
    )
