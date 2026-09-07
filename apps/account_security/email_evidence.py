"""Verified-email provenance helpers.

Evidence is append-only.  Eligibility always compares the evidence hash with
the account's *current* normalized email, so changing an address immediately
invalidates older evidence without mutating history.
"""

from django.db import transaction
from django.utils import timezone

from apps.account_security.audit import log_security_event
from apps.account_security.models import VerifiedEmailEvidence
from apps.account_security.tokens import hash_identifier
from apps.access_control.rules import is_active_nonlegacy_actor


def normalized_email(user_or_email) -> str:
    value = getattr(user_or_email, "email", user_or_email)
    return str(value or "").strip().lower()


def current_email_hash(user_or_email) -> str:
    return hash_identifier(normalized_email(user_or_email))


def get_current_verified_email_evidence(user):
    if not is_active_nonlegacy_actor(user) or not normalized_email(user):
        return None
    return (
        VerifiedEmailEvidence.objects.filter(
            user=user,
            status="verified",
            email_hash=current_email_hash(user),
        )
        .order_by("-verified_at", "-created_at")
        .first()
    )


def has_verified_current_email(user) -> bool:
    return get_current_verified_email_evidence(user) is not None


@transaction.atomic
def record_verified_email_evidence(
    user,
    *,
    verification_method: str,
    verified_by=None,
    source_model: str = "",
    source_object_id: str = "",
    reason_category: str = "",
    ip_address: str = None,
    user_agent: str = None,
):
    """Append evidence for the current address and emit only safe audit data."""
    if verification_method not in {
        "activation_invitation",
        "staff_activation_invitation",
        "staff_out_of_band",
    }:
        raise ValueError("Unsupported email verification method")
    email_hash = current_email_hash(user)
    if not email_hash:
        raise ValueError("A usable email address is required")
    existing = VerifiedEmailEvidence.objects.filter(
        user=user,
        email_hash=email_hash,
        status="verified",
    ).order_by("-verified_at", "-created_at").first()
    if existing:
        return existing, False
    evidence = VerifiedEmailEvidence.objects.create(
        user=user,
        email_hash=email_hash,
        status="verified",
        verification_method=verification_method,
        verified_at=timezone.now(),
        verified_by=verified_by,
        source_model=(source_model or "")[:100],
        source_object_id=str(source_object_id or "")[:255],
        reason_category=(reason_category or "")[:60],
        metadata_json={},
    )
    log_security_event(
        action_type="verified_email_recorded",
        target_model="accounts.User",
        target_object_id=str(user.pk),
        actor_user=verified_by or user,
        ip_address=ip_address,
        user_agent=user_agent,
        metadata={
            "verification_method": verification_method,
            "reason_category": reason_category or "unspecified",
            "status": "verified",
        },
    )
    return evidence, True
