# Project: COMPASS
# File: apps/form_collection/rate_limits.py
# Module: apps.form_collection
# Purpose: Rate limiting for token verification attempts using hashed identifiers
# Domain boundary and service policy.

from apps.account_security.abuse_controls import AbuseAction, evaluate


def is_rate_limited(
    ip_address: str = None,
    session_id: str = None,
    form_invitation=None,
    identifier_hash: str = None,
) -> bool:
    """Delegate token throttling to the shared progressive-abuse service.

    ``identifier_hash`` is already an HMAC from the token service and is
    intentionally treated as an opaque subject value here; the shared service
    hashes it again before durable/cache use.  An IP-only scope can trigger a
    challenge but can never hard-block a shared campus NAT.
    """
    token_value = getattr(form_invitation, "selector", None) if form_invitation else None
    decision = evaluate(
        AbuseAction.TOKEN_VERIFY,
        subject=identifier_hash,
        ip=ip_address,
        session=session_id,
        token=token_value,
    )
    return not decision.allowed
