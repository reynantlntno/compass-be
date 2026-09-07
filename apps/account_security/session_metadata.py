"""Privacy-safe metadata stored inside authenticated Django sessions."""

from django.utils import timezone

from apps.account_security.network import classify_network_class
from apps.account_security.tokens import get_safe_user_agent_summary
from apps.common.contracts import RequestMetadata


def record_authenticated_session(session, request_context: RequestMetadata) -> None:
    """Record bounded session metadata without storing raw request details.

    Only the safe browser/OS summary and the bounded coarse network class
    (``campus_network`` / ``private_network`` / ``public_network`` /
    ``unknown``) are stored. A raw IP or User-Agent is never persisted.
    """
    now = timezone.now().isoformat()
    session.setdefault("_compass_session_started_at", now)
    session["_compass_session_last_activity_at"] = now
    session["_compass_session_device_summary"] = get_safe_user_agent_summary(
        request_context.user_agent
    )
    session["_compass_session_network_class"] = classify_network_class(
        request_context.ip_address
    )
    session.modified = True
