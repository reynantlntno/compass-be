from typing import Optional, List
from django.utils import timezone
from apps.account_security.models import AccountRecoveryRequest, TwoStepChallenge, TrustedDevice
from apps.account_security.tokens import hash_token, parse_recovery_token, RECOVERY_TOKEN_VERSION
from apps.account_security.projections import (
    project_activity_log,
    project_decode_state,
    project_session_row,
    project_trusted_device,
    project_user_activity_entry,
)
from django.contrib.sessions.models import Session
from apps.audit.models import AuditLogEntry
from apps.access_control.rules import is_active_nonlegacy_actor
from apps.access_control.rules import is_it_admin
from apps.access_control.authority import has_fixed_capability
from apps.access_control.capabilities import Capability
from datetime import timedelta


ACTIVITY_FILTER_ACTIONS = {
    "login": frozenset({"login_success", "login_failure"}),
    "password": frozenset({"password_changed"}),
    "two_step": frozenset(
        {
            "twostep_challenge_created",
            "twostep_challenge_email_failed",
            "twostep_challenge_failed",
            "twostep_challenge_verify_failed",
            "twostep_challenge_locked",
            "twostep_challenge_resend_denied",
            "twostep_challenge_resend_failed",
            "twostep_challenge_resent",
            "twostep_challenge_verified",
            "twostep_setup_unavailable",
            "internal_assurance_established",
            "internal_assurance_rejected",
        }
    ),
    "trusted": frozenset(
        {
            "trusted_device_created",
            "trusted_device_rejected",
            "trusted_device_revoked",
            "trusted_device_used",
            "trusted_devices_bulk_revoked",
        }
    ),
    "recovery": frozenset(
        {
            "recovery_request_no_user",
            "recovery_request_policy_denied",
            "recovery_requested",
            "recovery_request_email_failed",
            "recovery_verify_failed",
            "recovery_verify_success",
            "recovery_locked",
            "verified_email_recorded",
            "staff_assisted_recovery_requested",
            "staff_assisted_recovery_denied",
        }
    ),
    "session": frozenset({"session_terminated", "sessions_terminated_bulk"}),
}


def get_active_recovery_request(token: str) -> Optional[AccountRecoveryRequest]:
    """Retrieve an active recovery request by the raw token string.

    Only returns requests that are pending and have not expired.
    """
    if not token:
        return None
    request_id = parse_recovery_token(token)
    if request_id is None:
        return None
    token_hash = hash_token(token)
    try:
        return AccountRecoveryRequest.objects.get(
            id=request_id,
            token_hash=token_hash,
            token_version=RECOVERY_TOKEN_VERSION,
            status="pending",
            expires_at__gt=timezone.now(),
        )
    except AccountRecoveryRequest.DoesNotExist:
        return None


def get_active_twostep_challenge(challenge_id: str) -> Optional[TwoStepChallenge]:
    """Retrieve a two-step challenge by ID.

    Only returns challenges that are pending and have not expired.
    """
    if not challenge_id:
        return None
    try:
        return TwoStepChallenge.objects.get(
            id=challenge_id,
            status="pending",
            expires_at__gt=timezone.now()
        )
    except (TwoStepChallenge.DoesNotExist, ValueError):
        return None


def get_active_trusted_devices(user) -> List[TrustedDevice]:
    """Retrieve all active and non-expired trusted devices for a given user."""
    if not is_active_nonlegacy_actor(user):
        return []
    return list(
        TrustedDevice.objects.filter(
            user=user,
            status="active",
            trusted_until__gt=timezone.now()
        ).order_by("-created_at")
    )


def _privacy_activity_allowed(user) -> bool:
    if not is_active_nonlegacy_actor(user):
        return False
    from apps.privacy.policies import is_current_dpo
    from apps.privacy.services import has_reviewer_scope

    if is_current_dpo(user):
        return True
    return any(
        has_reviewer_scope(user, scope)
        for scope in (
            "request_review",
            "request_sensitive",
            "request_assign",
            "incident_record",
            "legal_hold",
        )
    )


def _technical_activity_allowed(user) -> bool:
    return bool(
        is_it_admin(user)
        and has_fixed_capability(user, Capability.AUDIT_VIEW)
    )


def _activity_categories_for_actor(user, category: str) -> frozenset[str]:
    category = str(category or "all").strip().lower()
    if category == "security":
        return frozenset({"SECURITY"})
    if category == "work":
        return frozenset({"WORKFLOW", "CONTENT", "FORM", "FORM_COLLECTION", "UNLINKED_FORM_SUBMISSION"})
    if category == "technical":
        return frozenset({"SYSTEM", "AUTHORIZATION", "TOKEN_BATCH"}) if _technical_activity_allowed(user) else frozenset()
    if category == "privacy":
        return frozenset({"PRIVACY", "PRIVACY_GOVERNANCE", "DATA_ACCESS"}) if _privacy_activity_allowed(user) else frozenset()
    if category == "all":
        categories = {"SECURITY", "WORKFLOW", "CONTENT", "FORM", "FORM_COLLECTION", "UNLINKED_FORM_SUBMISSION"}
        if _technical_activity_allowed(user):
            categories.update({"SYSTEM", "AUTHORIZATION", "TOKEN_BATCH"})
        if _privacy_activity_allowed(user):
            categories.update({"PRIVACY", "PRIVACY_GOVERNANCE", "DATA_ACCESS"})
        return frozenset(categories)
    return frozenset()


def get_user_activity_queryset(user, category: str = "all"):
    """Return only the current actor's safe, category-scoped audit rows."""
    categories = _activity_categories_for_actor(user, category)
    if not categories or not is_active_nonlegacy_actor(user):
        return AuditLogEntry.objects.none()
    return AuditLogEntry.objects.filter(
        actor_user=user,
        event_category__in=categories,
    ).only(
        "action_type",
        "event_category",
        "severity",
        "reference_code",
        "safe_metadata",
        "created_at",
    ).order_by("-created_at", "-pk")


def get_user_activity_logs(user, days=90, action_filter=None):
    """Retrieve a safe, user-owned projection of recent security activity."""
    if not is_active_nonlegacy_actor(user):
        return []
    try:
        days = max(0, int(days))
    except (TypeError, ValueError):
        days = 90
    cutoff_date = timezone.now() - timedelta(days=days)
    logs = AuditLogEntry.objects.filter(
        actor_user=user,
        event_category="SECURITY",
        created_at__gte=cutoff_date,
    )
    allowed_actions = ACTIVITY_FILTER_ACTIONS.get(action_filter)
    if allowed_actions is not None:
        logs = logs.filter(action_type__in=allowed_actions)
    return [project_activity_log(log) for log in logs.order_by("-created_at", "-pk")]


def get_active_sessions(user, current_session_key=None) -> dict:
    """Retrieve bounded projections of the user's active Django sessions.

    Returns ``{"sessions": [...], "decode": {...}}``.  An undecodable session
    row is never silently dropped and never attributed to the account owner
    (it cannot be safely decoded).  The undecodable count is kept server-side
    and only surfaces as a safe ``decode`` diagnostic state.  Anonymous callers
    receive ``not_authorized``.
    """
    if not is_active_nonlegacy_actor(user):
        return {"sessions": [], "decode": project_decode_state(0, authorized=False)}

    active_sessions = []
    user_id_str = str(user.pk)
    undecodable_count = 0

    # Query non-expired sessions
    sessions = Session.objects.filter(expire_date__gte=timezone.now()).order_by(
        "-expire_date", "-session_key"
    )
    for session in sessions:
        try:
            session_data = session.get_decoded()
        except Exception:
            # A malformed/stale session cannot be attributed safely; surface a
            # diagnostic state instead of silently omitting it.
            undecodable_count += 1
            continue
        if str(session_data.get("_auth_user_id")) == user_id_str:
            active_sessions.append(
                project_session_row(session, session_data, current_session_key)
            )

    return {
        "sessions": active_sessions,
        "decode": project_decode_state(undecodable_count),
    }


def get_user_trusted_devices(user):
    if not is_active_nonlegacy_actor(user):
        return TrustedDevice.objects.none()
    return TrustedDevice.objects.filter(
        user=user,
        status="active",
        trusted_until__gt=timezone.now(),
    ).only(
        "id",
        "label",
        "status",
        "trusted_until",
        "last_used_at",
        "revoked_at",
    ).order_by("-last_used_at", "-id")
