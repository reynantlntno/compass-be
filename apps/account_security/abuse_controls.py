"""Central, privacy-safe abuse policy and progressive challenge service."""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass, replace
from enum import StrEnum

from django.conf import settings
from django.core.cache import caches
from django.db import DatabaseError, IntegrityError, transaction
from django.core import signing
from django.utils import timezone

from apps.account_security.captcha import CaptchaVerificationResult, verify_captcha
from apps.account_security.models import CaptchaChallengeState, SecurityThrottleState
from apps.account_security.tokens import hash_identifier
from apps.account_security.defaults import ABUSE_POLICY_DEFAULTS
from apps.common.exceptions import ConditionalChallengeError, DependencyFailureError


class AbuseAction(StrEnum):
    LOGIN = "login"
    RECOVERY_REQUEST = "recovery_request"
    RECOVERY_RESEND = "recovery_resend"
    RECOVERY_VERIFY = "recovery_verify"
    CONTACT = "contact"
    ACTIVATION = "activation"
    TOKEN_VERIFY = "token_verify"
    ECOCOUNSELING_JOIN = "ecounseling_join"
    STUDENT_SEARCH = "student_search"
    API_ADMIN_WRITE = "api_admin_write"
    API_PROTECTED_DOWNLOAD = "api_protected_download"
    API_EXPORT = "api_export"


@dataclass(frozen=True)
class AbusePolicy:
    action: str
    window_seconds: int
    challenge_threshold: int
    hard_limit: int
    ip_challenge_threshold: int
    ip_hard_limit: int


@dataclass(frozen=True)
class AbuseDecision:
    allowed: bool
    challenge_required: bool = False
    retry_after: int | None = None
    reason_code: str = "ABUSE_ALLOWED"
    scope: str = ""

    @property
    def unavailable(self) -> bool:
        return self.reason_code == "ABUSE_CONTROL_UNAVAILABLE"


POLICIES: dict[str, AbusePolicy] = {
    action: AbusePolicy(action=action, **values)
    for action, values in ABUSE_POLICY_DEFAULTS.items()
}

CAPTCHA_ACTIONS = {
    AbuseAction.LOGIN: "login",
    AbuseAction.RECOVERY_REQUEST: "recovery",
    AbuseAction.RECOVERY_VERIFY: "recovery",
    AbuseAction.CONTACT: "contact",
    AbuseAction.ACTIVATION: "activation",
}

INLINE_CHALLENGE_ABUSE_ACTIONS = frozenset(
    str(action)
    for action in (
        AbuseAction.LOGIN,
        AbuseAction.RECOVERY_REQUEST,
        AbuseAction.RECOVERY_VERIFY,
        AbuseAction.ACTIVATION,
        AbuseAction.CONTACT,
    )
)

_SAFE_REASON_PREFIXES = (
    "ABUSE_",
    "CAPTCHA_",
    "RECOVERY_",
    "ACTIVATION_",
    "CONTACT_",
    "TOKEN_",
    "ECOUNSELING_",
)
_SAFE_REASON_VALUES = frozenset(
    {
        "INVALID_VERIFIER",
        "INVALID_TOKEN",
        "RATE_LIMITED",
        "REVOKED",
        "EXPIRED",
        "MAX_USES",
        "FAILED",
        "SUCCESS",
    }
)


def _safe_reason_code(reason_code: object) -> str:
    """Reduce internal reason labels to the metadata allowlist."""
    value = str(reason_code or "ABUSE_FAILURE").upper()
    if (
        len(value) <= 80
        and re.fullmatch(r"[A-Z0-9_]+", value)
        and (value in _SAFE_REASON_VALUES or value.startswith(_SAFE_REASON_PREFIXES))
    ):
        return value
    return "ABUSE_FAILURE"


def sign_challenge_return(action: str | AbuseAction, return_path: str, session: object) -> str:
    """Sign a session-bound, query-free return target for a CAPTCHA page."""
    path = str(return_path or "")
    if not path.startswith("/") or path.startswith("//") or "?" in path or "#" in path:
        raise ValueError("Challenge return path is invalid.")
    payload = {"action": str(action), "return_path": path}
    salt = f"compass.abuse.challenge:{_hash(session)}"
    return signing.TimestampSigner(salt=salt).sign(
        json.dumps(payload, separators=(",", ":"))
    )


def unsign_challenge_return(value: str, session: object, *, max_age: int = 300) -> dict | None:
    """Validate a signed challenge target without exposing its payload."""
    if not value or len(str(value)) > 2048:
        return None
    try:
        salt = f"compass.abuse.challenge:{_hash(session)}"
        payload = json.loads(signing.TimestampSigner(salt=salt).unsign(value, max_age=max_age))
    except (signing.BadSignature, signing.SignatureExpired, TypeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    action = str(payload.get("action") or "")
    path = str(payload.get("return_path") or "")
    if action not in {str(item) for item in AbuseAction}:
        return None
    if not path.startswith("/") or path.startswith("//") or "?" in path or "#" in path:
        return None
    return {"action": action, "return_path": path}


def get_policy(action: str | AbuseAction) -> AbusePolicy:
    key = str(action)
    if key not in POLICIES:
        raise ValueError("Unknown abuse action.")
    configured = None
    try:
        from apps.governance.selectors import resolve_effective_policy

        central_policy = resolve_effective_policy(
            "security.abuse_controls",
            target_type="account_security.AbuseAction",
            target_reference=key,
        )
        configured = central_policy.configuration_json if central_policy else None
    except DatabaseError:
        # Bootstrap/rollback safety: the code-owned catalog remains the
        # conservative fallback until the Governance table is available.
        configured = None
    if configured is None:
        configured = {
            "window_seconds": POLICIES[key].window_seconds,
            "challenge_threshold": POLICIES[key].challenge_threshold,
            "hard_limit": POLICIES[key].hard_limit,
            "ip_challenge_threshold": POLICIES[key].ip_challenge_threshold,
            "ip_hard_limit": POLICIES[key].ip_hard_limit,
        }
    if not isinstance(configured, dict):
        raise ValueError("Unknown abuse action.")
    try:
        policy = AbusePolicy(
            action=key,
            window_seconds=int(configured["window_seconds"]),
            challenge_threshold=int(configured["challenge_threshold"]),
            hard_limit=int(configured["hard_limit"]),
            ip_challenge_threshold=int(configured.get("ip_challenge_threshold", configured["challenge_threshold"])),
            ip_hard_limit=int(configured.get("ip_hard_limit", configured["hard_limit"])),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Invalid abuse policy.") from exc
    if min(
        policy.window_seconds,
        policy.challenge_threshold,
        policy.hard_limit,
        policy.ip_challenge_threshold,
        policy.ip_hard_limit,
    ) <= 0 or policy.challenge_threshold > policy.hard_limit or policy.ip_challenge_threshold > policy.ip_hard_limit:
        raise ValueError("Invalid abuse policy thresholds.")
    return policy


def _hash(value: object) -> str:
    if value is None or value == "":
        return ""
    return hash_identifier(str(value))


def _scope_rows(subject_hash: str, ip_hash: str, session_hash: str, token_hash: str) -> list[tuple[str, str, str, str, str]]:
    """Build scope tuples; only hashes leave this process."""
    rows = []
    if subject_hash:
        rows.append(("subject", subject_hash, "", "", ""))
    if ip_hash:
        rows.append(("ip", "", ip_hash, "", ""))
    if session_hash:
        rows.append(("session", "", "", session_hash, ""))
    if token_hash:
        rows.append(("token", "", "", "", token_hash))
    if subject_hash and ip_hash:
        rows.append(("combined", subject_hash, ip_hash, session_hash or "", token_hash or ""))
    return rows


def _scopes_for_action(
    action: str,
    subject_hash: str,
    ip_hash: str,
    session_hash: str,
    token_hash: str,
) -> list[tuple[str, str, str, str, str]]:
    """Return action-specific scope rows without broadening a shared tenant.

    E-counseling denials must be isolated to the hashed user/browser/session
    tuple.  A user joining another scheduled session, or another user joining
    the same session, must not inherit a hard lock from a different tuple.
    """

    if action == str(AbuseAction.ECOCOUNSELING_JOIN):
        # Keep e-counseling denials isolated to the full user/browser/e-session
        # tuple.  A request identified only by an IP remains an ``ip`` scope so
        # a campus NAT can escalate verification but can never hard-block.
        if any((subject_hash, session_hash, token_hash)):
            return [("combined", subject_hash, ip_hash, session_hash, token_hash)]
        if ip_hash and not any((subject_hash, session_hash, token_hash)):
            return [("ip", "", ip_hash, "", "")]
        return []
    return _scope_rows(subject_hash, ip_hash, session_hash, token_hash)


def _cache():
    alias = getattr(settings, "ABUSE_CONTROL_CACHE_ALIAS", getattr(settings, "ACCOUNT_SECURITY_CACHE_ALIAS", "default"))
    try:
        return caches[alias]
    except Exception:
        return None


def _cache_key(action: str, scope: tuple[str, str, str, str, str]) -> str:
    scope_name, subject_hash, ip_hash, session_hash, token_hash = scope
    values = ":".join((action, scope_name, subject_hash, ip_hash, session_hash, token_hash))
    return "compass:abuse:v1:" + hashlib.sha256(values.encode("utf-8")).hexdigest()


def _scope_key(scope: tuple[str, str, str, str, str]) -> str:
    return hashlib.sha256(":".join(scope).encode("utf-8")).hexdigest()


def _retry_after(until: datetime.datetime | None, now: datetime.datetime | None = None) -> int | None:
    if not until:
        return None
    now = now or timezone.now()
    return max(1, int((until - now).total_seconds()))


def _get_or_create_state(action: str, scope: tuple[str, str, str, str, str], now):
    scope_name, subject_hash, ip_hash, session_hash, token_hash = scope
    lookup = {
        "action_scope": action,
        "scope_name": scope_name,
        "scope_key": _scope_key(scope),
        "subject_hash": subject_hash,
        "ip_hash": ip_hash,
        "session_hash": session_hash,
        "token_hash": token_hash,
        "status": "active",
    }
    try:
        state, created = SecurityThrottleState.objects.get_or_create(
            **lookup,
            defaults={"window_start": now, "attempts": 0},
        )
        if not created:
            state = SecurityThrottleState.objects.select_for_update().get(pk=state.pk)
        return state
    except IntegrityError:
        state = SecurityThrottleState.objects.select_for_update().get(**lookup)
        return state


def _read_states(action: str, scopes: list[tuple[str, str, str, str, str]], now):
    for scope in scopes:
        state = SecurityThrottleState.objects.filter(
            action_scope=action,
            scope_name=scope[0],
            scope_key=_scope_key(scope),
            subject_hash=scope[1],
            ip_hash=scope[2],
            session_hash=scope[3],
            token_hash=scope[4],
            status="active",
        ).first()
        if state:
            yield scope, state


def evaluate(
    action: str | AbuseAction,
    *,
    subject: object = None,
    ip: object = None,
    session: object = None,
    token: object = None,
) -> AbuseDecision:
    try:
        policy = get_policy(action)
    except (TypeError, ValueError, KeyError):
        return AbuseDecision(False, False, 60, "ABUSE_CONTROL_UNAVAILABLE", "")
    key = str(action)
    scopes = _scopes_for_action(key, _hash(subject), _hash(ip), _hash(session), _hash(token))
    now = timezone.now()
    cache = _cache()
    saw_cache_error = False
    for scope in scopes:
        try:
            marker = cache.get(_cache_key(key, scope)) if cache else None
        except Exception:
            marker = None
            saw_cache_error = True
        if isinstance(marker, dict) and marker.get("locked_until"):
            until = marker["locked_until"]
            if until > now and scope[0] != "ip":
                return AbuseDecision(False, True, _retry_after(until, now), "ABUSE_RATE_LIMITED", scope[0])
    try:
        for scope, state in _read_states(key, scopes, now):
            if state.window_start + datetime.timedelta(seconds=policy.window_seconds) <= now:
                continue
            locked = state.locked_until and state.locked_until > now
            threshold = policy.ip_challenge_threshold if scope[0] == "ip" else policy.challenge_threshold
            hard_limit = policy.ip_hard_limit if scope[0] == "ip" else policy.hard_limit
            if locked or state.attempts >= hard_limit:
                if scope[0] != "ip":
                    return AbuseDecision(False, True, _retry_after(state.locked_until, now), "ABUSE_RATE_LIMITED", scope[0])
            if state.attempts >= threshold:
                return AbuseDecision(True, True, _retry_after(state.captcha_required_until, now), "ABUSE_CHALLENGE_REQUIRED", scope[0])
    except (DatabaseError, OSError, TypeError, ValueError):
        return AbuseDecision(False, False, 60, "ABUSE_CONTROL_UNAVAILABLE", "")
    if saw_cache_error:
        # The DB evaluation above remains authoritative.  Cache loss never
        # grants an action and is intentionally not surfaced to the client.
        return AbuseDecision(True, False, None, "ABUSE_ALLOWED_DB_FALLBACK", "")
    return AbuseDecision(True)


@transaction.atomic
def record_failure(
    action: str | AbuseAction,
    *,
    subject: object = None,
    ip: object = None,
    session: object = None,
    token: object = None,
    reason_code: str = "ABUSE_FAILURE",
    _outcome: str = "failure",
) -> AbuseDecision:
    try:
        policy = get_policy(action)
    except ValueError:
        return AbuseDecision(False, False, 60, "ABUSE_CONTROL_UNAVAILABLE", "")
    key = str(action)
    scopes = _scopes_for_action(key, _hash(subject), _hash(ip), _hash(session), _hash(token))
    now = timezone.now()
    highest = AbuseDecision(True)
    cache = _cache()
    for scope in scopes:
        try:
            state = _get_or_create_state(key, scope, now)
        except (DatabaseError, OSError, TypeError, ValueError):
            return AbuseDecision(False, False, 60, "ABUSE_CONTROL_UNAVAILABLE", "")
        if state.window_start + datetime.timedelta(seconds=policy.window_seconds) <= now:
            state.window_start = now
            state.attempts = 0
            state.locked_until = None
            state.captcha_required_until = None
        state.attempts += 1
        threshold = policy.ip_challenge_threshold if scope[0] == "ip" else policy.challenge_threshold
        hard_limit = policy.ip_hard_limit if scope[0] == "ip" else policy.hard_limit
        if state.attempts >= hard_limit and scope[0] != "ip":
            state.locked_until = now + datetime.timedelta(seconds=policy.window_seconds)
        elif state.attempts >= threshold:
            state.captcha_required_until = now + datetime.timedelta(seconds=policy.window_seconds)
        state.metadata_json = {
            "outcome": _outcome if _outcome in {"failure", "volume"} else "failure",
            "reason_code": _safe_reason_code(reason_code),
            "scope": scope[0],
        }
        try:
            with transaction.atomic():
                state.save(update_fields=["window_start", "attempts", "locked_until", "captcha_required_until", "metadata_json", "updated_at"])
        except (DatabaseError, OSError, TypeError, ValueError):
            return AbuseDecision(False, False, 60, "ABUSE_CONTROL_UNAVAILABLE", "")
        if state.locked_until and state.locked_until > now and scope[0] != "ip":
            highest = AbuseDecision(False, True, _retry_after(state.locked_until, now), "ABUSE_RATE_LIMITED", scope[0])
        elif state.attempts >= threshold:
            highest = AbuseDecision(True, True, _retry_after(state.captcha_required_until, now), "ABUSE_CHALLENGE_REQUIRED", scope[0])
        if cache:
            try:
                cache.set(
                    _cache_key(key, scope),
                    {"locked_until": state.locked_until, "captcha_required_until": state.captcha_required_until},
                    policy.window_seconds,
                )
            except Exception:
                pass
    return highest


@transaction.atomic
def record_volume(
    action: str | AbuseAction,
    *,
    subject: object = None,
    ip: object = None,
    session: object = None,
    token: object = None,
    reason_code: str = "ABUSE_VOLUME",
) -> AbuseDecision:
    """Count a submitted/requested action without treating it as a failure."""
    return record_failure(
        action,
        subject=subject,
        ip=ip,
        session=session,
        token=token,
        reason_code=reason_code,
        _outcome="volume",
    )


@transaction.atomic
def record_success(
    action: str | AbuseAction,
    *,
    subject: object = None,
    ip: object = None,
    session: object = None,
    token: object = None,
) -> AbuseDecision:
    """Clear non-IP failure state after an authorized success."""
    try:
        key = str(action)
        get_policy(key)
        scopes = _scopes_for_action(key, _hash(subject), _hash(ip), _hash(session), _hash(token))
        cache = _cache()
        for scope in scopes:
            if scope[0] == "ip":
                continue
            SecurityThrottleState.objects.filter(
                action_scope=key,
                scope_name=scope[0],
                scope_key=_scope_key(scope),
                subject_hash=scope[1],
                ip_hash=scope[2],
                session_hash=scope[3],
                token_hash=scope[4],
                status="active",
            ).update(attempts=0, locked_until=None, captcha_required_until=None, metadata_json={"outcome": "success"})
            if cache:
                try:
                    cache.delete(_cache_key(key, scope))
                except Exception:
                    pass
    except (DatabaseError, OSError, TypeError, ValueError):
        return AbuseDecision(False, False, 60, "ABUSE_CONTROL_UNAVAILABLE", "")
    return AbuseDecision(True)


def verify_challenge(
    action: str | AbuseAction,
    response_token: str,
    *,
    ip: object = None,
    session: object = None,
    subject: object = None,
) -> CaptchaVerificationResult:
    result = verify_captcha(
        response_token,
        action=CAPTCHA_ACTIONS.get(str(action), str(action)),
        ip_address=str(ip or "") or None,
        idempotency_key=secrets.token_hex(16),
    )
    subject_hash, ip_hash, session_hash = _hash(subject), _hash(ip), _hash(session)
    if result.valid:
        # The grant is returned only in memory so a caller can bind a bounded
        # retry to the same action/session.  Its HMAC is the only stored form.
        try:
            result = replace(result, grant=issue_captcha_grant(
                action,
                subject=subject,
                ip=ip,
                session=session,
            ))
        except (DatabaseError, OSError, TypeError, ValueError):
            return CaptchaVerificationResult("unavailable", "CAPTCHA_PROVIDER_UNAVAILABLE")
    else:
        try:
            CaptchaChallengeState.objects.create(
                action_scope=str(action),
                subject_hash=subject_hash,
                ip_hash=ip_hash,
                session_hash=session_hash,
                captcha_required_until=timezone.now() + datetime.timedelta(minutes=5),
                last_provider=str(getattr(settings, "ACCOUNT_SECURITY_CAPTCHA_PROVIDER", "turnstile"))[:50],
                status="failed",
                failure_count=1,
                metadata_json={"outcome": "failed", "reason_code": result.reason_code},
            )
        except (DatabaseError, OSError, TypeError, ValueError):
            return CaptchaVerificationResult("unavailable", "CAPTCHA_PROVIDER_UNAVAILABLE")
    return result


def issue_captcha_grant(
    action: str | AbuseAction,
    *,
    subject: object = None,
    ip: object = None,
    session: object = None,
    ttl_seconds: int = 300,
) -> str:
    """Issue an opaque, single-use retry grant after a verified challenge.

    Only an HMAC of the opaque value is retained in the existing challenge
    evidence table.  The grant is scoped to action, subject, IP, and browser
    session and expires within the Turnstile five-minute credential window.
    It authorizes a bounded form retry only; workflow services still perform
    their normal database authorization and token checks.
    """

    ttl = max(1, min(int(ttl_seconds), 300))
    raw_grant = secrets.token_urlsafe(32)
    CaptchaChallengeState.objects.create(
        action_scope=str(action),
        subject_hash=_hash(subject),
        ip_hash=_hash(ip),
        session_hash=_hash(session),
        captcha_required_until=timezone.now() + datetime.timedelta(seconds=ttl),
        last_provider=str(getattr(settings, "ACCOUNT_SECURITY_CAPTCHA_PROVIDER", "turnstile"))[:50],
        status="passed",
        metadata_json={"outcome": "grant_issued", "grant_hash": hash_identifier(raw_grant)},
    )
    return raw_grant


@transaction.atomic
def consume_captcha_grant(
    action: str | AbuseAction,
    grant: str,
    *,
    subject: object = None,
    ip: object = None,
    session: object = None,
) -> bool:
    """Consume one retry grant atomically and fail closed on mismatch/expiry."""

    if not grant or len(str(grant)) > 256:
        return False
    grant_hash = hash_identifier(str(grant))
    now = timezone.now()
    rows = CaptchaChallengeState.objects.select_for_update().filter(
        action_scope=str(action),
        subject_hash=_hash(subject),
        ip_hash=_hash(ip),
        session_hash=_hash(session),
        status="passed",
        captcha_required_until__gt=now,
    ).order_by("-created_at")
    for row in rows:
        metadata = row.metadata_json if isinstance(row.metadata_json, dict) else {}
        if not hmac.compare_digest(str(metadata.get("grant_hash", "")), grant_hash):
            continue
        row.status = "consumed"
        row.metadata_json = {"outcome": "grant_consumed"}
        row.save(update_fields=["status", "metadata_json", "updated_at"])
        return True
    return False


def enforce_inline_challenge(
    action: str | AbuseAction,
    response_token: str | None,
    *,
    ip: object = None,
    session: object = None,
    subject: object = None,
    retry_after: int | None = None,
) -> CaptchaVerificationResult:
    """Verify and consume one endpoint-scoped challenge in the same request."""

    action_key = str(action)
    if action_key not in INLINE_CHALLENGE_ABUSE_ACTIONS:
        raise ValueError("Inline CAPTCHA is not enabled for this action.")

    result = verify_challenge(
        action,
        str(response_token or ""),
        ip=ip,
        session=session,
        subject=subject,
    )
    if result.unavailable or result.configuration_error:
        raise DependencyFailureError(retry_after=60)
    if not result.valid or not result.grant:
        raise ConditionalChallengeError(
            CAPTCHA_ACTIONS.get(action) or CAPTCHA_ACTIONS[action_key],
            retry_after=retry_after or 60,
        )
    if not consume_captcha_grant(
        action,
        result.grant,
        subject=subject,
        ip=ip,
        session=session,
    ):
        raise ConditionalChallengeError(
            CAPTCHA_ACTIONS.get(action) or CAPTCHA_ACTIONS[action_key],
            retry_after=retry_after or 60,
        )
    return result


@transaction.atomic
def consume_captcha_grant_for_scope(
    action: str | AbuseAction,
    *,
    subject: object = None,
    ip: object = None,
    session: object = None,
) -> bool:
    """Consume the newest one-time grant for a bound retry request.

    The raw grant never needs to cross the browser boundary.  This operation
    is used by signed-return challenge pages whose next request is the bounded
    retry itself.
    """
    now = timezone.now()
    rows = CaptchaChallengeState.objects.select_for_update().filter(
        action_scope=str(action),
        subject_hash=_hash(subject),
        ip_hash=_hash(ip),
        session_hash=_hash(session),
        status="passed",
        captcha_required_until__gt=now,
    ).order_by("-created_at")
    row = rows.first()
    if row is None:
        return False
    metadata = row.metadata_json if isinstance(row.metadata_json, dict) else {}
    if not metadata.get("grant_hash"):
        return False
    row.status = "consumed"
    row.metadata_json = {"outcome": "grant_consumed"}
    row.save(update_fields=["status", "metadata_json", "updated_at"])
    return True


def verify_and_issue_challenge(
    action: str | AbuseAction,
    response_token: str,
    *,
    ip: object = None,
    session: object = None,
    subject: object = None,
) -> tuple[CaptchaVerificationResult, str | None]:
    """Verify a provider token and return a bounded retry grant when valid."""

    result = verify_challenge(
        action,
        response_token,
        ip=ip,
        session=session,
        subject=subject,
    )
    return result, result.grant if result.valid else None
