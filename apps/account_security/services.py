import datetime
import logging
import secrets
import uuid
from urllib.parse import urlencode, urljoin
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.validators import validate_email
from django.db import transaction
from django.utils import timezone

from apps.account_security.models import (
    AccountRecoveryRequest,
    ApiSession,
    ApiSessionStatusChoices,
    TwoStepChallenge,
    TrustedDevice,
)
from apps.account_security.email_evidence import has_verified_current_email, record_verified_email_evidence
from apps.account_security.tokens import (
    generate_random_token,
    generate_otp,
    hash_token,
    hash_identifier,
    compare_tokens,
    get_safe_user_agent_summary,
    get_session_action_token,
    build_recovery_token,
    parse_recovery_token,
    RECOVERY_TOKEN_VERSION,
)
from apps.account_security.network import classify_network_class
from apps.account_security.adapters import send_security_email
from apps.account_security.policies import (
    is_2fa_required_for_user,
    get_trusted_device_duration_days,
    can_user_recover_online,
    can_start_staff_assisted_recovery,
)
from apps.account_security.password_policy import validate_new_password
from apps.account_security.audit import log_security_event
from apps.account_security.assurance import ASSURANCE_CONTEXT, ASSURANCE_POLICY_VERSION
from apps.account_security.assurance import validate_request_assurance
from apps.account_security.abuse_controls import (
    AbuseAction,
    record_failure as record_abuse_failure,
    record_success as record_abuse_success,
)
from apps.accounts.models import RoleChoices
from apps.common.django_adapters import ModelValidationError
from apps.common.exceptions import AssuranceRequiredError
from apps.governance.runtime_config import resolve_runtime_setting

logger = logging.getLogger(__name__)
User = get_user_model()


def _security_setting(setting_key: str):
    return resolve_runtime_setting(
        "security.account_security_controls",
        setting_key,
    )


def build_recovery_reset_url(raw_token: str) -> str:
    query = urlencode({"token": raw_token})
    # Password-reset screens belong to the separate client application. The
    # backend only mints the signed token and places it in the client route.
    path = f"/account/recovery/reset/?{query}"
    base_url = getattr(settings, "COMPASS_CLIENT_BASE_URL", "").strip()
    if base_url:
        return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))

    raise ValueError("Recovery URL generation requires a trusted request or configured base URL.")


GENERIC_RECOVERY_MESSAGE = "If an account exists for the information provided, we'll send recovery instructions."


def _recovery_cooldown_active(identifier_hash: str, now=None):
    now = now or timezone.now()
    cooldown = int(_security_setting("ACCOUNT_SECURITY_RECOVERY_RESEND_COOLDOWN_SECONDS"))
    return AccountRecoveryRequest.objects.select_for_update().filter(
        identifier_hash=identifier_hash,
        status="pending",
        created_at__gte=now - datetime.timedelta(seconds=cooldown),
    ).order_by("-created_at").first()


def _queue_recovery_request(recovery_request, *, actor=None, ip=None, user_agent=None):
    """Queue a safe event; the worker reconstructs the signed token at send time."""
    from apps.notifications.dispatch import enqueue_notification_event

    enqueue_notification_event(
        "account_security.recovery_requested",
        {
            "recovery_request_id": str(recovery_request.id),
        },
        event_key=f"account_security:recovery_requested:{recovery_request.id}:v1",
    )
    log_security_event(
        action_type="recovery_requested",
        target_model="account_security.AccountRecoveryRequest",
        target_object_id=str(recovery_request.id),
        severity="INFO",
        actor_user=actor or recovery_request.user,
        ip_address=ip,
        user_agent=user_agent,
        metadata={
            "recovery_request_id": str(recovery_request.id),
            "status": "queued",
            "token_version": RECOVERY_TOKEN_VERSION,
        },
    )


def request_recovery(email: str, ip: str = None, user_agent: str = None) -> tuple:
    """Initiate a password recovery request for the given email address.

    Returns a generic message indicating recovery instructions are sent if an account exists.
    """
    cleaned_email = (email or "").strip().lower()
    identifier_hash = hash_identifier(cleaned_email)
    ip_hash = hash_identifier(ip) if ip else ""
    ua_hash = hash_identifier(user_agent) if user_agent else ""

    now = timezone.now()
    try:
        with transaction.atomic():
            user = User.objects.select_for_update().get(email__iexact=cleaned_email, is_active=True)
            # Repeated submissions during cooldown reuse the existing action.
            if _recovery_cooldown_active(identifier_hash, now):
                return True, GENERIC_RECOVERY_MESSAGE
            AccountRecoveryRequest.objects.filter(
                identifier_hash=identifier_hash, status="pending"
            ).update(status="revoked", revoked_at=now)
            if not can_user_recover_online(user):
                raise PermissionError("recovery_policy_denied")
            recovery_request = AccountRecoveryRequest(
                user=user,
                identifier_hash=identifier_hash,
                delivery_email_hash=identifier_hash,
                token_version=RECOVERY_TOKEN_VERSION,
                request_source="self_service",
                status="pending",
                request_ip_hash=ip_hash,
                request_user_agent_hash=ua_hash,
                token_issued_at=now,
                expires_at=now + datetime.timedelta(
                    seconds=_security_setting("ACCOUNT_SECURITY_RECOVERY_TOKEN_EXPIRY_SECONDS")
                ),
            )
            # Allocate the UUID before signing it.  Only the HMAC enters storage.
            recovery_request.token_hash = hash_token(build_recovery_token(recovery_request.id))
            recovery_request.save()
            _queue_recovery_request(recovery_request, ip=ip, user_agent=user_agent)
    except User.DoesNotExist:
        log_security_event(
            action_type="recovery_request_no_user",
            target_model="accounts.User",
            target_object_id="",
            severity="WARNING",
            ip_address=ip,
            user_agent=user_agent,
            metadata={"email_delivery_id": "none", "reason": "user_not_found"}
        )
        return True, GENERIC_RECOVERY_MESSAGE
    except PermissionError:
        log_security_event(
            action_type="recovery_request_policy_denied",
            target_model="accounts.User",
            target_object_id=str(user.pk),
            severity="WARNING",
            actor_user=user,
            ip_address=ip,
            user_agent=user_agent,
            metadata={"reason": "recovery_policy_denied"}
        )
        return True, GENERIC_RECOVERY_MESSAGE
    except Exception:
        logger.error("Recovery request could not be queued.")
        return True, GENERIC_RECOVERY_MESSAGE

    return True, GENERIC_RECOVERY_MESSAGE


@transaction.atomic
def record_recovery_verification_failure(
    token: str,
    *,
    ip: str = None,
    session: str = None,
    reason_code: str = "RECOVERY_TOKEN_INVALID",
) -> None:
    """Record a failed bearer-token attempt and lock its request when known.

    A signed identifier plus a matching stored HMAC is sufficient to identify
    the existing request without ever persisting the raw bearer value.  Any
    malformed or mismatched token is recorded only in the shared hashed scope.
    """
    request_id = parse_recovery_token(token) if token else None
    if request_id is not None:
        request = AccountRecoveryRequest.objects.select_for_update().filter(
            id=request_id,
        ).first()
        if request is not None and compare_tokens(request.token_hash, hash_token(token)):
            request.failed_attempts += 1
            max_attempts = int(_security_setting("ACCOUNT_SECURITY_RECOVERY_MAX_ATTEMPTS"))
            if request.failed_attempts >= max_attempts and request.status == "pending":
                request.status = "locked"
                request.locked_at = timezone.now()
            request.save(update_fields=["failed_attempts", "status", "locked_at", "updated_at"])
            record_abuse_failure(
                AbuseAction.RECOVERY_VERIFY,
                subject=request.identifier_hash,
                ip=ip,
                session=session,
                token=token,
                reason_code=reason_code,
            )
            return
    record_abuse_failure(
        AbuseAction.RECOVERY_VERIFY,
        ip=ip,
        session=session,
        token=token,
        reason_code=reason_code,
    )


from apps.account_security.recovery_assistance import STAFF_RECOVERY_REASON_CODES
STAFF_RECOVERY_REASONS = STAFF_RECOVERY_REASON_CODES


def _log_staff_recovery_outcome(
    actor,
    target,
    *,
    reason_category: str,
    outcome: str,
    ip: str = None,
    user_agent: str = None,
    recovery_request_id: str = "",
):
    """Record a bounded assisted-recovery outcome without entered PII."""
    safe_reason = reason_category if reason_category in STAFF_RECOVERY_REASONS else "invalid"
    log_security_event(
        action_type=(
            "staff_assisted_recovery_requested"
            if outcome == "queued"
            else "staff_assisted_recovery_denied"
        ),
        target_model="accounts.User",
        target_object_id=str(getattr(target, "pk", "") or ""),
        severity="INFO" if outcome == "queued" else "WARNING",
        actor_user=actor,
        ip_address=ip,
        user_agent=user_agent,
        metadata={
            "target_role": str(getattr(target, "role", "")),
            "reason_category": safe_reason or "unspecified",
            "outcome": outcome,
            "recovery_request_id": str(recovery_request_id or ""),
        },
    )


@transaction.atomic
def request_staff_assisted_recovery(
    actor,
    target,
    *,
    reason_category: str,
    email_ownership_attested: bool = False,
    ip: str = None,
    user_agent: str = None,
    assurance_token=None,
    expected_security_stamp=None,
):
    """Create a recovery request only after an assured IT Admin review."""
    assured, _ = validate_request_assurance(
        actor,
        token=assurance_token,
    )
    if not assured:
        raise AssuranceRequiredError()
    if target is not None:
        try:
            target = User.objects.select_for_update().get(pk=target.pk)
        except User.DoesNotExist:
            target = None
    if target is not None and target.role == RoleChoices.COUNSELOR:
        # Lock the designation row together with the account before policy
        # evaluation. A concurrent Head Guidance assignment must not change
        # the meaning of this IT Admin-authorized recovery operation midway.
        from apps.profiles.models import CounselorProfile

        CounselorProfile.objects.select_for_update().filter(user_id=target.pk).first()
    if expected_security_stamp is not None and target is not None and str(target.auth_security_stamp) != str(expected_security_stamp):
        _log_staff_recovery_outcome(
            actor, target, reason_category=reason_category,
            outcome="stale_confirmation", ip=ip, user_agent=user_agent,
        )
        return False, "stale_confirmation"
    if not can_start_staff_assisted_recovery(actor, target):
        _log_staff_recovery_outcome(
            actor, target, reason_category=reason_category,
            outcome="assurance_or_target_denied", ip=ip, user_agent=user_agent,
        )
        return False, "assurance_or_target_denied"
    if reason_category not in STAFF_RECOVERY_REASONS:
        _log_staff_recovery_outcome(
            actor, target, reason_category=reason_category,
            outcome="reason_required", ip=ip, user_agent=user_agent,
        )
        return False, "reason_required"
    if not _normalized_usable_email(target):
        _log_staff_recovery_outcome(
            actor, target, reason_category=reason_category,
            outcome="usable_email_unavailable", ip=ip, user_agent=user_agent,
        )
        return False, "usable_email_unavailable"
    if not has_verified_current_email(target):
        if not email_ownership_attested:
            _log_staff_recovery_outcome(
                actor, target, reason_category=reason_category,
                outcome="email_ownership_attestation_required", ip=ip,
                user_agent=user_agent,
            )
            return False, "email_ownership_attestation_required"
        record_verified_email_evidence(
            target,
            verification_method="staff_out_of_band",
            verified_by=actor,
            reason_category=reason_category,
            ip_address=ip,
            user_agent=user_agent,
        )
    identifier_hash = hash_identifier((target.email or "").strip().lower())
    now = timezone.now()
    if _recovery_cooldown_active(identifier_hash, now):
        _log_staff_recovery_outcome(
            actor, target, reason_category=reason_category,
            outcome="cooldown", ip=ip, user_agent=user_agent,
        )
        return True, "cooldown"
    AccountRecoveryRequest.objects.filter(
        identifier_hash=identifier_hash, status="pending"
    ).update(status="revoked", revoked_at=now)
    recovery_request = AccountRecoveryRequest(
        id=uuid.uuid4(),
        user=target,
        identifier_hash=identifier_hash,
        delivery_email_hash=identifier_hash,
        token_version=RECOVERY_TOKEN_VERSION,
        request_source="staff_assisted",
        staff_actor=actor,
        status="pending",
        request_ip_hash=hash_identifier(ip) if ip else "",
        request_user_agent_hash=hash_identifier(user_agent) if user_agent else "",
        token_issued_at=now,
        expires_at=now + datetime.timedelta(
        seconds=_security_setting("ACCOUNT_SECURITY_RECOVERY_TOKEN_EXPIRY_SECONDS")
        ),
    )
    recovery_request.token_hash = hash_token(build_recovery_token(recovery_request.id))
    recovery_request.save()
    _queue_recovery_request(recovery_request, actor=actor, ip=ip, user_agent=user_agent)
    _log_staff_recovery_outcome(
        actor,
        target,
        reason_category=reason_category,
        outcome="queued",
        ip=ip,
        user_agent=user_agent,
        recovery_request_id=recovery_request.id,
    )
    return True, recovery_request


def apply_password_reset_security_state(
    user,
    new_password: str,
    *,
    ip: str = None,
    user_agent: str = None,
    trusted_device_reason: str = "password_reset",
):
    """Apply one password and invalidate every prior authentication state.

    Callers own the surrounding transaction and any purpose-specific audit or
    recovery-request lifecycle.  Keeping the mutation here ensures password
    change, token reset, and operator recovery share the same invalidation
    behavior without moving secrets across boundaries.
    """
    user.set_password(new_password)
    user.auth_security_stamp = uuid.uuid4()
    # User.save() owns the API-token revocation hook for security-stamp
    # changes; this keeps all password mutation paths on the same boundary.
    user.save(update_fields=["password", "auth_security_stamp", "updated_at"])
    terminate_all_sessions_for_user(user, ip=ip, user_agent=user_agent)
    revoke_all_trusted_devices_for_user(
        user,
        reason=trusted_device_reason,
        ip=ip,
        audit_when_empty=True,
    )
    return user


@transaction.atomic
def reset_password_with_token(
    token: str,
    new_password: str,
    ip: str = None,
    user_agent: str = None,
    session: str = None,
) -> bool:
    """Complete password recovery using a recovery token."""
    if not token:
        record_abuse_failure(AbuseAction.RECOVERY_VERIFY, ip=ip, session=session, reason_code="RECOVERY_TOKEN_MISSING")
        return False

    request_id = parse_recovery_token(token)
    if request_id is None:
        record_abuse_failure(AbuseAction.RECOVERY_VERIFY, ip=ip, session=session, token=token, reason_code="RECOVERY_TOKEN_INVALID")
        log_security_event(
            action_type="recovery_verify_failed",
            target_model="account_security.AccountRecoveryRequest",
            target_object_id="",
            severity="WARNING",
            ip_address=ip,
            user_agent=user_agent,
            metadata={"reason": "invalid_or_expired_token"}
        )
        return False

    token_hash = hash_token(token)
    try:
        request = AccountRecoveryRequest.objects.select_for_update().get(
            id=request_id,
        )
    except AccountRecoveryRequest.DoesNotExist:
        record_abuse_failure(AbuseAction.RECOVERY_VERIFY, ip=ip, session=session, token=token, reason_code="RECOVERY_TOKEN_UNKNOWN")
        return False
    if (
        request.token_version != RECOVERY_TOKEN_VERSION
        or request.status != "pending"
        or request.expires_at <= timezone.now()
        or not compare_tokens(request.token_hash, token_hash)
    ):
        request.failed_attempts += 1
        max_attempts = _security_setting("ACCOUNT_SECURITY_RECOVERY_MAX_ATTEMPTS")
        if request.failed_attempts >= max_attempts:
            request.status = "locked"
            request.locked_at = timezone.now()
        request.save(update_fields=["failed_attempts", "status", "locked_at", "updated_at"])
        record_abuse_failure(
            AbuseAction.RECOVERY_VERIFY,
            subject=request.identifier_hash,
            ip=ip,
            session=session,
            token=token,
            reason_code="RECOVERY_TOKEN_INVALID",
        )
        log_security_event(
            action_type="recovery_verify_failed",
            target_model="account_security.AccountRecoveryRequest",
            target_object_id=str(request.id),
            severity="WARNING",
            ip_address=ip,
            user_agent=user_agent,
            metadata={"reason": "invalid_or_expired_token", "token_version": RECOVERY_TOKEN_VERSION},
        )
        return False

    user = User.objects.get(pk=request.user_id) if request.user_id else None
    if not user or not user.is_active:
        record_abuse_failure(AbuseAction.RECOVERY_VERIFY, subject=request.identifier_hash, ip=ip, session=session, token=token, reason_code="RECOVERY_ACCOUNT_INVALID")
        return False
    if hash_identifier((user.email or "").strip().lower()) != request.delivery_email_hash:
        request.status = "revoked"
        request.revoked_at = timezone.now()
        request.save(update_fields=["status", "revoked_at", "updated_at"])
        record_abuse_failure(AbuseAction.RECOVERY_VERIFY, subject=request.identifier_hash, ip=ip, session=session, token=token, reason_code="RECOVERY_EMAIL_MISMATCH")
        return False

    # Check max failed attempts on token
    max_attempts = _security_setting("ACCOUNT_SECURITY_RECOVERY_MAX_ATTEMPTS")
    if request.failed_attempts >= max_attempts:
        request.status = "locked"
        request.locked_at = timezone.now()
        request.save()
        log_security_event(
            action_type="recovery_locked",
            target_model="account_security.AccountRecoveryRequest",
            target_object_id=str(request.id),
            severity="WARNING",
            actor_user=user,
            ip_address=ip,
            user_agent=user_agent,
            metadata={"recovery_request_id": str(request.id), "reason": "max_attempts_exceeded"}
        )
        record_abuse_failure(AbuseAction.RECOVERY_VERIFY, subject=request.identifier_hash, ip=ip, session=session, token=token, reason_code="RECOVERY_REQUEST_LOCKED")
        return False

    # Resolve the account before the final policy check so recovery applies
    # user-attribute similarity validation and rejects password reuse.  This
    # runs before any password or security-state mutation.
    validate_new_password(new_password, user=user, reject_reuse=True)

    # Update password and invalidate every prior authentication state.
    apply_password_reset_security_state(
        user,
        new_password,
        ip=ip,
        user_agent=user_agent,
        trusted_device_reason="password_reset",
    )

    # Revoke recovery token
    request.status = "used"
    request.used_at = timezone.now()
    request.save()

    log_security_event(
        action_type="recovery_verify_success",
        target_model="account_security.AccountRecoveryRequest",
        target_object_id=str(request.id),
        severity="INFO",
        actor_user=user,
        ip_address=ip,
        user_agent=user_agent,
        metadata={"recovery_request_id": str(request.id)}
    )

    from apps.account_security.notification_services import enqueue_security_event
    enqueue_security_event("password_changed", user, source_id=request.id)

    record_abuse_success(
        AbuseAction.RECOVERY_VERIFY,
        subject=request.identifier_hash,
        ip=ip,
        session=session,
        token=token,
    )

    return True


def _normalized_usable_email(user):
    email = str(getattr(user, "email", "") or "").strip().lower()
    try:
        validate_email(email)
    except ModelValidationError:
        return ""
    return email


def create_twostep_challenge(
    user,
    purpose: str,
    ip: str = None,
    user_agent: str = None,
    pending_nonce: str = None,
) -> tuple:
    """Create a new 2FA email challenge (OTP)."""
    if purpose == "login" and not pending_nonce:
        return None, None
    delivery_email = _normalized_usable_email(user)
    if not delivery_email:
        log_security_event(
            action_type="twostep_setup_unavailable",
            target_model="accounts.User",
            target_object_id=str(user.pk),
            severity="WARNING",
            actor_user=user,
            ip_address=ip,
            user_agent=user_agent,
            metadata={"reason": "usable_email_unavailable"},
        )
        return None, None

    if purpose == "login":
        TwoStepChallenge.objects.filter(
            user=user, purpose="login", status="pending"
        ).update(status="revoked")

    raw_otp = generate_otp()
    otp_hash = hash_token(raw_otp)
    expiry = timezone.now() + datetime.timedelta(
        seconds=_security_setting("ACCOUNT_SECURITY_OTP_EXPIRY_SECONDS")
    )

    challenge = TwoStepChallenge.objects.create(
        user=user,
        purpose=purpose,
        otp_hash=otp_hash,
        status="pending",
        delivery_channel="email",
        delivery_email_hash=hash_identifier(delivery_email),
        request_ip_hash=hash_identifier(ip) if ip else "",
        request_user_agent_hash=hash_identifier(user_agent) if user_agent else "",
        expires_at=expiry,
        last_sent_at=timezone.now(),
        security_stamp=user.auth_security_stamp,
        assurance_policy_version=(
            ASSURANCE_POLICY_VERSION
            if purpose in {"login", "sensitive_action"}
            else ""
        ),
        assurance_context=(
            ASSURANCE_CONTEXT
            if purpose in {"login", "sensitive_action"}
            else ""
        ),
        metadata_json={
            "pending_nonce_hash": hash_token(pending_nonce) if pending_nonce else ""
        },
    )

    try:
        msg_id = send_security_email(
            recipient_email=delivery_email,
            subject="COMPASS Verification Code",
            template_key="two_step_code",
            context={"purpose": purpose},
            runtime_context={
                "otp": raw_otp,
                "expires_text": challenge.expires_at.strftime("%Y-%m-%d %H:%M UTC"),
            },
        )
        log_security_event(
            action_type="twostep_challenge_created",
            target_model="account_security.TwoStepChallenge",
            target_object_id=str(challenge.id),
            severity="INFO",
            actor_user=user,
            ip_address=ip,
            user_agent=user_agent,
            metadata={
                "challenge_id": str(challenge.id),
                "purpose": purpose,
                "email_delivery_id": msg_id
            }
        )
    except Exception:
        logger.error("Two-step verification email delivery failed.")
        challenge.status = "revoked"
        challenge.save()
        log_security_event(
            action_type="twostep_challenge_email_failed",
            target_model="account_security.TwoStepChallenge",
            target_object_id=str(challenge.id),
            severity="ERROR",
            actor_user=user,
            ip_address=ip,
            user_agent=user_agent,
            metadata={"challenge_id": str(challenge.id), "reason": "delivery_failed"}
        )
        return None, None

    return challenge, None


def verify_otp(
    challenge_id: str,
    raw_otp: str,
    *,
    expected_user_id,
    purpose: str,
    pending_nonce: str = None,
    ip: str = None,
    user_agent: str = None,
) -> bool:
    """Verify the OTP for a two-step challenge."""
    if not challenge_id or not raw_otp:
        return False

    with transaction.atomic():
        try:
            challenge = TwoStepChallenge.objects.select_for_update().select_related("user").get(
                id=challenge_id
            )
        except (TwoStepChallenge.DoesNotExist, ValueError):
            log_security_event(
                action_type="twostep_challenge_failed",
                target_model="account_security.TwoStepChallenge",
                target_object_id=str(challenge_id) if challenge_id else "",
                severity="WARNING",
                ip_address=ip,
                user_agent=user_agent,
                metadata={"reason": "invalid_challenge"},
            )
            return False
        current_user = User.objects.select_for_update().get(pk=challenge.user_id)

        now = timezone.now()
        if challenge.status != "pending":
            reason = "replayed_challenge" if challenge.status == "verified" else "inactive_challenge"
            log_security_event(
                action_type="twostep_challenge_failed",
                target_model="account_security.TwoStepChallenge",
                target_object_id=str(challenge.id),
                severity="WARNING",
                actor_user=challenge.user,
                ip_address=ip,
                user_agent=user_agent,
                metadata={"challenge_id": str(challenge.id), "reason": reason},
            )
            return False
        if challenge.expires_at <= now:
            challenge.status = "expired"
            challenge.save(update_fields=["status", "updated_at"])
            return False
        if str(challenge.user_id) != str(expected_user_id) or challenge.purpose != purpose:
            return False
        expected_nonce_hash = (challenge.metadata_json or {}).get("pending_nonce_hash", "")
        if pending_nonce is not None:
            if not expected_nonce_hash or not compare_tokens(expected_nonce_hash, hash_token(pending_nonce)):
                return False
        if challenge.purpose in {"login", "sensitive_action", "two_factor_change"}:
            if challenge.security_stamp != current_user.auth_security_stamp:
                challenge.status = "revoked"
                challenge.save(update_fields=["status", "updated_at"])
                return False
        if challenge.purpose in {"login", "sensitive_action"}:
            if not expected_nonce_hash or not pending_nonce:
                return False
            if (
                challenge.assurance_policy_version != ASSURANCE_POLICY_VERSION
                or challenge.assurance_context != ASSURANCE_CONTEXT
            ):
                challenge.status = "revoked"
                challenge.save(update_fields=["status", "updated_at"])
                return False
        current_email = _normalized_usable_email(challenge.user)
        if not current_email or challenge.delivery_email_hash != hash_identifier(current_email):
            challenge.status = "revoked"
            challenge.save(update_fields=["status", "updated_at"])
            return False

        max_attempts = _security_setting("ACCOUNT_SECURITY_OTP_MAX_ATTEMPTS")
        if challenge.failed_attempts >= max_attempts:
            challenge.status = "locked"
            challenge.save(update_fields=["status", "updated_at"])
            return False

        target_otp_hash = hash_token(raw_otp)
        if not compare_tokens(challenge.otp_hash, target_otp_hash):
            challenge.failed_attempts += 1
            if challenge.failed_attempts >= max_attempts:
                challenge.status = "locked"
            challenge.save(update_fields=["failed_attempts", "status", "updated_at"])
            log_security_event(
                action_type=(
                    "twostep_challenge_locked"
                    if challenge.status == "locked"
                    else "twostep_challenge_verify_failed"
                ),
                target_model="account_security.TwoStepChallenge",
                target_object_id=str(challenge.id),
                severity="WARNING",
                actor_user=challenge.user,
                ip_address=ip,
                user_agent=user_agent,
                metadata={"challenge_id": str(challenge.id), "attempts": challenge.failed_attempts},
            )
            return False

        challenge.status = "verified"
        challenge.verified_at = now
        challenge.save(update_fields=["status", "verified_at", "updated_at"])

    log_security_event(
        action_type="twostep_challenge_verified",
        target_model="account_security.TwoStepChallenge",
        target_object_id=str(challenge.id),
        severity="INFO",
        actor_user=challenge.user,
        ip_address=ip,
        user_agent=user_agent,
        metadata={"challenge_id": str(challenge.id)}
    )

    return True


def resend_otp(
    challenge_id: str,
    *,
    expected_user_id=None,
    pending_nonce: str = None,
    ip: str = None,
    user_agent: str = None,
) -> tuple:
    """Resend a new OTP for an active challenge if the cooldown has expired."""
    with transaction.atomic():
        try:
            challenge = TwoStepChallenge.objects.select_for_update().select_related("user").get(
                id=challenge_id, status="pending"
            )
        except (TwoStepChallenge.DoesNotExist, ValueError):
            return False, "Verification request has expired or is invalid."
        current_user = User.objects.select_for_update().get(pk=challenge.user_id)

        now = timezone.now()
        absolute_deadline = challenge.created_at + datetime.timedelta(
                seconds=_security_setting("ACCOUNT_SECURITY_LOGIN_CHALLENGE_MAX_LIFETIME_SECONDS")
        )
        if challenge.expires_at <= now or now >= absolute_deadline:
            challenge.status = "expired"
            challenge.save(update_fields=["status", "updated_at"])
            return False, "Verification request has expired or is invalid."
        max_resends = _security_setting("ACCOUNT_SECURITY_OTP_MAX_RESENDS")
        if challenge.resend_count >= max_resends:
            log_security_event(
                action_type="twostep_challenge_resend_denied",
                target_model="account_security.TwoStepChallenge",
                target_object_id=str(challenge.id),
                severity="WARNING",
                actor_user=challenge.user,
                ip_address=ip,
                user_agent=user_agent,
                metadata={"challenge_id": str(challenge.id), "reason": "max_resends_reached"},
            )
            return False, "Verification resend limit reached. Start sign-in again."
        nonce_hash = (challenge.metadata_json or {}).get("pending_nonce_hash", "")
        if pending_nonce is not None and (
            str(challenge.user_id) != str(expected_user_id)
            or not nonce_hash
            or not compare_tokens(nonce_hash, hash_token(pending_nonce))
        ):
            return False, "Verification request has expired or is invalid."
        if challenge.purpose in {"login", "sensitive_action", "two_factor_change"} and (
            challenge.security_stamp != current_user.auth_security_stamp
        ):
            return False, "Verification request has expired or is invalid."
        if challenge.purpose in {"login", "sensitive_action"} and (
            challenge.assurance_policy_version != ASSURANCE_POLICY_VERSION
            or challenge.assurance_context != ASSURANCE_CONTEXT
        ):
            return False, "Verification request has expired or is invalid."
        if challenge.purpose == "login" and (
            str(challenge.user_id) != str(expected_user_id)
            or not nonce_hash
            or not pending_nonce
            or not compare_tokens(nonce_hash, hash_token(pending_nonce))
        ):
            return False, "Verification request has expired or is invalid."

        cooldown = _security_setting("ACCOUNT_SECURITY_OTP_RESEND_COOLDOWN_SECONDS")
        if challenge.last_sent_at and challenge.last_sent_at + datetime.timedelta(seconds=cooldown) > now:
            return False, f"Resend cooldown active. Please wait {cooldown} seconds before requesting a new code."

        delivery_email = _normalized_usable_email(challenge.user)
        if not delivery_email or challenge.delivery_email_hash != hash_identifier(delivery_email):
            challenge.status = "revoked"
            challenge.save(update_fields=["status", "updated_at"])
            return False, "Verification could not be completed. Contact authorized support."

        raw_otp = generate_otp()
        try:
            msg_id = send_security_email(
                recipient_email=delivery_email,
                subject="COMPASS Verification Code",
                template_key="two_step_code",
                context={"purpose": challenge.purpose},
                runtime_context={
                    "otp": raw_otp,
                    "expires_text": challenge.expires_at.strftime("%Y-%m-%d %H:%M UTC"),
                },
            )
        except Exception:
            logger.error("Two-step verification resend delivery failed.")
            log_security_event(
                action_type="twostep_challenge_resend_failed",
                target_model="account_security.TwoStepChallenge",
                target_object_id=str(challenge.id),
                severity="ERROR",
                actor_user=challenge.user,
                ip_address=ip,
                user_agent=user_agent,
                metadata={"challenge_id": str(challenge.id), "reason": "delivery_failed"},
            )
            return False, "Verification email could not be sent. The previous code remains valid."

        challenge.otp_hash = hash_token(raw_otp)
        challenge.resend_count += 1
        challenge.last_sent_at = now
        challenge.expires_at = min(
            now
            + datetime.timedelta(
                seconds=_security_setting("ACCOUNT_SECURITY_OTP_EXPIRY_SECONDS")
            ),
            absolute_deadline,
        )
        challenge.save(update_fields=["otp_hash", "resend_count", "last_sent_at", "expires_at", "updated_at"])
        log_security_event(
            action_type="twostep_challenge_resent",
            target_model="account_security.TwoStepChallenge",
            target_object_id=str(challenge.id),
            severity="INFO",
            actor_user=challenge.user,
            ip_address=ip,
            user_agent=user_agent,
            metadata={
                "challenge_id": str(challenge.id),
                "resend_count": challenge.resend_count,
                "email_delivery_id": msg_id
            }
        )
    return True, "A new verification code has been sent to your email."


def _trusted_device_max_active() -> int:
    return int(_security_setting("ACCOUNT_SECURITY_TRUSTED_DEVICE_MAX_ACTIVE"))


def issue_trusted_device_after_otp(
    challenge,
    *,
    user_agent: str = "",
    ip: str | None = None,
) -> tuple[str | None, object | None, object | None]:
    """Issue a 256-bit remembered-device credential after a verified login OTP."""

    with transaction.atomic():
        challenge = (
            TwoStepChallenge.objects.select_for_update()
            .select_related("user")
            .filter(pk=getattr(challenge, "pk", challenge), purpose="login", status="verified")
            .first()
        )
        if challenge is None:
            return None, None, None
        current_user = User.objects.select_for_update().filter(
            pk=challenge.user_id,
            is_active=True,
        ).first()
        if current_user is None or challenge.trusted_device_issued_at:
            return None, None, None
        if (
            challenge.security_stamp != current_user.auth_security_stamp
            or challenge.assurance_policy_version != ASSURANCE_POLICY_VERSION
            or challenge.assurance_context != ASSURANCE_CONTEXT
        ):
            return None, None, None
        duration_days = get_trusted_device_duration_days(current_user)
        if duration_days <= 0:
            return None, None, None
        now = timezone.now()
        if not challenge.verified_at or challenge.verified_at > now:
            return None, None, None
        lifetime = datetime.timedelta(
            seconds=_security_setting("ACCOUNT_SECURITY_LOGIN_CHALLENGE_MAX_LIFETIME_SECONDS")
        )
        if challenge.created_at + lifetime <= now:
            return None, None, None

        active_devices = list(
            TrustedDevice.objects.select_for_update()
            .filter(user=current_user, status="active", trusted_until__gt=now)
            .order_by("created_at", "id")
        )
        max_active = _trusted_device_max_active()
        for old_device in active_devices[: max(0, len(active_devices) - max_active + 1)]:
            old_device.status = "revoked"
            old_device.revoked_at = now
            old_device.revoked_reason = "active_device_limit"
            old_device.save(update_fields=["status", "revoked_at", "revoked_reason", "updated_at"])

        raw_device_token = secrets.token_urlsafe(32)
        expiry = now + datetime.timedelta(days=duration_days)
        label = get_safe_user_agent_summary(user_agent)
        device = TrustedDevice.objects.create(
            user=current_user,
            device_hash=hash_token(raw_device_token),
            label=label,
            status="active",
            trusted_until=expiry,
            request_ip_hash=hash_identifier(ip) if ip else "",
            network_class=classify_network_class(ip),
            security_stamp=current_user.auth_security_stamp,
            assurance_policy_version=ASSURANCE_POLICY_VERSION,
            assurance_context=ASSURANCE_CONTEXT,
        )
        challenge.trusted_device_issued_at = now
        challenge.save(update_fields=["trusted_device_issued_at", "updated_at"])

    log_security_event(
        action_type="trusted_device_created",
        target_model="account_security.TrustedDevice",
        target_object_id=str(device.id),
        severity="INFO",
        actor_user=current_user,
        ip_address=ip,
        user_agent=user_agent,
        metadata={"device_id": str(device.id), "device_label": label},
    )
    return raw_device_token, expiry, device.id


def issue_trusted_device(
    user,
    user_agent: str,
    *,
    verified_challenge_id,
    pending_nonce: str = None,
    active_session=None,
    ip: str = None,
) -> tuple:
    """Backward-compatible wrapper for the OTP-bound issuer.

    The legacy Django-session projection is intentionally no longer
    consulted; the verified challenge is the source of truth.
    """

    receipt = issue_trusted_device_after_otp(
        TwoStepChallenge(id=verified_challenge_id),
        user_agent=user_agent,
        ip=ip,
    )
    return (receipt[0], receipt[1]) if receipt else (None, None)


def consume_trusted_device_for_login(
    user,
    device_token: str,
    *,
    ip: str | None = None,
    user_agent: str | None = None,
) -> tuple[str, object, object] | None:
    """Validate and rotate a remembered-device credential without extending it."""

    if (
        not device_token
        or not isinstance(device_token, str)
        or len(device_token) > 512
        or not user
        or not user.is_authenticated
    ):
        return None
    now = timezone.now()
    with transaction.atomic():
        # Keep lock ordering aligned with issuance and account-state changes:
        # user first, then device.  This serializes concurrent rotations for
        # one account without introducing a user/device lock inversion.
        current_user = User.objects.select_for_update().filter(
            pk=getattr(user, "pk", None),
            is_active=True,
        ).first()
        device = (
            TrustedDevice.objects.select_for_update()
            .filter(device_hash=hash_token(device_token))
            .first()
        )
        if device is None or current_user is None or device.user_id != current_user.pk:
            return None
        duration_days = get_trusted_device_duration_days(current_user)
        current_label = get_safe_user_agent_summary(user_agent or "")
        valid = (
            device.status == "active"
            and device.trusted_until > now
            and duration_days > 0
            and device.security_stamp == current_user.auth_security_stamp
            and device.assurance_policy_version == ASSURANCE_POLICY_VERSION
            and device.assurance_context == ASSURANCE_CONTEXT
            and device.label == current_label
        )
        if not valid:
            if device.status == "active" and device.trusted_until <= now:
                device.status = "expired"
                device.save(update_fields=["status", "updated_at"])
            return None
        raw_rotated = secrets.token_urlsafe(32)
        device.device_hash = hash_token(raw_rotated)
        device.last_used_at = now
        device.save(update_fields=["device_hash", "last_used_at", "updated_at"])
        expiry = device.trusted_until
        device_id = device.id
    log_security_event(
        action_type="trusted_device_used",
        target_model="account_security.TrustedDevice",
        target_object_id=str(device_id),
        severity="INFO",
        actor_user=current_user,
        ip_address=ip,
        user_agent=user_agent,
        metadata={"device_id": str(device_id)},
    )
    return raw_rotated, expiry, device_id


def verify_trusted_device(user, device_token: str, ip: str = None, user_agent: str = None) -> bool:
    """Compatibility verifier; successful use still rotates the stored hash."""

    return consume_trusted_device_for_login(
        user,
        device_token,
        ip=ip,
        user_agent=user_agent,
    ) is not None


@transaction.atomic
def revoke_trusted_device(user, device_id: str, ip: str = None, user_agent: str = None) -> bool:
    """Revoke a specific trusted device for a user."""
    try:
        device = TrustedDevice.objects.select_for_update().get(
            id=device_id,
            user=user,
            status="active"
        )
        device.status = "revoked"
        device.revoked_at = timezone.now()
        device.revoked_reason = "user_revoked"
        device.save()

        log_security_event(
            action_type="trusted_device_revoked",
            target_model="account_security.TrustedDevice",
            target_object_id=str(device.id),
            severity="INFO",
            actor_user=user,
            ip_address=ip,
            user_agent=user_agent,
            metadata={"device_id": str(device.id), "reason": "user_revoked"}
        )
        from apps.account_security.notification_services import enqueue_security_event
        enqueue_security_event("device_revoked", user, source_id=device.id, device_label="Trusted device")
        return True
    except (TrustedDevice.DoesNotExist, ValueError):
        return False


@transaction.atomic
def revoke_all_trusted_devices_for_user(
    user,
    reason: str = None,
    ip: str = None,
    audit_when_empty: bool = False,
) -> int:
    """Revoke all trusted devices for a user and record the action."""
    devices = TrustedDevice.objects.select_for_update().filter(user=user, status="active")
    count = devices.count()
    if count > 0:
        devices.update(
            status="revoked",
            revoked_at=timezone.now(),
            revoked_reason=reason or "forced_revocation"
        )
    if count > 0 or audit_when_empty:
        log_security_event(
            action_type="trusted_devices_bulk_revoked",
            target_model="accounts.User",
            target_object_id=str(user.pk),
            severity="WARNING",
            actor_user=user,
            ip_address=ip,
            metadata={"reason": reason or "forced_revocation", "attempts": count},
        )
    return count


@transaction.atomic
def terminate_other_sessions(current_session_key: str, user, ip: str = None, user_agent: str = None) -> int:
    """Sign out all active API sessions except the current token family."""
    from apps.account_security.api_tokens import revoke_api_session

    current_id = str(current_session_key or "")
    try:
        current_uuid = uuid.UUID(current_id)
    except (AttributeError, TypeError, ValueError):
        current_uuid = None
    current = (
        ApiSession.objects.filter(pk=current_uuid, user=user).first()
        if current_uuid is not None
        else None
    )
    if current is None:
        from apps.account_security.tokens import get_session_action_token

        current = next(
            (
                row
                for row in ApiSession.objects.filter(user=user, status=ApiSessionStatusChoices.ACTIVE)
                if compare_tokens(current_id, get_session_action_token(str(row.id)))
            ),
            None,
        )
    terminated_count = 0
    for session in ApiSession.objects.select_for_update().filter(
        user=user,
        status=ApiSessionStatusChoices.ACTIVE,
    ):
        if current is not None and session.id == current.id:
            continue
        terminated_count += revoke_api_session(
            session.id,
            actor_user=user,
            ip=ip,
            user_agent=user_agent,
            reason="user_terminated_others",
        )

    # The action itself is security-relevant even when there were no other
    # sessions. Keep the user's activity history truthful for both outcomes.
    log_security_event(
        action_type="sessions_terminated_bulk",
        target_model="accounts.User",
        target_object_id=str(user.pk),
        severity="INFO",
        actor_user=user,
        ip_address=ip,
        user_agent=user_agent,
        metadata={"reason": "user_terminated_others", "attempts": terminated_count},
    )

    if terminated_count:
        from apps.account_security.notification_services import enqueue_security_event
        enqueue_security_event("session_terminated", user, source_id=f"bulk:{timezone.now().isoformat()}")

    return terminated_count


@transaction.atomic
def terminate_all_sessions_for_user(user, ip: str = None, user_agent: str = None) -> int:
    """Invalidate every active API session after a recovery/password reset."""
    from apps.account_security.api_tokens import revoke_all_api_tokens_for_user

    terminated_count = revoke_all_api_tokens_for_user(
        user,
        ip=ip,
        user_agent=user_agent,
        reason="password_reset",
    )
    log_security_event(
        action_type="sessions_terminated_bulk",
        target_model="accounts.User",
        target_object_id=str(user.pk),
        severity="WARNING",
        actor_user=user,
        ip_address=ip,
        user_agent=user_agent,
        metadata={"reason": "password_reset", "attempts": terminated_count},
    )
    return terminated_count


@transaction.atomic
def terminate_session(
    session_token: str,
    user,
    ip: str = None,
    user_agent: str = None,
    current_session_key: str = None,
) -> bool:
    """Invalidate one of the user's active sessions using an opaque token."""
    if not session_token or not user:
        return False

    from apps.account_security.api_tokens import revoke_api_session

    current_id = str(current_session_key or "")
    from apps.account_security.tokens import get_session_action_token

    if current_id and (
        session_token == current_id
        or compare_tokens(session_token, get_session_action_token(current_id))
    ):
        return False

    try:
        candidate_id = uuid.UUID(str(session_token))
    except (AttributeError, TypeError, ValueError):
        candidate_id = None
    candidate = None
    if candidate_id is not None:
        candidate = ApiSession.objects.filter(
            user=user,
            status=ApiSessionStatusChoices.ACTIVE,
            id=candidate_id,
        ).first()
    if candidate is None:
        for row in ApiSession.objects.filter(user=user, status=ApiSessionStatusChoices.ACTIVE):
            if compare_tokens(session_token, get_session_action_token(str(row.id))):
                candidate = row
                break
    if candidate is not None:
        revoke_api_session(
            candidate.id,
            actor_user=user,
            ip=ip,
            user_agent=user_agent,
            reason="user_terminated_session",
        )
        log_security_event(
            action_type="session_terminated",
            target_model="accounts.User",
            target_object_id=str(user.pk),
            severity="INFO",
            actor_user=user,
            ip_address=ip,
            user_agent=user_agent,
            metadata={"reason": "user_terminated_session"},
        )
        from apps.account_security.notification_services import enqueue_security_event
        enqueue_security_event("session_terminated", user, source_id=f"session:{timezone.now().isoformat()}")
        return True

    return False
