"""Typed application services for the account-security API boundary."""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from django.contrib.auth.password_validation import validate_password
from django.db import transaction
from django.utils import timezone

from apps.access_control.authority import has_fixed_capability
from apps.access_control.capabilities import Capability
from apps.access_control.rules import is_active_nonlegacy_actor, is_it_admin
from apps.accounts.models import RoleChoices
from apps.accounts.validation import normalize_staff_email
from apps.account_security.audit import log_security_event
from apps.account_security.commands import (
    ITAdminRecoveryCommand,
    OtpResendCommand,
    PasswordChangeCommand,
    RecoveryRequestCommand,
    RecoveryResetCommand,
    StaffAssistedRecoveryCommand,
)
from apps.account_security.models import AccountRecoveryRequest, TwoStepChallenge
from apps.account_security.services import (
    apply_password_reset_security_state,
    request_recovery,
    resend_otp,
    request_staff_assisted_recovery,
    reset_password_with_token,
)
from apps.account_security.notification_services import enqueue_security_event
from apps.common.exceptions import (
    DependencyFailureError,
    InvalidCredentialsError,
    LifecycleConflictError,
    PermissionDeniedError,
    ValidationError,
)
from apps.common.django_adapters import ModelValidationError
from apps.common.request_dedup import RequestKeyPolicy, validate_and_lock_request_key


User = get_user_model()


IT_ADMIN_RECOVERY_LOCK_POLICY = RequestKeyPolicy(
    namespace="account-security:operator-recovery",
    max_length=64,
)


STAFF_RECOVERY_SUCCESS_MESSAGE = (
    "Recovery instructions were queued for the selected staff account."
)


@transaction.atomic
def change_password(*, actor, command: PasswordChangeCommand, ip: str = "", user_agent: str = "") -> dict:
    """Change the current account password after reloading the account."""
    if not is_active_nonlegacy_actor(actor):
        raise PermissionDeniedError()
    if not isinstance(command, PasswordChangeCommand):
        raise ValidationError("A typed password-change command is required.")
    try:
        user = User.objects.select_for_update().get(pk=actor.pk, is_active=True)
    except User.DoesNotExist as exc:
        raise PermissionDeniedError() from exc
    if bool(getattr(user, "is_superuser", False)):
        raise PermissionDeniedError()
    if not check_password(command.current_password, user.password):
        raise InvalidCredentialsError()
    try:
        validate_password(command.new_password, user=user)
    except ModelValidationError as exc:
        messages = [str(message) for message in exc.messages[:5]]
        raise ValidationError(field_errors={"new_password": messages}) from exc
    if check_password(command.new_password, user.password):
        raise ValidationError(field_errors={"new_password": ["The new password must be different."]})

    apply_password_reset_security_state(
        user,
        command.new_password,
        ip=ip,
        user_agent=user_agent,
        trusted_device_reason="password_changed",
    )
    log_security_event(
        action_type="password_changed",
        target_model="accounts.User",
        target_object_id=str(user.pk),
        severity="INFO",
        actor_user=user,
        ip_address=ip,
        user_agent=user_agent,
        metadata={"reason": "user_password_changed"},
    )
    enqueue_security_event("password_changed", user, source_id=user.pk)
    return {"changed": True}


@transaction.atomic
def recover_it_admin_password(
    *,
    command: ITAdminRecoveryCommand,
    ip: str = "",
    user_agent: str = "",
) -> dict:
    """Recover one existing IT Admin through the operator-only boundary."""
    if type(command) is not ITAdminRecoveryCommand:
        raise ValidationError("A typed IT Admin recovery command is required.")

    from django.conf import settings

    if str(getattr(settings, "COMPASS_ACCESS_MODE", "active") or "").strip().lower() != "health_only":
        raise PermissionDeniedError("IT Admin recovery is available only in health-only mode.")

    validate_and_lock_request_key(
        IT_ADMIN_RECOVERY_LOCK_POLICY,
        "it-admin-password-recovery",
    )
    email = normalize_staff_email(command.email)
    candidates = list(
        User.objects.select_for_update()
        .filter(email__iexact=email)
        .order_by("pk")[:2]
    )
    if len(candidates) != 1:
        raise LifecycleConflictError("The IT Admin recovery target is not unambiguous.")

    user = candidates[0]
    if (
        user.role != RoleChoices.IT_ADMIN
        or not user.is_active
        or bool(user.is_superuser)
    ):
        raise PermissionDeniedError("The IT Admin recovery target is not eligible.")
    if check_password(command.new_password, user.password):
        raise ValidationError(field_errors={"new_password": ["The new password must be different."]})
    try:
        validate_password(command.new_password, user=user)
    except ModelValidationError as exc:
        messages = [str(message) for message in exc.messages[:5]]
        raise ValidationError(field_errors={"new_password": messages}) from exc

    now = timezone.now()
    AccountRecoveryRequest.objects.select_for_update().filter(
        user=user,
        status="pending",
    ).update(status="revoked", revoked_at=now, updated_at=now)
    apply_password_reset_security_state(
        user,
        command.new_password,
        ip=ip,
        user_agent=user_agent,
        trusted_device_reason="operator_it_admin_recovery",
    )
    log_security_event(
        action_type="it_admin_password_recovered",
        target_model="accounts.User",
        target_object_id=str(user.pk),
        severity="WARNING",
        ip_address=ip,
        user_agent=user_agent,
        metadata={
            "target_role": RoleChoices.IT_ADMIN,
            "reason": "operator_it_admin_recovery",
            "outcome": "completed",
        },
    )
    enqueue_security_event("password_changed", user, source_id=user.pk)
    return {"completed": True}


@transaction.atomic
def request_staff_account_recovery(
    *,
    actor,
    command: StaffAssistedRecoveryCommand,
    ip: str = "",
    user_agent: str = "",
    assurance_token=None,
) -> dict:
    """Queue a safe recovery email for an active staff account.

    This includes a designated Head Guidance Counselor, while keeping the
    target set separate from student self-service and IT Admin operator
    recovery.
    """
    if type(command) is not StaffAssistedRecoveryCommand:
        raise ValidationError("A typed staff recovery command is required.")
    if (
        not is_active_nonlegacy_actor(actor)
        or not is_it_admin(actor)
        or not has_fixed_capability(actor, Capability.ACCOUNT_SECURITY_RECOVERY_ASSIST)
    ):
        raise PermissionDeniedError()

    target = (
        User.objects.select_for_update()
        .filter(pk=command.target_account_id)
        .first()
    )
    if (
        target is None
        or target.role not in {RoleChoices.COUNSELOR, RoleChoices.GCO_STAFF}
        or not target.is_active
        or bool(target.is_superuser)
    ):
        raise PermissionDeniedError()

    accepted, outcome = request_staff_assisted_recovery(
        actor,
        target,
        reason_category=command.reason_category,
        email_ownership_attested=command.email_ownership_attested,
        ip=ip,
        user_agent=user_agent,
        assurance_token=assurance_token,
    )
    if not accepted:
        if outcome in {
            "reason_required",
            "email_ownership_attestation_required",
            "usable_email_unavailable",
        }:
            raise ValidationError()
        if outcome == "stale_confirmation":
            raise LifecycleConflictError()
        raise PermissionDeniedError()
    return {"accepted": True, "detail": STAFF_RECOVERY_SUCCESS_MESSAGE}


def reset_password(*, command: RecoveryResetCommand, ip: str = "", user_agent: str = "", session: str = "") -> dict:
    """Consume a recovery token at the public reset boundary."""
    if not isinstance(command, RecoveryResetCommand):
        raise ValidationError("A typed recovery-reset command is required.")
    try:
        validate_password(command.new_password)
    except ModelValidationError as exc:
        messages = [str(message) for message in exc.messages[:5]]
        raise ValidationError(field_errors={"new_password": messages}) from exc
    try:
        completed = reset_password_with_token(
            command.token,
            command.new_password,
            ip=ip,
            user_agent=user_agent,
            session=session,
        )
    except (ModelValidationError, ValueError) as exc:
        raise ValidationError() from exc
    except Exception as exc:
        raise DependencyFailureError() from exc
    if not completed:
        raise InvalidCredentialsError()
    return {"reset": True}


def resend_login_otp(*, command: OtpResendCommand, ip: str = "", user_agent: str = "") -> dict:
    """Resend a login OTP without trusting a client-supplied user id."""
    if not isinstance(command, OtpResendCommand):
        raise ValidationError("A typed OTP resend command is required.")
    challenge = (
        TwoStepChallenge.objects
        .filter(id=command.challenge_id, purpose="login", status="pending")
        .only("id", "user_id")
        .first()
    )
    if challenge is None:
        raise InvalidCredentialsError()
    delivered, message = resend_otp(
        str(command.challenge_id),
        expected_user_id=challenge.user_id,
        pending_nonce=command.pending_nonce,
        ip=ip,
        user_agent=user_agent,
    )
    if not delivered:
        raise InvalidCredentialsError()
    return {"resent": True, "detail": message}


def request_password_recovery(*, command: RecoveryRequestCommand, ip: str = "", user_agent: str = "") -> dict:
    """Return the generic recovery response for every account lookup result."""
    if not isinstance(command, RecoveryRequestCommand):
        raise ValidationError("A typed recovery-request command is required.")
    try:
        _sent, message = request_recovery(command.email, ip=ip, user_agent=user_agent)
    except Exception:
        # The public recovery boundary must not disclose account or provider
        # state. The underlying service records bounded failure evidence.
        message = "If an account exists for the information provided, we'll send recovery instructions."
    return {"detail": message}
