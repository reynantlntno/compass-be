# Project: COMPASS
# File: apps/student_activation/services.py
# Module: apps.student_activation
# Purpose: Service functions for invitation generation, token validation, and account activation
# Domain boundary and service policy.

from datetime import datetime, timedelta
from typing import Optional, Tuple
import uuid

from django.db import transaction
from django.utils import timezone

from apps.accounts.models import RoleChoices, User
from apps.account_security.activation import (
    ActivationPurpose,
    activation_profile,
    issue_activation_token,
    consume_activation_invitation,
    hash_activation_token,
    invitation_state_reason,
    decode_activation_reference,
    validate_activation_password,
)
from apps.audit.services import audit_log
from apps.common.exceptions import NotFoundError, PermissionDeniedError, StaleStateError, ValidationError
from apps.student_activation.models import StudentActivationInvitation
from apps.governance.runtime_config import resolve_runtime_setting
from apps.student_activation.commands import ActivationInvitationReceipt, StudentActivationCommand


def create_activation_invitation(
    user: User,
    created_by: Optional[User] = None,
    validity_days: Optional[int] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    request_id: Optional[str] = None,
    trace_id: Optional[str] = None,
    source_view: Optional[str] = None,
) -> Tuple[StudentActivationInvitation, str]:
    """Generates a secure activation token for an inactive STUDENT.

    Revokes any previous active tokens for this user.
    SECURITY: Enforces that role is strictly STUDENT and is_active is False.
    """
    if user.is_active:
        raise ValidationError("Cannot create activation invitation for an active user.")
    if user.role != RoleChoices.STUDENT:
        raise ValidationError("Activation flow is restricted to STUDENT role users.")

    if validity_days is None:
        validity_days = resolve_runtime_setting(
            "security.account_security_controls",
            "ACCOUNT_ACTIVATION_TOKEN_VALIDITY_DAYS",
        )

    now = timezone.now()
    expires_at = now + timedelta(days=validity_days)

    with transaction.atomic():
        # Revoke existing unused invitations
        previous = list(StudentActivationInvitation.objects.filter(
            user=user, used_at__isnull=True, revoked_at__isnull=True
        ))
        previous_count = len(previous)
        if previous:
            StudentActivationInvitation.objects.filter(pk__in=[item.pk for item in previous]).update(
                revoked_at=now,
                revoked_by=created_by,
                revocation_reason="reissued",
            )
            from apps.orchestration.commands import ActivationDeliveryCancellationCommand
            from apps.orchestration.use_cases import cancel_activation_deliveries_for_composition

            cancel_activation_deliveries_for_composition(
                ActivationDeliveryCancellationCommand(
                    template_key="student_activation",
                    invitation_ids=tuple(item.pk for item in previous),
                )
            )

        # The signed token is reconstructable from the opaque invitation UUID;
        # only its HMAC is persisted.  Build the unsaved instance first so a
        # pending/random marker is never written to the database, even
        # transiently, in place of the HMAC.
        invitation = StudentActivationInvitation(
            user=user,
            token_reference=uuid.uuid4(),
            token_version=activation_profile(ActivationPurpose.STUDENT).version,
            delivery_email_hash=_email_hash(user.email),
            expires_at=expires_at,
            created_by=created_by,
            reissued_from=previous[-1] if previous else None,
        )
        raw_token = issue_activation_token(invitation, ActivationPurpose.STUDENT)
        invitation.token_hash = hash_activation_token(raw_token)
        invitation.save(force_insert=True)

    # Determine audit log type
    action_type = "INVITATION_REISSUE" if previous_count > 0 else "INVITATION_CREATE"

    # Log generation event safely (without raw token)
    audit_log(
        action_type=action_type,
        event_category="SECURITY",
        target_model="accounts.User",
        target_object_id=user.id,
        actor_user=created_by,
        ip_address=ip_address,
        user_agent=user_agent,
        request_id=request_id,
        trace_id=trace_id,
        source_app="student_activation",
        source_view=source_view,
        metadata={
            "invitation_id": invitation.id,
            "expires_at": expires_at.isoformat(),
            "previous_revoked_count": previous_count,
        },
    )

    return invitation, raw_token


def _email_hash(email: str) -> str:
    from apps.account_security.tokens import hash_identifier

    return hash_identifier((email or "").strip().lower())


@transaction.atomic
def revoke_activation_invitation(invitation, *, actor_user=None, reason: str = "manual_revocation"):
    invitation = StudentActivationInvitation.objects.select_for_update().get(pk=invitation.pk)
    if invitation.used_at is None and invitation.revoked_at is None:
        invitation.revoked_at = timezone.now()
        invitation.revoked_by = actor_user
        invitation.revocation_reason = reason[:80]
        invitation.save(update_fields=["revoked_at", "revoked_by", "revocation_reason", "updated_at"])
        from apps.orchestration.commands import ActivationDeliveryCancellationCommand
        from apps.orchestration.use_cases import cancel_activation_deliveries_for_composition

        cancel_activation_deliveries_for_composition(
            ActivationDeliveryCancellationCommand(
                template_key="student_activation",
                invitation_ids=(invitation.pk,),
            )
        )
    return invitation


def queue_activation_delivery(invitation: StudentActivationInvitation):
    """Queue activation through the shared transactional outbox."""
    from apps.workflow.services import enqueue_outbox_event

    return enqueue_outbox_event(
        "student_activation.invitation_requested",
        {"invitation_id": str(invitation.token_reference)},
        related_object=invitation,
        event_key=f"student-activation:{invitation.token_reference}",
    )


def queue_activation_delivery_by_id(invitation_id: str):
    """Queue one invitation after reloading it by stable ID."""
    invitation = StudentActivationInvitation.objects.filter(pk=invitation_id).first()
    if invitation is None:
        raise NotFoundError("The activation invitation was not found.")
    return queue_activation_delivery(invitation)


@transaction.atomic
def issue_activation_invitation_for_user_id(
    user_id: str,
    *,
    created_by=None,
    validity_days: int | None = None,
    source_view: str = "",
) -> ActivationInvitationReceipt:
    """Create a safe invitation using only a stable user ID.

    Delivery is deliberately queued by the orchestration composition boundary
    after this service returns its safe receipt.
    """
    from apps.student_activation.policies import can_manage_activation_invitations

    if not can_manage_activation_invitations(created_by):
        raise PermissionDeniedError()
    user = User.objects.select_for_update().filter(pk=user_id).first()
    if user is None:
        raise NotFoundError("The student account was not found.")
    invitation, _raw_token = create_activation_invitation(
        user,
        created_by=created_by,
        validity_days=validity_days,
        source_view=source_view,
    )
    return ActivationInvitationReceipt(
        invitation_id=str(invitation.pk),
        expires_at=invitation.expires_at,
        delivery_queued=False,
    )


def _assert_expected_updated_at(instance, expected_updated_at: str | None) -> None:
    if not expected_updated_at:
        return
    try:
        expected = datetime.fromisoformat(expected_updated_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError("expected_updated_at is invalid.") from exc
    actual = instance.updated_at
    if timezone.is_naive(expected):
        expected = timezone.make_aware(expected, timezone.get_current_timezone())
    if timezone.is_naive(actual):
        actual = timezone.make_aware(actual, timezone.get_current_timezone())
    if actual != expected:
        raise StaleStateError()


@transaction.atomic
def reissue_activation_invitation_by_id(
    invitation_id: str,
    *,
    actor_user=None,
    reason: str = "manual_reissue",
    expected_updated_at: str | None = None,
) -> ActivationInvitationReceipt:
    """Reissue one invitation without exposing the new raw verifier."""
    invitation = (
        StudentActivationInvitation.objects.select_for_update().select_related("user")
        .filter(pk=invitation_id)
        .first()
    )
    if invitation is None:
        raise NotFoundError("The activation invitation was not found.")
    _assert_expected_updated_at(invitation, expected_updated_at)
    return issue_activation_invitation_for_user_id(
        str(invitation.user_id),
        created_by=actor_user,
        source_view=reason,
    )


@transaction.atomic
def revoke_activation_invitation_by_id(
    invitation_id: str,
    *,
    actor_user=None,
    reason: str = "manual_revocation",
    expected_updated_at: str | None = None,
) -> ActivationInvitationReceipt:
    """Revoke one invitation using a stable ID and return safe state."""
    invitation = StudentActivationInvitation.objects.select_for_update().filter(pk=invitation_id).first()
    if invitation is None:
        raise NotFoundError("The activation invitation was not found.")
    _assert_expected_updated_at(invitation, expected_updated_at)
    updated = revoke_activation_invitation(invitation, actor_user=actor_user, reason=reason)
    return ActivationInvitationReceipt(
        invitation_id=str(updated.pk),
        expires_at=updated.expires_at,
        delivery_queued=False,
    )


def validate_activation_token(
    raw_token: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    request_id: Optional[str] = None,
    trace_id: Optional[str] = None,
    source_view: Optional[str] = None,
) -> StudentActivationInvitation:
    """Validates the raw activation token.

    Checks:
    - Hash lookup matches
    - Token not already used
    - Token not revoked
    - Token not expired
    - User role is STUDENT and is inactive (is_active=False)

    SECURITY: Returns generic ValidationError("Invalid or expired activation link.")
    for any failure type to prevent enumeration, but records precise reasons internally via audit.
    """
    generic_error = ValidationError("Invalid or expired activation link.")

    if not raw_token or not isinstance(raw_token, str):
        # Malformed or missing raw token string
        audit_log(
            action_type="ACCOUNT_ACTIVATION_FAIL",
            event_category="SECURITY",
            target_model="accounts.User",
            target_object_id="",
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            trace_id=trace_id,
            source_app="student_activation",
            source_view=source_view,
            metadata={"reason": "Missing or malformed raw token format."},
        )
        raise generic_error

    token_hash = hash_activation_token(raw_token)
    reference = decode_activation_reference(raw_token, ActivationPurpose.STUDENT)
    if not reference:
        raise generic_error
    invitation = (
        StudentActivationInvitation.objects
        .filter(
            token_reference=reference,
            token_hash=token_hash,
            token_version=activation_profile(ActivationPurpose.STUDENT).version,
        )
        .select_related("user")
        .first()
    )

    if not invitation:
        audit_log(
            action_type="ACCOUNT_ACTIVATION_FAIL",
            event_category="SECURITY",
            target_model="accounts.User",
            target_object_id="",
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            trace_id=trace_id,
            source_app="student_activation",
            source_view=source_view,
            metadata={"reason": "Token hash look up mismatch."},
        )
        raise generic_error

    user = invitation.user

    state_reason = invitation_state_reason(invitation)
    if state_reason == "used":
        audit_log(
            action_type="ACCOUNT_ACTIVATION_SUSPICIOUS",
            event_category="SECURITY",
            target_model="accounts.User",
            target_object_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            trace_id=trace_id,
            source_app="student_activation",
            source_view=source_view,
            metadata={
                "reason": "Attempted token reuse/replay.",
                "invitation_id": invitation.id,
            },
        )
        raise generic_error

    if state_reason == "revoked":
        audit_log(
            action_type="ACCOUNT_ACTIVATION_FAIL",
            event_category="SECURITY",
            target_model="accounts.User",
            target_object_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            trace_id=trace_id,
            source_app="student_activation",
            source_view=source_view,
            metadata={
                "reason": "Token has been manually or programmatically revoked.",
                "invitation_id": invitation.id,
            },
        )
        raise generic_error

    if state_reason == "expired":
        audit_log(
            action_type="ACCOUNT_ACTIVATION_FAIL",
            event_category="SECURITY",
            target_model="accounts.User",
            target_object_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            trace_id=trace_id,
            source_app="student_activation",
            source_view=source_view,
            metadata={
                "reason": "Token has expired.",
                "invitation_id": invitation.id,
            },
        )
        raise generic_error

    if user.is_active:
        audit_log(
            action_type="ACCOUNT_ACTIVATION_SUSPICIOUS",
            event_category="SECURITY",
            target_model="accounts.User",
            target_object_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            trace_id=trace_id,
            source_app="student_activation",
            source_view=source_view,
            metadata={
                "reason": "User is already active.",
                "invitation_id": invitation.id,
            },
        )
        raise generic_error

    if user.role != RoleChoices.STUDENT:
        audit_log(
            action_type="ACCOUNT_ACTIVATION_SUSPICIOUS",
            event_category="SECURITY",
            target_model="accounts.User",
            target_object_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            trace_id=trace_id,
            source_app="student_activation",
            source_view=source_view,
            metadata={
                "reason": "Target user holds non-student role.",
                "role": user.role,
                "invitation_id": invitation.id,
            },
        )
        raise generic_error

    if invitation.delivery_email_hash and invitation.delivery_email_hash != _email_hash(user.email):
        raise generic_error

    return invitation


def execute_student_activation(
    raw_token: str,
    password: str,
    confirm_password: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    request_id: Optional[str] = None,
    trace_id: Optional[str] = None,
    source_view: Optional[str] = None,
) -> User:
    """Atomically validates the token and updates the student password to activate the user account.

    SECURITY: Enforces row locking using select_for_update() inside transaction.atomic() to
    prevent double-submit/replay concurrency race conditions.
    """
    # 1. Validate form fields
    if password != confirm_password:
        raise ValidationError("Passwords do not match.")

    generic_error = ValidationError("Invalid or expired activation link.")

    if not raw_token or not isinstance(raw_token, str):
        raise generic_error

    token_hash = hash_activation_token(raw_token)
    token_reference = decode_activation_reference(raw_token, ActivationPurpose.STUDENT)
    if not token_reference:
        raise generic_error

    with transaction.atomic():
        # Retrieve invitation with select_for_update row lock
        invitation = (
            StudentActivationInvitation.objects.select_for_update()
            .select_related("user")
            .filter(
                token_reference=token_reference,
                token_hash=token_hash,
                token_version=activation_profile(ActivationPurpose.STUDENT).version,
            )
            .first()
        )

        if not invitation:
            audit_log(
                action_type="ACCOUNT_ACTIVATION_FAIL",
                event_category="SECURITY",
                target_model="accounts.User",
                target_object_id="",
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
                trace_id=trace_id,
                source_app="student_activation",
                source_view=source_view,
                metadata={"reason": "Token hash lookup mismatch inside transaction lock."},
            )
            raise generic_error

        user = invitation.user

        state_reason = invitation_state_reason(invitation)
        if state_reason == "used":
            audit_log(
                action_type="ACCOUNT_ACTIVATION_SUSPICIOUS",
                event_category="SECURITY",
                target_model="accounts.User",
                target_object_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
                trace_id=trace_id,
                source_app="student_activation",
                source_view=source_view,
                metadata={
                    "reason": "Attempted token reuse/replay inside transaction lock.",
                    "invitation_id": invitation.id,
                },
            )
            raise generic_error

        if state_reason == "revoked":
            audit_log(
                action_type="ACCOUNT_ACTIVATION_FAIL",
                event_category="SECURITY",
                target_model="accounts.User",
                target_object_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
                trace_id=trace_id,
                source_app="student_activation",
                source_view=source_view,
                metadata={
                    "reason": "Token has been manually or programmatically revoked inside transaction lock.",
                    "invitation_id": invitation.id,
                },
            )
            raise generic_error

        if state_reason == "expired":
            audit_log(
                action_type="ACCOUNT_ACTIVATION_FAIL",
                event_category="SECURITY",
                target_model="accounts.User",
                target_object_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
                trace_id=trace_id,
                source_app="student_activation",
                source_view=source_view,
                metadata={
                    "reason": "Token has expired inside transaction lock.",
                    "invitation_id": invitation.id,
                },
            )
            raise generic_error

        if user.is_active:
            audit_log(
                action_type="ACCOUNT_ACTIVATION_SUSPICIOUS",
                event_category="SECURITY",
                target_model="accounts.User",
                target_object_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
                trace_id=trace_id,
                source_app="student_activation",
                source_view=source_view,
                metadata={
                    "reason": "User is already active inside transaction lock.",
                    "invitation_id": invitation.id,
                },
            )
            raise generic_error

        if user.role != RoleChoices.STUDENT:
            audit_log(
                action_type="ACCOUNT_ACTIVATION_SUSPICIOUS",
                event_category="SECURITY",
                target_model="accounts.User",
                target_object_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
                trace_id=trace_id,
                source_app="student_activation",
                source_view=source_view,
                metadata={
                    "reason": "Target user holds non-student role inside transaction lock.",
                    "role": user.role,
                    "invitation_id": invitation.id,
                },
            )
            raise generic_error

        if invitation.delivery_email_hash and invitation.delivery_email_hash != _email_hash(user.email):
            raise generic_error

        # The domain has already checked the STUDENT role and email binding;
        # the shared primitive performs password validation and consumes the
        # locked invitation exactly once.
        validate_activation_password(password, confirm_password, user)
        consume_activation_invitation(user, invitation, password)

        # A consumed, server-issued Student activation invitation is the only
        # automatic source of verified-email provenance.  The evidence row
        # stores an HMAC, never the address itself.
        from apps.account_security.email_evidence import record_verified_email_evidence
        record_verified_email_evidence(
            user,
            verification_method="activation_invitation",
            source_model="student_activation.StudentActivationInvitation",
            source_object_id=str(invitation.pk),
            reason_category="activation_completed",
            ip_address=ip_address,
            user_agent=user_agent,
        )

        # Log successful event securely inside lock
        audit_log(
            action_type="ACCOUNT_ACTIVATION_SUCCESS",
            event_category="SECURITY",
            target_model="accounts.User",
            target_object_id=user.id,
            actor_user=user,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            trace_id=trace_id,
            source_app="student_activation",
            source_view=source_view,
            metadata={
                "invitation_id": invitation.id,
            },
        )

    return user


def activate_student_account(
    command: StudentActivationCommand,
    *,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    request_id: Optional[str] = None,
    trace_id: Optional[str] = None,
    source_view: Optional[str] = None,
) -> User:
    """Typed activation boundary used by the authentication API."""
    if not isinstance(command, StudentActivationCommand):
        raise ValidationError("Student activation requires a typed command.")
    return execute_student_activation(
        command.token,
        command.password,
        command.password_confirmation,
        ip_address=ip_address,
        user_agent=user_agent,
        request_id=request_id,
        trace_id=trace_id,
        source_view=source_view,
    )
