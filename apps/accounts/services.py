"""Transactional staff-account provisioning and invitation lifecycle."""

from __future__ import annotations

import hmac
import uuid
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.accounts.commands import (
    ITAdminBootstrapCommand,
    InitialHeadGuidanceBootstrapCommand,
    StaffAccountCreateCommand,
)
from apps.accounts.models import (
    RoleChoices,
    StaffAccountInvitation,
    User,
)
from apps.accounts.policies import can_manage_head_guidance, can_manage_staff_accounts
from apps.access_control.rules import is_head_guidance
from apps.account_security.activation import (
    ActivationPurpose,
    activation_url_for_token,
    issue_activation_token,
    consume_activation_invitation,
    hash_activation_token,
    invitation_state_reason,
    decode_activation_reference,
    validate_activation_password,
)
from apps.account_security.email_evidence import record_verified_email_evidence
from apps.audit.services import audit_log
from apps.common.exceptions import (
    GovernanceError,
    LifecycleConflictError,
    NotFoundError,
    PermissionDeniedError,
    ValidationError,
)
from apps.common.request_dedup import RequestKeyPolicy, validate_and_lock_request_key
from apps.accounts.validation import normalize_staff_email
from apps.profiles.models import CounselorProfile, GCOStaffProfile
from apps.governance.runtime_config import resolve_runtime_setting


STAFF_INVITABLE_ROLES = frozenset({RoleChoices.COUNSELOR, RoleChoices.GCO_STAFF})
INSTITUTIONAL_BOOTSTRAP_LOCK_POLICY = RequestKeyPolicy(
    namespace="accounts:institutional-bootstrap",
    max_length=64,
)

UserModel = get_user_model()


def _email_hash(email: str) -> str:
    from apps.account_security.tokens import hash_identifier

    return hash_identifier((email or "").strip().lower())


def _audit_or_raise(*, action_type: str, actor=None, target=None, metadata=None):
    event = audit_log(
        action_type=action_type,
        event_category="ACCOUNT_GOVERNANCE",
        target_model="accounts.User" if target is None else target.__class__.__name__,
        target_object_id=str(getattr(target, "pk", "") or ""),
        actor_user=actor,
        source_app="accounts",
        metadata=metadata or {},
    )
    if event is None:
        raise GovernanceError("The account governance audit could not be recorded.")
    return event


def _cancel_pending_staff_deliveries(invitation_ids):
    if not invitation_ids:
        return
    from apps.orchestration.commands import ActivationDeliveryCancellationCommand
    from apps.orchestration.use_cases import cancel_activation_deliveries_for_composition

    cancel_activation_deliveries_for_composition(
        ActivationDeliveryCancellationCommand(
            template_key="staff_activation",
            invitation_ids=tuple(invitation_ids),
        )
    )


def _queue_staff_invitation(invitation):
    from apps.notifications.dispatch import enqueue_notification_event

    return enqueue_notification_event(
        "staff_account.invitation_requested",
        {"invitation_id": str(invitation.token_reference)},
        related_object=invitation,
        event_key=f"staff-account:{invitation.token_reference}:v1",
    )


def _create_invitation(user, *, created_by=None, validity_days=None, reissued_from=None):
    validity_days = (
        resolve_runtime_setting(
            "security.account_security_controls",
            "ACCOUNT_ACTIVATION_TOKEN_VALIDITY_DAYS",
        )
        if validity_days is None else validity_days
    )
    if not isinstance(validity_days, int) or not 1 <= validity_days <= 14:
        raise ValidationError("Invitation validity must be between one and fourteen days.")
    if user.role not in STAFF_INVITABLE_ROLES or user.is_active or user.is_superuser:
        raise ValidationError("Only inactive regular staff accounts may receive invitations.")
    now = timezone.now()
    previous = list(StaffAccountInvitation.objects.select_for_update().filter(
        user=user, used_at__isnull=True, revoked_at__isnull=True,
    ).order_by("-created_at"))
    if previous:
        StaffAccountInvitation.objects.filter(pk__in=[item.pk for item in previous]).update(
            revoked_at=now, revoked_by=created_by, revocation_reason="reissued",
        )
        _cancel_pending_staff_deliveries([item.pk for item in previous])
    invitation = StaffAccountInvitation(
        user=user,
        role_snapshot=user.role,
        profile_type=user.role,
        token_reference=uuid.uuid4(),
        token_hash="pending",
        delivery_email_hash=_email_hash(user.email),
        expires_at=now + timedelta(days=validity_days),
        created_by=created_by,
        reissued_from=reissued_from or (previous[-1] if previous else None),
    )
    raw_token = issue_activation_token(invitation, ActivationPurpose.STAFF)
    invitation.token_hash = hash_activation_token(raw_token)
    invitation.save(force_insert=True)
    return invitation


def _validate_staff_role(role: str) -> None:
    if role not in {RoleChoices.COUNSELOR, RoleChoices.GCO_STAFF, RoleChoices.IT_ADMIN}:
        raise ValidationError("Only supported staff roles may be provisioned.")


def _require_institutional_bootstrap_posture() -> None:
    if str(getattr(settings, "COMPASS_ACCESS_MODE", "active") or "").strip().lower() != "health_only":
        raise PermissionDeniedError("Institutional bootstrap is available only in health-only mode.")


def _lock_institutional_bootstrap() -> str:
    # The raw lock value is fixed and never persisted. PostgreSQL receives an
    # advisory transaction lock; other databases retain the same validation
    # and database uniqueness backstops used by request deduplication.
    return validate_and_lock_request_key(
        INSTITUTIONAL_BOOTSTRAP_LOCK_POLICY,
        "initial-account-bootstrap",
    )


def _require_initial_head_activation_configuration() -> None:
    if not str(getattr(settings, "ACCOUNT_ACTIVATION_TOKEN_SECRET", "") or "").strip():
        raise ValidationError("Account activation security is not configured.")
    try:
        activation_url_for_token("bootstrap-readiness", ActivationPurpose.STAFF)
    except ValidationError:
        raise ValidationError("The canonical client activation configuration is invalid.") from None
    from apps.notifications.models import NotificationTemplate
    if not NotificationTemplate.objects.filter(stable_key="staff_activation", status="active").exists():
        raise ValidationError("Staff activation notification is not configured.")


def _create_staff_account(
    command: StaffAccountCreateCommand,
    *,
    actor: User | None = None,
    initial_head: bool = False,
) -> tuple[User, StaffAccountInvitation]:
    """Create one normal staff account inside an already guarded transaction."""
    _validate_staff_role(command.role)
    if command.role == RoleChoices.IT_ADMIN:
        raise PermissionDeniedError("IT Admin accounts require institutional bootstrap.")
    if initial_head and command.role != RoleChoices.COUNSELOR:
        raise ValidationError("The initial Head Guidance account must be a counselor.")
    if initial_head and CounselorProfile.objects.select_for_update().filter(is_head_guidance=True).exists():
        raise LifecycleConflictError("A Head Guidance designation already exists.")

    email = normalize_staff_email(command.email)
    if UserModel.objects.filter(email__iexact=email).exists():
        raise ValidationError("An account with this email already exists.")

    user = UserModel.objects.create_user(
        email=email,
        password=None,
        first_name=(command.first_name or "").strip()[:150],
        last_name=(command.last_name or "").strip()[:150],
        role=command.role,
        is_active=False,
    )
    profile = None
    if command.role == RoleChoices.COUNSELOR:
        profile = CounselorProfile.objects.create(
            user=user,
            license_number=(command.license_number or "").strip()[:50],
            is_head_guidance=bool(initial_head),
        )
    elif command.role == RoleChoices.GCO_STAFF:
        profile = GCOStaffProfile.objects.create(
            user=user,
            designation=(command.designation or "").strip()[:100],
        )

    invitation = _create_invitation(
        user,
        created_by=actor,
        validity_days=command.validity_days,
    )
    _queue_staff_invitation(invitation)
    _audit_or_raise(
        action_type="STAFF_ACCOUNT_CREATED",
        actor=actor,
        target=user,
        metadata={
            "role": command.role,
            "profile_created": bool(profile),
            "invitation_issued": True,
            "source_reference": (command.source_reference or "")[:120],
        },
    )
    if profile is not None:
        _audit_or_raise(
            action_type="STAFF_PROFILE_CREATED",
            actor=actor,
            target=user,
            metadata={"profile_type": command.role},
        )
    _audit_or_raise(
        action_type="STAFF_INVITATION_ISSUED",
        actor=actor,
        target=user,
        metadata={"invitation_id": str(invitation.id), "expires_at": invitation.expires_at.isoformat()},
    )
    return user, invitation


@transaction.atomic
def provision_staff_account(
    actor: User,
    command: StaffAccountCreateCommand,
) -> tuple[User, StaffAccountInvitation]:
    """Create a regular disabled counselor or GCO Staff account."""
    _validate_staff_role(command.role)
    if command.role == RoleChoices.IT_ADMIN:
        raise PermissionDeniedError("IT Admin accounts require institutional bootstrap.")
    if not can_manage_staff_accounts(actor, command.role):
        raise PermissionDeniedError("Only Head Guidance may provision counselor or GCO Staff accounts.")
    try:
        return _create_staff_account(command, actor=actor)
    except (IntegrityError, ValueError) as exc:
        raise ValidationError("The staff account could not be created without a duplicate record.") from exc


@transaction.atomic
def bootstrap_it_admin(command: ITAdminBootstrapCommand) -> User:
    """Create the first active, login-ready IT Admin during controlled setup."""
    if type(command) is not ITAdminBootstrapCommand:
        raise ValidationError("The IT Admin bootstrap command is invalid.")
    _require_institutional_bootstrap_posture()
    _lock_institutional_bootstrap()

    if UserModel.objects.select_for_update().filter(role=RoleChoices.IT_ADMIN).exists():
        raise LifecycleConflictError("An IT Admin account already exists.")
    email = normalize_staff_email(command.email)
    if UserModel.objects.filter(email__iexact=email).exists():
        raise ValidationError("An account with this email already exists.")

    candidate = UserModel(
        email=email,
        first_name=command.first_name,
        last_name=command.last_name,
        role=RoleChoices.IT_ADMIN,
        is_active=True,
    )
    try:
        validate_activation_password(command.password, command.password, candidate)
    except ValidationError as exc:
        raise ValidationError("The bootstrap password does not meet the account requirements.") from exc

    try:
        user = UserModel.objects.create_user(
            email=email,
            password=command.password,
            first_name=command.first_name,
            last_name=command.last_name,
            role=RoleChoices.IT_ADMIN,
            is_active=True,
        )
        _audit_or_raise(
            action_type="STAFF_ACCOUNT_CREATED",
            target=user,
            metadata={
                "role": RoleChoices.IT_ADMIN,
                "profile_created": False,
                "invitation_issued": False,
                "bootstrap_context": "institutional",
            },
        )
        return user
    except IntegrityError as exc:
        raise ValidationError("The IT Admin account could not be created without a duplicate record.") from exc


@transaction.atomic
def bootstrap_initial_head_guidance(
    command: InitialHeadGuidanceBootstrapCommand,
) -> tuple[User, StaffAccountInvitation]:
    """Create the first inactive Head Guidance counselor and invite them."""
    if type(command) is not InitialHeadGuidanceBootstrapCommand:
        raise ValidationError("The initial Head Guidance bootstrap command is invalid.")
    _require_institutional_bootstrap_posture()
    _lock_institutional_bootstrap()
    _require_initial_head_activation_configuration()

    active_it_admins = list(
        UserModel.objects.select_for_update().filter(
            role=RoleChoices.IT_ADMIN,
            is_active=True,
            is_superuser=False,
        ).order_by("pk")[:2]
    )
    if len(active_it_admins) != 1:
        raise LifecycleConflictError("An active IT Admin is required for initial Head Guidance bootstrap.")
    if CounselorProfile.objects.select_for_update().filter(is_head_guidance=True).exists():
        raise LifecycleConflictError("A Head Guidance designation already exists.")

    staff_command = StaffAccountCreateCommand(
        email=command.email,
        first_name=command.first_name,
        last_name=command.last_name,
        role=RoleChoices.COUNSELOR,
        license_number=command.license_number,
        validity_days=command.validity_days,
        source_reference="institutional_bootstrap",
    )
    try:
        return _create_staff_account(
            staff_command,
            actor=active_it_admins[0],
            initial_head=True,
        )
    except (IntegrityError, ValueError) as exc:
        raise ValidationError("The initial Head Guidance account could not be created safely.") from exc


@transaction.atomic
def activate_staff_invitation(command, *, ip_address=None, user_agent=None, actor=None):
    reference = decode_activation_reference(command.token, ActivationPurpose.STAFF)
    if reference is None or command.password != command.password_confirmation:
        raise ValidationError("The invitation or password confirmation is invalid.")
    invitation = StaffAccountInvitation.objects.select_for_update().select_related("user").filter(
        token_reference=reference,
    ).first()
    now = timezone.now()
    if (
        invitation is None
        or invitation_state_reason(invitation, now=now) is not None
        or invitation.user.is_active
        or invitation.user.is_superuser
        or invitation.user.role != invitation.role_snapshot
        or not hmac.compare_digest(invitation.token_hash, hash_activation_token(command.token))
    ):
        raise ValidationError("The invitation is invalid or no longer available.")
    try:
        validate_activation_password(
            command.password,
            command.password_confirmation,
            invitation.user,
        )
    except Exception as exc:
        raise ValidationError("The password does not meet the account requirements.") from exc
    user = invitation.user
    consume_activation_invitation(user, invitation, command.password, now=now)
    record_verified_email_evidence(
        user,
        verification_method="staff_activation_invitation",
        verified_by=user,
        ip_address=ip_address,
        user_agent=user_agent,
        source_model="accounts.StaffAccountInvitation",
        source_object_id=str(invitation.id),
        reason_category="staff_account_activation",
    )
    _audit_or_raise(
        action_type="STAFF_ACCOUNT_ACTIVATED",
        actor=user,
        target=user,
        metadata={"invitation_id": str(invitation.id), "role": user.role},
    )
    return user


@transaction.atomic
def reissue_staff_invitation(actor, user, *, validity_days=None):
    user = UserModel.objects.select_for_update().filter(pk=getattr(user, "pk", user)).first()
    if user is None:
        raise NotFoundError("The staff account was not found.")
    if not can_manage_staff_accounts(actor, user.role) or user.is_active:
        raise PermissionDeniedError("Only an inactive counselor or GCO Staff account may be reinvited.")
    invitation = _create_invitation(user, created_by=actor, validity_days=validity_days)
    _queue_staff_invitation(invitation)
    _audit_or_raise(action_type="STAFF_INVITATION_REISSUED", actor=actor, target=user,
                    metadata={"invitation_id": str(invitation.id)})
    return invitation


@transaction.atomic
def revoke_staff_invitation(actor, invitation, *, reason="manual_revocation"):
    invitation = StaffAccountInvitation.objects.select_for_update().select_related("user").filter(
        pk=getattr(invitation, "pk", invitation),
    ).first()
    if invitation is None:
        raise NotFoundError("The invitation was not found.")
    if not can_manage_staff_accounts(actor, invitation.user.role):
        raise PermissionDeniedError("The invitation cannot be revoked by this actor.")
    if invitation.used_at:
        raise LifecycleConflictError("A used invitation cannot be revoked.")
    if invitation.revoked_at:
        return invitation
    invitation.revoked_at = timezone.now()
    invitation.revoked_by = actor
    invitation.revocation_reason = (reason or "manual_revocation")[:80]
    invitation.save(update_fields=["revoked_at", "revoked_by", "revocation_reason"])
    _cancel_pending_staff_deliveries([invitation.pk])
    _audit_or_raise(action_type="STAFF_INVITATION_REVOKED", actor=actor, target=invitation.user,
                    metadata={"invitation_id": str(invitation.id), "reason_code": invitation.revocation_reason})
    return invitation


@transaction.atomic
def deactivate_staff_account(actor, user, *, reason="manual_deactivation"):
    user = UserModel.objects.select_for_update().filter(pk=getattr(user, "pk", user)).first()
    if user is None:
        raise NotFoundError("The staff account was not found.")
    if not can_manage_staff_accounts(actor, user.role):
        raise PermissionDeniedError("Only Head Guidance may deactivate this account.")
    if user.role == RoleChoices.COUNSELOR and is_head_guidance(user):
        raise LifecycleConflictError("Remove the Head Guidance designation before deactivation.")
    was_active = bool(user.is_active)
    if was_active:
        user.is_active = False
        user.save(update_fields=["is_active", "updated_at"])
    pending = list(StaffAccountInvitation.objects.filter(user=user, used_at__isnull=True, revoked_at__isnull=True))
    now = timezone.now()
    if pending:
        StaffAccountInvitation.objects.filter(pk__in=[item.pk for item in pending]).update(
            revoked_at=now, revoked_by=actor, revocation_reason="account_deactivated",
        )
        _cancel_pending_staff_deliveries([item.pk for item in pending])
    if was_active or pending:
        _audit_or_raise(action_type="STAFF_ACCOUNT_DEACTIVATED", actor=actor, target=user,
                        metadata={"reason_code": (reason or "manual_deactivation")[:80]})
    return user


@transaction.atomic
def assign_head_guidance(actor, counselor):
    counselor = UserModel.objects.select_for_update().filter(pk=getattr(counselor, "pk", counselor)).first()
    if counselor is None or counselor.role != RoleChoices.COUNSELOR:
        raise ValidationError("Head Guidance must be assigned to a counselor account.")
    if not can_manage_head_guidance(actor, counselor):
        raise PermissionDeniedError("This actor cannot assign Head Guidance.")
    if not counselor.is_active:
        raise ValidationError("Only an active counselor may be designated Head Guidance.")
    profile = CounselorProfile.objects.select_for_update().filter(user=counselor).first()
    if profile is None:
        raise ValidationError("The counselor profile is missing.")
    if profile.is_head_guidance:
        return profile
    if CounselorProfile.objects.select_for_update().filter(is_head_guidance=True).exclude(pk=profile.pk).exists():
        raise LifecycleConflictError("An active Head Guidance designation already exists.")
    profile.is_head_guidance = True
    profile.save(update_fields=["is_head_guidance", "updated_at"])
    _audit_or_raise(action_type="HEAD_GUIDANCE_ASSIGNED", actor=actor, target=counselor,
                    metadata={"designation": "HEAD_GUIDANCE"})
    return profile


@transaction.atomic
def revoke_head_guidance(actor, counselor):
    counselor = UserModel.objects.select_for_update().filter(pk=getattr(counselor, "pk", counselor)).first()
    if counselor is None or counselor.role != RoleChoices.COUNSELOR:
        raise NotFoundError("The counselor account was not found.")
    if not can_manage_head_guidance(actor, counselor):
        raise PermissionDeniedError("This actor cannot revoke Head Guidance.")
    profile = CounselorProfile.objects.select_for_update().filter(user=counselor, is_head_guidance=True).first()
    if profile is None:
        raise LifecycleConflictError("The counselor is not the active Head Guidance.")
    profile.is_head_guidance = False
    profile.save(update_fields=["is_head_guidance", "updated_at"])
    _audit_or_raise(action_type="HEAD_GUIDANCE_REVOKED", actor=actor, target=counselor,
                    metadata={"designation": "HEAD_GUIDANCE"})
    return profile
