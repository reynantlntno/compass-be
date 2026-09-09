# Project: COMPASS
# File: apps/counseling/ecounseling_services.py
# Module: apps.counseling
# Purpose: Transactional services for secure e-counseling delivery

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.audit.services import audit_log
from apps.account_security.abuse_controls import (
    AbuseAction,
    evaluate as evaluate_abuse,
    record_failure as record_abuse_failure,
    record_success as record_abuse_success,
)
from apps.common.contracts import RequestMetadata
from apps.counseling.ecounseling_providers import (
    ProviderConfigurationError,
    ProviderOperationError,
    get_ecounseling_provider,
)
from apps.counseling.models import (
    CounselingSession,
    CounselingStatusHistoryReasonChoices,
    ECounselingDeniedReasonCodeChoices,
    ECounselingJoinAttemptStatusChoices,
    ECounselingJoinEvent,
    ECounselingParticipant,
    ECounselingParticipantRoleChoices,
    ECounselingProviderChoices,
    ECounselingProviderModeChoices,
    ECounselingPurposeCodeChoices,
    ECounselingRecordingConsentEvent,
    ECounselingRecordingConsentStatusChoices,
    ECounselingRecordingDecisionChoices,
    ECounselingRetentionPolicyCodeChoices,
    ECounselingSession,
    ECounselingStatusChoices,
    ECounselingRecordingScopeCodeChoices,
    SessionModeChoices,
    SessionSourceChoices,
    SessionStatusChoices,
    SessionTypeChoices,
)
from apps.counseling.commands import (
    ECounselingCancelCommand,
    ECounselingCompletionCommand,
    ECounselingConsentDecisionCommand,
    ECounselingConsentRequestCommand,
    ECounselingCreateCommand,
    ECounselingParticipantAddCommand,
    ECounselingParticipantRevokeCommand,
    CounselingNoteCommand,
)
from apps.counseling.encryption import SESSION_CONCERN, initialize_group
from apps.counseling.history import create_session_status_history
from apps.counseling.policies import (
    ECounselingJoinState,
    ECounselingJoinStateCode,
    can_add_ecounseling_participant,
    can_cancel_ecounseling_session,
    can_create_ecounseling_session,
    can_decide_recording_consent,
    can_end_ecounseling_session,
    can_request_recording_consent,
    can_revoke_ecounseling_participant,
    can_withdraw_recording_consent,
    project_ecounseling_join_state,
)
from apps.access_control.rules import is_active_nonlegacy_actor, is_counselor, is_student, owns_user
from apps.counseling.recording_policy import (
    RECORDING_UNAVAILABLE_MESSAGE,
    recording_availability_projection,
    recording_is_blocked,
)
from apps.counseling.reference_codes import (
    generate_ecounseling_reference_code,
    generate_session_reference_code,
)
from apps.common.exceptions import PermissionDeniedError, ValidationError


class ECounselingPermissionError(PermissionDeniedError):
    pass


class ECounselingValidationError(ValidationError):
    pass


RECORDING_REQUEST_UNAVAILABLE_MESSAGE = (
    RECORDING_UNAVAILABLE_MESSAGE
)


class ECounselingJoinDenied(PermissionDeniedError):
    def __init__(self, reason_code, join_state=None):
        self.reason_code = reason_code
        self.join_state = join_state
        super().__init__(reason_code)


@dataclass(frozen=True)
class JoinValidationResult:
    allowed: bool
    reason_code: str = ""
    join_state: ECounselingJoinState | None = None


def _hash_value(value: str) -> str:
    if not value:
        return ""
    key = getattr(settings, "AUDIT_HASH_SECRET", settings.SECRET_KEY).encode("utf-8")
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()


def _room_slug_and_hash(reference_code: str) -> tuple[str, str]:
    prefix = getattr(settings, "ECOUNSELING_ROOM_PREFIX", "compass-ecs") or "compass-ecs"
    random_part = secrets.token_urlsafe(18).replace("_", "-").lower()
    slug = f"{prefix}-{random_part}"[:120].strip("-")
    key = getattr(settings, "ECOUNSELING_ROOM_SALT", settings.SECRET_KEY).encode("utf-8")
    digest = hmac.new(key, f"{reference_code}:{slug}".encode("utf-8"), hashlib.sha256).hexdigest()
    return slug, digest


def _join_window(start_at, end_at):
    before = resolve_runtime_setting(
        "counseling.ecounseling_controls",
        "ECOUNSELING_JOIN_WINDOW_BEFORE_MINUTES",
    )
    after = resolve_runtime_setting(
        "counseling.ecounseling_controls",
        "ECOUNSELING_JOIN_WINDOW_AFTER_MINUTES",
    )
    return start_at - timedelta(minutes=before), end_at + timedelta(minutes=after)


def _audit(action_type, user, ecounseling_session, metadata=None, severity="INFO"):
    audit_log(
        action_type=action_type,
        event_category="ECOUNSELING",
        severity=severity,
        target_model="ECounselingSession",
        target_object_id=str(ecounseling_session.pk),
        actor_user=user,
        reference_code=ecounseling_session.reference_code,
        source_app="counseling",
        metadata=metadata or {},
    )


def recording_consent_requests_available() -> bool:
    # recording.safety is the server-authoritative scope boundary. Provider capability
    # alone is never an authorization to collect a new consent.
    projection = recording_availability_projection()
    if not projection.allow_new_consent:
        return False
    # privacy.boundary additionally requires an approved recording notice and active
    # category-specific retention rule before any future reactivation.
    from apps.privacy.services import recording_consent_is_available

    if not recording_consent_is_available():
        return False
    try:
        provider = get_ecounseling_provider()
    except (ProviderConfigurationError, ProviderOperationError):
        return False
    return bool(provider.capabilities().supports_recording_controls)


def _participant_role(user, ecounseling_session) -> str:
    if not is_active_nonlegacy_actor(user) or not ecounseling_session:
        return ""
    session = ecounseling_session.counseling_session
    if is_student(user) and owns_user(user, session.student_id):
        return ECounselingParticipantRoleChoices.STUDENT
    if is_counselor(user) and session.assigned_counselor_id == user.pk:
        return ECounselingParticipantRoleChoices.COUNSELOR
    grant = ecounseling_session.participants.filter(
        user=user,
        role=ECounselingParticipantRoleChoices.APPROVED_PARTICIPANT,
        is_active=True,
        revoked_at__isnull=True,
    ).first()
    if grant:
        return grant.role
    return ""


def _create_derived_participants(user, ecounseling_session):
    now = timezone.now()
    session = ecounseling_session.counseling_session
    rows = [
        (session.student, ECounselingParticipantRoleChoices.STUDENT),
    ]
    if session.assigned_counselor_id:
        rows.append((session.assigned_counselor, ECounselingParticipantRoleChoices.COUNSELOR))
    for participant_user, role in rows:
        if participant_user and is_active_nonlegacy_actor(participant_user):
            ECounselingParticipant.objects.get_or_create(
                ecounseling_session=ecounseling_session,
                user=participant_user,
                is_active=True,
                defaults={
                    "role": role,
                    "approved_by": user,
                    "approved_at": now,
                    "purpose_code": ECounselingPurposeCodeChoices.COUNSELING_DELIVERY,
                },
            )


def create_ecounseling_session(user, command: ECounselingCreateCommand):
    if not isinstance(command, ECounselingCreateCommand):
        raise ECounselingValidationError(
            "E-counseling creation requires an ECounselingCreateCommand."
        )
    from django.contrib.auth import get_user_model

    User = get_user_model()
    student = User.objects.filter(pk=command.student_id, is_active=True).first()
    if student is None:
        raise ECounselingValidationError("The student is not available.")
    assigned_counselor = user
    if command.assigned_counselor_id:
        assigned_counselor = User.objects.filter(
            pk=command.assigned_counselor_id,
            is_active=True,
        ).first()
        if assigned_counselor is None:
            raise ECounselingValidationError("The assigned counselor is not available.")
    if not can_create_ecounseling_session(user, student=student, assigned_counselor=assigned_counselor):
        raise ECounselingPermissionError("You cannot create this e-counseling session.")

    scheduled_start_at = command.scheduled_start_at
    scheduled_end_at = command.scheduled_end_at
    if not scheduled_start_at or not scheduled_end_at:
        raise ECounselingValidationError("Scheduled start and end are required.")
    if scheduled_start_at >= scheduled_end_at:
        raise ECounselingValidationError("Scheduled end must be after scheduled start.")

    with transaction.atomic():
        session = CounselingSession(
            reference_code=generate_session_reference_code(),
            student=student,
            assigned_counselor=assigned_counselor,
            session_type=command.session_type or SessionTypeChoices.COUNSELING,
            session_mode=SessionModeChoices.ONLINE,
            session_source=SessionSourceChoices.ECOUNSELING,
            status=SessionStatusChoices.SCHEDULED,
            scheduled_start_at=scheduled_start_at,
            scheduled_end_at=scheduled_end_at,
            concern_summary="",
        )
        initialize_group(session, SESSION_CONCERN, {"concern_summary": ""})
        session.save()
        create_session_status_history(
            session=session,
            from_status="",
            to_status=session.status,
            changed_by=user,
            reason=CounselingStatusHistoryReasonChoices.ECOUNSELING_CREATED,
        )
    ecounseling_session = attach_ecounseling_to_session(user, session, command)
    return ecounseling_session


def attach_ecounseling_to_session(user, counseling_session, command: ECounselingCreateCommand):
    """Persist the workspace, then reconcile its Daily room after commit.

    Provider calls are deliberately outside the database transaction. Retries
    reuse the stored room slug, while the workspace GET path never invokes
    this explicit attach operation.
    """
    if not isinstance(command, ECounselingCreateCommand):
        raise ECounselingValidationError(
            "E-counseling attach requires an ECounselingCreateCommand."
        )
    with transaction.atomic():
        counseling_session = CounselingSession.objects.select_for_update().get(pk=counseling_session.pk)
        if not can_create_ecounseling_session(user, counseling_session=counseling_session):
            raise ECounselingPermissionError("You cannot attach e-counseling to this session.")
        existing = getattr(counseling_session, "ecounseling_session", None)
        if existing is not None:
            ecounseling_session = existing
            created = False
        else:
            scheduled_start_at = command.scheduled_start_at or counseling_session.scheduled_start_at
            scheduled_end_at = command.scheduled_end_at or counseling_session.scheduled_end_at
            if not scheduled_start_at or not scheduled_end_at:
                raise ECounselingValidationError("Scheduled start and end are required.")
            if scheduled_start_at >= scheduled_end_at:
                raise ECounselingValidationError("Scheduled end must be after scheduled start.")

            reference_code = generate_ecounseling_reference_code()
            room_slug, room_hash = _room_slug_and_hash(reference_code)
            window_start, window_end = _join_window(scheduled_start_at, scheduled_end_at)
            ecounseling_session = ECounselingSession.objects.create(
                reference_code=reference_code,
                counseling_session=counseling_session,
                provider=ECounselingProviderChoices.DAILY,
                provider_mode=getattr(
                    settings,
                    "ECOUNSELING_PROVIDER_MODE",
                    ECounselingProviderModeChoices.DAILY_CLOUD,
                ),
                room_slug=room_slug,
                room_name_hash=room_hash,
                room_display_name=f"COMPASS {reference_code}",
                scheduled_start_at=scheduled_start_at,
                scheduled_end_at=scheduled_end_at,
                join_window_start_at=window_start,
                join_window_end_at=window_end,
                moderator_user=counseling_session.assigned_counselor,
            )
            _create_derived_participants(user, ecounseling_session)
            created = True

    try:
        provider = get_ecounseling_provider()
        provider.ensure_private_room(
            ecounseling_session.room_slug,
            nbf=int(ecounseling_session.join_window_start_at.timestamp()),
            exp=int(ecounseling_session.join_window_end_at.timestamp()),
        )
    except (ProviderConfigurationError, ProviderOperationError) as exc:
        if isinstance(exc, ProviderConfigurationError) and "not private" in str(exc).lower():
            if created:
                ECounselingSession.objects.filter(pk=ecounseling_session.pk).delete()
            raise ECounselingValidationError("Failed to provision a private e-counseling room.") from exc
        # The official session can exist while provider provisioning is
        # unavailable. Join remains fail-closed until a later explicit
        # reconciliation succeeds; the appointment workflow must not fabricate
        # a provider room or roll back the authoritative session record.
        _audit(
            "ECOUNSELING_ROOM_PROVISIONING_DEFERRED",
            user,
            ecounseling_session,
            metadata={"safe_code": getattr(exc, "safe_code", "DAILY_UNAVAILABLE")},
            severity="WARNING",
        )

    _audit(
        "ECOUNSELING_ATTACHED",
        user,
        ecounseling_session,
        metadata={"session_id": str(counseling_session.pk), "status": ecounseling_session.status},
    )
    return ecounseling_session


def _load_ecounseling_session(reference_code):
    """Resolve a stable e-counseling reference into a locked row."""
    normalized = str(getattr(reference_code, "reference_code", reference_code) or "").strip()
    if not normalized:
        raise ECounselingValidationError("An e-counseling reference is required.")
    return ECounselingSession.objects.select_for_update().get(reference_code=normalized)


def request_recording_consent(user, ecounseling_reference, command: ECounselingConsentRequestCommand):
    if not isinstance(command, ECounselingConsentRequestCommand):
        raise ECounselingValidationError(
            "Recording consent requests require an ECounselingConsentRequestCommand."
        )
    if recording_is_blocked():
        raise ECounselingValidationError(RECORDING_REQUEST_UNAVAILABLE_MESSAGE)
    ecounseling_session = _load_ecounseling_session(ecounseling_reference)
    if not can_request_recording_consent(user, ecounseling_session):
        raise ECounselingPermissionError("You cannot request recording consent.")
    if not recording_consent_requests_available():
        raise ECounselingValidationError(RECORDING_REQUEST_UNAVAILABLE_MESSAGE)
    if ecounseling_session.recording_consent_status != ECounselingRecordingConsentStatusChoices.NOT_REQUESTED:
        raise ECounselingValidationError(
            "Recording consent may be requested only once for this session."
        )
    projection = recording_availability_projection()
    purpose_code = command.purpose_code
    if purpose_code != ECounselingPurposeCodeChoices.COUNSELING_DELIVERY:
        raise ECounselingValidationError("Recording consent purpose is not available for counseling delivery.")
    scope_code = command.scope_code or ECounselingRecordingScopeCodeChoices.AUDIO_ONLY
    if scope_code not in projection.available_scopes:
        raise ECounselingValidationError("The requested recording scope is not currently available.")
    # The retention snapshot is derived from the exact active Governance
    # category.  The client cannot select a legacy/deferred retention value.
    from apps.privacy.services import recording_retention_days

    if recording_retention_days() <= 0:
        raise ECounselingValidationError("Recording retention is not approved for this environment.")
    retention_policy_code = ECounselingRetentionPolicyCodeChoices.GOVERNANCE_RETENTION_POLICY
    now = timezone.now()
    from apps.privacy.services import resolve_current_notice
    recording_notice = resolve_current_notice(
        "ecounseling-recording",
        "ecounseling_recording",
    )
    ecounseling_session.recording_requested = True
    ecounseling_session.recording_consent_status = ECounselingRecordingConsentStatusChoices.PENDING
    ecounseling_session.recording_consent_requested_by = user
    ecounseling_session.recording_consent_requested_at = now
    ecounseling_session.recording_consent_decided_by = None
    ecounseling_session.recording_consent_decided_at = None
    ecounseling_session.recording_consent_withdrawn_at = None
    ecounseling_session.save(update_fields=[
        "recording_requested",
        "recording_consent_status",
        "recording_consent_requested_by",
        "recording_consent_requested_at",
        "recording_consent_decided_by",
        "recording_consent_decided_at",
        "recording_consent_withdrawn_at",
        "updated_at",
    ])
    ECounselingRecordingConsentEvent.objects.create(
        ecounseling_session=ecounseling_session,
        requested_by=user,
        requested_at=now,
        decision=ECounselingRecordingDecisionChoices.REQUESTED,
        purpose_code=purpose_code,
        scope_code=scope_code,
        retention_policy_code=retention_policy_code,
        notice_version=str(recording_notice.version)[:40],
        privacy_notice_revision=recording_notice,
    )
    _audit("RECORDING_CONSENT_REQUESTED", user, ecounseling_session, metadata={"decision": "REQUESTED"})
    from apps.notifications.dispatch import enqueue_notification_event

    enqueue_notification_event(
        "ecounseling.recording_consent_requested",
        {
            "session_id": str(ecounseling_session.pk),
            "action": "consent_requested",
            "status": "Pending",
        },
        related_object=ecounseling_session,
        event_key=f"ecounseling:recording_consent_requested:{ecounseling_session.pk}:{now.isoformat()}",
    )
    return ecounseling_session


@transaction.atomic
def decide_recording_consent(user, ecounseling_reference, command: ECounselingConsentDecisionCommand):
    if not isinstance(command, ECounselingConsentDecisionCommand):
        raise ECounselingValidationError(
            "Recording consent decisions require an ECounselingConsentDecisionCommand."
        )
    decision = command.decision
    if recording_is_blocked():
        raise ECounselingValidationError(RECORDING_UNAVAILABLE_MESSAGE)
    ecounseling_session = _load_ecounseling_session(ecounseling_reference)
    if not can_decide_recording_consent(user, ecounseling_session):
        raise ECounselingPermissionError("You cannot decide recording consent.")
    if decision not in (ECounselingRecordingDecisionChoices.APPROVED, ECounselingRecordingDecisionChoices.DENIED):
        raise ECounselingValidationError("Invalid recording consent decision.")
    if ecounseling_session.recording_consent_status != ECounselingRecordingConsentStatusChoices.PENDING:
        raise ECounselingValidationError("Recording consent decisions require a pending request.")
    now = timezone.now()
    request_event = (
        ecounseling_session.recording_consent_events.filter(
            decision=ECounselingRecordingDecisionChoices.REQUESTED,
        )
        .order_by("-created_at")
        .first()
    )
    if request_event is None:
        raise ECounselingValidationError("Recording consent request evidence is unavailable.")
    status = (
        ECounselingRecordingConsentStatusChoices.APPROVED
        if decision == ECounselingRecordingDecisionChoices.APPROVED
        else ECounselingRecordingConsentStatusChoices.DENIED
    )
    ecounseling_session.recording_consent_status = status
    ecounseling_session.recording_consent_decided_by = user
    ecounseling_session.recording_consent_decided_at = now
    ecounseling_session.recording_consent_withdrawn_at = None
    ecounseling_session.save(update_fields=[
        "recording_consent_status",
        "recording_consent_decided_by",
        "recording_consent_decided_at",
        "recording_consent_withdrawn_at",
        "updated_at",
    ])
    ECounselingRecordingConsentEvent.objects.create(
        ecounseling_session=ecounseling_session,
        decided_by=user,
        decision=decision,
        decision_at=now,
        notice_version=request_event.notice_version,
        purpose_code=request_event.purpose_code,
        scope_code=request_event.scope_code,
        retention_policy_code=request_event.retention_policy_code,
        privacy_notice_revision=request_event.privacy_notice_revision,
    )
    _audit("RECORDING_CONSENT_DECIDED", user, ecounseling_session, metadata={"decision": decision})
    return ecounseling_session


@transaction.atomic
def withdraw_recording_consent(user, ecounseling_reference):
    ecounseling_session = _load_ecounseling_session(ecounseling_reference)
    if not can_withdraw_recording_consent(user, ecounseling_session):
        raise ECounselingPermissionError("You cannot withdraw recording consent.")
    if ecounseling_session.recording_consent_status != ECounselingRecordingConsentStatusChoices.APPROVED:
        raise ECounselingValidationError("Only approved recording consent can be withdrawn.")
    now = timezone.now()
    ecounseling_session.recording_consent_status = ECounselingRecordingConsentStatusChoices.WITHDRAWN
    ecounseling_session.recording_consent_withdrawn_at = now
    ecounseling_session.save(update_fields=[
        "recording_consent_status",
        "recording_consent_withdrawn_at",
        "updated_at",
    ])
    ECounselingRecordingConsentEvent.objects.create(
        ecounseling_session=ecounseling_session,
        withdrawn_by=user,
        decision=ECounselingRecordingDecisionChoices.WITHDRAWN,
        withdrawn_at=now,
        privacy_notice_revision=(
            ecounseling_session.recording_consent_events.order_by("-created_at").first().privacy_notice_revision
            if ecounseling_session.recording_consent_events.exists()
            else None
        ),
    )
    _audit("RECORDING_CONSENT_WITHDRAWN", user, ecounseling_session, metadata={"decision": "WITHDRAWN"})
    from apps.counseling.recording_services import stop_active_recording_for_withdrawal

    transaction.on_commit(
        lambda: stop_active_recording_for_withdrawal(user, ecounseling_session)
    )
    return ecounseling_session


@transaction.atomic
def add_ecounseling_participant(user, ecounseling_reference, command: ECounselingParticipantAddCommand):
    if not isinstance(command, ECounselingParticipantAddCommand):
        raise ECounselingValidationError(
            "Participant additions require an ECounselingParticipantAddCommand."
        )
    role = command.role
    purpose_code = command.purpose_code
    from django.contrib.auth import get_user_model

    target_user = (
        get_user_model()
        .objects.filter(pk=command.user_id, is_active=True)
        .first()
    )
    if target_user is None:
        raise ECounselingValidationError("The participant account is not available.")
    ecounseling_session = _load_ecounseling_session(ecounseling_reference)
    if not can_add_ecounseling_participant(
        user,
        ecounseling_session,
        target_user,
        role=role,
        purpose_code=purpose_code,
    ):
        raise ECounselingPermissionError("You cannot add this e-counseling participant.")

    if role != ECounselingParticipantRoleChoices.APPROVED_PARTICIPANT:
        raise ECounselingValidationError("Only exact-session approved participant grants may be added.")
    if purpose_code not in ECounselingPurposeCodeChoices.values:
        raise ECounselingValidationError("Invalid e-counseling participant purpose.")

    if ECounselingParticipant.objects.filter(
        ecounseling_session=ecounseling_session,
        user=target_user,
        is_active=True,
    ).exists():
        raise ECounselingValidationError("This participant already has an active grant for the session.")

    had_revoked_grant = ECounselingParticipant.objects.filter(
        ecounseling_session=ecounseling_session,
        user=target_user,
        is_active=False,
        revoked_at__isnull=False,
    ).exists()
    participant = ECounselingParticipant.objects.create(
        ecounseling_session=ecounseling_session,
        user=target_user,
        role=role,
        approved_by=user,
        approved_at=timezone.now(),
        purpose_code=purpose_code,
    )
    _audit(
        "ECOUNSELING_PARTICIPANT_REGRANTED" if had_revoked_grant else "ECOUNSELING_PARTICIPANT_ADDED",
        user,
        ecounseling_session,
        metadata={
            "participant_user_id": str(target_user.pk),
            "participant_role": role,
            "purpose_code": purpose_code,
            "new_grant_after_revocation": had_revoked_grant,
        },
    )
    return participant


@transaction.atomic
def revoke_ecounseling_participant(user, ecounseling_reference, command: ECounselingParticipantRevokeCommand):
    if not isinstance(command, ECounselingParticipantRevokeCommand):
        raise ECounselingValidationError(
            "Participant revocation requires an ECounselingParticipantRevokeCommand."
        )
    from apps.counseling.models import ECounselingParticipant

    try:
        participant = ECounselingParticipant.objects.select_for_update().get(
            pk=command.participant_id,
        )
    except (ECounselingParticipant.DoesNotExist, ValueError, TypeError) as exc:
        from apps.common.exceptions import NotFoundError

        raise NotFoundError("The e-counseling participant was not found.") from exc
    if not can_revoke_ecounseling_participant(user, participant):
        raise ECounselingPermissionError("You cannot revoke this e-counseling participant.")
    participant.is_active = False
    participant.revoked_by = user
    participant.revoked_at = timezone.now()
    participant.save(update_fields=["is_active", "revoked_by", "revoked_at", "updated_at"])
    _audit(
        "ECOUNSELING_PARTICIPANT_REVOKED",
        user,
        participant.ecounseling_session,
        metadata={"participant_user_id": str(participant.user_id), "participant_role": participant.role},
    )
    return participant


def validate_provider_runtime_safety(provider, django_settings=settings, debug=None):
    return provider.validate_runtime_safety()


def get_ecounseling_join_state(
    user,
    ecounseling_session,
    *,
    now=None,
    provider=None,
    check_provider=True,
) -> ECounselingJoinState:
    """Return the server-authoritative, presentation-safe join projection.

    The provider check is deliberately local/runtime-only. It validates the
    configured provider boundary but does not call Daily or mint credentials.
    """

    state = project_ecounseling_join_state(
        user,
        ecounseling_session,
        now=now,
    )
    if not check_provider or not state.available:
        return state

    try:
        provider = provider or get_ecounseling_provider()
        validate_provider_runtime_safety(provider)
    except (ProviderConfigurationError, ProviderOperationError):
        return project_ecounseling_join_state(
            user,
            ecounseling_session,
            now=now,
            provider_available=False,
        )
    return state


def validate_join_request(user, ecounseling_session, now=None) -> JoinValidationResult:
    now = now or timezone.now()
    if not user or not user.is_authenticated:
        return JoinValidationResult(False, ECounselingDeniedReasonCodeChoices.NOT_AUTHENTICATED)

    if ecounseling_session.counseling_session.session_mode != SessionModeChoices.ONLINE:
        return JoinValidationResult(False, ECounselingDeniedReasonCodeChoices.SESSION_NOT_ONLINE)

    state = get_ecounseling_join_state(
        user,
        ecounseling_session,
        now=now,
        check_provider=False,
    )
    reason = {
        ECounselingJoinStateCode.CANCELLED.value: ECounselingDeniedReasonCodeChoices.SESSION_CANCELLED,
        ECounselingJoinStateCode.CLOSED.value: ECounselingDeniedReasonCodeChoices.SESSION_COMPLETED,
        ECounselingJoinStateCode.ENDED.value: ECounselingDeniedReasonCodeChoices.OUTSIDE_JOIN_WINDOW,
        ECounselingJoinStateCode.NOT_YET_OPEN.value: ECounselingDeniedReasonCodeChoices.OUTSIDE_JOIN_WINDOW,
        ECounselingJoinStateCode.UNAUTHORIZED_OR_NOT_FOUND.value: ECounselingDeniedReasonCodeChoices.NOT_PARTICIPANT,
    }.get(state.code)
    if reason:
        return JoinValidationResult(False, reason, state)
    return JoinValidationResult(True, join_state=state)


def record_join_event(user, ecounseling_session, role, request_context: RequestMetadata | None = None):
    request_context = request_context or RequestMetadata()
    return ECounselingJoinEvent.objects.create(
        ecounseling_session=ecounseling_session,
        counseling_session=ecounseling_session.counseling_session,
        user=user,
        role=role,
        attempt_status=ECounselingJoinAttemptStatusChoices.ALLOWED,
        ip_hash=_hash_value(request_context.ip_address),
        user_agent_hash=_hash_value(request_context.user_agent),
        joined_at=timezone.now(),
    )


def record_denied_join_event(user, ecounseling_session, reason_code, request_context: RequestMetadata | None = None):
    request_context = request_context or RequestMetadata()
    return ECounselingJoinEvent.objects.create(
        ecounseling_session=ecounseling_session,
        counseling_session=ecounseling_session.counseling_session,
        user=user if user and user.is_authenticated else None,
        role=_participant_role(user, ecounseling_session),
        attempt_status=ECounselingJoinAttemptStatusChoices.DENIED,
        denied_reason_code=reason_code,
        ip_hash=_hash_value(request_context.ip_address),
        user_agent_hash=_hash_value(request_context.user_agent),
    )


def record_leave_event(user, ecounseling_session):
    event = ECounselingJoinEvent.objects.filter(
        ecounseling_session=ecounseling_session,
        user=user,
        attempt_status=ECounselingJoinAttemptStatusChoices.ALLOWED,
        left_at__isnull=True,
    ).order_by("-created_at").first()
    if event:
        event.left_at = timezone.now()
        event.save(update_fields=["left_at", "updated_at"])
    return event


def generate_join_context(
    user,
    ecounseling_session,
    request_context: RequestMetadata | None = None,
):
    request_context = request_context or RequestMetadata()
    now = timezone.now()
    ip = request_context.ip_address
    session_key = request_context.session_key
    subject = getattr(user, "pk", None) if user and user.is_authenticated else None
    token_scope = getattr(ecounseling_session, "reference_code", None)
    decision = evaluate_abuse(
        AbuseAction.ECOCOUNSELING_JOIN,
        subject=subject,
        ip=ip,
        session=session_key,
        token=token_scope,
    )

    def deny(reason_code, join_state=None, *, abuse_already_recorded=False):
        if not abuse_already_recorded:
            record_abuse_failure(
                AbuseAction.ECOCOUNSELING_JOIN,
                subject=subject,
                ip=ip,
                session=session_key,
                token=token_scope,
                reason_code=str(reason_code),
            )
        record_denied_join_event(
            user,
            ecounseling_session,
            reason_code,
            request_context=request_context,
        )
        _audit(
            "ECOUNSELING_JOIN_DENIED",
            user if user and user.is_authenticated else None,
            ecounseling_session,
            metadata={"reason_code": reason_code},
            severity="WARNING",
        )
        raise ECounselingJoinDenied(reason_code, join_state=join_state)

    if not decision.allowed:
        deny(ECounselingDeniedReasonCodeChoices.RATE_LIMITED)

    validation = validate_join_request(user, ecounseling_session, now=now)
    if not validation.allowed:
        deny(validation.reason_code, join_state=validation.join_state)

    try:
        provider = get_ecounseling_provider()
        # GET projections only perform this local safety check. The explicit
        # join request is the first point at which provider credentials may be
        # generated or a remote provider operation may occur.
        validate_provider_runtime_safety(provider)
    except (ProviderConfigurationError, ProviderOperationError) as exc:
        current_state = project_ecounseling_join_state(
            user,
            ecounseling_session,
            now=timezone.now(),
        )
        if current_state.code in {
            ECounselingJoinStateCode.ENDED.value,
            ECounselingJoinStateCode.CANCELLED.value,
            ECounselingJoinStateCode.CLOSED.value,
            ECounselingJoinStateCode.NOT_YET_OPEN.value,
        }:
            state = current_state
            reason = {
                ECounselingJoinStateCode.ENDED.value: ECounselingDeniedReasonCodeChoices.OUTSIDE_JOIN_WINDOW,
                ECounselingJoinStateCode.CANCELLED.value: ECounselingDeniedReasonCodeChoices.SESSION_CANCELLED,
                ECounselingJoinStateCode.CLOSED.value: ECounselingDeniedReasonCodeChoices.SESSION_COMPLETED,
                ECounselingJoinStateCode.NOT_YET_OPEN.value: ECounselingDeniedReasonCodeChoices.OUTSIDE_JOIN_WINDOW,
            }[current_state.code]
            try:
                deny(reason, join_state=state)
            except ECounselingJoinDenied as denied:
                raise denied from exc
        reason = (
            ECounselingDeniedReasonCodeChoices.UNSAFE_PROVIDER_CONFIGURATION
            if any(
                marker in str(exc).lower()
                for marker in (
                    "production",
                    "protection",
                    "authentication",
                    "authenticated",
                    "meeting-token",
                )
            )
            else ECounselingDeniedReasonCodeChoices.PROVIDER_UNAVAILABLE
        )
        state = project_ecounseling_join_state(
            user,
            ecounseling_session,
            now=now,
            provider_available=False,
        )
        deny(reason, join_state=state)

    try:
        recording_allowed = (
            recording_availability_projection().controls_available
            and ecounseling_session.recording_consent_status
            == ECounselingRecordingConsentStatusChoices.APPROVED
        )
        role = _participant_role(user, ecounseling_session)
        display_name = (
            "Student"
            if role == ECounselingParticipantRoleChoices.STUDENT
            else "Guidance Counselor"
            if role == ECounselingParticipantRoleChoices.COUNSELOR
            else "Approved participant"
        )
        context = provider.build_join_context(
            ecounseling_session,
            display_name=display_name,
            participant_role=role,
            recording_allowed=recording_allowed,
            now=now,
        )
    except (ProviderConfigurationError, ProviderOperationError) as exc:
        current_state = project_ecounseling_join_state(
            user,
            ecounseling_session,
            now=timezone.now(),
        )
        if current_state.code in {
            ECounselingJoinStateCode.ENDED.value,
            ECounselingJoinStateCode.CANCELLED.value,
            ECounselingJoinStateCode.CLOSED.value,
            ECounselingJoinStateCode.NOT_YET_OPEN.value,
        }:
            reason = {
                ECounselingJoinStateCode.ENDED.value: ECounselingDeniedReasonCodeChoices.OUTSIDE_JOIN_WINDOW,
                ECounselingJoinStateCode.CANCELLED.value: ECounselingDeniedReasonCodeChoices.SESSION_CANCELLED,
                ECounselingJoinStateCode.CLOSED.value: ECounselingDeniedReasonCodeChoices.SESSION_COMPLETED,
                ECounselingJoinStateCode.NOT_YET_OPEN.value: ECounselingDeniedReasonCodeChoices.OUTSIDE_JOIN_WINDOW,
            }[current_state.code]
            try:
                deny(reason, join_state=current_state)
            except ECounselingJoinDenied as denied:
                raise denied from exc
        reason = (
            ECounselingDeniedReasonCodeChoices.UNSAFE_PROVIDER_CONFIGURATION
            if any(
                marker in str(exc).lower()
                for marker in (
                    "production",
                    "protection",
                    "authentication",
                    "authenticated",
                    "meeting-token",
                )
            )
            else ECounselingDeniedReasonCodeChoices.PROVIDER_UNAVAILABLE
        )
        state = project_ecounseling_join_state(
            user,
            ecounseling_session,
            now=timezone.now(),
            provider_available=False,
        )
        try:
            deny(reason, join_state=state)
        except ECounselingJoinDenied as denied:
            raise denied from exc

    # The provider call can race expiry, cancellation, reassignment, or grant
    # revocation. Re-read the authoritative row and discard the context unless
    # the same actor/session is still joinable at response time.
    fresh_session = (
        ECounselingSession.objects.select_related("counseling_session")
        .get(pk=ecounseling_session.pk)
    )
    final_state = get_ecounseling_join_state(
        user,
        fresh_session,
        now=timezone.now(),
        provider=provider,
    )
    if not final_state.available:
        reason = {
            ECounselingJoinStateCode.CANCELLED.value: ECounselingDeniedReasonCodeChoices.SESSION_CANCELLED,
            ECounselingJoinStateCode.CLOSED.value: ECounselingDeniedReasonCodeChoices.SESSION_COMPLETED,
            ECounselingJoinStateCode.ENDED.value: ECounselingDeniedReasonCodeChoices.OUTSIDE_JOIN_WINDOW,
            ECounselingJoinStateCode.NOT_YET_OPEN.value: ECounselingDeniedReasonCodeChoices.OUTSIDE_JOIN_WINDOW,
            ECounselingJoinStateCode.PROVIDER_UNAVAILABLE.value: ECounselingDeniedReasonCodeChoices.PROVIDER_UNAVAILABLE,
        }.get(final_state.code, ECounselingDeniedReasonCodeChoices.NOT_PARTICIPANT)
        ecounseling_session = fresh_session
        deny(reason, join_state=final_state)

    ecounseling_session = fresh_session
    role = _participant_role(user, ecounseling_session)
    record_join_event(user, ecounseling_session, role, request_context=request_context)
    record_abuse_success(
        AbuseAction.ECOCOUNSELING_JOIN,
        subject=subject,
        ip=ip,
        session=session_key,
        token=token_scope,
    )
    _audit("ECOUNSELING_JOIN_ALLOWED", user, ecounseling_session, metadata={"participant_role": role})
    return context


@transaction.atomic
def expire_ecounseling_session(user_or_system, ecounseling_session):
    ecounseling_session = ECounselingSession.objects.select_for_update().get(pk=ecounseling_session.pk)
    if ecounseling_session.status not in (
        ECounselingStatusChoices.COMPLETED,
        ECounselingStatusChoices.CANCELLED,
        ECounselingStatusChoices.EXPIRED,
    ):
        ecounseling_session.status = ECounselingStatusChoices.EXPIRED
        ecounseling_session.save(update_fields=["status", "updated_at"])
        _audit("ECOUNSELING_EXPIRED", user_or_system if getattr(user_or_system, "is_authenticated", False) else None, ecounseling_session)
        from apps.counseling.recording_services import stop_active_recording_for_withdrawal

        transaction.on_commit(
            lambda: stop_active_recording_for_withdrawal(
                user_or_system if getattr(user_or_system, "is_authenticated", False) else None,
                ecounseling_session,
            )
        )
    return ecounseling_session


@transaction.atomic
def cancel_ecounseling_session(user, ecounseling_reference, command: ECounselingCancelCommand | None = None):
    if command is None:
        command = ECounselingCancelCommand()
    if not isinstance(command, ECounselingCancelCommand):
        raise ECounselingValidationError(
            "E-counseling cancellation requires an ECounselingCancelCommand."
        )
    ecounseling_session = _load_ecounseling_session(ecounseling_reference)
    if not can_cancel_ecounseling_session(user, ecounseling_session):
        raise ECounselingPermissionError("You cannot cancel this e-counseling session.")
    from apps.orchestration.commands import LinkedCounselingSessionCommand
    from apps.orchestration.use_cases import cancel_counseling_session_with_linked_appointment

    cancel_counseling_session_with_linked_appointment(
        user,
        LinkedCounselingSessionCommand(
            session_id=str(ecounseling_session.counseling_session_id),
            reason="Online counseling session cancelled by the office.",
        ),
    )
    ecounseling_session.refresh_from_db()
    from apps.counseling.recording_services import stop_active_recording_for_withdrawal

    transaction.on_commit(lambda: stop_active_recording_for_withdrawal(user, ecounseling_session))
    return ecounseling_session


@transaction.atomic
def complete_ecounseling_session(user, ecounseling_session, command: ECounselingCompletionCommand | None = None):
    if command is None:
        command = ECounselingCompletionCommand()
    if not isinstance(command, ECounselingCompletionCommand):
        raise ECounselingPermissionError("E-counseling completion requires a validated command.")
    ecounseling_session = ECounselingSession.objects.select_for_update().get(pk=ecounseling_session.pk)
    if not can_end_ecounseling_session(user, ecounseling_session):
        raise ECounselingPermissionError("You cannot complete this e-counseling session.")
    note_command = command.note if isinstance(command.note, CounselingNoteCommand) else CounselingNoteCommand()
    from apps.orchestration.commands import CompleteCounselingSessionCommand
    from apps.orchestration.use_cases import complete_counseling_session_with_linked_appointment

    complete_counseling_session_with_linked_appointment(
        user,
        CompleteCounselingSessionCommand(
            session_id=str(ecounseling_session.counseling_session_id),
            note=note_command,
        ),
    )
    ecounseling_session.refresh_from_db()
    return ecounseling_session


def sync_ecounseling_projection(session):
    """Mirror the delivery status from the authoritative CounselingSession."""
    try:
        ecounseling_session = session.ecounseling_session
    except ECounselingSession.DoesNotExist:
        return None
    mapping = {
        SessionStatusChoices.SCHEDULED: ECounselingStatusChoices.SCHEDULED,
        SessionStatusChoices.IN_PROGRESS: ECounselingStatusChoices.ACTIVE,
        SessionStatusChoices.COUNSELOR_NOTES_DRAFT: ECounselingStatusChoices.WAITING,
        SessionStatusChoices.COMPLETED: ECounselingStatusChoices.COMPLETED,
        SessionStatusChoices.FINALIZED: ECounselingStatusChoices.COMPLETED,
        SessionStatusChoices.LOCKED: ECounselingStatusChoices.COMPLETED,
        SessionStatusChoices.CANCELLED: ECounselingStatusChoices.CANCELLED,
        SessionStatusChoices.NO_SHOW: ECounselingStatusChoices.EXPIRED,
    }
    target = mapping.get(session.status)
    if target and ecounseling_session.status != target:
        ECounselingSession.objects.filter(pk=ecounseling_session.pk).update(
            status=target,
            updated_at=timezone.now(),
        )
        ecounseling_session.status = target
    return ecounseling_session
