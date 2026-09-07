"""Provider-controlled, consent-bound e-counseling recording lifecycle."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import tempfile
import time
from datetime import timedelta
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import uuid4

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.utils import timezone

from apps.access_control.rules import is_active_nonlegacy_actor
from apps.access_control.authority import has_fixed_capability
from apps.access_control.capabilities import Capability
from apps.audit.services import audit_log
from apps.counseling.ecounseling_providers import (
    ProviderConfigurationError,
    ProviderOperationError,
    get_ecounseling_provider,
)
from apps.counseling.models import (
    ECounselingRecordingCallbackReceipt,
    ECounselingRecordingConsentStatusChoices,
    ECounselingRecordingDecisionChoices,
    ECounselingRecordingEvent,
    ECounselingRecordingEventTypeChoices,
    ECounselingRecordingRun,
    ECounselingRecordingRunStatusChoices,
    ECounselingSession,
    ECounselingTranscriptionStatusChoices,
    SessionStatusChoices,
)
from apps.counseling.recording_policy import (
    RECORDING_UNAVAILABLE_MESSAGE,
    recording_availability_projection,
    recording_is_blocked,
)
from apps.security.file_services import store_protected_file_from_path
from apps.security.models import ClassificationChoices, FileStatusChoices, PurposeChoices
from apps.security.storage_adapters import get_storage_adapter
from apps.security.exceptions import SecurityError, StorageError
from apps.governance.runtime_config import resolve_runtime_setting
from apps.common.exceptions import PermissionDeniedError, ValidationError


RECORDING_FILE_POLICY_KEY = "ecounseling_recording"
TRANSCRIPT_FILE_POLICY_KEY = "ecounseling_transcript"
ACTIVE_RUN_STATUSES = {
    ECounselingRecordingRunStatusChoices.REQUESTED,
    ECounselingRecordingRunStatusChoices.STARTING,
    ECounselingRecordingRunStatusChoices.RECORDING,
    ECounselingRecordingRunStatusChoices.STOP_REQUESTED,
    ECounselingRecordingRunStatusChoices.PROCESSING,
}
STOPPABLE_RUN_STATUSES = {
    ECounselingRecordingRunStatusChoices.STARTING,
    ECounselingRecordingRunStatusChoices.RECORDING,
    ECounselingRecordingRunStatusChoices.STOP_REQUESTED,
}
MAX_CLOCK_SKEW_SECONDS = 300
MAX_CALLBACK_BODY_BYTES = 256 * 1024
CALLBACK_INGESTION_STALE_AFTER = timedelta(minutes=10)
SUPPORTED_PROVIDER_EVENTS = {
    "recording.started",
    "recording.ready-to-download",
    "recording.error",
    "transcript.started",
    "transcript.ready-to-download",
    "transcript.error",
}


class RecordingPermissionError(PermissionDeniedError):
    pass


class RecordingValidationError(ValidationError):
    pass


class RecordingFinalizationPending(RecordingValidationError):
    pass


def _event(run, event_type, actor=None, safe_code=""):
    return ECounselingRecordingEvent.objects.create(
        recording_run=run,
        event_type=event_type,
        actor=actor,
        safe_code=safe_code,
    )


def _audit(run, action, actor=None, safe_code=""):
    audit_log(
        action_type=action,
        event_category="ECOUNSELING",
        target_model="ECounselingRecordingRun",
        target_object_id=str(run.pk),
        actor_user=actor,
        reference_code=run.ecounseling_session.reference_code,
        source_app="counseling",
        metadata={"status": run.status, "safe_code": safe_code},
    )


def recording_file_policy(user, protected_file, action: str) -> bool:
    if (
        not is_active_nonlegacy_actor(user)
        or protected_file.status != FileStatusChoices.ACTIVE
        or action not in {"read_content", "download", "playback"}
    ):
        return False
    try:
        run = protected_file.ecounseling_recording_run
        session = run.ecounseling_session.counseling_session
    except (AttributeError, ObjectDoesNotExist):
        return False
    if (
        run.status != ECounselingRecordingRunStatusChoices.AVAILABLE
        or not run.expires_at
        or run.expires_at <= timezone.now()
    ):
        return False
    return bool(session.assigned_counselor_id and session.assigned_counselor_id == user.pk)


def transcript_file_policy(user, protected_file, action: str) -> bool:
    """Purpose-specific transcript reader; technical actors get metadata only."""

    if not is_active_nonlegacy_actor(user) or protected_file.status != FileStatusChoices.ACTIVE:
        return False
    if action in {"read_metadata", "inspect"} and has_fixed_capability(
        user, Capability.PROTECTED_FILES_METADATA_INSPECT
    ):
        return True
    if action not in {"read_content", "download", "playback"}:
        return False
    try:
        run = protected_file.ecounseling_transcript_run
        session = run.ecounseling_session.counseling_session
    except (AttributeError, ObjectDoesNotExist):
        return False
    if (
        run.transcription_status != ECounselingTranscriptionStatusChoices.AVAILABLE
        or not run.transcription_expires_at
        or run.transcription_expires_at <= timezone.now()
    ):
        return False
    return bool(session.assigned_counselor_id and session.assigned_counselor_id == user.pk)


def _assigned_counselor(user, ecounseling_session) -> bool:
    session = ecounseling_session.counseling_session
    return bool(
        is_active_nonlegacy_actor(user)
        and session.assigned_counselor_id == user.pk
    )


def _hard_stop_at(ecounseling_session):
    return ecounseling_session.scheduled_end_at + timedelta(minutes=30)


def _latest_approved_consent(ecounseling_session):
    return (
        ecounseling_session.recording_consent_events.filter(
            decision=ECounselingRecordingDecisionChoices.APPROVED,
        )
        .order_by("-created_at")
        .first()
    )


def start_recording(user, ecounseling_reference, command=None):
    """Ask Daily to start a consent-bound recording and post-call transcript."""

    if recording_is_blocked():
        raise RecordingValidationError(RECORDING_UNAVAILABLE_MESSAGE)

    from apps.counseling.commands import ECounselingRecordingStartCommand

    command = command or ECounselingRecordingStartCommand()
    if not isinstance(command, ECounselingRecordingStartCommand):
        raise RecordingValidationError("Recording start requires a typed command.")
    provider = get_ecounseling_provider()
    with transaction.atomic():
        reference_code = str(
            getattr(ecounseling_reference, "reference_code", ecounseling_reference) or ""
        ).strip()
        ecounseling_session = (
            ECounselingSession.objects.select_for_update(of=("self",))
            .select_related("counseling_session", "counseling_session__assigned_counselor")
            .get(reference_code=reference_code)
        )
        session = ecounseling_session.counseling_session
        if not _assigned_counselor(user, ecounseling_session):
            raise RecordingPermissionError("Only the assigned counselor can start recording.")
        if session.status != SessionStatusChoices.IN_PROGRESS:
            raise RecordingValidationError("Start the counseling session before recording.")
        if not session.appointment_id or not session.scheduled_end_at:
            raise RecordingValidationError("Recording requires a confirmed appointment schedule.")
        if timezone.now() >= _hard_stop_at(ecounseling_session):
            raise RecordingValidationError("The recording window for this session has ended.")
        if ecounseling_session.recording_consent_status != ECounselingRecordingConsentStatusChoices.APPROVED:
            raise RecordingValidationError("Student recording consent is not approved.")
        consent = _latest_approved_consent(ecounseling_session)
        if consent is None:
            raise RecordingValidationError("Approved consent evidence is unavailable.")
        projection = recording_availability_projection()
        if command.scope_code not in projection.available_scopes:
            raise RecordingValidationError("The requested recording scope is not currently available.")
        if consent.scope_code != command.scope_code:
            raise RecordingValidationError("Recording scope does not match the approved consent.")
        capabilities = provider.validate_runtime_safety()
        if not capabilities.supports_recording_controls:
            raise RecordingValidationError(
                "Recording is unavailable because the recording service is not ready."
            )
        if ecounseling_session.recording_runs.filter(status__in=ACTIVE_RUN_STATUSES).exists():
            raise RecordingValidationError("Another recording is already active for this session.")

        instance_id = str(uuid4())
        run = ECounselingRecordingRun.objects.create(
            id=uuid4(),
            provider_instance_id=instance_id,
            ecounseling_session=ecounseling_session,
            consent_event=consent,
            status=ECounselingRecordingRunStatusChoices.STARTING,
            purpose_code_snapshot=consent.purpose_code,
            scope_code_snapshot=consent.scope_code,
            retention_policy_code_snapshot=consent.retention_policy_code,
            notice_version_snapshot=consent.notice_version,
            transcription_status=ECounselingTranscriptionStatusChoices.STARTING,
            provider_transcription_instance_id=instance_id,
            requested_by=user,
            hard_stop_at=_hard_stop_at(ecounseling_session),
        )
        _event(run, ECounselingRecordingEventTypeChoices.START_REQUESTED, user)
        _event(run, ECounselingRecordingEventTypeChoices.TRANSCRIPTION_REQUESTED, user)
        _audit(run, "ECOUNSELING_RECORDING_START_REQUESTED", user)

    try:
        provider.ensure_private_room(
            ecounseling_session.room_slug,
            nbf=int(ecounseling_session.join_window_start_at.timestamp()),
            exp=int(ecounseling_session.join_window_end_at.timestamp()),
        )
        # Daily returns an acknowledgement here. The actual recording id is
        # intentionally not expected until a recording.started event arrives.
        response = provider.api.start_recording(
            ecounseling_session.room_slug,
            instance_id,
            scope_code=command.scope_code,
            transcript_enabled=True,
        )
        if not isinstance(response, dict):
            raise ProviderOperationError("DAILY_INVALID_RESPONSE")
    except (ProviderConfigurationError, ProviderOperationError) as exc:
        safe_code = getattr(exc, "safe_code", "DAILY_UNAVAILABLE")
        fail_recording_run(run, safe_code=safe_code)
        raise RecordingValidationError(
            "Recording could not start. The counseling session can continue without recording."
        ) from exc
    return run


def request_recording_stop(actor, recording_run_reference, command=None, *, allow_student_withdrawal=False, safe_code=""):
    from apps.counseling.commands import ECounselingRecordingStopCommand

    command = command or ECounselingRecordingStopCommand(safe_reason_code=safe_code)
    if not isinstance(command, ECounselingRecordingStopCommand):
        raise RecordingValidationError("Recording stop requires a typed command.")
    provider = get_ecounseling_provider()
    with transaction.atomic():
        run_reference = str(getattr(recording_run_reference, "pk", recording_run_reference) or "").strip()
        run = (
            ECounselingRecordingRun.objects.select_for_update()
            .select_related("ecounseling_session__counseling_session")
            .get(pk=run_reference)
        )
        if run.status not in STOPPABLE_RUN_STATUSES:
            return run
        if not (
            _assigned_counselor(actor, run.ecounseling_session)
            or allow_student_withdrawal
            or actor is None
        ):
            raise RecordingPermissionError("Only the assigned counselor can stop recording.")
        if run.status != ECounselingRecordingRunStatusChoices.STOP_REQUESTED:
            run.status = ECounselingRecordingRunStatusChoices.STOP_REQUESTED
            run.stop_requested_at = timezone.now()
            run.save(update_fields=["status", "stop_requested_at", "updated_at"])
            _event(run, ECounselingRecordingEventTypeChoices.STOP_REQUESTED, actor, command.safe_reason_code)
            _audit(run, "ECOUNSELING_RECORDING_STOP_REQUESTED", actor, command.safe_reason_code)
        if allow_student_withdrawal and run.transcription_status in {
            ECounselingTranscriptionStatusChoices.STARTING,
            ECounselingTranscriptionStatusChoices.TRANSCRIBING,
            ECounselingTranscriptionStatusChoices.PROCESSING,
        }:
            run.transcription_status = ECounselingTranscriptionStatusChoices.FAILED
            run.transcription_failure_code = "CONSENT_WITHDRAWN"
            run.save(update_fields=["transcription_status", "transcription_failure_code", "updated_at"])
            _event(
                run,
                ECounselingRecordingEventTypeChoices.TRANSCRIPTION_FAILED,
                actor,
                "CONSENT_WITHDRAWN",
            )
    try:
        provider.api.stop_recording(
            run.ecounseling_session.room_slug,
            run.provider_instance_id,
            scope_code=run.scope_code_snapshot,
        )
    except (ProviderConfigurationError, ProviderOperationError) as exc:
        raise RecordingFinalizationPending(
            "Recording stop is pending. Please retry before completing the session."
        ) from exc
    return run


def stop_active_recording_for_withdrawal(user, ecounseling_session):
    run = (
        ecounseling_session.recording_runs.filter(
            status__in=STOPPABLE_RUN_STATUSES | {
                ECounselingRecordingRunStatusChoices.PROCESSING,
            }
        )
        .order_by("-created_at")
        .first()
    )
    if run and run.status in STOPPABLE_RUN_STATUSES:
        return request_recording_stop(
            user,
            run,
            allow_student_withdrawal=True,
            safe_code="CONSENT_WITHDRAWN",
        )
    if run and run.transcription_status in {
        ECounselingTranscriptionStatusChoices.STARTING,
        ECounselingTranscriptionStatusChoices.TRANSCRIBING,
        ECounselingTranscriptionStatusChoices.PROCESSING,
    }:
        with transaction.atomic():
            locked = ECounselingRecordingRun.objects.select_for_update().get(pk=run.pk)
            locked.transcription_status = ECounselingTranscriptionStatusChoices.FAILED
            locked.transcription_failure_code = "CONSENT_WITHDRAWN"
            locked.save(update_fields=["transcription_status", "transcription_failure_code", "updated_at"])
            _event(
                locked,
                ECounselingRecordingEventTypeChoices.TRANSCRIPTION_FAILED,
                user,
                "CONSENT_WITHDRAWN",
            )
        return run
    return None


def ensure_no_active_recording_before_completion(user, session):
    # New recording consent is governed by the current readiness projection,
    # but an already-running recording must still be stopped and finalized if
    # that projection is later withdrawn.
    try:
        ecounseling_session = session.ecounseling_session
    except ECounselingSession.DoesNotExist:
        return
    run = (
        ecounseling_session.recording_runs.filter(status__in=ACTIVE_RUN_STATUSES)
        .order_by("-created_at")
        .first()
    )
    if not run:
        return
    if run.status in STOPPABLE_RUN_STATUSES:
        try:
            request_recording_stop(user, run, safe_code="SESSION_COMPLETION")
        except RecordingFinalizationPending:
            pass
    # A successful provider stop is only an acknowledgement. Completion must
    # remain blocked through STOP_REQUESTED and PROCESSING until Daily's ready
    # event has been ingested and the worker has protected the file, or the run
    # has reached a terminal failure state.
    raise RecordingFinalizationPending("The recording is being finalized; complete the session after it finishes.")


@transaction.atomic
def mark_recording_status(run, status, *, safe_code="", actor=None):
    allowed = {
        ECounselingRecordingRunStatusChoices.RECORDING,
        ECounselingRecordingRunStatusChoices.PROCESSING,
        ECounselingRecordingRunStatusChoices.FAILED,
    }
    if status not in allowed:
        raise RecordingValidationError("Unsupported provider recording status.")
    run = ECounselingRecordingRun.objects.select_for_update().get(pk=run.pk)
    if run.status in {
        ECounselingRecordingRunStatusChoices.AVAILABLE,
        ECounselingRecordingRunStatusChoices.EXPIRED,
        ECounselingRecordingRunStatusChoices.DELETED,
    }:
        return run
    if run.status == status:
        return run
    now = timezone.now()
    run.status = status
    fields = ["status", "updated_at"]
    event = ECounselingRecordingEventTypeChoices.FAILED
    if status == ECounselingRecordingRunStatusChoices.RECORDING:
        run.started_at = run.started_at or now
        fields.append("started_at")
        event = ECounselingRecordingEventTypeChoices.STARTED
    elif status == ECounselingRecordingRunStatusChoices.PROCESSING:
        run.stopped_at = run.stopped_at or now
        fields.append("stopped_at")
        event = ECounselingRecordingEventTypeChoices.PROCESSING
    else:
        run.safe_failure_code = safe_code or "PROVIDER_FAILED"
        fields.append("safe_failure_code")
    run.save(update_fields=fields)
    _event(run, event, actor, safe_code)
    return run


def fail_recording_run(run, *, safe_code):
    return mark_recording_status(
        run,
        ECounselingRecordingRunStatusChoices.FAILED,
        safe_code=safe_code,
    )


def verify_callback(*, signature_header: str, timestamp_header: str, body: bytes):
    """Verify Daily's X-Webhook-Timestamp/X-Webhook-Signature contract."""

    secret = (getattr(settings, "ECOUNSELING_DAILY_WEBHOOK_SECRET", "") or "").strip()
    if not secret:
        raise RecordingValidationError("Recording callback verification is unavailable.")
    try:
        secret_bytes = base64.b64decode(secret, validate=True)
        timestamp = str(int(timestamp_header))
    except (ValueError, TypeError, binascii.Error) as exc:
        raise RecordingPermissionError("Invalid recording callback.") from exc
    if not timestamp_header or abs(int(time.time()) - int(timestamp)) > MAX_CLOCK_SKEW_SECONDS:
        raise RecordingPermissionError("Invalid recording callback.")
    signed_payload = timestamp.encode("ascii") + b"." + body
    expected = base64.b64encode(hmac.new(secret_bytes, signed_payload, hashlib.sha256).digest()).decode("ascii")
    if not signature_header or not hmac.compare_digest(expected, signature_header.strip()):
        raise RecordingPermissionError("Invalid recording callback.")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecordingValidationError("Invalid recording callback payload.") from exc
    if not isinstance(payload, dict):
        raise RecordingValidationError("Invalid recording callback payload.")
    return payload


def _run_for_provider_event(data, event_type=""):
    info = data.get("info") if isinstance(data.get("info"), dict) else {}
    recording_id = data.get("recording_id") or data.get("recordingId")
    transcript_id = data.get("transcript_id") or data.get("transcriptId")
    instance_id = data.get("instance_id") or data.get("instanceId") or info.get("instanceId")
    room_name = data.get("room_name") or data.get("roomName") or info.get("roomName")
    if event_type.startswith("transcript.") and not transcript_id:
        transcript_id = data.get("id")
    if transcript_id:
        run = ECounselingRecordingRun.objects.filter(provider_transcript_id=transcript_id).first()
        if run:
            return run
    if recording_id:
        run = ECounselingRecordingRun.objects.filter(provider_recording_id=recording_id).first()
        if run:
            return run
    if instance_id:
        run = ECounselingRecordingRun.objects.filter(provider_instance_id=instance_id).first()
        if run:
            return run
    if room_name:
        candidates = list(
            ECounselingRecordingRun.objects.filter(
                ecounseling_session__room_slug=room_name,
                status__in=ACTIVE_RUN_STATUSES,
            ).order_by("-created_at")[:2]
        )
        # A room-only callback is safe only when it maps to one active run.
        # Choosing the newest row could mutate the wrong counseling record.
        return candidates[0] if len(candidates) == 1 else None
    return None


def process_provider_callback(*, signature_header: str, timestamp_header: str, body: bytes):
    """Verify and enqueue provider state; never download inside the webhook."""

    if not isinstance(body, (bytes, bytearray)) or len(body) > MAX_CALLBACK_BODY_BYTES:
        raise RecordingValidationError("Invalid recording callback payload.")

    # Daily sends this exact unsigned probe while creating or reactivating a
    # webhook. It has no event data or side effects, so acknowledge it before
    # applying the signature requirement used for real provider events.
    try:
        probe = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        probe = None
    if probe == {"test": "test"}:
        return None

    payload = verify_callback(
        signature_header=signature_header,
        timestamp_header=timestamp_header,
        body=body,
    )
    if payload.get("test") == "test":
        return None
    event_type = payload.get("type")
    if event_type not in SUPPORTED_PROVIDER_EVENTS:
        return None
    event_id = payload.get("id")
    data = payload.get("payload") or {}
    if not event_id or not isinstance(data, dict):
        raise RecordingValidationError("Invalid Daily recording event.")
    run = _run_for_provider_event(data, event_type)
    # Unknown rooms/events are acknowledged by the view without revealing
    # internal identifiers; Daily may deliver old events after local cleanup.
    if run is None:
        return None

    digest = hashlib.sha256(body).hexdigest()
    with transaction.atomic():
        run = ECounselingRecordingRun.objects.select_for_update().get(pk=run.pk)
        duplicate_body = ECounselingRecordingCallbackReceipt.objects.filter(nonce_digest=digest).first()
        if duplicate_body:
            return run
        receipt, created = ECounselingRecordingCallbackReceipt.objects.get_or_create(
            provider_event_id=event_id,
            defaults={
                "recording_run": run,
                "nonce_digest": digest,
                "callback_status": event_type[:20].upper(),
            },
        )
        if not created:
            if receipt.recording_run_id != run.pk:
                raise RecordingPermissionError("Daily recording event was already consumed.")
            return run

        now = timezone.now()
        fields = ["updated_at"]
        recording_id = data.get("recording_id") or data.get("recordingId")
        transcript_id = data.get("transcript_id") or data.get("transcriptId")
        if event_type.startswith("transcript.") and not transcript_id:
            transcript_id = data.get("id")
        info = data.get("info") if isinstance(data.get("info"), dict) else {}
        instance_id = data.get("instance_id") or data.get("instanceId") or info.get("instanceId")
        if recording_id and run.provider_recording_id != recording_id:
            run.provider_recording_id = str(recording_id)[:128]
            fields.append("provider_recording_id")
        if transcript_id and run.provider_transcript_id != transcript_id:
            run.provider_transcript_id = str(transcript_id)[:128]
            fields.append("provider_transcript_id")
        if instance_id and run.provider_transcription_instance_id != instance_id:
            run.provider_transcription_instance_id = str(instance_id)[:128]
            fields.append("provider_transcription_instance_id")

        terminal_statuses = {
            ECounselingRecordingRunStatusChoices.AVAILABLE,
            ECounselingRecordingRunStatusChoices.DELETED,
            ECounselingRecordingRunStatusChoices.FAILED,
        }
        if event_type == "recording.started":
            if run.status in terminal_statuses:
                receipt.callback_status = "IGNORED"
            else:
                if run.status == ECounselingRecordingRunStatusChoices.STARTING:
                    run.status = ECounselingRecordingRunStatusChoices.RECORDING
                    fields.append("status")
                run.started_at = run.started_at or now
                fields.append("started_at")
                receipt.callback_status = "STARTED"
                _event(run, ECounselingRecordingEventTypeChoices.STARTED, safe_code="DAILY_EVENT")
        elif event_type == "recording.ready-to-download":
            if not recording_id:
                raise RecordingValidationError("Daily recording-ready event has no recording id.")
            if run.status not in terminal_statuses:
                run.status = ECounselingRecordingRunStatusChoices.PROCESSING
                run.stopped_at = run.stopped_at or now
                fields.extend(["status", "stopped_at"])
                receipt.callback_status = "PROCESSING"
                _event(run, ECounselingRecordingEventTypeChoices.PROCESSING, safe_code="DAILY_EVENT")
            else:
                receipt.callback_status = "IGNORED"
        elif event_type == "recording.error":
            if run.status in terminal_statuses:
                receipt.callback_status = "IGNORED"
            else:
                run.status = ECounselingRecordingRunStatusChoices.FAILED
                run.safe_failure_code = "DAILY_RECORDING_ERROR"
                fields.extend(["status", "safe_failure_code"])
                receipt.callback_status = "FAILED"
                _event(run, ECounselingRecordingEventTypeChoices.FAILED, safe_code="DAILY_RECORDING_ERROR")
        elif event_type == "transcript.started":
            if run.transcription_status in {
                ECounselingTranscriptionStatusChoices.AVAILABLE,
                ECounselingTranscriptionStatusChoices.EXPIRED,
                ECounselingTranscriptionStatusChoices.DELETED,
                ECounselingTranscriptionStatusChoices.FAILED,
            }:
                receipt.callback_status = "IGNORED"
            else:
                run.transcription_status = ECounselingTranscriptionStatusChoices.TRANSCRIBING
                run.transcription_started_at = run.transcription_started_at or now
                fields.extend(["transcription_status", "transcription_started_at"])
                receipt.callback_status = "TRANSCRIPT_STARTED"
                _event(run, ECounselingRecordingEventTypeChoices.TRANSCRIPTION_STARTED, safe_code="DAILY_EVENT")
        elif event_type == "transcript.ready-to-download":
            if not transcript_id:
                raise RecordingValidationError("Daily transcript-ready event has no transcript id.")
            if run.transcription_status not in {
                ECounselingTranscriptionStatusChoices.AVAILABLE,
                ECounselingTranscriptionStatusChoices.EXPIRED,
                ECounselingTranscriptionStatusChoices.DELETED,
            }:
                run.transcription_status = ECounselingTranscriptionStatusChoices.PROCESSING
                fields.append("transcription_status")
                receipt.callback_status = "TRANSCRIPT_PROCESSING"
                _event(run, ECounselingRecordingEventTypeChoices.TRANSCRIPTION_PROCESSING, safe_code="DAILY_EVENT")
            else:
                receipt.callback_status = "IGNORED"
        else:
            if run.transcription_status in {
                ECounselingTranscriptionStatusChoices.AVAILABLE,
                ECounselingTranscriptionStatusChoices.EXPIRED,
                ECounselingTranscriptionStatusChoices.DELETED,
            }:
                receipt.callback_status = "IGNORED"
            else:
                run.transcription_status = ECounselingTranscriptionStatusChoices.FAILED
                run.transcription_failure_code = "DAILY_TRANSCRIPTION_ERROR"
                fields.extend(["transcription_status", "transcription_failure_code"])
                receipt.callback_status = "TRANSCRIPT_FAILED"
                _event(run, ECounselingRecordingEventTypeChoices.TRANSCRIPTION_FAILED, safe_code="DAILY_TRANSCRIPTION_ERROR")

        run.save(update_fields=list(dict.fromkeys(fields)))
        receipt.save(update_fields=["callback_status", "updated_at"])
    return run


def _download_to_tempfile(download_url: str, max_size: int, *, suffix=".mp4", label="Recording") -> Path:
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    tmp_path = Path(tmp_file.name)
    total = 0
    try:
        req = Request(download_url)
        with urlopen(req, timeout=120) as response:
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > max_size:
                raise RecordingValidationError(f"{label} exceeds the configured download limit.")
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_size:
                    raise RecordingValidationError(f"{label} exceeds the configured download limit.")
                tmp_file.write(chunk)
        tmp_file.close()
        return tmp_path
    except RecordingValidationError:
        tmp_file.close()
        tmp_path.unlink(missing_ok=True)
        raise
    except (TypeError, ValueError, URLError, HTTPError, OSError) as exc:
        tmp_file.close()
        tmp_path.unlink(missing_ok=True)
        raise RecordingValidationError(f"Failed to download {label.lower()}.") from exc


def finalize_recording_file(run, recording_id: str | None = None):
    provider = get_ecounseling_provider()
    run.refresh_from_db()
    recording_id = recording_id or run.provider_recording_id
    if not recording_id:
        raise RecordingFinalizationPending("Daily recording is still being finalized.")
    if run.protected_file_id:
        return run
    from apps.privacy.services import recording_retention_days

    retention_days = recording_retention_days()
    if retention_days <= 0:
        raise RecordingValidationError(
            "Recording retention is not approved for this environment."
        )
    try:
        download_url = provider.api.get_recording_download_url(recording_id)
    except (ProviderConfigurationError, ProviderOperationError) as exc:
        fail_recording_run(run, safe_code="PROVIDER_FAILED")
        raise RecordingValidationError("Failed to get recording download URL.") from exc
    if not download_url:
        fail_recording_run(run, safe_code="PROVIDER_FAILED")
        raise RecordingValidationError("Failed to get recording download URL.")

    max_size = int(
        resolve_runtime_setting(
            "counseling.ecounseling_controls",
            "ECOUNSELING_RECORDING_MAX_FILE_SIZE_BYTES",
        )
    )
    try:
        tmp_path = _download_to_tempfile(download_url, max_size)
    except RecordingValidationError as exc:
        safe_code = "DOWNLOAD_TOO_LARGE" if "limit" in str(exc) else "DOWNLOAD_FAILED"
        fail_recording_run(run, safe_code=safe_code)
        raise

    from apps.security.models import ProtectedFile

    protected_file = ProtectedFile.objects.filter(
        purpose=PurposeChoices.ECOUNSELING_RECORDING,
        owning_app_label="counseling",
        owning_model_name="ECounselingRecordingRun",
        owning_object_id=str(run.pk),
        status=FileStatusChoices.ACTIVE,
    ).first()
    if protected_file is None:
        try:
            protected_file = store_protected_file_from_path(
                run.requested_by,
                tmp_path,
                original_filename="e-counseling-recording.mp4",
                content_type="video/mp4",
                purpose=PurposeChoices.ECOUNSELING_RECORDING,
                classification=ClassificationChoices.CONFIDENTIAL,
                app_label="counseling",
                model_name="ECounselingRecordingRun",
                object_id=str(run.pk),
                access_policy_key=RECORDING_FILE_POLICY_KEY,
                max_file_size_bytes=max_size,
            )
        except (OSError, SecurityError, StorageError, ValueError) as exc:
            tmp_path.unlink(missing_ok=True)
            fail_recording_run(run, safe_code="INGEST_FAILED")
            raise RecordingValidationError("Recording could not be stored safely.") from exc

    with transaction.atomic():
        run = ECounselingRecordingRun.objects.select_for_update().get(pk=run.pk)
        if run.protected_file_id:
            tmp_path.unlink(missing_ok=True)
            return run
        now = timezone.now()
        run.protected_file = protected_file
        run.file_size_bytes = protected_file.file_size_bytes
        run.checksum_sha256 = protected_file.checksum_sha256
        run.available_at = now
        run.expires_at = now + timedelta(days=retention_days)
        run.status = ECounselingRecordingRunStatusChoices.AVAILABLE
        run.save(
            update_fields=[
                "protected_file",
                "file_size_bytes",
                "checksum_sha256",
                "available_at",
                "expires_at",
                "status",
                "updated_at",
            ]
        )
        _event(run, ECounselingRecordingEventTypeChoices.AVAILABLE)
    tmp_path.unlink(missing_ok=True)
    return run


def finalize_transcript_file(run, transcript_id: str | None = None):
    """Fetch a provider transcript through the worker and retain only the protected file."""
    provider = get_ecounseling_provider()
    run = ECounselingRecordingRun.objects.get(pk=getattr(run, "pk", run))
    transcript_id = transcript_id or run.provider_transcript_id
    if not transcript_id:
        raise RecordingFinalizationPending("The transcript is still being finalized.")
    if run.transcript_protected_file_id:
        return run
    from apps.privacy.services import recording_retention_days

    retention_days = recording_retention_days()
    if retention_days <= 0:
        raise RecordingValidationError("Transcript retention is not approved for this environment.")
    max_size = int(resolve_runtime_setting(
        "counseling.ecounseling_controls",
        "ECOUNSELING_RECORDING_TRANSCRIPTION_MAX_FILE_SIZE_BYTES",
    ) or 0)
    if max_size <= 0:
        raise RecordingValidationError("Transcript storage is not configured.")
    try:
        download_url = provider.api.get_transcript_download_url(transcript_id)
    except (ProviderConfigurationError, ProviderOperationError) as exc:
        with transaction.atomic():
            locked = ECounselingRecordingRun.objects.select_for_update().get(pk=run.pk)
            locked.transcription_status = ECounselingTranscriptionStatusChoices.FAILED
            locked.transcription_failure_code = "PROVIDER_FAILED"
            locked.save(update_fields=["transcription_status", "transcription_failure_code", "updated_at"])
        raise RecordingValidationError("Failed to get transcript access link.") from exc
    if not download_url:
        raise RecordingValidationError("Failed to get transcript access link.")
    try:
        tmp_path = _download_to_tempfile(
            download_url,
            max_size,
            suffix=".vtt",
            label="Transcript",
        )
    except RecordingValidationError as exc:
        safe_code = "TRANSCRIPT_TOO_LARGE" if "limit" in str(exc) else "TRANSCRIPT_DOWNLOAD_FAILED"
        with transaction.atomic():
            locked = ECounselingRecordingRun.objects.select_for_update().get(pk=run.pk)
            locked.transcription_status = ECounselingTranscriptionStatusChoices.FAILED
            locked.transcription_failure_code = safe_code
            locked.save(update_fields=["transcription_status", "transcription_failure_code", "updated_at"])
        raise

    from apps.security.models import ProtectedFile

    protected_file = ProtectedFile.objects.filter(
        purpose=PurposeChoices.ECOUNSELING_TRANSCRIPT,
        owning_app_label="counseling",
        owning_model_name="ECounselingRecordingRun",
        owning_object_id=str(run.pk),
        status=FileStatusChoices.ACTIVE,
    ).first()
    if protected_file is None:
        try:
            protected_file = store_protected_file_from_path(
                run.requested_by,
                tmp_path,
                original_filename="e-counseling-transcript.vtt",
                content_type="text/vtt",
                purpose=PurposeChoices.ECOUNSELING_TRANSCRIPT,
                classification=ClassificationChoices.CONFIDENTIAL,
                app_label="counseling",
                model_name="ECounselingRecordingRun",
                object_id=str(run.pk),
                access_policy_key=TRANSCRIPT_FILE_POLICY_KEY,
                max_file_size_bytes=max_size,
            )
        except (OSError, SecurityError, StorageError, ValueError) as exc:
            tmp_path.unlink(missing_ok=True)
            raise RecordingValidationError("Transcript could not be stored safely.") from exc

    with transaction.atomic():
        locked = ECounselingRecordingRun.objects.select_for_update().get(pk=run.pk)
        if locked.transcript_protected_file_id:
            tmp_path.unlink(missing_ok=True)
            return locked
        now = timezone.now()
        locked.transcript_protected_file = protected_file
        locked.transcription_status = ECounselingTranscriptionStatusChoices.AVAILABLE
        locked.transcription_available_at = now
        locked.transcription_expires_at = now + timedelta(days=retention_days)
        locked.transcription_failure_code = ""
        locked.save(update_fields=[
            "transcript_protected_file",
            "transcription_status",
            "transcription_available_at",
            "transcription_expires_at",
            "transcription_failure_code",
            "updated_at",
        ])
        _event(locked, ECounselingRecordingEventTypeChoices.TRANSCRIPTION_AVAILABLE)
    tmp_path.unlink(missing_ok=True)
    return locked


def _delete_daily_recording(run, now):
    if not run.provider_recording_id or run.provider_deleted_at:
        return True
    try:
        get_ecounseling_provider().api.delete_recording(run.provider_recording_id)
    except ProviderOperationError as exc:
        if getattr(exc, "safe_code", "") != "DAILY_HTTP_404":
            run.provider_delete_failure_code = "DAILY_DELETE_FAILED"
            run.save(update_fields=["provider_delete_failure_code", "updated_at"])
            return False
    except ProviderConfigurationError:
        run.provider_delete_failure_code = "DAILY_DELETE_UNAVAILABLE"
        run.save(update_fields=["provider_delete_failure_code", "updated_at"])
        return False
    run.provider_deleted_at = now
    run.provider_delete_failure_code = ""
    run.save(update_fields=["provider_deleted_at", "provider_delete_failure_code", "updated_at"])
    return True


def _delete_daily_transcript(run, now):
    if not run.provider_transcript_id or run.transcription_deleted_at:
        return True
    try:
        get_ecounseling_provider().api.delete_transcript(run.provider_transcript_id)
    except ProviderOperationError as exc:
        if getattr(exc, "safe_code", "") != "DAILY_HTTP_404":
            run.transcription_failure_code = "DAILY_TRANSCRIPT_DELETE_FAILED"
            run.save(update_fields=["transcription_failure_code", "updated_at"])
            return False
    except ProviderConfigurationError:
        run.transcription_failure_code = "DAILY_TRANSCRIPT_DELETE_UNAVAILABLE"
        run.save(update_fields=["transcription_failure_code", "updated_at"])
        return False
    run.transcription_deleted_at = now
    run.save(update_fields=["transcription_deleted_at", "updated_at"])
    return True


def expire_recordings(*, now=None):
    # Safety monitoring (stop/finalize) is separate from disposal.  privacy.boundary
    # has no Active recording rule, so this worker must not delete local or
    # provider recordings. An explicit, authorized disposal invocation is not
    # exposed by the privacy.boundary command path.
    from apps.privacy.services import can_dispose_record_category

    if not can_dispose_record_category(
        "ecounseling_recordings",
        explicit_confirmation=False,
    ):
        return 0
    now = now or timezone.now()
    expired = 0
    candidates = ECounselingRecordingRun.objects.filter(
        status__in=[
            ECounselingRecordingRunStatusChoices.AVAILABLE,
            ECounselingRecordingRunStatusChoices.DELETED,
        ],
    ).filter(expires_at__lte=now)
    for candidate in candidates.iterator():
        with transaction.atomic():
            run = (
                ECounselingRecordingRun.objects.select_for_update()
                .get(pk=candidate.pk)
            )
            if run.expires_at and run.expires_at > now:
                continue
            if run.status == ECounselingRecordingRunStatusChoices.AVAILABLE:
                protected_file = run.protected_file if run.protected_file_id else None
                if protected_file and protected_file.retention_hold:
                    continue
                transcript_file = run.transcript_protected_file if run.transcript_protected_file_id else None
                if transcript_file and transcript_file.retention_hold:
                    continue
                if not _delete_daily_transcript(run, now):
                    continue
                if protected_file:
                    adapter = get_storage_adapter()
                    adapter.delete(protected_file.object_key)
                    protected_file.status = FileStatusChoices.DELETED_MARKER
                    protected_file.deleted_marker_at = now
                    protected_file.save(update_fields=["status", "deleted_marker_at", "updated_at"])
                if transcript_file:
                    adapter = get_storage_adapter()
                    adapter.delete(transcript_file.object_key)
                    transcript_file.status = FileStatusChoices.DELETED_MARKER
                    transcript_file.deleted_marker_at = now
                    transcript_file.save(update_fields=["status", "deleted_marker_at", "updated_at"])
                run.transcription_status = ECounselingTranscriptionStatusChoices.DELETED
                run.transcription_deleted_at = now
                run.status = ECounselingRecordingRunStatusChoices.DELETED
                run.deleted_at = now
                run.save(update_fields=[
                    "status",
                    "deleted_at",
                    "transcription_status",
                    "transcription_deleted_at",
                    "updated_at",
                ])
                _event(run, ECounselingRecordingEventTypeChoices.DELETED)
                _event(run, ECounselingRecordingEventTypeChoices.TRANSCRIPTION_DELETED)
                expired += 1
            elif (
                run.transcript_protected_file_id
                and run.transcription_expires_at
                and run.transcription_expires_at <= now
            ):
                transcript_file = run.transcript_protected_file
                if transcript_file.retention_hold:
                    continue
                if not _delete_daily_transcript(run, now):
                    continue
                adapter = get_storage_adapter()
                adapter.delete(transcript_file.object_key)
                transcript_file.status = FileStatusChoices.DELETED_MARKER
                transcript_file.deleted_marker_at = now
                transcript_file.save(update_fields=["status", "deleted_marker_at", "updated_at"])
                run.transcription_status = ECounselingTranscriptionStatusChoices.DELETED
                run.transcription_deleted_at = now
                run.save(update_fields=["transcription_status", "transcription_deleted_at", "updated_at"])
                _event(run, ECounselingRecordingEventTypeChoices.TRANSCRIPTION_DELETED)
            _delete_daily_recording(run, now)
    return expired


def monitor_recordings(*, now=None):
    # Existing runs remain under lifecycle control when new consent is
    # disabled.  Provider/storage failures stay bounded and retryable; the
    # current readiness projection must not strand an already-started run.
    now = now or timezone.now()
    stopped = 0
    for run in ECounselingRecordingRun.objects.filter(status__in=STOPPABLE_RUN_STATUSES).iterator():
        if now >= run.hard_stop_at:
            try:
                request_recording_stop(None, run, safe_code="SAFETY_LIMIT")
            except RecordingFinalizationPending:
                continue
            else:
                stopped += 1

    # Webhooks only transition to PROCESSING. The worker performs access-link
    # retrieval and protected storage ingestion outside the request thread.
    for run in ECounselingRecordingRun.objects.filter(
        status=ECounselingRecordingRunStatusChoices.PROCESSING,
        provider_recording_id__isnull=False,
    ).iterator():
        try:
            finalize_recording_file(run)
        except (RecordingFinalizationPending, RecordingValidationError):
            continue

    for run in ECounselingRecordingRun.objects.filter(
        transcription_status=ECounselingTranscriptionStatusChoices.PROCESSING,
        provider_transcript_id__isnull=False,
    ).iterator():
        try:
            finalize_transcript_file(run)
        except (RecordingFinalizationPending, RecordingValidationError):
            continue

    stale_before = now - CALLBACK_INGESTION_STALE_AFTER
    for run in ECounselingRecordingRun.objects.filter(
        status__in=[
            ECounselingRecordingRunStatusChoices.PROCESSING,
            ECounselingRecordingRunStatusChoices.STOP_REQUESTED,
        ],
        updated_at__lte=stale_before,
    ).iterator():
        fail_recording_run(
            run,
            safe_code=(
                "INGEST_TIMEOUT"
                if run.status == ECounselingRecordingRunStatusChoices.PROCESSING
                else "FINALIZE_TIMEOUT"
            ),
        )
    return stopped
