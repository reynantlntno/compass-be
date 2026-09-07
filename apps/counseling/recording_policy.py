"""Server-authoritative e-counseling recording availability policy.

The projection is derived from the approved Governance controls and the
runtime safety evidence.  It deliberately has no request, provider payload,
credential, or database-row escape hatch: missing or malformed evidence keeps
recording unavailable.  Audio-only recording with post-call transcription is
the default available scope; video is an independent Governance opt-in.
"""

from dataclasses import dataclass
from enum import StrEnum

from django.db import DatabaseError


_PROJECTION_TOKEN = object()


class RecordingPolicyState(StrEnum):
    """Current approved recording scope."""

    RECORDING_DISABLED = "RECORDING_DISABLED"
    RECORDING_READY = "RECORDING_READY"


@dataclass(frozen=True, init=False)
class RecordingAvailabilityProjection:
    """Immutable, safe projection shared by every recording boundary."""

    state: RecordingPolicyState
    allow_new_consent: bool
    controls_available: bool
    playback_available: bool
    callbacks_enabled: bool
    worker_processing_enabled: bool
    scheduled_deletion_enabled: bool
    transcription_available: bool
    available_scopes: tuple[str, ...]
    reason_code: str
    user_message: str
    operations_message: str

    def __init__(
        self,
        *,
        _token=None,
        state=RecordingPolicyState.RECORDING_DISABLED,
        transcription_available=False,
        available_scopes=(),
        reason_code="recording_disabled_by_safety_floor",
        user_message=None,
        operations_message=None,
    ):
        # The projection is issued only by recording_availability_projection;
        # callers cannot construct a conflicting "ready" projection from
        # provider-looking settings, request data, or historical rows.
        if _token is not _PROJECTION_TOKEN:
            raise TypeError("RecordingAvailabilityProjection is server-authoritative.")
        ready = state == RecordingPolicyState.RECORDING_READY
        scopes = tuple(str(scope) for scope in available_scopes)
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "allow_new_consent", ready)
        object.__setattr__(self, "controls_available", ready)
        object.__setattr__(self, "playback_available", ready)
        object.__setattr__(self, "callbacks_enabled", ready)
        object.__setattr__(self, "worker_processing_enabled", ready)
        object.__setattr__(self, "scheduled_deletion_enabled", ready)
        object.__setattr__(self, "transcription_available", bool(ready and transcription_available))
        object.__setattr__(self, "available_scopes", scopes if ready else ())
        object.__setattr__(self, "reason_code", reason_code)
        object.__setattr__(self, "user_message", user_message or RECORDING_UNAVAILABLE_MESSAGE)
        object.__setattr__(self, "operations_message", operations_message or RECORDING_OPERATIONS_MESSAGE)

    @property
    def blocked(self) -> bool:
        return self.state == RecordingPolicyState.RECORDING_DISABLED


RECORDING_UNAVAILABLE_MESSAGE = (
    "Recording is not available for this session. This session is not recorded. "
    "You can continue the counseling session without recording."
)
RECORDING_POLICY_REASON_CODE = "recording_disabled_by_safety_floor"
RECORDING_GOVERNANCE_REASON_CODE = "recording_disabled_by_governance"
RECORDING_NOTICE_REASON_CODE = "recording_disabled_by_notice"
RECORDING_RETENTION_REASON_CODE = "recording_disabled_by_retention"
RECORDING_PROVIDER_REASON_CODE = "recording_disabled_by_provider"
RECORDING_STORAGE_REASON_CODE = "recording_disabled_by_storage"
RECORDING_WORKER_REASON_CODE = "recording_disabled_by_worker"
RECORDING_TRANSCRIPTION_REASON_CODE = "recording_disabled_by_transcription"
RECORDING_OPERATIONS_MESSAGE = (
    "Recording is disabled by approved policy and deferred; no new consent, "
    "recording processing, playback, or scheduled deletion is enabled."
)


def _runtime_setting(name: str):
    from apps.governance.runtime_config import resolve_runtime_setting

    return resolve_runtime_setting("counseling.ecounseling_controls", name)


def _durable_storage_ready():
    from django.conf import settings

    backend = str(getattr(settings, "PROTECTED_STORAGE_BACKEND", "local") or "").lower()
    return backend == "s3" and all(
        getattr(settings, setting_name, "")
        for setting_name in (
            "PROTECTED_STORAGE_S3_ENDPOINT_URL",
            "PROTECTED_STORAGE_S3_ACCESS_KEY",
            "PROTECTED_STORAGE_S3_SECRET_KEY",
            "PROTECTED_STORAGE_S3_BUCKET_NAME",
        )
    )


def _provider_configuration_ready():
    from django.conf import settings

    return bool(
        getattr(settings, "ECOUNSELING_DAILY_API_KEY", "")
        and getattr(settings, "ECOUNSELING_DAILY_DOMAIN", "")
        and getattr(settings, "ECOUNSELING_DAILY_WEBHOOK_SECRET", "")
        and getattr(settings, "ECOUNSELING_DAILY_WEBHOOK_ID", "")
        and getattr(settings, "ECOUNSELING_DAILY_WEBHOOK_URL", "")
    )


def _policy_evidence_ready():
    try:
        from apps.privacy.services import recording_consent_is_available, recording_retention_days

        return bool(recording_consent_is_available() and recording_retention_days() > 0)
    except (DatabaseError, AttributeError, TypeError, ValueError, LookupError):
        return False


def recording_controls_available() -> bool:
    """Return only the Governance control gate, without provider recursion."""

    return bool(
        _runtime_setting("ECOUNSELING_RECORDING_ENABLED")
        and _runtime_setting("ECOUNSELING_RECORDING_WORKER_ENABLED")
    )


def transcription_controls_available() -> bool:
    return bool(
        _runtime_setting("ECOUNSELING_RECORDING_TRANSCRIPTION_ENABLED")
        and _runtime_setting("ECOUNSELING_RECORDING_TRANSCRIPTION_WORKER_ENABLED")
    )


def recording_availability_projection() -> RecordingAvailabilityProjection:
    """Return the immutable, safe recording readiness projection."""

    if not recording_controls_available():
        return RecordingAvailabilityProjection(
            _token=_PROJECTION_TOKEN,
            reason_code=RECORDING_GOVERNANCE_REASON_CODE,
            operations_message="Recording remains disabled until its Governance controls are approved and active.",
        )
    if not _policy_evidence_ready():
        return RecordingAvailabilityProjection(
            _token=_PROJECTION_TOKEN,
            reason_code=RECORDING_NOTICE_REASON_CODE,
            operations_message="Recording remains disabled until the approved notice and exact retention policy are available.",
        )
    if not _provider_configuration_ready():
        return RecordingAvailabilityProjection(
            _token=_PROJECTION_TOKEN,
            reason_code=RECORDING_PROVIDER_REASON_CODE,
            operations_message="Recording remains disabled until the provider and signed webhook configuration are ready.",
        )
    if not _durable_storage_ready():
        return RecordingAvailabilityProjection(
            _token=_PROJECTION_TOKEN,
            reason_code=RECORDING_STORAGE_REASON_CODE,
            operations_message="Recording remains disabled until durable protected storage is ready.",
        )
    if not transcription_controls_available():
        return RecordingAvailabilityProjection(
            _token=_PROJECTION_TOKEN,
            reason_code=RECORDING_TRANSCRIPTION_REASON_CODE,
            operations_message="Recording remains disabled until protected transcription is approved and ready.",
        )
    from apps.governance.runtime_config import resolve_runtime_setting

    if int(resolve_runtime_setting(
        "counseling.ecounseling_controls",
        "ECOUNSELING_RECORDING_MAX_FILE_SIZE_BYTES",
    ) or 0) <= 0 or int(resolve_runtime_setting(
        "counseling.ecounseling_controls",
        "ECOUNSELING_RECORDING_TRANSCRIPTION_MAX_FILE_SIZE_BYTES",
    ) or 0) <= 0:
        return RecordingAvailabilityProjection(
            _token=_PROJECTION_TOKEN,
            reason_code=RECORDING_WORKER_REASON_CODE,
            operations_message="Recording remains disabled until bounded recording and transcript limits are active.",
        )
    video_enabled = bool(_runtime_setting("ECOUNSELING_RECORDING_AUDIO_VIDEO_ENABLED"))
    return RecordingAvailabilityProjection(
        _token=_PROJECTION_TOKEN,
        state=RecordingPolicyState.RECORDING_READY,
        transcription_available=True,
        available_scopes=("AUDIO_ONLY", "AUDIO_VIDEO") if video_enabled else ("AUDIO_ONLY",),
        reason_code="recording_ready_audio_video" if video_enabled else "recording_ready_audio_only",
        user_message="Recording is available with protected post-call transcription.",
        operations_message="Audio-only recording is available; audio/video requires the separate Governance control.",
    )


def recording_is_blocked() -> bool:
    """Return whether the authoritative recording projection is blocked."""

    return recording_availability_projection().blocked
