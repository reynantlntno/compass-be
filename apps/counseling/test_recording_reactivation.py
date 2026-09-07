import base64
import hashlib
import hmac
import json
import time
from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase

from apps.common.exceptions import ValidationError
from apps.counseling.commands import (
    ECounselingConsentRequestCommand,
    ECounselingProviderLifecycleReceipt,
    ECounselingRecordingStartCommand,
    ECounselingRecordingStopCommand,
)
from apps.counseling.ecounseling_providers import DailyAPIClient
from apps.counseling.recording_policy import (
    RecordingAvailabilityProjection,
    RecordingPolicyState,
    recording_availability_projection,
)
from apps.counseling.recording_services import verify_callback


class RecordingCommandBoundaryTests(SimpleTestCase):
    def test_recording_commands_are_frozen_and_wire_typed(self):
        command = ECounselingRecordingStartCommand()
        with self.assertRaises((AttributeError, TypeError)):
            command.scope_code = "AUDIO_VIDEO"
        with self.assertRaises(ValidationError):
            ECounselingRecordingStartCommand(scope_code={"scope": "AUDIO_ONLY"})
        with self.assertRaises(ValidationError):
            ECounselingRecordingStopCommand(safe_reason_code=object())
        with self.assertRaises(ValidationError):
            ECounselingConsentRequestCommand(scope_code=["AUDIO_ONLY"])
        with self.assertRaises(ValidationError):
            ECounselingProviderLifecycleReceipt(event_type={"type": "recording.started"})

    def test_recording_scope_defaults_to_audio_only(self):
        self.assertEqual(ECounselingRecordingStartCommand().scope_code, "AUDIO_ONLY")
        self.assertEqual(ECounselingConsentRequestCommand().scope_code, "AUDIO_ONLY")
        self.assertEqual(
            ECounselingConsentRequestCommand().retention_policy_code,
            "GOVERNANCE_RETENTION_POLICY",
        )


class RecordingReadinessTests(SimpleTestCase):
    def _ready_controls(self, *, video=False, transcription=True):
        return {
            "ECOUNSELING_RECORDING_ENABLED": True,
            "ECOUNSELING_RECORDING_WORKER_ENABLED": True,
            "ECOUNSELING_RECORDING_AUDIO_VIDEO_ENABLED": video,
            "ECOUNSELING_RECORDING_TRANSCRIPTION_ENABLED": transcription,
            "ECOUNSELING_RECORDING_TRANSCRIPTION_WORKER_ENABLED": transcription,
            "ECOUNSELING_RECORDING_MAX_FILE_SIZE_BYTES": 2_000_000,
            "ECOUNSELING_RECORDING_TRANSCRIPTION_MAX_FILE_SIZE_BYTES": 500_000,
        }

    def _projection(self, controls):
        with patch(
            "apps.counseling.recording_policy._runtime_setting",
            side_effect=lambda key: controls[key],
        ), patch(
            "apps.counseling.recording_policy._policy_evidence_ready",
            return_value=True,
        ), patch(
            "apps.counseling.recording_policy._provider_configuration_ready",
            return_value=True,
        ), patch(
            "apps.counseling.recording_policy._durable_storage_ready",
            return_value=True,
        ), patch(
            "apps.governance.runtime_config.resolve_runtime_setting",
            side_effect=lambda _policy_key, key: controls[key],
        ):
            return recording_availability_projection()

    def test_policy_center_readiness_defaults_to_audio_only(self):
        projection = self._projection(self._ready_controls())
        self.assertEqual(projection.state, RecordingPolicyState.RECORDING_READY)
        self.assertEqual(projection.available_scopes, ("AUDIO_ONLY",))
        self.assertTrue(projection.transcription_available)
        self.assertEqual(projection.reason_code, "recording_ready_audio_only")

    def test_video_requires_independent_governance_control(self):
        projection = self._projection(self._ready_controls(video=True))
        self.assertEqual(projection.available_scopes, ("AUDIO_ONLY", "AUDIO_VIDEO"))
        self.assertEqual(projection.reason_code, "recording_ready_audio_video")

    def test_missing_transcription_gate_keeps_recording_fail_closed(self):
        projection = self._projection(self._ready_controls(transcription=False))
        self.assertEqual(projection.state, RecordingPolicyState.RECORDING_DISABLED)
        self.assertEqual(projection.reason_code, "recording_disabled_by_transcription")
        self.assertFalse(projection.transcription_available)
        self.assertEqual(projection.available_scopes, ())

    def test_projection_cannot_be_fabricated_by_callers(self):
        with self.assertRaises(TypeError):
            RecordingAvailabilityProjection(state=RecordingPolicyState.RECORDING_READY)


class DailyRecordingPayloadTests(SimpleTestCase):
    def setUp(self):
        self.client = DailyAPIClient(
            SimpleNamespace(
                ECOUNSELING_DAILY_API_KEY="daily-key",
                ECOUNSELING_DAILY_DOMAIN="compass.daily.co",
            )
        )

    def test_audio_only_start_requests_audio_only_and_webvtt(self):
        with patch.object(self.client, "_request", return_value={}) as request:
            self.client.start_recording(
                "room-1",
                "instance-1",
                scope_code="AUDIO_ONLY",
                transcript_enabled=True,
            )
        request.assert_called_once_with(
            "POST",
            "/rooms/room-1/recordings/start",
            {
                "instanceId": "instance-1",
                "type": "cloud-audio-only",
                "dataOutputs": ["transcript-webvtt"],
            },
        )

    def test_video_start_uses_cloud_only_when_explicitly_requested(self):
        with patch.object(self.client, "_request", return_value={}) as request:
            self.client.start_recording(
                "room-1",
                "instance-2",
                scope_code="AUDIO_VIDEO",
                transcript_enabled=True,
            )
        self.assertEqual(request.call_args.args[2]["type"], "cloud")
        self.assertEqual(request.call_args.args[2]["dataOutputs"], ["transcript-webvtt"])

    def test_transcript_access_link_uses_the_protected_provider_boundary(self):
        with patch.object(
            self.client,
            "_request",
            return_value={"download_link": "https://provider.invalid/one-time"},
        ) as request:
            link = self.client.get_transcript_download_url("transcript/1")
        self.assertEqual(link, "https://provider.invalid/one-time")
        request.assert_called_once_with("GET", "/transcript/transcript%2F1/access-link")


class RecordingCallbackVerificationTests(SimpleTestCase):
    def test_signed_callback_is_verified_without_exposing_payload(self):
        raw_secret = b"test-webhook-secret"
        secret = base64.b64encode(raw_secret).decode("ascii")
        body = json.dumps({"id": "evt-1", "type": "transcript.started", "payload": {"id": "tr-1"}}).encode()
        timestamp = str(int(time.time()))
        signature = base64.b64encode(
            hmac.new(raw_secret, timestamp.encode() + b"." + body, hashlib.sha256).digest()
        ).decode("ascii")
        with patch("apps.counseling.recording_services.settings.ECOUNSELING_DAILY_WEBHOOK_SECRET", secret):
            result = verify_callback(
                signature_header=signature,
                timestamp_header=timestamp,
                body=body,
            )
        self.assertEqual(result["type"], "transcript.started")

    def test_invalid_callback_signature_is_rejected(self):
        with patch("apps.counseling.recording_services.settings.ECOUNSELING_DAILY_WEBHOOK_SECRET", "dGVzdA=="):
            with self.assertRaises(Exception) as raised:
                verify_callback(
                    signature_header="invalid",
                    timestamp_header=str(int(time.time())),
                    body=b'{"id":"evt-1"}',
                )
        self.assertNotIn("evt-1", str(raised.exception))


class RecordingProjectionSafetyTests(SimpleTestCase):
    def test_openapi_contains_recording_and_transcription_operations(self):
        from config.api.v1 import api_v1

        schema = api_v1.get_openapi_schema()
        operation_ids = {
            operation.get("operationId")
            for path in schema.get("paths", {}).values()
            for operation in path.values()
            if isinstance(operation, dict) and operation.get("operationId")
        }
        self.assertTrue(
            {
                "counseling_ecounseling_recording_availability",
                "counseling_ecounseling_recording_status",
                "counseling_ecounseling_recording_start",
                "counseling_ecounseling_recording_stop",
                "counseling_ecounseling_recording_run_status",
                "counseling_ecounseling_transcription_status",
                "counseling_ecounseling_transcript_metadata",
                "counseling_ecounseling_transcript_download",
                "counseling_ecounseling_recording_download",
                "counseling_ecounseling_provider_webhook",
            }.issubset(operation_ids)
        )
        recording_download = schema["paths"][
            "/api/v1/counseling/ecounseling/{reference_code}/recording/{run_id}/download/"
        ]["get"]
        self.assertIn("video/mp4", recording_download["responses"]["200"]["content"])

    def test_run_projection_excludes_provider_and_storage_values(self):
        from apps.counseling.api import _recording_run_projection

        run = SimpleNamespace(
            pk="run-1",
            ecounseling_session=SimpleNamespace(
                reference_code="ECS-1",
                recording_consent_status="APPROVED",
            ),
            status="AVAILABLE",
            scope_code_snapshot="AUDIO_ONLY",
            transcription_status="AVAILABLE",
            started_at=None,
            stopped_at=None,
            available_at=None,
            expires_at=None,
            transcription_started_at=None,
            transcription_available_at=None,
            transcription_expires_at=None,
            transcript_protected_file_id="protected-file-id",
            safe_failure_code="",
            transcription_failure_code="",
        )
        projection = _recording_run_projection(run)
        self.assertEqual(
            set(projection),
            {
                "run_id",
                "reference_code",
                "status",
                "scope",
                "consent_status",
                "transcription_status",
                "started_at",
                "stopped_at",
                "available_at",
                "expires_at",
                "transcription_started_at",
                "transcription_available_at",
                "transcription_expires_at",
                "transcript_available",
                "safe_failure_code",
                "transcription_failure_code",
            },
        )
