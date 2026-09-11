import io
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from django.test import SimpleTestCase

from apps.common.exceptions import NotFoundError
from apps.counseling.api import (
    AccessGrantSchema,
    CounselingCaseProjectionSchema,
    CounselingMutationResponseSchema,
    CounselingSessionProjectionSchema,
    CounselingStudentSummarySchema,
    CollaboratorSchema,
    ConsentRequestSchema,
    ECounselingJoinContextSchema,
    ECounselingJoinStateSchema,
    EvaluationSchema,
    IntakeSchema,
    RecordingAvailabilitySchema,
    RecordingMutationResponseSchema,
    RecordingRunProjectionSchema,
    RecordingStatusSchema,
    RoutineInterviewQueueProjectionSchema,
    RoutineInterviewProjectionSchema,
    RoutineInterviewSensitiveDetailSchema,
    TranscriptMetadataSchema,
    TranscriptionStatusSchema,
    UrgentSupportCounselorOptionPageSchema,
    UrgentSupportQueueProjectionSchema,
    UrgentSupportProjectionSchema,
    add_collaborator_route,
    consent_request_route,
    grant_access_route,
    recording_download_route,
    save_evaluation_route,
    save_intake_route,
    routine_interview_sensitive_detail,
)


def _request():
    return SimpleNamespace(auth=SimpleNamespace(user=object()))


def _execute_operation(_request, _operation_id, _payload, operation):
    return operation()


class CounselingApiMutationWiringTests(SimpleTestCase):
    """API mutations must invoke the domain service exactly once."""

    @patch("apps.counseling.api._run", side_effect=_execute_operation)
    @patch("apps.counseling.services.save_student_intake_draft")
    def test_intake_save_calls_domain_service(self, service, _run):
        result = save_intake_route(
            _request(),
            "SES-1",
            IntakeSchema(visit_date="2026-08-24", visit_time="09:30"),
        )

        service.assert_called_once()
        command = service.call_args.args[2]
        self.assertEqual(command.visit_date.isoformat(), "2026-08-24")
        self.assertEqual(command.visit_time.isoformat(), "09:30:00")
        self.assertEqual(result.value, {"saved": True})

    @patch("apps.counseling.api._run", side_effect=_execute_operation)
    @patch("apps.counseling.services.save_counselor_evaluation_draft")
    def test_evaluation_save_calls_domain_service(self, service, _run):
        result = save_evaluation_route(_request(), "SES-1", EvaluationSchema())

        service.assert_called_once()
        self.assertEqual(result.value, {"saved": True})

    @patch("apps.counseling.api._run", side_effect=_execute_operation)
    @patch("apps.counseling.services.add_case_collaborator")
    def test_case_collaborator_add_calls_domain_service(self, service, _run):
        service.return_value = SimpleNamespace(counseling_case=object())

        result = add_collaborator_route(
            _request(),
            "CAS-1",
            CollaboratorSchema(counselor="42"),
        )

        service.assert_called_once()
        self.assertEqual(result.value, {"added": True})

    @patch("apps.counseling.api._run", side_effect=_execute_operation)
    @patch("apps.counseling.services.grant_temporary_support_access")
    def test_temporary_access_grant_calls_domain_service(self, service, _run):
        service.return_value = SimpleNamespace(urgent_support=object())

        result = grant_access_route(
            _request(),
            "ESC-1",
            AccessGrantSchema(
                grantee_id="42",
                grant_type="SESSION_REVIEW",
                purpose_code="URGENT_TRIAGE",
            ),
        )

        service.assert_called_once()
        self.assertEqual(result.value, {"granted": True})

    @patch("apps.counseling.api._run", side_effect=_execute_operation)
    @patch("apps.counseling.ecounseling_services.request_recording_consent")
    def test_recording_consent_request_calls_domain_service(self, service, _run):
        service.return_value = SimpleNamespace(counseling_session=object())

        result = consent_request_route(
            _request(),
            "ECS-1",
            ConsentRequestSchema(
                purpose_code="COUNSELING_DELIVERY",
                scope_code="AUDIO_VIDEO",
                retention_policy_code="DEFERRED_STORAGE_POLICY",
            ),
        )

        service.assert_called_once()
        self.assertEqual(result.value, {"requested": True})


class CounselingApiRoutineInterviewReadTests(SimpleTestCase):
    """Sensitive routine details stay behind the scoped read operation."""

    @patch("apps.counseling.projections.project_routine_interview_api_sensitive_detail")
    @patch("apps.counseling.api._routine_record_or_404")
    @patch("apps.counseling.api.prepare_api_operation")
    def test_sensitive_detail_returns_the_bounded_projection(
        self,
        prepare_operation,
        get_record,
        project_detail,
    ):
        request = _request()
        record = object()
        payload = {
            "session_reference_code": "SES-AY2627-000002",
            "status": "EVALUATION_DRAFT",
            "special_concern": "bounded detail",
        }
        get_record.return_value = record
        project_detail.return_value = payload

        result = routine_interview_sensitive_detail(request, "SES-AY2627-000002")

        prepare_operation.assert_called_once_with(
            request,
            "counseling_routine_interview_sensitive_detail",
        )
        get_record.assert_called_once_with(request.auth.user, "SES-AY2627-000002")
        project_detail.assert_called_once_with(request.auth.user, record)
        self.assertEqual(result, payload)

    @patch("apps.counseling.projections.project_routine_interview_api_sensitive_detail", return_value=None)
    @patch("apps.counseling.api._routine_record_or_404", return_value=object())
    @patch("apps.counseling.api.prepare_api_operation")
    def test_sensitive_detail_uses_safe_not_found_for_denied_projection(
        self,
        _prepare_operation,
        _get_record,
        _project_detail,
    ):
        with self.assertRaises(NotFoundError):
            routine_interview_sensitive_detail(_request(), "SES-AY2627-000002")


class CounselingOutputSchemaTests(SimpleTestCase):
    """Response schemas preserve the domain projections and replay shapes."""

    def test_actor_dependent_session_and_case_projections_are_bounded(self):
        staff_session = CounselingSessionProjectionSchema(
            reference_code="SES-AY2627-000001",
            student_id=17,
            appointment_id=None,
            assigned_counselor_id=23,
            session_type="COUNSELING",
            session_mode="ONSITE",
            session_source="WALK_IN",
            status="COMPLETED",
            scheduled_start_at="2026-08-24T09:00:00+08:00",
            scheduled_end_at="2026-08-24T10:00:00+08:00",
            actual_duration_minutes=55,
            ended_early_flag=True,
        )
        student_session = CounselingSessionProjectionSchema(
            reference_code="SES-AY2627-000001",
            session_type="COUNSELING",
            session_mode="ONSITE",
            status="COMPLETED",
            completed_at="2026-08-24T10:00:00+08:00",
        )
        self.assertEqual(staff_session.student_id, 17)
        self.assertNotIn("student_id", student_session.dict(exclude_unset=True))

        staff_case = CounselingCaseProjectionSchema(
            reference_code="CAS-AY2627-000001",
            student_id=17,
            assigned_counselor_id=23,
            concern_category="ACADEMIC",
            priority="MEDIUM",
            status="OPEN",
            created_at="2026-08-24T09:00:00+08:00",
        )
        student_case = CounselingCaseProjectionSchema(
            reference_code="CAS-AY2627-000001",
            status="OPEN",
        )
        self.assertEqual(staff_case.assigned_counselor_id, 23)
        self.assertNotIn("concern_category", student_case.dict(exclude_unset=True))

    def test_routine_intake_and_staff_metadata_use_semantic_types(self):
        staff = RoutineInterviewProjectionSchema(
            session_reference_code="SES-AY2627-000002",
            status="EVALUATION_DRAFT",
            student_id=17,
            assigned_counselor_id=23,
            visit_date="2026-08-24",
            visit_time="09:30:00",
            duration_minutes=30,
            concern_academic=True,
            rating_emotionally=8,
            evaluation_date="2026-08-24",
        )
        student = RoutineInterviewProjectionSchema(
            session_reference_code="SES-AY2627-000002",
            status="INTAKE_SUBMITTED",
            visit_date="2026-08-24",
            visit_time="09:30:00",
            coping_challenges="bounded student intake",
            concern_others_text="",
            submitted_at="2026-08-24T10:00:00+08:00",
        )
        self.assertEqual(staff.visit_date.isoformat(), "2026-08-24")
        self.assertEqual(staff.visit_time.isoformat(), "09:30:00")
        self.assertEqual(staff.rating_emotionally, 8)
        self.assertNotIn("student_id", student.dict(exclude_unset=True))
        self.assertNotIn("special_concern", RoutineInterviewProjectionSchema.__annotations__)
        self.assertNotIn("recommendations", RoutineInterviewProjectionSchema.__annotations__)

        queue = RoutineInterviewQueueProjectionSchema(
            session_reference_code="SES-AY2627-000002",
            status="INTAKE_SUBMITTED",
            student_display_name="Test User",
            student_number="20260001",
            assignment_state="Assigned to you",
            updated_at="2026-08-24T10:00:00+08:00",
        )
        sensitive = RoutineInterviewSensitiveDetailSchema(
            session_reference_code="SES-AY2627-000002",
            status="EVALUATION_DRAFT",
            special_concern="bounded detail",
            recommendations="bounded recommendation",
        )
        self.assertNotIn("student_id", queue.dict(exclude_unset=True))
        self.assertNotIn("assigned_counselor_id", queue.dict(exclude_unset=True))
        self.assertNotIn("student_id", RoutineInterviewSensitiveDetailSchema.__annotations__)
        self.assertEqual(sensitive.special_concern, "bounded detail")

    def test_urgent_and_student_summary_outputs_are_explicit(self):
        queue = UrgentSupportQueueProjectionSchema(
            reference_code="URG-AY2627-000001",
            status="OPEN",
            urgency_level="IMMEDIATE_TRIAGE",
            source_type="COUNSELOR_MANUAL",
            documentation_status="NOT_STARTED",
            review_status="NOT_REVIEWED",
            student_display_name="Test User",
            student_number="20260001",
            assignment_state="Assigned to you",
            counseling_case_reference="CAS-AY2627-000001",
            originating_session_reference="SES-AY2627-000001",
            documentation_session_reference="SES-AY2627-000002",
        )
        urgent = UrgentSupportProjectionSchema(
            reference_code="URG-AY2627-000001",
            status="OPEN",
            urgency_level="HIGH",
            source_type="STUDENT_REQUEST",
            documentation_status="NOT_STARTED",
            counseling_case_reference="CAS-AY2627-000001",
        )
        summary = CounselingStudentSummarySchema(student_visible_summary="student-safe")
        option_page = UrgentSupportCounselorOptionPageSchema(
            page=1,
            page_size=20,
            total=1,
            items=[{"selection_token": "opaque-token", "display_name": "Counselor"}],
        )
        self.assertEqual(
            set(queue.dict(exclude_unset=True)),
            {
                "reference_code",
                "status",
                "urgency_level",
                "source_type",
                "documentation_status",
                "review_status",
                "student_display_name",
                "student_number",
                "assignment_state",
                "counseling_case_reference",
                "originating_session_reference",
                "documentation_session_reference",
            },
        )
        self.assertNotIn("active_access_grants", queue.dict(exclude_unset=True))
        self.assertEqual(option_page.items[0].selection_token, "opaque-token")
        self.assertEqual(urgent.counseling_case_reference, "CAS-AY2627-000001")
        self.assertEqual(summary.student_visible_summary, "student-safe")
        self.assertNotIn("student_id", UrgentSupportProjectionSchema.__annotations__)

    def test_sparse_mutation_and_recording_outputs_keep_replay_boundary(self):
        replay = CounselingMutationResponseSchema(saved=True)
        self.assertEqual(replay.dict(exclude_unset=True), {"saved": True})
        self.assertEqual(
            CounselingMutationResponseSchema(
                reference_code="SES-AY2627-000001",
                status="IN_PROGRESS",
                created=True,
            ).dict(exclude_unset=True),
            {
                "reference_code": "SES-AY2627-000001",
                "status": "IN_PROGRESS",
                "created": True,
            },
        )

        run = RecordingRunProjectionSchema(
            run_id="run-1",
            reference_code="ECS-AY2627-000001",
            status="AVAILABLE",
            scope="AUDIO_ONLY",
            consent_status="APPROVED",
            transcription_status="AVAILABLE",
            transcript_available=True,
            available_at="2026-08-24T10:00:00+08:00",
            safe_failure_code=None,
            transcription_failure_code=None,
        )
        recording = RecordingMutationResponseSchema(started=True, run=run)
        status = RecordingStatusSchema(
            reference_code="ECS-AY2627-000001",
            status="AVAILABLE",
            run=run,
        )
        self.assertEqual(recording.run.run_id, "run-1")
        self.assertEqual(status.run.transcription_status, "AVAILABLE")
        self.assertNotIn("provider_instance_id", RecordingRunProjectionSchema.__annotations__)
        self.assertNotIn("protected_file_id", RecordingRunProjectionSchema.__annotations__)

    def test_join_context_is_the_only_ephemeral_provider_output(self):
        state = ECounselingJoinStateSchema(
            code="available",
            message="Ready to join",
            scheduled_start_at="2026-08-24T09:00:00+08:00",
            next_action="join",
        )
        context = ECounselingJoinContextSchema(
            provider="DAILY",
            provider_mode="DAILY_CLOUD",
            room_url="https://compass.daily.co/room-1",
            public_base_url="https://compass.daily.co",
            room_slug="room-1",
            meeting_token="ephemeral-token",
            display_name="COMPASS participant",
            recording_allowed=False,
            recording_controls_enabled=False,
            provider_auth_enabled=True,
            production_ready=True,
        )
        availability = RecordingAvailabilitySchema(
            state="RECORDING_READY",
            available=True,
            available_scopes=["AUDIO_ONLY"],
            transcription_available=True,
            reason_code="recording_ready_audio_only",
            message="Recording is available.",
        )
        transcription = TranscriptionStatusSchema(status="AVAILABLE", available=True)
        transcript = TranscriptMetadataSchema(
            available=True,
            content_type="text/vtt",
            file_size_bytes=128,
        )
        self.assertEqual(state.scheduled_start_at.isoformat(), "2026-08-24T09:00:00+08:00")
        self.assertEqual(context.meeting_token, "ephemeral-token")
        self.assertNotIn("meeting_token", RecordingStatusSchema.__annotations__)
        self.assertNotIn("meeting_token", RecordingAvailabilitySchema.__annotations__)
        self.assertTrue(availability.available)
        self.assertTrue(transcription.available)
        self.assertEqual(transcript.file_size_bytes, 128)


class RecordingDownloadRouteTests(SimpleTestCase):
    def _request(self, user):
        return SimpleNamespace(auth=SimpleNamespace(user=user))

    def test_recording_download_is_streamed_for_assigned_counselor(self):
        counselor = SimpleNamespace(pk=17, is_authenticated=True)
        run_id = uuid4()
        run = SimpleNamespace(protected_file_id=uuid4(), protected_file=object())
        response = object()

        with patch("apps.counseling.api.prepare_api_operation"), patch(
            "apps.counseling.api._recording_run_for_actor", return_value=run
        ) as load_run, patch(
            "apps.counseling.recording_services.recording_file_policy", return_value=True
        ) as policy, patch(
            "apps.security.downloads.build_protected_file_stream_download_response",
            return_value=response,
        ) as build_response:
            result = recording_download_route(self._request(counselor), "ECS-1", str(run_id))

        self.assertIs(result, response)
        load_run.assert_called_once_with(counselor, "ECS-1", str(run_id))
        policy.assert_called_once_with(counselor, run.protected_file, "download")
        build_response.assert_called_once_with(counselor, run.protected_file_id)

    def test_recording_download_returns_not_found_for_non_counselor(self):
        student = SimpleNamespace(pk=19, is_authenticated=True)
        run = SimpleNamespace(protected_file_id=uuid4(), protected_file=object())

        with patch("apps.counseling.api.prepare_api_operation"), patch(
            "apps.counseling.api._recording_run_for_actor", return_value=run
        ), patch(
            "apps.counseling.recording_services.recording_file_policy", return_value=False
        ), patch(
            "apps.security.downloads.build_protected_file_stream_download_response"
        ) as build_response:
            with self.assertRaises(NotFoundError):
                recording_download_route(self._request(student), "ECS-1", str(uuid4()))

        build_response.assert_not_called()

    def test_recording_download_returns_not_found_for_invalid_run_id(self):
        counselor = SimpleNamespace(pk=17, is_authenticated=True)

        with patch("apps.counseling.api.prepare_api_operation"), patch(
            "apps.counseling.api._recording_run_for_actor"
        ) as load_run:
            with self.assertRaises(NotFoundError):
                recording_download_route(self._request(counselor), "ECS-1", "not-a-uuid")

        load_run.assert_not_called()

    def test_stream_download_response_does_not_buffer_content(self):
        user = SimpleNamespace(pk=17, is_authenticated=True)
        protected_file = SimpleNamespace(content_type="video/mp4")

        with patch(
            "apps.security.downloads.open_protected_file_stream",
            return_value=(io.BytesIO(b"recording"), 9, protected_file),
        ), patch("apps.security.downloads.audit_proxy_download_served") as audit:
            from apps.security.downloads import build_protected_file_stream_download_response

            response = build_protected_file_stream_download_response(user, uuid4())

        self.assertTrue(response.streaming)
        self.assertEqual(response["Content-Length"], "9")
        self.assertEqual(response["Content-Disposition"], 'attachment; filename="ecounseling-recording"')
        self.assertEqual(b"".join(response.streaming_content), b"recording")
        audit.assert_called_once_with(user, protected_file)
