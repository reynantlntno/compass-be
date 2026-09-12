import uuid
from types import SimpleNamespace

from django.contrib.auth.models import AnonymousUser
from django.test import Client, SimpleTestCase, TestCase
from django.utils import timezone

from apps.account_security.api_tokens import issue_token_pair
from apps.accounts.models import RoleChoices, User
from apps.access_control.capabilities import Capability
from apps.access_control.choices import GrantReasonCode, ScopeMode
from apps.access_control.models import CounselorCoverage, WorkflowAuthorityGrant
from apps.common.contracts import PageRequest
from apps.common.form_values import ValidatedAnswerSet
from apps.common.exceptions import ValidationError
from apps.exit_interviews.api import (
    ExitInterviewAssignmentPageSchema,
    ExitInterviewAssignmentSchema,
    ExitInterviewDetailSchema,
    ExitInterviewResponsePageSchema,
    ExitInterviewResponseSchema,
    ExitInterviewStatusSchema,
)
from apps.exit_interviews import projections
from apps.exit_interviews import queue as exit_interview_queue
from apps.exit_interviews.commands import ExitInterviewDraftCommand
from apps.exit_interviews.models import ExitInterviewResponse, ExitResponseStatus
from apps.exit_interviews.policies import can_view_exit_free_text
from apps.organizations.models import FormFamily, FormRevision, FormRevisionStatusChoices
from apps.profiles.models import StudentProfile


class ExitInterviewResponseContractTests(SimpleTestCase):
    def setUp(self):
        self.now = timezone.now()
        self.response = SimpleNamespace(
            pk=uuid.uuid4(),
            reference_code="EIT-2026-000001",
            student_id=uuid.uuid4(),
            lifecycle_snapshot="GRADUATING",
            program_snapshot="BS Computer Science",
            college_snapshot="CCMS",
            academic_year="2026-2027",
            graduation_year_snapshot="2026",
            eligibility_source="lifecycle",
            status="SUBMITTED",
            form_revision_id=uuid.uuid4(),
            form_collection_id=uuid.uuid4(),
            submitted_at=self.now,
            counselor_acknowledged_at=None,
            created_at=self.now,
            response_json={"self_esteem": 5, "private_comment": "must remain versioned data"},
            counselor_acknowledged_by_id=uuid.uuid4(),
            metadata_json={"must_not": "cross-boundary"},
            form_invitation_id=uuid.uuid4(),
            reopen_reason="must not be projected",
            void_reason="must not be projected",
        )
        self.assignment = SimpleNamespace(
            pk=uuid.uuid4(),
            student_id=self.response.student_id,
            collection_id=self.response.form_collection_id,
            due_at=self.now,
            status="ASSIGNED",
            assigned_at=self.now,
            metadata_json={"graduation_year": "2026"},
            assigned_by_id=uuid.uuid4(),
        )

    def test_metadata_sensitive_assignment_and_status_projections_match_output_schemas(self):
        metadata = projections.response_metadata(self.response)
        self.assertEqual(
            set(metadata),
            {
                "id",
                "reference_code",
                "student_id",
                "lifecycle_snapshot",
                "program_snapshot",
                "college_snapshot",
                "academic_year",
                "graduation_year_snapshot",
                "eligibility_source",
                "status",
                "form_revision_id",
                "form_collection_id",
                "submitted_at",
                "counselor_acknowledged_at",
                "created_at",
            },
        )
        self.assertEqual(ExitInterviewResponseSchema(**metadata).status, "SUBMITTED")

        sensitive = projections.response_sensitive(self.response)
        detail = ExitInterviewDetailSchema(**sensitive)
        self.assertEqual(detail.answers["self_esteem"], 5)
        self.assertIsNotNone(detail.counselor_acknowledged_by)
        self.assertNotIn("answers", metadata)

        assignment = projections.assignment(self.assignment)
        self.assertEqual(ExitInterviewAssignmentSchema(**assignment).status, "ASSIGNED")
        ExitInterviewResponsePageSchema(items=[metadata], page=1, page_size=25, total=1)
        ExitInterviewAssignmentPageSchema(items=[assignment], page=1, page_size=25, total=1)

        status = projections.status(
            {
                "has_response": True,
                "status": "SUBMITTED",
                "reference_code": self.response.reference_code,
                "submitted_at": self.now,
            }
        )
        self.assertTrue(ExitInterviewStatusSchema(**status).has_response)

    def test_output_projections_do_not_cross_request_or_private_boundaries(self):
        metadata = projections.response_metadata(self.response)
        sensitive = projections.response_sensitive(self.response)
        assignment = projections.assignment(self.assignment)
        forbidden = {
            "expected_updated_at",
            "reason",
            "response_json",
            "metadata_json",
            "form_invitation_id",
            "reopen_reason",
            "void_reason",
            "is_paper_transcription",
            "transcribed_by",
            "assigned_by",
            "assigned_by_id",
        }
        for output in (metadata, sensitive, assignment):
            self.assertTrue(forbidden.isdisjoint(output))
        self.assertNotIn("answers", metadata)
        self.assertEqual(sensitive["answers"]["self_esteem"], 5)


class ExitInterviewPrivacyBoundaryTests(SimpleTestCase):
    def test_metadata_readers_never_receive_sensitive_answers(self):
        response = SimpleNamespace(
            pk=uuid.uuid4(),
            reference_code="EIT-2026-000002",
            student_id=uuid.uuid4(),
            lifecycle_snapshot="GRADUATING",
            program_snapshot="Program",
            college_snapshot="College",
            academic_year="2026-2027",
            graduation_year_snapshot="2026",
            eligibility_source="assignment",
            status="DRAFT",
            form_revision_id=uuid.uuid4(),
            form_collection_id=None,
            submitted_at=None,
            counselor_acknowledged_at=None,
            created_at=timezone.now(),
            response_json={"answer": "private"},
            counselor_acknowledged_by_id=None,
        )
        metadata = projections.response_metadata(response)
        self.assertNotIn("answers", metadata)
        self.assertNotIn("response_json", metadata)
        self.assertFalse(can_view_exit_free_text(AnonymousUser(), response))

    def test_student_staff_and_it_roles_cannot_view_free_text(self):
        response = SimpleNamespace(student=SimpleNamespace())
        for role in (RoleChoices.STUDENT, RoleChoices.GCO_STAFF, RoleChoices.IT_ADMIN):
            actor = SimpleNamespace(
                is_authenticated=True,
                is_active=True,
                is_superuser=False,
                role=role,
            )
            with self.subTest(role=role):
                self.assertFalse(can_view_exit_free_text(actor, response))


class ExitInterviewApiResponseTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            email="exit-contract-student@example.test",
            password="correct-horse-battery-staple",
            first_name="Exit",
            last_name="Student",
            role=RoleChoices.STUDENT,
            is_active=True,
        )
        StudentProfile.objects.create(
            user=self.user,
            lifecycle_status="GRADUATING",
            college="CCMS",
            program="BS Computer Science",
        )
        self.token = issue_token_pair(self.user, assurance_verified=True).access_token

    def test_empty_student_pages_and_status_validate_at_api_boundary(self):
        headers = {"HTTP_AUTHORIZATION": f"Bearer {self.token}"}
        endpoints = (
            ("/api/v1/exit-interviews/", ExitInterviewResponsePageSchema),
            ("/api/v1/exit-interviews/assignments/", ExitInterviewAssignmentPageSchema),
            ("/api/v1/exit-interviews/status/", ExitInterviewStatusSchema),
        )
        for path, schema in endpoints:
            with self.subTest(path=path):
                response = self.client.get(path, **headers)
                self.assertEqual(response.status_code, 200, response.content)
                schema(**response.json())


class ExitInterviewQueueTests(TestCase):
    def setUp(self):
        self.student = User.objects.create_user(
            email="exit-queue-student@example.test",
            password="correct-horse-battery-staple",
            first_name="Queue",
            last_name="Student",
            role=RoleChoices.STUDENT,
            is_active=True,
        )
        self.profile = StudentProfile.objects.create(
            user=self.student,
            student_number="2026-0001",
            control_number="CONTROL-ONLY-0001",
            college="CCMS",
        )
        self.counselor = User.objects.create_user(
            email="exit-queue-counselor@example.test",
            password="correct-horse-battery-staple",
            role=RoleChoices.COUNSELOR,
            is_active=True,
        )
        CounselorCoverage.objects.create(
            counselor=self.counselor,
            college="CCMS",
            starts_at=timezone.localdate(),
        )
        self.family = FormFamily.objects.create(
            stable_key="exit-interview-queue",
            display_name="Exit Interview",
        )
        self.revision = FormRevision.objects.create(
            form_family=self.family,
            official_form_code="EXIT-QUEUE",
            official_revision="1",
            internal_schema_version="exit-1",
            display_title="Exit Interview",
            status=FormRevisionStatusChoices.ACTIVE,
        )
        self.response = ExitInterviewResponse.objects.create(
            reference_code="EIT-QUEUE-000001",
            student=self.profile,
            lifecycle_snapshot="GRADUATING",
            program_snapshot="BS Computer Science",
            college_snapshot="CCMS",
            academic_year="2025-2026",
            graduation_year_snapshot="2026",
            eligibility_source="assignment",
            form_family=self.family,
            form_revision=self.revision,
            status=ExitResponseStatus.SUBMITTED,
            submitted_at=timezone.now(),
            response_json={"suggestion": "private answer"},
        )

    def test_queue_filters_scope_and_projection_do_not_include_sensitive_fields(self):
        page = exit_interview_queue.queue_page(
            self.counselor,
            PageRequest(page=1, page_size=20),
            query="EIT-QUEUE-000001",
            academic_year="2025-2026",
            revision="1",
        )
        self.assertEqual(page["total"], 1)
        self.assertEqual(
            set(page["items"][0]),
            {
                "reference_code",
                "student_display_name",
                "student_number",
                "academic_year",
                "graduation_year_snapshot",
                "form_code",
                "form_revision",
                "form_title",
                "status",
                "submitted_at",
                "counselor_acknowledged_at",
                "created_at",
                "updated_at",
            },
        )
        self.assertEqual(
            exit_interview_queue.queue_page(
                self.counselor,
                PageRequest(page=1, page_size=20),
                query="exit-queue-student@example.test",
            )["total"],
            0,
        )
        self.assertEqual(
            exit_interview_queue.queue_page(
                self.counselor,
                PageRequest(page=1, page_size=20),
                query="CONTROL-ONLY-0001",
            )["total"],
            0,
        )
        detail = exit_interview_queue.queue_detail(
            self.counselor, self.response.reference_code
        )
        self.assertNotIn("answers", detail)
        self.assertNotIn("id", detail)
        self.assertIsNotNone(
            exit_interview_queue.queue_sensitive_detail(
                self.counselor, self.response.reference_code
            )["answers"]
        )

    def test_gco_requires_queue_grant_and_still_cannot_read_sensitive_answers(self):
        gco = User.objects.create_user(
            email="exit-queue-gco@example.test",
            password="correct-horse-battery-staple",
            role=RoleChoices.GCO_STAFF,
            is_active=True,
        )
        self.assertEqual(
            exit_interview_queue.queue_page(
                gco, PageRequest(page=1, page_size=20)
            )["total"],
            0,
        )
        WorkflowAuthorityGrant.objects.create(
            grantee=gco,
            capability=Capability.EXIT_INTERVIEWS_QUEUE_VIEW.value,
            scope_mode=ScopeMode.EXPLICIT_ORGANIZATION.value,
            college="CCMS",
            valid_from=timezone.localdate(),
            granted_by=self.counselor,
            grant_reason_code=GrantReasonCode.LOCAL_WORKFLOW,
        )
        page = exit_interview_queue.queue_page(
            gco, PageRequest(page=1, page_size=20)
        )
        self.assertEqual(page["total"], 1)
        self.assertIsNone(
            exit_interview_queue.queue_sensitive_detail(
                gco, self.response.reference_code
            )
        )

    def test_queue_http_contract_is_typed_safe_and_answer_gated(self):
        headers = {
            "HTTP_AUTHORIZATION": f"Bearer {issue_token_pair(self.counselor, assurance_verified=True).access_token}"
        }
        page = self.client.get("/api/v1/exit-interviews/queue/", **headers)
        self.assertEqual(page.status_code, 200, page.content)
        payload = page.json()
        self.assertEqual(set(payload), {"items", "page", "page_size", "total"})
        self.assertEqual(payload["total"], 1)
        row = payload["items"][0]
        self.assertEqual(
            set(row),
            {
                "reference_code",
                "student_display_name",
                "student_number",
                "academic_year",
                "graduation_year_snapshot",
                "form_code",
                "form_revision",
                "form_title",
                "status",
                "submitted_at",
                "counselor_acknowledged_at",
                "created_at",
                "updated_at",
            },
        )
        for forbidden in (
            "answers",
            "id",
            "response_id",
            "student_profile_id",
            "counselor_id",
            "email",
            "control_number",
        ):
            self.assertNotIn(forbidden, row)

        detail = self.client.get("/api/v1/exit-interviews/queue/EIT-QUEUE-000001/", **headers)
        self.assertEqual(detail.status_code, 200)
        self.assertNotIn("answers", detail.json())

        sensitive = self.client.get("/api/v1/exit-interviews/queue/EIT-QUEUE-000001/sensitive/", **headers)
        self.assertEqual(sensitive.status_code, 200)
        self.assertEqual(sensitive.json()["answers"], {"suggestion": "private answer"})


class ExitInterviewSensitiveTargetTests(SimpleTestCase):
    def test_free_text_reader_requires_concrete_response_target(self):
        self.assertFalse(can_view_exit_free_text(AnonymousUser(), None))

    def test_draft_command_requires_revision_validated_answers(self):
        command = ExitInterviewDraftCommand(
            answers=ValidatedAnswerSet(values={"self_esteem": 5}, form_revision_id="revision-1")
        )
        self.assertEqual(command.answers.form_revision_id, "revision-1")
        with self.assertRaises(ValidationError):
            ExitInterviewDraftCommand(answers={"self_esteem": 5})
