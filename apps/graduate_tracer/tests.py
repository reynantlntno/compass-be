import uuid
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth.models import AnonymousUser
from django.test import Client, SimpleTestCase, TestCase
from django.utils import timezone

from apps.account_security.api_tokens import issue_token_pair
from apps.accounts.models import RoleChoices, User
from apps.common.exceptions import ValidationError
from apps.common.form_values import ValidatedAnswerSet
from apps.graduate_tracer import projections
from apps.graduate_tracer.api import (
    GraduateTracerDetailSchema,
    GraduateTracerResponsePageSchema,
    GraduateTracerResponseSchema,
    GraduateTracerStatusSchema,
)
from apps.graduate_tracer.commands import GraduateTracerStartCommand
from apps.graduate_tracer.policies import can_view_gts_free_text
from apps.profiles.models import StudentProfile


class GraduateTracerResponseContractTests(SimpleTestCase):
    def setUp(self):
        self.now = timezone.now()
        self.response = SimpleNamespace(
            pk=uuid.uuid4(),
            reference_code="GTS-2026-000001",
            student_id=uuid.uuid4(),
            lifecycle_snapshot="ALUMNI",
            graduation_year="2026",
            program_snapshot="BS Computer Science",
            college_snapshot="CCMS",
            status="SUBMITTED",
            form_revision_id=uuid.uuid4(),
            form_collection_id=uuid.uuid4(),
            employment_status="EMPLOYED",
            submitted_at=self.now,
            created_at=self.now,
            response_json={"employment_status": "private answer"},
            metadata_json={"must_not": "cross-boundary"},
            form_invitation_id=uuid.uuid4(),
            telephone_number="must not be projected",
            place_of_work="must not be projected",
            initial_gross_earnings="must not be projected",
            reopen_reason="must not be projected",
            void_reason="must not be projected",
            is_paper_transcription=True,
            transcribed_by_id=uuid.uuid4(),
        )

    def test_metadata_sensitive_page_and_status_projections_match_output_schemas(self):
        metadata = projections.response_metadata(self.response)
        self.assertEqual(
            set(metadata),
            {
                "id",
                "reference_code",
                "student_id",
                "lifecycle_snapshot",
                "graduation_year",
                "program_snapshot",
                "college_snapshot",
                "status",
                "form_revision_id",
                "form_collection_id",
                "employment_status",
                "submitted_at",
                "created_at",
            },
        )
        self.assertEqual(GraduateTracerResponseSchema(**metadata).status, "SUBMITTED")

        sensitive = projections.response_sensitive(self.response)
        detail = GraduateTracerDetailSchema(**sensitive)
        self.assertEqual(detail.answers["employment_status"], "private answer")
        self.assertNotIn("answers", metadata)

        GraduateTracerResponsePageSchema(items=[metadata], page=1, page_size=25, total=1)
        status = projections.status(
            {
                "has_response": True,
                "status": "SUBMITTED",
                "reference_code": self.response.reference_code,
                "submitted_at": self.now,
            }
        )
        self.assertTrue(GraduateTracerStatusSchema(**status).has_response)

    def test_output_projections_do_not_cross_request_or_private_boundaries(self):
        metadata = projections.response_metadata(self.response)
        sensitive = projections.response_sensitive(self.response)
        forbidden = {
            "expected_updated_at",
            "reason",
            "response_json",
            "metadata_json",
            "form_invitation_id",
            "invitation_token",
            "token_hash",
            "telephone_number",
            "place_of_work",
            "initial_gross_earnings",
            "business_line",
            "first_job_level",
            "current_job_level",
            "reopen_reason",
            "void_reason",
            "is_paper_transcription",
            "transcribed_by",
            "transcribed_by_id",
            "actor_user_id",
        }
        self.assertTrue(forbidden.isdisjoint(metadata))
        self.assertTrue(forbidden.isdisjoint(sensitive))
        self.assertNotIn("answers", metadata)
        self.assertEqual(sensitive["answers"]["employment_status"], "private answer")


class GraduateTracerPrivacyBoundaryTests(SimpleTestCase):
    def test_metadata_readers_never_receive_sensitive_answers(self):
        response = SimpleNamespace(
            pk=uuid.uuid4(),
            reference_code="GTS-2026-000002",
            student_id=uuid.uuid4(),
            lifecycle_snapshot="ALUMNI",
            graduation_year="2026",
            program_snapshot="Program",
            college_snapshot="College",
            status="DRAFT",
            form_revision_id=uuid.uuid4(),
            form_collection_id=None,
            employment_status="",
            submitted_at=None,
            created_at=timezone.now(),
            response_json={"answer": "private"},
            metadata_json={"raw": "private"},
        )
        metadata = projections.response_metadata(response)
        self.assertNotIn("answers", metadata)
        self.assertNotIn("response_json", metadata)
        self.assertFalse(can_view_gts_free_text(AnonymousUser(), response))

    def test_student_staff_and_it_roles_cannot_view_free_text_without_explicit_scope(self):
        response = SimpleNamespace(student=SimpleNamespace())
        for role in (RoleChoices.STUDENT, RoleChoices.IT_ADMIN):
            actor = SimpleNamespace(
                is_authenticated=True,
                is_active=True,
                is_superuser=False,
                role=role,
            )
            with self.subTest(role=role):
                self.assertFalse(can_view_gts_free_text(actor, response))

    def test_scoped_gco_staff_can_view_free_text_only_when_policy_allows_scope(self):
        actor = SimpleNamespace(
            is_authenticated=True,
            is_active=True,
            is_superuser=False,
            role=RoleChoices.GCO_STAFF,
        )
        response = SimpleNamespace(student=SimpleNamespace())
        with (
            patch("apps.graduate_tracer.policies.has_capability", return_value=False),
            patch("apps.graduate_tracer.policies.workflow_authority_authorizes_record", return_value=True),
        ):
            self.assertTrue(can_view_gts_free_text(actor, response))

        with (
            patch("apps.graduate_tracer.policies.has_capability", return_value=False),
            patch("apps.graduate_tracer.policies.workflow_authority_authorizes_record", return_value=False),
        ):
            self.assertFalse(can_view_gts_free_text(actor, response))

    def test_covered_counselor_can_view_free_text_only_when_policy_allows_scope(self):
        actor = SimpleNamespace(
            is_authenticated=True,
            is_active=True,
            is_superuser=False,
            role=RoleChoices.COUNSELOR,
        )
        response = SimpleNamespace(student=SimpleNamespace())
        with (
            patch("apps.graduate_tracer.policies.can_view_gts_response", return_value=True),
            patch("apps.graduate_tracer.policies.has_capability", return_value=False),
            patch("apps.graduate_tracer.policies.counselor_has_live_coverage_for_student", return_value=True),
        ):
            self.assertTrue(can_view_gts_free_text(actor, response))

        with (
            patch("apps.graduate_tracer.policies.can_view_gts_response", return_value=True),
            patch("apps.graduate_tracer.policies.has_capability", return_value=False),
            patch("apps.graduate_tracer.policies.counselor_has_live_coverage_for_student", return_value=False),
        ):
            self.assertFalse(can_view_gts_free_text(actor, response))


class GraduateTracerApiResponseTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            email="graduate-tracer-contract-student@example.test",
            password="correct-horse-battery-staple",
            first_name="Graduate",
            last_name="Tracer",
            role=RoleChoices.STUDENT,
            is_active=True,
        )
        StudentProfile.objects.create(
            user=self.user,
            lifecycle_status="ALUMNI",
            college="CCMS",
            program="BS Computer Science",
        )
        self.token = issue_token_pair(self.user, assurance_verified=True).access_token

    def test_empty_student_page_and_status_validate_at_api_boundary(self):
        headers = {"HTTP_AUTHORIZATION": f"Bearer {self.token}"}
        endpoints = (
            ("/api/v1/graduate-tracer/", GraduateTracerResponsePageSchema),
            ("/api/v1/graduate-tracer/status/", GraduateTracerStatusSchema),
        )
        for path, schema in endpoints:
            with self.subTest(path=path):
                response = self.client.get(path, **headers)
                self.assertEqual(response.status_code, 200, response.content)
                schema(**response.json())


class GraduateTracerSensitiveTargetTests(SimpleTestCase):
    def test_free_text_reader_requires_concrete_response_target(self):
        self.assertFalse(can_view_gts_free_text(AnonymousUser(), None))

    def test_start_command_requires_one_bounded_owner(self):
        command = GraduateTracerStartCommand(
            student_profile_id="student-1",
            form_revision_id="revision-1",
        )
        self.assertEqual(command.student_profile_id, "student-1")
        with self.assertRaises(ValidationError):
            GraduateTracerStartCommand(student_profile_id=None, form_revision_id="revision-1")
        self.assertIsInstance(
            ValidatedAnswerSet(values={"employment_status": "EMPLOYED"}, form_revision_id="revision-1"),
            ValidatedAnswerSet,
        )
