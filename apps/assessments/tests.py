# Project: COMPASS
# File: apps/assessments/tests.py
# Module: apps.assessments
# Purpose: Focused tests for the assessment aggregate suppression boundary
#          (contract boundary).  Small nonzero counts are suppressed with the canonical
#          SUPPRESSION_LABEL and are never rendered as the numeric zero.

import json
from dataclasses import FrozenInstanceError
from datetime import timedelta
from types import SimpleNamespace

from apps.common.exceptions import PermissionDeniedError, StaleStateError, ValidationError
from django.test import Client, TestCase
from django.utils import timezone

from apps.accounts.models import RoleChoices, User
from apps.account_security.api_tokens import issue_token_pair
from apps.access_control.models import CounselorCoverage
from apps.assessments.api import (
    AssessmentFileMetadataSchema,
    AssessmentInstrumentPageSchema,
    AssessmentInstrumentSchema,
    AssessmentPageSchema,
    AssessmentSensitiveProjectionSchema,
    AssessmentStaffProjectionSchema,
    AssessmentStudentSummaryPageSchema,
    AssessmentStudentSummarySchema,
)
from apps.assessments.choices import AssessmentInstrumentCategory, AssessmentRecordStatus
from apps.assessments.choices import AssessmentInterpretationVisibility
from apps.assessments.commands import (
    AssessmentCreateCommand,
    AssessmentRecordCommand,
    AssessmentReleaseCommand,
    AssessmentSubmitReviewCommand,
    AssessmentReviewCommand,
)
from apps.assessments.models import AssessmentInstrument, StudentAssessmentRecord
from apps.assessments.services import (
    build_assessment_aggregate_dataset,
    create_assessment_record,
    record_assessment_result,
    release_assessment_to_student,
    review_assessment_record,
    submit_assessment_for_review,
)
from apps.assessments.projections import (
    assessment_sensitive_projection,
    assessment_staff_projection,
    instrument_projection,
    protected_file_metadata_projection,
    student_summary_projection,
)
from apps.profiles.models import CounselorProfile, StudentProfile
from apps.reports.suppression import MIN_SUPPRESSION_THRESHOLD, SUPPRESSION_LABEL
from apps.security.models import (
    ClassificationChoices,
    EncryptionKeyVersion,
    FileStatusChoices,
    KeyPurposeChoices,
    KeyStatusChoices,
    PurposeChoices,
    ProtectedFile,
)


def _build_user(email, role, *, is_active=True):
    return User.objects.create_user(
        email=email,
        password="correct-horse-battery-staple",
        first_name="Test",
        last_name="User",
        role=role,
        is_active=is_active,
    )


def _build_student(*, email, college):
    return StudentProfile.objects.create(
        user=_build_user(email=email, role=RoleChoices.STUDENT),
        campus="Main Campus",
        college=college,
        department="Nursing" if college == "CCMS" else "Biology Dept",
        program="BSN" if college == "CCMS" else "BS Biology",
        year_level=1,
    )


class AssessmentAggregateSuppressionTests(TestCase):
    """The builder must suppress 1..4 and never fabricate a zero count."""

    def setUp(self):
        self.counselor = _build_user(email="counselor@example.test", role=RoleChoices.COUNSELOR)
        self.no_scope_counselor = _build_user(
            email="no-scope-counselor@example.test", role=RoleChoices.COUNSELOR
        )
        self.staff = _build_user(email="staff@example.test", role=RoleChoices.GCO_STAFF)

        # Server-enforced coverage slice: college CCMS only.
        CounselorCoverage.objects.create(
            counselor=self.counselor,
            college="CCMS",
            starts_at=timezone.localdate(),
        )

        self.in_scope_student = _build_student(email="ccms-student@example.test", college="CCMS")
        self.out_of_scope_student = _build_student(email="bio-student@example.test", college="Biology")

        self.career_instrument = AssessmentInstrument.objects.create(
            key="career-guidance",
            title="Career Guidance",
            category=AssessmentInstrumentCategory.CAREER,
        )
        self.academic_instrument = AssessmentInstrument.objects.create(
            key="academic-readiness",
            title="Academic Readiness",
            category=AssessmentInstrumentCategory.ACADEMIC,
        )

        # Group (career, draft): 4 records -> suppressed.
        self._create_assessment_records(
            self.in_scope_student, self.career_instrument, MIN_SUPPRESSION_THRESHOLD - 1
        )
        # Group (academic, draft): 5 records -> intact integer count.
        self._create_assessment_records(
            self.in_scope_student, self.academic_instrument, MIN_SUPPRESSION_THRESHOLD
        )

    def _create_assessment_records(self, student, instrument, number):
        for _ in range(number):
            StudentAssessmentRecord.objects.create(
                student_profile=student,
                instrument=instrument,
                status=AssessmentRecordStatus.DRAFT,
            )

    def _counts_by_category(self, rows):
        return {row["instrument__category"]: row["count"] for row in rows}

    def test_small_nonzero_group_is_suppressed_not_zero(self):
        rows = build_assessment_aggregate_dataset(self.counselor)
        counts = self._counts_by_category(rows)
        self.assertEqual(counts[AssessmentInstrumentCategory.CAREER], SUPPRESSION_LABEL)

    def test_threshold_group_remains_integer_count(self):
        rows = build_assessment_aggregate_dataset(self.counselor)
        counts = self._counts_by_category(rows)
        self.assertEqual(counts[AssessmentInstrumentCategory.ACADEMIC], MIN_SUPPRESSION_THRESHOLD)
        self.assertIsInstance(counts[AssessmentInstrumentCategory.ACADEMIC], int)

    def test_out_of_scope_records_never_inflate_scope_counts(self):
        # Records for a Biology student are outside the CCMS coverage slice.
        self._create_assessment_records(
            self.out_of_scope_student, self.academic_instrument, MIN_SUPPRESSION_THRESHOLD
        )
        rows = build_assessment_aggregate_dataset(self.counselor)
        counts = self._counts_by_category(rows)
        self.assertEqual(counts[AssessmentInstrumentCategory.ACADEMIC], MIN_SUPPRESSION_THRESHOLD)

    def test_no_scope_counselor_gets_no_rows(self):
        # An active counselor without a live coverage scope has no legitimate
        # assessment reporting boundary.  Denial is safer than manufacturing
        # an empty report that could be mistaken for an authorized result.
        with self.assertRaises(PermissionDeniedError):
            build_assessment_aggregate_dataset(self.no_scope_counselor)

    def test_non_counselor_is_denied(self):
        with self.assertRaises(PermissionDeniedError):
            build_assessment_aggregate_dataset(self.staff)


class AssessmentCommandContractTests(TestCase):
    def test_commands_are_frozen_and_do_not_accept_models_or_mappings(self):
        command = AssessmentCreateCommand(student_profile_id=1, instrument_id=2)
        with self.assertRaises(FrozenInstanceError):
            command.instrument_id = 3
        with self.assertRaises(ValidationError):
            AssessmentCreateCommand(student_profile_id=StudentProfile(), instrument_id=2)

    def test_result_command_rejects_arbitrary_fields_and_unbounded_text(self):
        with self.assertRaises(ValidationError):
            AssessmentRecordCommand(fields=("metadata",))
        with self.assertRaises(ValidationError):
            AssessmentRecordCommand(fields=("interpretation_text",), interpretation_text="x" * 9000)


class AssessmentWorkflowServiceTests(TestCase):
    def setUp(self):
        EncryptionKeyVersion.objects.create(
            key_version="assessment-test-v1",
            key_purpose=KeyPurposeChoices.FIELD_ENCRYPTION,
            status=KeyStatusChoices.ACTIVE,
            source_alias="env",
            secret_reference="FIELD_ENCRYPTION_KEY",
            algorithm="Fernet",
        )
        self.head = _build_user(email="assessment-head@example.test", role=RoleChoices.COUNSELOR)
        CounselorProfile.objects.create(user=self.head, is_head_guidance=True)
        self.student = _build_student(email="assessment-owner@example.test", college="CCMS")
        self.instrument = AssessmentInstrument.objects.create(
            key="career-release",
            title="Career Release",
            category=AssessmentInstrumentCategory.CAREER,
            has_official_scoring_guide=True,
            allows_scores=True,
            official_source_reference="approved-source",
        )

    def _record(self):
        return create_assessment_record(
            self.head,
            AssessmentCreateCommand(
                student_profile_id=self.student.pk,
                instrument_id=self.instrument.pk,
            ),
        )

    def test_lifecycle_and_safe_student_release(self):
        record = self._record()
        record = record_assessment_result(
            self.head,
            record.pk,
            AssessmentRecordCommand(
                fields=("score_label", "interpretation_text", "interpretation_visibility"),
                score_label="High",
                interpretation_text="A bounded student-safe summary.",
                interpretation_visibility=AssessmentInterpretationVisibility.RELEASED_TO_STUDENT_SAFE_SUMMARY,
            ),
        )
        self.assertEqual(record.status, AssessmentRecordStatus.RECORDED)
        record = submit_assessment_for_review(
            self.head,
            record.pk,
            AssessmentSubmitReviewCommand(expected_updated_at=record.updated_at),
        )
        record = review_assessment_record(
            self.head,
            record.pk,
            AssessmentReviewCommand(expected_updated_at=record.updated_at),
        )
        record = release_assessment_to_student(
            self.head,
            record.pk,
            AssessmentReleaseCommand(expected_updated_at=record.updated_at),
        )
        self.assertEqual(record.status, AssessmentRecordStatus.RELEASED_TO_STUDENT)
        summary = student_summary_projection(
            StudentAssessmentRecord.objects.select_related("instrument").get(pk=record.pk)
        )
        self.assertEqual(summary["safe_summary"], "A bounded student-safe summary.")
        self.assertNotIn("raw_score", summary)
        self.assertNotIn("scaled_score", summary)
        self.assertNotIn("student_profile", summary)

    def test_stale_update_is_rejected(self):
        record = self._record()
        record = record_assessment_result(
            self.head,
            record.pk,
            AssessmentRecordCommand(),
        )
        with self.assertRaises(StaleStateError):
            submit_assessment_for_review(
                self.head,
                record.pk,
                AssessmentSubmitReviewCommand(expected_updated_at=timezone.now() - timedelta(days=1)),
            )

    def test_student_cannot_use_staff_detail_boundary(self):
        record = self._record()
        from apps.assessments.queries import assessment_detail

        self.assertIsNone(assessment_detail(self.student, record.pk))

    def test_it_can_read_only_protected_file_metadata(self):
        record = self._record()
        protected_file = ProtectedFile.objects.create(
            storage_backend_alias="local",
            bucket_name="local-root",
            object_key="protected/test-assessment-file",
            original_filename_display="assessment.pdf",
            content_type="application/pdf",
            file_size_bytes=10,
            checksum_sha256="a" * 64,
            classification=ClassificationChoices.CONFIDENTIAL,
            purpose=PurposeChoices.ASSESSMENT_RESULT_FILE,
            owning_app_label="assessments",
            owning_model_name="StudentAssessmentRecord",
            owning_object_id=str(record.pk),
            access_policy_key="assessment_result_file",
            status=FileStatusChoices.ACTIVE,
        )
        record.protected_file = protected_file
        record.save(update_fields=["protected_file"])
        it_admin = _build_user(email="assessment-it@example.test", role=RoleChoices.IT_ADMIN)
        from apps.assessments.selectors import (
            get_assessment_file_metadata_for_actor,
            get_assessment_record_for_file_metadata,
        )

        it_record = get_assessment_record_for_file_metadata(it_admin, record.pk)
        metadata = get_assessment_file_metadata_for_actor(it_admin, it_record)
        self.assertEqual(metadata["id"], str(protected_file.pk))
        self.assertNotIn("object_key", metadata)
        self.assertNotIn("checksum_sha256", metadata)
        self.assertEqual(AssessmentFileMetadataSchema(**metadata).size_bytes, 10)


class AssessmentApiContractTests(TestCase):
    def test_assessment_api_uses_standard_auth_and_no_store_boundary(self):
        from django.test import Client

        response = Client().get("/api/v1/assessments/")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertTrue(response["X-Request-ID"])

    def test_openapi_exposes_assessment_operations_without_generic_documents_routes(self):
        from config.api.v1 import api_v1

        schema = api_v1.get_openapi_schema()
        operation_ids = {
            operation.get("operationId")
            for path in schema["paths"].values()
            for operation in path.values()
            if isinstance(operation, dict)
        }
        self.assertIn("assessments_student_summaries", operation_ids)
        self.assertIn("assessments_file_attach", operation_ids)
        self.assertIn("assessments_release", operation_ids)
        self.assertNotIn("documents_crud", operation_ids)

    def test_staff_projection_has_no_sensitive_model_fields(self):
        instrument = AssessmentInstrument(
            id=7,
            key="safe-key",
            title="Safe Instrument",
            category=AssessmentInstrumentCategory.CAREER,
        )
        student = _build_student(email="projection-owner@example.test", college="CCMS")
        record = StudentAssessmentRecord(
            id=9,
            student_profile=student,
            instrument=instrument,
            status=AssessmentRecordStatus.DRAFT,
        )
        from apps.assessments.projections import assessment_staff_projection

        projection = assessment_staff_projection(record)
        self.assertNotIn("interpretation_text_encrypted", projection)
        self.assertNotIn("metadata_json", projection)
        self.assertNotIn("student_profile", projection)
        self.assertEqual(projection["student_reference"], "")


class AssessmentResponseSchemaContractTests(TestCase):
    @staticmethod
    def _instrument():
        return SimpleNamespace(
            id=7,
            key="safe-key",
            title="Safe Instrument",
            category=AssessmentInstrumentCategory.CAREER,
            allows_scores=True,
            allows_interpretation=True,
            is_active=True,
        )

    @classmethod
    def _record(cls):
        now = timezone.now()
        return SimpleNamespace(
            id=9,
            student_profile=SimpleNamespace(student_number="STUDENT-1234"),
            instrument=cls._instrument(),
            status=AssessmentRecordStatus.DRAFT,
            administered_at=now,
            reviewed_at=None,
            released_to_student=True,
            released_to_student_at=now,
            interpretation_visibility=AssessmentInterpretationVisibility.RELEASED_TO_STUDENT_SAFE_SUMMARY,
            protected_file_id=None,
            raw_score="12",
            scaled_score="80",
            score_label="High",
            interpretation_text="A bounded interpretation.",
        )

    def test_instrument_staff_and_student_summary_outputs_are_typed(self):
        record = self._record()
        instrument = instrument_projection(record.instrument)
        staff = assessment_staff_projection(record)
        summary = student_summary_projection(record)

        self.assertEqual(
            set(instrument),
            {
                "id",
                "key",
                "title",
                "category",
                "allows_scores",
                "allows_interpretation",
                "active",
            },
        )
        self.assertEqual(AssessmentInstrumentSchema(**instrument).key, "safe-key")
        self.assertEqual(AssessmentStaffProjectionSchema(**staff).id, 9)
        self.assertEqual(
            AssessmentPageSchema(items=[staff], page=1, page_size=25, total=1).items[0].id,
            9,
        )
        self.assertEqual(AssessmentStudentSummarySchema(**summary).safe_summary, "A bounded interpretation.")
        self.assertEqual(
            AssessmentStudentSummaryPageSchema(
                items=[summary], page=1, page_size=25, total=1
            ).items[0].instrument.key,
            "safe-key",
        )

        self.assertTrue(
            {
                "raw_score",
                "scaled_score",
                "score_label",
                "interpretation",
                "interpretation_text_encrypted",
                "metadata_json",
                "student_profile",
            }.isdisjoint(staff)
        )
        self.assertTrue(
            {"raw_score", "scaled_score", "score_label", "interpretation"}.isdisjoint(summary)
        )

    def test_sensitive_and_file_metadata_outputs_are_bounded(self):
        sensitive = assessment_sensitive_projection(self._record())
        self.assertEqual(
            {
                "raw_score",
                "scaled_score",
                "score_label",
                "interpretation",
            },
            set(sensitive) - set(assessment_staff_projection(self._record())),
        )
        self.assertEqual(
            AssessmentSensitiveProjectionSchema(**sensitive).interpretation,
            "A bounded interpretation.",
        )

        metadata = protected_file_metadata_projection(
            {
                "id": "file-1",
                "filename": "assessment.pdf",
                "content_type": "application/pdf",
                "size_bytes": 10,
                "classification": "CONFIDENTIAL",
                "purpose": "ASSESSMENT_RESULT_FILE",
                "status": "ACTIVE",
                "object_key": "must-not-cross",
                "checksum_sha256": "must-not-cross",
            }
        )
        self.assertEqual(
            set(metadata),
            {"id", "filename", "content_type", "size_bytes", "classification", "purpose", "status"},
        )
        self.assertEqual(AssessmentFileMetadataSchema(**metadata).filename, "assessment.pdf")


class AssessmentApiResponseRuntimeTests(TestCase):
    def setUp(self):
        from apps.inventory.tests import _enable_test_field_encryption

        _enable_test_field_encryption()
        self.client = Client()
        self.head = _build_user(email="assessment-api-head@example.test", role=RoleChoices.COUNSELOR)
        CounselorProfile.objects.create(user=self.head, is_head_guidance=True)
        self.student = _build_student(email="assessment-api-student@example.test", college="CCMS")
        self.instrument = AssessmentInstrument.objects.create(
            key="assessment-api-instrument",
            title="Assessment API Instrument",
            category=AssessmentInstrumentCategory.CAREER,
            allows_interpretation=True,
        )
        self.head_token = issue_token_pair(self.head, assurance_verified=True).access_token

    @staticmethod
    def _json(value):
        return json.dumps(value)

    def _headers(self, token=None, key=None):
        return {
            "HTTP_AUTHORIZATION": f"Bearer {token or self.head_token}",
            "HTTP_IDEMPOTENCY_KEY": key or "assessment-api-response-1",
        }

    def test_create_response_and_idempotent_replay_use_staff_schema(self):
        body = {
            "student_profile_id": self.student.pk,
            "instrument_id": self.instrument.pk,
        }
        response = self.client.post(
            "/api/v1/assessments/",
            data=self._json(body),
            content_type="application/json",
            **self._headers(key="assessment-api-create-replay"),
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        validated = AssessmentStaffProjectionSchema(**payload)
        self.assertEqual(validated.instrument.key, self.instrument.key)
        self.assertNotIn("expected_updated_at", payload)
        self.assertNotIn("metadata_json", payload)

        replay = self.client.post(
            "/api/v1/assessments/",
            data=self._json(body),
            content_type="application/json",
            **self._headers(key="assessment-api-create-replay"),
        )
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.json(), payload)

    def test_student_summary_is_safe_and_staff_detail_stays_denied(self):
        record = create_assessment_record(
            self.head,
            AssessmentCreateCommand(
                student_profile_id=self.student.pk,
                instrument_id=self.instrument.pk,
            ),
        )
        record = record_assessment_result(
            self.head,
            record.pk,
            AssessmentRecordCommand(
                fields=("interpretation_text", "interpretation_visibility"),
                interpretation_text="A bounded student-safe summary.",
                interpretation_visibility=AssessmentInterpretationVisibility.RELEASED_TO_STUDENT_SAFE_SUMMARY,
            ),
        )
        record = submit_assessment_for_review(
            self.head,
            record.pk,
            AssessmentSubmitReviewCommand(expected_updated_at=record.updated_at),
        )
        record = review_assessment_record(
            self.head,
            record.pk,
            AssessmentReviewCommand(expected_updated_at=record.updated_at),
        )
        release_assessment_to_student(
            self.head,
            record.pk,
            AssessmentReleaseCommand(expected_updated_at=record.updated_at),
        )

        student_token = issue_token_pair(self.student.user, assurance_verified=True).access_token
        summary_response = self.client.get(
            f"/api/v1/assessments/student/summaries/{record.pk}/",
            **self._headers(token=student_token),
        )
        self.assertEqual(summary_response.status_code, 200)
        summary = AssessmentStudentSummarySchema(**summary_response.json())
        self.assertEqual(summary.safe_summary, "A bounded student-safe summary.")
        self.assertNotIn("raw_score", summary_response.json())
        self.assertNotIn("interpretation", summary_response.json())

        staff_response = self.client.get(
            f"/api/v1/assessments/{record.pk}/",
            **self._headers(token=student_token),
        )
        self.assertEqual(staff_response.status_code, 404)

        sensitive_response = self.client.get(
            f"/api/v1/assessments/{record.pk}/interpretation/",
            **self._headers(),
        )
        self.assertEqual(sensitive_response.status_code, 200)
        self.assertEqual(
            AssessmentSensitiveProjectionSchema(**sensitive_response.json()).interpretation,
            "A bounded student-safe summary.",
        )
