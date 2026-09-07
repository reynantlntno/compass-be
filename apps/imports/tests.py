"""Focused contract tests for the governed onboarding API boundary."""

from datetime import timedelta
from types import SimpleNamespace

from django.test import Client, SimpleTestCase, TestCase
from django.utils import timezone

from apps.common.exceptions import ValidationError
from apps.imports.commands import ImportBatchExecuteCommand, ImportRowCorrectionCommand
from apps.imports.api import (
    ImportBatchExecutionResponseSchema,
    ImportBatchSchema,
    ImportCatalogPageSchema,
    ImportInvitationIssueResponseSchema,
    ImportInvitationSchema,
    ImportRowSchema,
)
from apps.imports.projections import batch_projection, catalog_projection, invitation_projection, row_editor_projection, row_projection
from apps.student_activation.commands import StudentActivationCommand


class ImportCommandContractTests(SimpleTestCase):
    def test_commands_are_frozen_and_reject_unbounded_values(self):
        command = ImportBatchExecuteCommand(request_key_digest="a" * 64)
        with self.assertRaises((AttributeError, TypeError)):
            command.request_key_digest = "b" * 64
        with self.assertRaises(ValidationError):
            ImportBatchExecuteCommand(request_key_digest="raw-key")
        with self.assertRaises(ValidationError):
            ImportRowCorrectionCommand()

    def test_sensitive_command_repr_does_not_contain_raw_values(self):
        command = StudentActivationCommand(
            token="raw-activation-token",
            password="correct-horse-battery-staple",
            password_confirmation="correct-horse-battery-staple",
        )
        rendered = repr(command)
        self.assertNotIn("raw-activation-token", rendered)
        self.assertNotIn("correct-horse-battery-staple", rendered)


class ImportProjectionContractTests(SimpleTestCase):
    def test_row_projection_has_no_raw_identifiers_or_arbitrary_metadata(self):
        row = SimpleNamespace(
            pk=10,
            row_number=2,
            validation_status="VALID",
            error_code="",
            error_message="",
            email="student@example.test",
            student_number="STUDENT-001",
            control_number="CONTROL-001",
            first_name="Student",
            last_name="Example",
            campus="Main",
            college="College",
            department="Department",
            program="Program",
            program_code="PROGRAM",
            year_level=1,
            correction_revision=0,
            reviewed_at=None,
        )
        projection = row_projection(row)
        self.assertNotIn("STUDENT-001", repr(projection))
        self.assertNotIn("CONTROL-001", repr(projection))
        self.assertNotIn("email", projection)
        self.assertIn("masked_email", projection)

    def test_invitation_projection_is_redacted(self):
        invitation = SimpleNamespace(
            pk=22,
            expires_at=timezone.now(),
            used_at=None,
            revoked_at=None,
        )
        projection = invitation_projection(invitation)
        self.assertEqual(set(projection), {"id", "status", "expires_at", "used_at", "revoked_at", "delivery_state"})
        self.assertNotIn("token", projection)


class ImportResponseSchemaContractTests(SimpleTestCase):
    @staticmethod
    def _batch():
        now = timezone.now()
        return SimpleNamespace(
            pk=10,
            source_name="Admissions Office",
            academic_year="2026-2027",
            status="DRAFT",
            template_version="student_onboarding-v1",
            catalog_version="ucn-2026",
            content_hmac="a" * 64,
            _row_count=2,
            validation_revision=1,
            validated_at=now,
            approved_at=None,
            approval_revoked_at=None,
            executed_at=None,
            execution_summary={
                "success": 1,
                "reconciled": 0,
                "excluded": 1,
                "total": 2,
                "internal_note": "must not cross the projection",
            },
        )

    @staticmethod
    def _row():
        return SimpleNamespace(
            pk=10,
            row_number=2,
            validation_status="VALID",
            error_code="",
            error_message="",
            email="student@example.test",
            student_number="STUDENT-001",
            control_number="CONTROL-001",
            first_name="Student",
            last_name="Example",
            campus="Main",
            college="College",
            department="Department",
            program="Program",
            program_code="PROGRAM",
            year_level=1,
            lifecycle_status="ACTIVE",
            correction_revision=0,
            reviewed_at=None,
        )

    def test_batch_catalog_and_execution_outputs_are_explicit_and_bounded(self):
        batch = batch_projection(self._batch())
        self.assertEqual(
            set(batch),
            {
                "id", "source_name", "academic_year", "status", "template_version",
                "catalog_version", "content_present", "row_count", "validation_revision",
                "validated_at", "approved_at", "approval_revoked_at", "executed_at",
                "execution_summary",
            },
        )
        self.assertEqual(
            set(batch["execution_summary"]),
            {"success", "reconciled", "excluded", "total"},
        )
        self.assertEqual(ImportBatchSchema(**batch).execution_summary.total, 2)

        execution = ImportBatchExecutionResponseSchema(
            **{**batch, "execution_result": batch["execution_summary"]}
        )
        replay = ImportBatchExecutionResponseSchema(**batch)
        self.assertEqual(execution.execution_result.success, 1)
        self.assertIsNone(replay.execution_result)

        catalog = catalog_projection(
            {
                "version": "ucn-2026",
                "demo_only": True,
                "source_reference": "internal-only",
                "placements": [
                    {
                        "program_code": "PROGRAM",
                        "campus": "Main",
                        "college": "College",
                        "department": "Department",
                        "program": "Program",
                        "max_year_level": 4,
                        "internal": "not emitted",
                    }
                ],
            }
        )
        catalog_page = {
            "items": catalog["placements"],
            "page": 1,
            "page_size": 20,
            "total": 1,
            "version": catalog["version"],
            "demo_only": catalog["demo_only"],
        }
        self.assertEqual(ImportCatalogPageSchema(**catalog_page).items[0].program_code, "PROGRAM")
        self.assertNotIn("source_reference", catalog_page)

    def test_row_editor_and_invitation_outputs_preserve_redaction_boundary(self):
        row = self._row()
        normal = row_projection(row)
        self.assertNotIn("email", normal)
        self.assertNotIn("student_number", normal)
        self.assertNotIn("control_number", normal)
        self.assertIsNone(ImportRowSchema(**normal).editable_fields)

        editor = row_editor_projection(row)
        editor_schema = ImportRowSchema(**editor)
        self.assertIsNotNone(editor_schema.editable_fields)
        self.assertEqual(editor_schema.editable_fields.email, "student@example.test")

        invitation = invitation_projection(
            SimpleNamespace(
                pk=22,
                expires_at=timezone.now() + timedelta(hours=1),
                used_at=None,
                revoked_at=None,
            )
        )
        invitation_schema = ImportInvitationSchema(**invitation)
        self.assertEqual(invitation_schema.id, "22")
        self.assertNotIn("token", invitation)

    def test_invitation_issue_response_models_mutation_and_replay_shapes(self):
        issued = ImportInvitationIssueResponseSchema(issued=2, skipped=1, eligible=3)
        replay = ImportInvitationIssueResponseSchema(status="completed", batch_id="10")
        self.assertEqual((issued.issued, issued.skipped, issued.eligible), (2, 1, 3))
        self.assertEqual((replay.status, replay.batch_id), ("completed", "10"))
        self.assertIsNone(replay.issued)


class ImportApiContractTests(TestCase):
    def test_import_routes_are_bearer_protected_and_activation_is_public_boundary(self):
        client = Client()
        response = client.get("/api/v1/imports/")
        self.assertEqual(response.status_code, 401)
        schema = client.get("/api/v1/openapi.json").json()
        operation_ids = {
            operation.get("operationId")
            for path in schema["paths"].values()
            for operation in path.values()
            if isinstance(operation, dict)
        }
        self.assertIn("imports_execute", operation_ids)
        self.assertIn("auth_student_activation", operation_ids)
