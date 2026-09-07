"""Focused regression tests for the decommissioned wellness cleanup boundary."""

import uuid
from dataclasses import FrozenInstanceError
from types import SimpleNamespace

from django.db import connection
from django.test import Client, SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from apps.account_security.api_tokens import issue_token_pair
from apps.accounts.models import RoleChoices, User
from apps.assessments.choices import AssessmentInstrumentCategory
from apps.backups import choices as backup_choices
from apps.backups import models as backup_models
from apps.backups.validation import validate_manifest_payload
from apps.common.exceptions import DependencyFailureError, ValidationError
from apps.counseling.models import CounselingCaseConcernCategory
from apps.backups.commands import BackupCompletionReceipt, BackupRequestCommand, RestoreTransitionCommand
from apps.backups.api import (
    BackupArtifactPageSchema,
    BackupArtifactProjectionSchema,
    BackupDashboardSchema,
    BackupJobPageSchema,
    BackupJobProjectionSchema,
    RestoreRequestPageSchema,
    RestoreRequestProjectionSchema,
)
from apps.backups.projections import (
    backup_artifact_projection,
    backup_dashboard_projection,
    backup_job_projection,
    restore_dashboard_projection,
    restore_request_projection,
)
from apps.backups.models import BackupArtifact, BackupJob, RestoreRequest
from apps.backups.services import _configured_backup_storage_target


class BackupResponseContractTests(SimpleTestCase):
    def setUp(self):
        self.now = timezone.now()
        self.job = SimpleNamespace(
            pk=uuid.uuid4(),
            job_type="full",
            status="verified",
            environment="testing",
            includes_database=True,
            includes_media=False,
            includes_protected_files=True,
            includes_manifest=True,
            encrypted_at_rest=True,
            storage_target_type="s3_compatible",
            retention_class="daily",
            artifact_count=1,
            total_size_bytes=42,
            safe_failure_reason_code=None,
            requested_at=self.now,
            queued_at=None,
            started_at=self.now,
            completed_at=self.now,
            failed_at=None,
            cancelled_at=None,
            verified_at=self.now,
            expires_at=None,
        )
        self.artifact = SimpleNamespace(
            pk=uuid.uuid4(),
            backup_job_id=self.job.pk,
            artifact_type="database_dump",
            size_bytes=42,
            encryption_status="encrypted",
            created_at=self.now,
            storage_reference="must-not-cross-the-boundary",
            checksum_sha256="must-not-cross-the-boundary",
            key_version_reference="must-not-cross-the-boundary",
        )
        checklist = SimpleNamespace(
            pk=uuid.uuid4(),
            step_key="manifest",
            status="passed",
            safe_message_code="MANIFEST_OK",
            recorded_at=self.now,
        )
        self.restore_request = SimpleNamespace(
            pk=uuid.uuid4(),
            target_backup_job_id=self.job.pk,
            restore_scope="full",
            status="restore_ready",
            safe_reason_code="authorized",
            dry_run_result_code="passed",
            institutional_authorization_type="change_ticket",
            authorization_recorded_at=self.now,
            started_at=None,
            completed_at=None,
            failed_at=None,
            cancelled_at=None,
            created_at=self.now,
            updated_at=self.now,
            checklist_items=SimpleNamespace(all=lambda: [checklist]),
            metadata_json={"must_not": "cross-the-boundary"},
            institutional_authorization_reference="must-not-cross-the-boundary",
        )

    def test_job_artifact_restore_and_dashboard_projections_match_typed_outputs(self):
        job_projection = backup_job_projection(self.job)
        self.assertEqual(
            set(job_projection),
            {
                "id",
                "scope",
                "status",
                "environment",
                "includes_database",
                "includes_media",
                "includes_protected_files",
                "includes_manifest",
                "encrypted_at_rest",
                "storage_target_type",
                "retention_class",
                "artifact_count",
                "total_size_bytes",
                "safe_failure_reason_code",
                "requested_at",
                "queued_at",
                "started_at",
                "completed_at",
                "failed_at",
                "cancelled_at",
                "verified_at",
                "expires_at",
                "resource_version",
            },
        )
        self.assertIsInstance(BackupJobProjectionSchema(**job_projection).artifact_count, int)

        artifact_projection = backup_artifact_projection(self.artifact)
        self.assertEqual(
            set(artifact_projection),
            {"id", "backup_job_id", "artifact_type", "size_bytes", "encryption_status", "created_at"},
        )
        self.assertIsInstance(BackupArtifactProjectionSchema(**artifact_projection).size_bytes, int)

        restore_projection = restore_request_projection(self.restore_request)
        self.assertEqual(
            set(restore_projection),
            {
                "id",
                "target_backup_job_id",
                "restore_scope",
                "status",
                "safe_reason_code",
                "dry_run_result_code",
                "institutional_authorization_type",
                "authorization_recorded_at",
                "started_at",
                "completed_at",
                "failed_at",
                "cancelled_at",
                "created_at",
                "updated_at",
                "checklist",
            },
        )
        restore_schema = RestoreRequestProjectionSchema(**restore_projection)
        self.assertEqual(restore_schema.checklist[0].step_key, "manifest")

        dashboard_projection = {
            "backups": backup_dashboard_projection({
                "total_jobs": 1,
                "queued_or_running_count": 0,
                "archive_count": 1,
                "verified_archive_count": 1,
                "failed_count": 0,
                "latest_job": self.job,
            }),
            "restores": restore_dashboard_projection({
                "total_requests": 1,
                "completed_count": 0,
                "active_count": 1,
                "latest_request": self.restore_request,
            }),
        }
        dashboard = BackupDashboardSchema(**dashboard_projection)
        self.assertEqual(dashboard.backups.latest_job.id, str(self.job.pk))
        self.assertEqual(dashboard.restores.latest_request.id, str(self.restore_request.pk))

        BackupJobPageSchema(items=[job_projection], page=1, page_size=25, total=1)
        BackupArtifactPageSchema(items=[artifact_projection], page=1, page_size=25, total=1)
        RestoreRequestPageSchema(items=[restore_projection], page=1, page_size=25, total=1)

        serialized = str([job_projection, artifact_projection, restore_projection])
        for forbidden in (
            "storage_reference",
            "checksum_sha256",
            "key_version_reference",
            "metadata_json",
            "institutional_authorization_reference",
            "expected_updated_at",
        ):
            self.assertNotIn(forbidden, serialized)


class BackupApiResponseTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.it_admin = User.objects.create_user(
            email="backups-contract-it@example.test",
            password="correct-horse-battery-staple",
            role=RoleChoices.IT_ADMIN,
            is_active=True,
        )
        self.token = issue_token_pair(self.it_admin, assurance_verified=True).access_token

    def test_empty_operational_pages_and_dashboard_validate_at_the_api_boundary(self):
        headers = {"HTTP_AUTHORIZATION": f"Bearer {self.token}"}
        endpoints = (
            ("/api/v1/backups/", BackupDashboardSchema),
            ("/api/v1/backups/jobs/", BackupJobPageSchema),
            ("/api/v1/backups/restores/", RestoreRequestPageSchema),
        )
        for path, schema in endpoints:
            with self.subTest(path=path):
                response = self.client.get(path, **headers)
                self.assertEqual(response.status_code, 200, response.content)
                schema(**response.json())


class BackupApiBoundaryTests(SimpleTestCase):
    @override_settings(BACKUP_STORAGE_BACKEND="metadata_only")
    def test_unconfigured_storage_is_an_operational_failure(self):
        with self.assertRaises(DependencyFailureError):
            _configured_backup_storage_target()

    def test_commands_are_frozen_and_reject_unbounded_inputs(self):
        command = BackupRequestCommand(scope="full", reason="operator_request")
        with self.assertRaises(FrozenInstanceError):
            command.scope = "media"
        with self.assertRaises(ValidationError):
            BackupRequestCommand(scope={"scope": "full"})
        with self.assertRaises(ValidationError):
            RestoreTransitionCommand(reason={"unsafe": True})
        with self.assertRaises(ValidationError):
            BackupCompletionReceipt(manifest_hash="not-a-hash", artifact_count=1, total_size_bytes=1)

    def test_worker_receipts_are_bounded_and_immutable(self):
        receipt = BackupCompletionReceipt(
            manifest_hash="a" * 64,
            artifact_count=1,
            total_size_bytes=42,
        )
        self.assertEqual(receipt.artifact_count, 1)
        with self.assertRaises(FrozenInstanceError):
            receipt.artifact_count = 2

    def test_metadata_projections_exclude_storage_and_secret_fields(self):
        artifact = SimpleNamespace(
            pk=uuid.uuid4(),
            backup_job_id=uuid.uuid4(),
            artifact_type="database_dump",
            size_bytes=10,
            encryption_status="encrypted",
            created_at=None,
            storage_reference="s3://private/archive.tar",
            checksum_sha256="secret-checksum",
            key_version_reference="key-v1",
        )
        job = SimpleNamespace(
            pk=uuid.uuid4(), job_type="full", status="verified", environment="testing",
            includes_database=True, includes_media=False, includes_protected_files=False,
            includes_manifest=True, encrypted_at_rest=True, storage_target_type="s3_compatible",
            retention_class="daily", artifact_count=1, total_size_bytes=10,
            safe_failure_reason_code=None, requested_at=None, queued_at=None,
            started_at=None, completed_at=None, failed_at=None, cancelled_at=None,
            verified_at=None, expires_at=None,
        )
        artifact_projection = backup_artifact_projection(artifact)
        job_projection = backup_job_projection(job)
        self.assertNotIn("storage_reference", artifact_projection)
        self.assertNotIn("checksum_sha256", artifact_projection)
        self.assertNotIn("key_version_reference", artifact_projection)
        self.assertNotIn("metadata_json", job_projection)

    def test_projection_rejects_untrusted_operational_codes(self):
        job = SimpleNamespace(
            pk=uuid.uuid4(), job_type="full", status="verified", environment="secret=value",
            includes_database=True, includes_media=False, includes_protected_files=False,
            includes_manifest=True, encrypted_at_rest=True, storage_target_type="private://archive",
            retention_class="daily", artifact_count=1, total_size_bytes=10,
            safe_failure_reason_code="password=leak", requested_at=None, queued_at=None,
            started_at=None, completed_at=None, failed_at=None, cancelled_at=None,
            verified_at=None, expires_at=None,
        )
        projection = backup_job_projection(job)
        self.assertEqual(projection["environment"], "unknown")
        self.assertEqual(projection["storage_target_type"], "other")
        self.assertEqual(projection["safe_failure_reason_code"], "")

    def test_openapi_exposes_only_the_operational_routes(self):
        from config.api.v1 import api_v1

        schema = api_v1.get_openapi_schema()
        self.assertIn("/api/v1/backups/", schema["paths"])
        self.assertIn("/api/v1/system/health/", schema["paths"])
        self.assertIn("/api/v1/system/operations/runs/", schema["paths"])
        operations = {
            operation.get("operationId")
            for path in schema["paths"].values()
            for operation in path.values()
            if isinstance(operation, dict)
        }
        self.assertNotIn("backups_restore_start", operations)
        self.assertNotIn("backups_restore_complete", operations)
        self.assertIn("system_maintenance_schedule", operations)


def _canonical_manifest(*, include_journal_key=False):
    payload = {
        "schema_version": "3.0",
        "backup_operation_id": str(uuid.uuid4()),
        "archive_identifier": str(uuid.uuid4()),
        "job_type": "full",
        "environment_class": "testing",
        "created_at": "2026-08-23T00:00:00.000000Z",
        "storage_target_type": "metadata_only",
        "included": {
            "database": False,
            "media": False,
            "protected_files": False,
            "manifest": True,
        },
        "database_dump": None,
        "archive_member_allowlist": [
            {
                "member_name": "manifest.json",
                "member_class": "MANIFEST",
                "required": True,
                "sha256": None,
                "size_bytes": None,
            }
        ],
        "transient_state_exclusion": None,
        "protected_file_manifest": [],
        "public_media_manifest": [],
        "components": [],
    }
    if include_journal_key:
        payload["journal_crypto"] = {"state": "retired"}
    return payload


class DecommissionedWellnessCleanupTests(TestCase):
    def test_manifest_schema_rejects_retired_journal_crypto_key(self):
        validate_manifest_payload(_canonical_manifest())
        with self.assertRaises(ValidationError):
            validate_manifest_payload(_canonical_manifest(include_journal_key=True))

    def test_removed_backup_gate_and_status_are_not_runtime_surfaces(self):
        self.assertFalse(hasattr(backup_models, "RestoreReconciliationGate"))
        self.assertFalse(hasattr(backup_choices, "RestoreReconciliationGateState"))
        self.assertNotIn(
            "journal_reconciled",
            {choice.value for choice in backup_choices.RestoreStatusChoices},
        )
        table_names = set(connection.introspection.table_names())
        self.assertNotIn("backups_restorereconciliationgate", table_names)

    def test_legitimate_wellness_categories_remain_available(self):
        self.assertEqual(
            AssessmentInstrumentCategory.WELLNESS_SCREENING_NON_DIAGNOSTIC,
            "wellness_screening_non_diagnostic",
        )
        self.assertEqual(
            CounselingCaseConcernCategory.MENTAL_WELLNESS,
            "MENTAL_WELLNESS",
        )
