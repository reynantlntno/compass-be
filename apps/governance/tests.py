import ast
import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from django.test import Client, TestCase, override_settings
from django.utils import timezone

from apps.accounts.models import RoleChoices, User
from apps.account_security.api_tokens import issue_token_pair
from apps.common.exceptions import GovernanceError, PermissionDeniedError, ValidationError
from apps.common.policy import PolicyDefinition
from apps.governance.choices import DPOAppointmentStatus, PolicyLifecycleStatus
from apps.common.policy import PolicyChangeRequest
from apps.governance.dpo_api import DPOAppointmentSchema
from apps.privacy.governance_api import (
    PrivacyNoticeRevisionSchema,
    PrivacyReviewerAuthorizationPageSchema,
    PrivacyReviewerAuthorizationSchema,
)
from apps.governance.models import DPOAppointment, PolicyRecord, PolicyTransition
from apps.governance.projections import (
    project_dpo_appointment,
    project_policy,
)
from apps.privacy.projections import reviewer_authorization_projection
from apps.governance.registry import (
    POLICY_SPECS,
    get_policy_definition,
    register_policy_definition,
    validate_policy_registry,
)
from apps.governance.selectors import resolve_effective_policy, resolve_feature_flag
from apps.governance.runtime_config import resolve_runtime_setting
from apps.governance.policy_lifecycle import (
    activate_policy,
    approve_policy,
    can_manage_policy,
    create_policy_draft,
    retire_policy,
    submit_policy,
)
from apps.governance.dpo_services import create_dpo_appointment, is_current_dpo
from config.runtime_settings import (
    ENVIRONMENT_RUNTIME_SETTINGS,
    RUNTIME_SETTING_INVENTORY,
    RUNTIME_SETTING_DEFAULTS,
    RUNTIME_SETTING_RULES,
)
from apps.profiles.models import CounselorProfile
from apps.privacy.services import create_privacy_reviewer_authorization, revoke_privacy_reviewer_authorization
from apps.reports.models import ReportDefinition


def _user(email, role, *, active=True, superuser=False):
    actor = User.objects.create_user(
        email=email,
        password="correct-horse-battery-staple",
        first_name="Policy",
        last_name="Tester",
        role=role,
        is_active=active,
    )
    if superuser:
        actor.is_superuser = True
        actor.save(update_fields=["is_superuser"])
    return actor


class PolicyRegistryTests(TestCase):
    def test_governance_lifecycle_has_no_domain_model_imports(self):
        services = (Path(__file__).resolve().parent / "policy_lifecycle.py").read_text()
        for domain in ("good_moral", "reports", "form_collection", "privacy", "exit_interviews"):
            self.assertNotIn(f"apps.{domain}.models", services)
            self.assertNotIn(f"apps.{domain}.services", services)

    def test_registry_is_complete_and_has_owner_planes(self):
        validate_policy_registry()
        self.assertGreaterEqual(len(POLICY_SPECS), 9)
        self.assertEqual({getattr(spec.owner_plane, "value", spec.owner_plane) for spec in POLICY_SPECS}, {"HEAD_BUSINESS", "DPO_PRIVACY", "IT_TECHNICAL"})

    def test_domain_policy_registration_rejects_conflicting_duplicates(self):
        definition = get_policy_definition("good_moral.exit_prerequisite")
        self.assertIsInstance(definition, PolicyDefinition)
        with self.assertRaises(RuntimeError):
            register_policy_definition(replace(definition, normalize=lambda value: dict(value)))

    def test_every_registered_policy_declares_typed_runtime_contract(self):
        self.assertTrue(all(spec.runtime_reader for spec in POLICY_SPECS))
        self.assertTrue(all(spec.runtime_consumer for spec in POLICY_SPECS))
        validate_policy_registry()

    def test_runtime_defaults_have_one_code_owned_source_and_safety_bounds(self):
        self.assertEqual(set(RUNTIME_SETTING_DEFAULTS), set(RUNTIME_SETTING_RULES))
        validate_policy_registry()
        for setting_key, expected in RUNTIME_SETTING_DEFAULTS.items():
            self.assertEqual(RUNTIME_SETTING_INVENTORY[setting_key].default, expected)

    def test_runtime_setting_falls_back_to_code_catalog_without_database_policy(self):
        from unittest.mock import patch

        with patch("apps.governance.runtime_config.resolve_effective_policy", return_value=None):
            for setting_key, expected in RUNTIME_SETTING_DEFAULTS.items():
                self.assertEqual(
                    resolve_runtime_setting("technical.configuration", setting_key),
                    expected,
                )

    def test_runtime_settings_are_not_read_from_django_environment_config(self):
        settings_root = Path(__file__).resolve().parents[2] / "config" / "settings"
        governed_keys = set(RUNTIME_SETTING_DEFAULTS)
        environment_reads = []
        runtime_setting_reads = []
        for path in settings_root.glob("*.py"):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                function = node.func if isinstance(node, ast.Call) else None
                is_environment_reader = (
                    isinstance(function, ast.Name)
                    and function.id == "env"
                ) or (
                    isinstance(function, ast.Attribute)
                    and isinstance(function.value, ast.Name)
                    and function.value.id == "env"
                )
                is_runtime_reader = isinstance(function, ast.Name) and function.id == "runtime_env"
                if (is_environment_reader or is_runtime_reader) and node.args:
                    first = node.args[0]
                    if isinstance(first, ast.Constant) and first.value in governed_keys:
                        if is_runtime_reader:
                            runtime_setting_reads.append((path.name, first.value))
                        else:
                            environment_reads.append((path.name, first.value))
        self.assertEqual(environment_reads, [])
        self.assertEqual(set(setting for _, setting in runtime_setting_reads), ENVIRONMENT_RUNTIME_SETTINGS)

    def test_runtime_inventory_is_complete_and_bounded(self):
        self.assertEqual(set(RUNTIME_SETTING_DEFAULTS), set(RUNTIME_SETTING_INVENTORY))
        self.assertEqual(set(RUNTIME_SETTING_RULES), set(RUNTIME_SETTING_INVENTORY))
        for spec in RUNTIME_SETTING_INVENTORY.values():
            self.assertEqual(spec.validate(spec.default), spec.default)
            if spec.source == "environment":
                self.assertEqual(spec.env_name, spec.key)
                self.assertFalse(spec.policy_approval_required)
                self.assertEqual(spec.reload_mode, "restart")
                self.assertEqual(spec.deprecation_status, "migrated-to-environment")
            else:
                self.assertIsNone(spec.env_name)
                self.assertTrue(spec.policy_approval_required)
                self.assertEqual(spec.reload_mode, "database-effective")
                self.assertEqual(spec.deprecation_status, "active")

    def test_environment_owned_settings_are_propagated_to_deployment_contracts(self):
        repo_root = Path(__file__).resolve().parents[2]
        deployment_files = (
            ".env.example",
            "deploy/local-staging.env.example",
            "deploy/staging.env.example",
            "compose.yaml",
            "compose.override.yaml",
            "compose.local-staging.yaml",
            "compose.staging.yaml",
        )
        contents = {
            relative_path: (repo_root / relative_path).read_text()
            for relative_path in deployment_files
        }
        for setting_key in ENVIRONMENT_RUNTIME_SETTINGS:
            missing = [path for path, content in contents.items() if setting_key not in content]
            self.assertEqual(missing, [], setting_key)

    def test_backup_worker_polling_uses_the_central_runtime_boundary(self):
        self.assertEqual(
            resolve_runtime_setting(
                "technical.backup_metadata",
                "BACKUP_WORKER_POLL_INTERVAL_SECONDS",
            ),
            15,
        )

    def test_feature_flag_reader_is_target_scoped_and_fails_closed(self):
        self.assertFalse(resolve_feature_flag("missing.flag"))

    def test_maintenance_enforcement_is_environment_owned(self):
        self.assertEqual(
            RUNTIME_SETTING_INVENTORY["MAINTENANCE_ENFORCEMENT_ENABLED"].source,
            "environment",
        )
        with override_settings(MAINTENANCE_ENFORCEMENT_ENABLED=True):
            self.assertTrue(resolve_runtime_setting(
                "technical.configuration",
                "MAINTENANCE_ENFORCEMENT_ENABLED",
            ))

    def test_environment_owned_setting_ignores_historical_policy_record(self):
        from unittest.mock import patch

        with override_settings(EMAIL_TIMEOUT=17):
            with patch("apps.governance.runtime_config.resolve_effective_policy") as resolver:
                self.assertEqual(
                    resolve_runtime_setting("technical.delivery_operations", "EMAIL_TIMEOUT"),
                    17,
                )
                resolver.assert_not_called()

    def test_environment_owned_policy_rows_are_explicitly_audit_only(self):
        policy = PolicyRecord.objects.filter(
            configuration_json__setting_key="EMAIL_TIMEOUT",
        ).first()
        if policy is not None:
            self.assertEqual(policy.effectiveness, "DEPRECATED")

    def test_delivery_controls_are_environment_owned_settings(self):
        expected = {
            "EMAIL_TIMEOUT": 10,
            "NOTIFICATION_WORKER_ENABLED": False,
            "NOTIFICATION_WORKER_INTERVAL_SECONDS": 5,
            "NOTIFICATION_WORKER_BATCH_SIZE": 20,
            "NOTIFICATION_WORKER_LOCK_TIMEOUT_SECONDS": 300,
        }
        for setting_key, default in expected.items():
            self.assertEqual(RUNTIME_SETTING_INVENTORY[setting_key].source, "environment")
            self.assertEqual(
                resolve_runtime_setting(
                    "technical.delivery_operations",
                    setting_key,
                ),
                default,
            )

    def test_upload_and_import_controls_are_domain_owned_policies(self):
        assessment = next(spec for spec in POLICY_SPECS if spec.key == "security.assessment_upload_controls")
        imports = next(spec for spec in POLICY_SPECS if spec.key == "student_import.controls")
        self.assertIsNotNone(assessment.normalize)
        self.assertIsNotNone(imports.normalize)
        self.assertEqual(assessment.target_type, "")
        self.assertEqual(imports.target_type, "")


class CentralUploadControlConsumerTests(TestCase):
    def test_assessment_and_student_import_readers_use_central_records(self):
        from apps.imports.onboarding import _max_upload_bytes, _max_upload_rows
        from apps.security.file_services import _assessment_upload_policy

        assessment_policy = resolve_effective_policy("security.assessment_upload_controls")
        import_policy = resolve_effective_policy("student_import.controls")
        self.assertIsNotNone(assessment_policy)
        self.assertIsNotNone(import_policy)
        self.assertEqual(_assessment_upload_policy()[2], assessment_policy.configuration_json["max_file_size_bytes"])
        self.assertEqual(_max_upload_bytes(), import_policy.configuration_json["max_upload_bytes"])
        self.assertEqual(_max_upload_rows(), import_policy.configuration_json["max_upload_rows"])

    def test_malformed_upload_policy_fails_closed_at_runtime(self):
        policy = resolve_effective_policy("security.assessment_upload_controls")
        config = dict(policy.configuration_json)
        config["allowed_extensions"] = [".exe"]
        stored = PolicyRecord.objects.get(pk=policy.pk)
        stored.configuration_json = config
        with self.captureOnCommitCallbacks(execute=True):
            stored.save(update_fields=["configuration_json", "updated_at"])
        self.assertIsNone(resolve_effective_policy("security.assessment_upload_controls"))


class PolicyLifecycleTests(TestCase):
    def setUp(self):
        self.head = _user("policy-head@example.test", RoleChoices.COUNSELOR)
        CounselorProfile.objects.create(user=self.head, is_head_guidance=True)
        self.it = _user("policy-it@example.test", RoleChoices.IT_ADMIN)
        self.dpo = _user("policy-dpo@example.test", RoleChoices.COUNSELOR)
        CounselorProfile.objects.create(user=self.dpo, is_head_guidance=False)
        self.inactive = _user("policy-inactive@example.test", RoleChoices.COUNSELOR, active=False)
        self.legacy = _user("policy-legacy@example.test", RoleChoices.COUNSELOR, superuser=True)
        self.now = timezone.now()

    def test_business_policy_is_head_owned_not_it_owned(self):
        command = PolicyChangeRequest(
            key="organizations.governance",
            configuration={},
            source_reference="GOV-2026-001",
        )
        policy = create_policy_draft(self.head, command)
        self.assertEqual(policy.status, PolicyLifecycleStatus.DRAFT)
        with self.assertRaises(PermissionDeniedError):
            create_policy_draft(self.it, command)
        self.assertFalse(can_manage_policy(self.inactive, command.key))
        self.assertFalse(can_manage_policy(self.legacy, command.key))

    def test_typed_good_moral_policy_has_audited_lifecycle(self):
        command = PolicyChangeRequest(
            key="good_moral.exit_prerequisite",
            configuration={
                "enforcement_enabled": True,
                "effective_graduation_year": 2026,
                "effective_academic_year": "2025-2026",
                "qualifying_exit_statuses": ["SUBMITTED"],
                "counselor_acknowledgment_required": False,
                "enforce_on_submission": False,
                "enforce_on_approval": False,
                "enforce_on_generation": False,
                "enforce_on_release": False,
                "grandfather_existing_requests": False,
                "reopen_void_behavior": "BLOCK_FINAL_BOUNDARY",
                "decision_record_reference": "GCO-MINUTES-2026-01",
            },
            effective_from=self.now,
            source_reference="GCO-POLICY-2026",
        )
        policy = create_policy_draft(self.head, command)
        submit_policy(self.head, policy)
        approve_policy(self.head, policy)
        activate_policy(self.head, policy)
        policy.refresh_from_db()
        self.assertEqual(policy.status, PolicyLifecycleStatus.ACTIVE)
        self.assertEqual(PolicyTransition.objects.filter(policy=policy).count(), 4)
        self.assertEqual(project_policy(policy)["owner_plane"], "HEAD_BUSINESS")
        retire_policy(self.head, policy)
        self.assertEqual(policy.__class__.objects.get(pk=policy.pk).status, PolicyLifecycleStatus.RETIRED)

    def test_non_retired_policy_windows_cannot_overlap(self):
        first = PolicyChangeRequest(
            key="good_moral.exit_prerequisite",
            configuration={
                "enforcement_enabled": True,
                "effective_graduation_year": 2026,
                "effective_academic_year": "",
                "qualifying_exit_statuses": ["SUBMITTED"],
                "counselor_acknowledgment_required": False,
                "enforce_on_submission": False,
                "enforce_on_approval": False,
                "enforce_on_generation": False,
                "enforce_on_release": False,
                "grandfather_existing_requests": False,
                "reopen_void_behavior": "BLOCK_FINAL_BOUNDARY",
                "decision_record_reference": "GCO-MINUTES-WINDOW-001",
            },
            effective_from=self.now,
            effective_until=self.now + timedelta(days=30),
            source_reference="GCO-POLICY-WINDOW-001",
        )
        create_policy_draft(self.head, first)
        second = PolicyChangeRequest(
            key="good_moral.exit_prerequisite",
            configuration={
                "enforcement_enabled": True,
                "effective_graduation_year": 2027,
                "effective_academic_year": "",
                "qualifying_exit_statuses": ["SUBMITTED"],
                "counselor_acknowledgment_required": False,
                "enforce_on_submission": False,
                "enforce_on_approval": False,
                "enforce_on_generation": False,
                "enforce_on_release": False,
                "grandfather_existing_requests": False,
                "reopen_void_behavior": "BLOCK_FINAL_BOUNDARY",
                "decision_record_reference": "GCO-MINUTES-WINDOW-002",
            },
            effective_from=self.now + timedelta(days=1),
            effective_until=self.now + timedelta(days=31),
            source_reference="GCO-POLICY-WINDOW-002",
        )
        with self.assertRaises(GovernanceError):
            create_policy_draft(self.head, second)

    def test_dpo_appointment_is_separate_from_it_role_and_single_active(self):
        with self.assertRaises(PermissionDeniedError):
            create_dpo_appointment(
                actor=self.dpo,
                holder=self.dpo,
                valid_from=self.now,
                valid_until=self.now + timedelta(days=365),
                appointment_reference="DPO-SELF",
                contact_email="dpo@example.test",
            )
        appointment = create_dpo_appointment(
            actor=self.head,
            holder=self.dpo,
            valid_from=self.now,
            valid_until=self.now + timedelta(days=365),
            appointment_reference="DPO-2026-001",
            contact_email="dpo@example.test",
        )
        self.assertTrue(is_current_dpo(self.dpo))
        self.assertFalse(is_current_dpo(self.it))
        with self.assertRaises(ValidationError):
            create_dpo_appointment(
                actor=self.head,
                holder=self.it,
                valid_from=self.now,
                valid_until=self.now + timedelta(days=30),
                appointment_reference="DPO-2026-002",
                contact_email="other@example.test",
            )
        appointment.status = DPOAppointmentStatus.RETIRED
        appointment.save(update_fields=["status", "updated_at"])
        self.assertFalse(is_current_dpo(self.dpo))

    def test_dpo_controls_report_suppression_not_it(self):
        appointment = create_dpo_appointment(
            actor=self.head,
            holder=self.dpo,
            valid_from=self.now,
            valid_until=self.now + timedelta(days=365),
            appointment_reference="DPO-2026-003",
            contact_email="dpo@example.test",
        )
        definition = ReportDefinition.objects.create(
            key="students_profile",
            title="Students Profile",
            family="student_profile_inventory",
        )
        command = PolicyChangeRequest(
            key="reports.suppression",
            configuration={
                "report_key": definition.key,
                "mode": "SECTION",
                "requires_suppression": True,
                "default_threshold": 5,
                "threshold": 7,
                "sensitive_categories": ["small_cohort"],
            },
            effective_from=self.now,
            source_reference="DPO-REPORT-2026",
            target_type="reports.ReportDefinition",
            target_reference=str(definition.pk),
        )
        policy = create_policy_draft(self.dpo, command)
        submit_policy(self.dpo, policy)
        approve_policy(self.dpo, policy)
        activate_policy(self.dpo, policy)
        self.assertEqual(PolicyRecord.objects.get(pk=policy.pk).status, PolicyLifecycleStatus.ACTIVE)
        self.assertFalse(can_manage_policy(self.it, command.key))
        appointment.refresh_from_db()

    def test_privacy_reviewer_authorization_uses_the_dpo_plane(self):
        create_dpo_appointment(
            actor=self.head,
            holder=self.dpo,
            valid_from=self.now,
            valid_until=self.now + timedelta(days=365),
            appointment_reference="DPO-2026-004",
            contact_email="dpo@example.test",
        )
        reviewer = _user("policy-reviewer@example.test", RoleChoices.GCO_STAFF)
        authorization = create_privacy_reviewer_authorization(
            actor=self.dpo,
            authorized_user=reviewer,
            scopes={"scopes": ["request_review"], "categories": ["student_record"]},
            valid_from=self.now,
            valid_until=self.now + timedelta(days=30),
            source_reference="DPO-AUTH-2026-001",
        )
        self.assertEqual(authorization.authorized_by_id, self.dpo.pk)
        authorization = revoke_privacy_reviewer_authorization(actor=self.dpo, authorization=authorization)
        self.assertEqual(authorization.status, "REVOKED")


class GovernanceApiContractTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.head = _user("governance-api-head@example.test", RoleChoices.COUNSELOR)
        CounselorProfile.objects.create(user=self.head, is_head_guidance=True)
        self.dpo = _user("governance-api-dpo@example.test", RoleChoices.COUNSELOR)
        self.reviewer = _user("governance-api-reviewer@example.test", RoleChoices.GCO_STAFF)
        self.it = _user("governance-api-it@example.test", RoleChoices.IT_ADMIN)
        self.now = timezone.now()
        self.tokens = {
            actor.pk: issue_token_pair(actor, assurance_verified=True).access_token
            for actor in (self.head, self.dpo, self.reviewer, self.it)
        }

    def _headers(self, actor):
        return {"HTTP_AUTHORIZATION": f"Bearer {self.tokens[actor.pk]}"}

    def _create_dpo_service(self):
        return create_dpo_appointment(
            actor=self.head,
            holder=self.dpo,
            valid_from=self.now - timedelta(minutes=1),
            valid_until=self.now + timedelta(days=365),
            appointment_reference="DPO-API-SERVICE-001",
            contact_email="dpo-api@example.test",
        )

    def _dpo_payload(self, reference="DPO-API-001"):
        return {
            "holder_id": str(self.dpo.pk),
            "valid_from": (self.now - timedelta(minutes=1)).isoformat(),
            "valid_until": (self.now + timedelta(days=365)).isoformat(),
            "appointment_reference": reference,
            "contact_email": "dpo-api@example.test",
        }

    def test_governance_projections_match_exact_output_schema_contracts(self):
        appointment = self._create_dpo_service()
        appointment_projection = project_dpo_appointment(appointment)
        self.assertEqual(
            set(appointment_projection),
            {
                "id",
                "holder_id",
                "valid_from",
                "valid_until",
                "appointment_reference",
                "contact_email",
                "status",
                "appointed_at",
                "retired_at",
            },
        )
        appointment_schema = DPOAppointmentSchema(**appointment_projection)
        self.assertIsInstance(appointment_schema.holder_id, int)

        authorization = create_privacy_reviewer_authorization(
            actor=self.dpo,
            authorized_user=self.reviewer,
            scopes={"scopes": ["request_review"], "categories": ["student_record"]},
            valid_from=self.now,
            valid_until=self.now + timedelta(days=30),
            source_reference="DPO-API-AUTH-001",
        )
        authorization_projection = reviewer_authorization_projection(authorization)
        self.assertEqual(
            set(authorization_projection),
            {
                "id",
                "authorized_user_id",
                "scopes",
                "categories",
                "valid_from",
                "valid_until",
                "source_reference",
                "status",
                "authorized_at",
                "revoked_at",
            },
        )
        authorization_schema = PrivacyReviewerAuthorizationSchema(**authorization_projection)
        self.assertIsInstance(authorization_schema.authorized_user_id, int)
        for forbidden in (
            "reason_code",
            "expected_updated_at",
            "appointed_by",
            "retired_by",
            "authorized_by",
            "revoked_by",
            "token",
            "token_hash",
            "metadata_json",
        ):
            self.assertNotIn(forbidden, appointment_projection)
            self.assertNotIn(forbidden, authorization_projection)

    def test_dpo_api_responses_are_typed_and_replay_safe(self):
        body = self._dpo_payload()
        headers = {
            **self._headers(self.head),
            "HTTP_IDEMPOTENCY_KEY": "governance-api-dpo-create-001",
        }
        created = self.client.post(
            "/api/v1/policies/dpo-appointment/",
            data=json.dumps(body),
            content_type="application/json",
            **headers,
        )
        self.assertEqual(created.status_code, 200, created.content)
        created_payload = created.json()
        created_schema = DPOAppointmentSchema(**created_payload)
        self.assertEqual(created_schema.holder_id, self.dpo.pk)
        self.assertNotIn("reason_code", created_payload)
        self.assertNotIn("expected_updated_at", created_payload)

        replay = self.client.post(
            "/api/v1/policies/dpo-appointment/",
            data=json.dumps(body),
            content_type="application/json",
            **headers,
        )
        self.assertEqual(replay.status_code, 200, replay.content)
        self.assertEqual(replay.json(), created_payload)
        DPOAppointmentSchema(**replay.json())

        viewed = self.client.get(
            "/api/v1/policies/dpo-appointment/",
            **self._headers(self.head),
        )
        self.assertEqual(viewed.status_code, 200, viewed.content)
        self.assertEqual(DPOAppointmentSchema(**viewed.json()).id, created_schema.id)

        retired = self.client.post(
            f"/api/v1/policies/dpo-appointment/{created_schema.id}/retire/",
            data=json.dumps({"reason_code": "planned_rotation"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="governance-api-dpo-retire-001",
            **self._headers(self.head),
        )
        self.assertEqual(retired.status_code, 200, retired.content)
        retired_payload = retired.json()
        self.assertEqual(DPOAppointmentSchema(**retired_payload).status, DPOAppointmentStatus.RETIRED)
        self.assertNotIn("reason_code", retired_payload)

        retire_replay = self.client.post(
            f"/api/v1/policies/dpo-appointment/{created_schema.id}/retire/",
            data=json.dumps({"reason_code": "planned_rotation"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="governance-api-dpo-retire-001",
            **self._headers(self.head),
        )
        self.assertEqual(retire_replay.status_code, 200, retire_replay.content)
        self.assertEqual(retire_replay.json(), retired_payload)

    def test_reviewer_api_responses_are_typed_listable_and_replay_safe(self):
        self._create_dpo_service()
        body = {
            "authorized_user_id": str(self.reviewer.pk),
            "scopes": ["request_review"],
            "categories": ["student_record"],
            "valid_from": self.now.isoformat(),
            "valid_until": (self.now + timedelta(days=30)).isoformat(),
            "source_reference": "DPO-API-AUTH-002",
        }
        headers = {
            **self._headers(self.dpo),
            "HTTP_IDEMPOTENCY_KEY": "governance-api-reviewer-create-001",
        }
        created = self.client.post(
            "/api/v1/privacy/reviewer-authorizations/",
            data=json.dumps(body),
            content_type="application/json",
            **headers,
        )
        self.assertEqual(created.status_code, 200, created.content)
        created_payload = created.json()
        created_schema = PrivacyReviewerAuthorizationSchema(**created_payload)
        self.assertEqual(created_schema.authorized_user_id, self.reviewer.pk)
        self.assertNotIn("reason_code", created_payload)
        self.assertNotIn("expected_updated_at", created_payload)

        replay = self.client.post(
            "/api/v1/privacy/reviewer-authorizations/",
            data=json.dumps(body),
            content_type="application/json",
            **headers,
        )
        self.assertEqual(replay.status_code, 200, replay.content)
        self.assertEqual(replay.json(), created_payload)

        listing = self.client.get(
            "/api/v1/privacy/reviewer-authorizations/",
            **self._headers(self.dpo),
        )
        self.assertEqual(listing.status_code, 200, listing.content)
        page = PrivacyReviewerAuthorizationPageSchema(**listing.json())
        self.assertEqual(page.total, 1)
        self.assertEqual(page.items[0].id, created_schema.id)

        revoked = self.client.post(
            f"/api/v1/privacy/reviewer-authorizations/{created_schema.id}/revoke/",
            data=json.dumps({"reason_code": "review_complete"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="governance-api-reviewer-revoke-001",
            **self._headers(self.dpo),
        )
        self.assertEqual(revoked.status_code, 200, revoked.content)
        revoked_payload = revoked.json()
        self.assertEqual(PrivacyReviewerAuthorizationSchema(**revoked_payload).status, "REVOKED")
        self.assertNotIn("reason_code", revoked_payload)

        revoke_replay = self.client.post(
            f"/api/v1/privacy/reviewer-authorizations/{created_schema.id}/revoke/",
            data=json.dumps({"reason_code": "review_complete"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="governance-api-reviewer-revoke-001",
            **self._headers(self.dpo),
        )
        self.assertEqual(revoke_replay.status_code, 200, revoke_replay.content)
        self.assertEqual(revoke_replay.json(), revoked_payload)

    def test_privacy_notice_revision_api_uses_integer_primary_keys(self):
        self._create_dpo_service()
        created = self.client.post(
            "/api/v1/privacy/notice-revisions/",
            data=json.dumps({
                "notice_identifier": "governance-api-notice",
                "version": "2026.1",
                "body_markdown": "# Governance API notice",
                "source_reference": "DPO-API-NOTICE-SOURCE-001",
                "purpose_workflow": "governance_api_test",
            }),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="governance-api-notice-create-001",
            **self._headers(self.dpo),
        )
        self.assertEqual(created.status_code, 200, created.content)
        created_schema = PrivacyNoticeRevisionSchema(**created.json())
        self.assertTrue(created_schema.id.isdigit())

        approved = self.client.post(
            f"/api/v1/privacy/notice-revisions/{created_schema.id}/approve/",
            data=json.dumps({"approval_reference": "DPO-API-NOTICE-APPROVAL-001"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="governance-api-notice-approve-001",
            **self._headers(self.dpo),
        )
        self.assertEqual(approved.status_code, 200, approved.content)
        self.assertEqual(PrivacyNoticeRevisionSchema(**approved.json()).approval_state, "APPROVED")

        retired = self.client.post(
            f"/api/v1/privacy/notice-revisions/{created_schema.id}/retire/",
            data=json.dumps({"reason_code": "test_cleanup"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="governance-api-notice-retire-001",
            **self._headers(self.dpo),
        )
        self.assertEqual(retired.status_code, 200, retired.content)
        self.assertEqual(PrivacyNoticeRevisionSchema(**retired.json()).status, "RETIRED")

    def test_dpo_and_reviewer_api_authorization_planes_remain_separate(self):
        for legacy_path in (
            "/api/v1/policies/privacy-reviewer-authorizations/",
            "/api/v1/policies/privacy-notice-revisions/",
            "/api/v1/policies/privacy-notice-bindings/",
        ):
            with self.subTest(legacy_path=legacy_path):
                self.assertEqual(
                    self.client.get(legacy_path, **self._headers(self.it)).status_code,
                    404,
                )
        self.assertEqual(
            self.client.get(
                "/api/v1/policies/dpo-appointment/",
                **self._headers(self.it),
            ).status_code,
            404,
        )
        self.assertEqual(
            self.client.get(
                "/api/v1/privacy/reviewer-authorizations/",
                **self._headers(self.head),
            ).status_code,
            404,
        )

        self._create_dpo_service()
        response = self.client.post(
            "/api/v1/privacy/reviewer-authorizations/",
            data=json.dumps({
                "authorized_user_id": str(self.reviewer.pk),
                "scopes": ["request_review"],
                "categories": ["student_record"],
                "valid_from": self.now.isoformat(),
                "source_reference": "DPO-API-AUTH-DENIED",
            }),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="governance-api-reviewer-denied-001",
            **self._headers(self.head),
        )
        self.assertEqual(response.status_code, 403, response.content)
