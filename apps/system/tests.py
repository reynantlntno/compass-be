"""Focused tests for the contract boundary diagnostic and public-error boundaries."""

import json
from dataclasses import FrozenInstanceError
from datetime import timedelta
from io import StringIO
from types import SimpleNamespace
from unittest.mock import patch

from django.core.management import call_command
from django.test import Client, RequestFactory, TestCase, override_settings
from django.utils import timezone

from apps.account_security.api_tokens import issue_token_pair
from apps.accounts.models import RoleChoices, User
from apps.profiles.models import CounselorProfile
from apps.system.choices import ErrorCategoryChoices, MaintenanceStatusChoices
from apps.system.diagnostic_services import (
    get_application_error_diagnostic_by_error_id,
    get_application_error_diagnostics_visible_to,
)
from apps.system.error_services import capture_application_error_event
from apps.system.http import api_internal_server_error
from apps.system.models import ApplicationErrorEvent
from apps.system.models import MaintenanceWindow
from apps.system.api import (
    ApplicationErrorProjectionSchema,
    EnvironmentSummarySchema,
    HealthProjectionSchema,
    MaintenancePageSchema,
    MaintenanceProjectionSchema,
    OperationalCommandCatalogSchema,
    OperationalRunPageSchema,
    PublicServiceStatusSchema,
    ReleaseMetadataSchema,
    SystemErrorPageSchema,
)
from apps.system.policies import (
    can_list_application_error_events,
    can_reopen_application_error_event,
    can_resolve_application_error_event,
    can_view_application_error_event,
    can_view_redacted_stack_trace,
)
from apps.system.projections import (
    maintenance_projection,
    operational_command_run_projection,
    project_application_error_event,
)
from apps.system.maintenance_services import public_service_status
from apps.common.api.correlation import attach_request_correlation
from apps.system.commands import DiagnosticTransitionCommand, MaintenanceScheduleCommand


def _user(email, role, *, is_active=True):
    return User.objects.create_user(
        email=email,
        password="correct-horse-battery-staple",
        first_name="Test",
        last_name="User",
        role=role,
        is_active=is_active,
    )


class ApplicationErrorPolicyTests(TestCase):
    def setUp(self):
        self.event = ApplicationErrorEvent.objects.create(
            error_id="ERR-2026-000001",
            category=ErrorCategoryChoices.UNKNOWN,
            safe_message="An unexpected error occurred.",
        )
        self.it_admin = _user("it@example.test", RoleChoices.IT_ADMIN)
        self.student = _user("student@example.test", RoleChoices.STUDENT)
        self.counselor = _user("counselor@example.test", RoleChoices.COUNSELOR)
        self.gco_staff = _user("staff@example.test", RoleChoices.GCO_STAFF)
        self.head = _user("head@example.test", RoleChoices.COUNSELOR)
        CounselorProfile.objects.create(user=self.head, is_head_guidance=True)
        self.inactive_it_admin = _user(
            "inactive-it@example.test",
            RoleChoices.IT_ADMIN,
            is_active=False,
        )
        self.legacy_it_admin = _user("legacy-it@example.test", RoleChoices.IT_ADMIN)
        self.legacy_it_admin.is_superuser = True
        self.legacy_it_admin.save(update_fields=["is_superuser"])

    def test_active_it_admin_can_use_application_error_policies(self):
        self.assertTrue(can_list_application_error_events(self.it_admin))
        self.assertTrue(can_view_application_error_event(self.it_admin, self.event))
        self.assertTrue(can_resolve_application_error_event(self.it_admin, self.event))
        self.assertTrue(can_reopen_application_error_event(self.it_admin, self.event))

    def test_non_it_and_fail_closed_actors_are_denied(self):
        actors = (
            self.student,
            self.counselor,
            self.gco_staff,
            self.head,
            self.inactive_it_admin,
            self.legacy_it_admin,
            None,
        )
        for actor in actors:
            self.assertFalse(can_list_application_error_events(actor))
            self.assertFalse(can_view_application_error_event(actor, self.event))
            self.assertFalse(can_resolve_application_error_event(actor, self.event))
            self.assertFalse(can_reopen_application_error_event(actor, self.event))

    def test_stack_trace_is_denied_even_to_it_admin(self):
        self.assertFalse(can_view_redacted_stack_trace(self.it_admin, self.event))


class SystemApiBoundaryTests(TestCase):
    def test_commands_are_frozen_and_bounded(self):
        command = MaintenanceScheduleCommand(
            starts_at="2026-08-25T10:00:00+00:00",
            ends_at="2026-08-25T11:00:00+00:00",
            reason_code="planned_maintenance",
        )
        with self.assertRaises(FrozenInstanceError):
            command.starts_at = "changed"
        with self.assertRaises(Exception):
            DiagnosticTransitionCommand(error_id={"raw": "id"})

    def test_openapi_exposes_system_operation_ids(self):
        from config.api.v1 import api_v1

        schema = api_v1.get_openapi_schema()
        self.assertIn("/api/v1/system/health/", schema["paths"])
        self.assertIn("/api/v1/system/public-status/", schema["paths"])
        self.assertIn("/api/v1/system/errors/{error_id}/", schema["paths"])
        operation_ids = {
            operation.get("operationId")
            for path in schema["paths"].values()
            for operation in path.values()
            if isinstance(operation, dict)
        }
        self.assertIn("system_health_check", operation_ids)
        self.assertIn("system_public_status", operation_ids)
        self.assertIn("system_operations_catalog", operation_ids)


class PublicServiceStatusTests(TestCase):
    def setUp(self):
        self.client = Client()

    def _window(self, *, status, starts_at, ends_at, message="Scheduled maintenance."):
        return MaintenanceWindow.objects.create(
            status=status,
            starts_at=starts_at,
            ends_at=ends_at,
            safe_public_message=message,
            internal_reason_code="DB_UPGRADE",
        )

    @patch("apps.system.maintenance_services.resolve_runtime_setting", return_value=False)
    def test_scheduled_status_uses_next_window_within_fourteen_days(self, _setting):
        now = timezone.now()
        self._window(
            status=MaintenanceStatusChoices.SCHEDULED,
            starts_at=now + timedelta(days=15),
            ends_at=now + timedelta(days=15, hours=1),
            message="Too far away.",
        )
        next_window = self._window(
            status=MaintenanceStatusChoices.SCHEDULED,
            starts_at=now + timedelta(days=3),
            ends_at=now + timedelta(days=3, hours=1),
            message="A short planned pause.",
        )
        earlier_window = self._window(
            status=MaintenanceStatusChoices.SCHEDULED,
            starts_at=now + timedelta(days=1),
            ends_at=now + timedelta(days=1, hours=1),
            message="The next planned pause.",
        )

        result = public_service_status()

        self.assertEqual(result["status"], "maintenance_scheduled")
        self.assertEqual(result["message"], "The next planned pause.")
        self.assertEqual(result["starts_at"], earlier_window.starts_at)
        self.assertEqual(result["ends_at"], earlier_window.ends_at)
        self.assertNotEqual(result["starts_at"], next_window.starts_at)

    @patch("apps.system.maintenance_services.resolve_runtime_setting", return_value=True)
    def test_active_status_takes_precedence_only_when_enforced(self, _setting):
        now = timezone.now()
        active = self._window(
            status=MaintenanceStatusChoices.ACTIVE,
            starts_at=now - timedelta(minutes=5),
            ends_at=now + timedelta(hours=1),
            message="COMPASS is briefly unavailable while we update the service.",
        )
        self._window(
            status=MaintenanceStatusChoices.SCHEDULED,
            starts_at=now + timedelta(hours=1),
            ends_at=now + timedelta(hours=2),
        )

        result = public_service_status()

        self.assertEqual(result["status"], "maintenance_active")
        self.assertEqual(result["message"], active.safe_public_message)
        self.assertEqual(result["starts_at"], active.starts_at)

    @patch("apps.system.maintenance_services.resolve_runtime_setting", return_value=False)
    def test_expired_and_non_scheduled_windows_are_not_public_schedule(self, _setting):
        now = timezone.now()
        self._window(
            status=MaintenanceStatusChoices.ACTIVE,
            starts_at=now - timedelta(days=2),
            ends_at=now - timedelta(days=1),
        )
        self._window(
            status=MaintenanceStatusChoices.COMPLETED,
            starts_at=now + timedelta(days=1),
            ends_at=now + timedelta(days=1, hours=1),
        )
        self._window(
            status=MaintenanceStatusChoices.CANCELLED,
            starts_at=now + timedelta(days=2),
            ends_at=now + timedelta(days=2, hours=1),
        )

        result = public_service_status()

        self.assertEqual(
            result,
            {
                "status": "operational",
                "message": None,
                "starts_at": None,
                "ends_at": None,
            },
        )

    @patch("apps.system.maintenance_services.resolve_runtime_setting", return_value=False)
    def test_malformed_persisted_message_fails_closed(self, _setting):
        now = timezone.now()
        self._window(
            status=MaintenanceStatusChoices.SCHEDULED,
            starts_at=now + timedelta(hours=1),
            ends_at=now + timedelta(hours=2),
            message="<script>alert(1)</script>",
        )

        response = self.client.get("/api/v1/system/public-status/")

        self.assertEqual(response.status_code, 503)
        payload = response.json()
        self.assertEqual(payload["code"], "dependency_failure")
        self.assertNotIn("script", response.content.decode().lower())

    @override_settings(COMPASS_ACCESS_MODE="active")
    @patch("apps.system.maintenance_services.resolve_runtime_setting", return_value=False)
    def test_status_is_anonymous_and_has_only_safe_fields(self, _setting):
        response = self.client.get("/api/v1/system/public-status/")

        self.assertEqual(response.status_code, 200, response.content)
        payload = response.json()
        self.assertEqual(set(payload), {"status", "message", "starts_at", "ends_at"})
        PublicServiceStatusSchema(**payload)

    @override_settings(COMPASS_ACCESS_MODE="health_only")
    @patch("apps.system.maintenance_services.resolve_runtime_setting", return_value=False)
    def test_status_remains_available_in_health_only_mode(self, _setting):
        response = self.client.get("/api/v1/system/public-status/")

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["status"], "operational")

    @override_settings(COMPASS_ACCESS_MODE="active")
    @patch("apps.system.maintenance_services.resolve_runtime_setting", return_value=True)
    def test_status_remains_available_during_active_maintenance(self, _setting):
        now = timezone.now()
        self._window(
            status=MaintenanceStatusChoices.ACTIVE,
            starts_at=now - timedelta(minutes=1),
            ends_at=now + timedelta(hours=1),
            message="A short service pause is in progress.",
        )

        response = self.client.get("/api/v1/system/public-status/")

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["status"], "maintenance_active")


class SystemResponseContractTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.it_admin = _user("system-contract-it@example.test", RoleChoices.IT_ADMIN)
        self.token = issue_token_pair(self.it_admin, assurance_verified=True).access_token

    def test_empty_operational_pages_and_fixed_summaries_validate_at_the_api_boundary(self):
        headers = {"HTTP_AUTHORIZATION": f"Bearer {self.token}"}
        endpoints = (
            ("/api/v1/system/health/", HealthProjectionSchema),
            ("/api/v1/system/errors/", SystemErrorPageSchema),
            ("/api/v1/system/maintenance/", MaintenancePageSchema),
            ("/api/v1/system/release/", ReleaseMetadataSchema),
            ("/api/v1/system/environment/", EnvironmentSummarySchema),
            ("/api/v1/system/operations/", OperationalCommandCatalogSchema),
            ("/api/v1/system/operations/runs/", OperationalRunPageSchema),
        )
        for path, schema in endpoints:
            with self.subTest(path=path):
                response = self.client.get(path, **headers)
                self.assertEqual(response.status_code, 200, response.content)
                schema(**response.json())

    def test_system_output_shapes_are_explicit_and_projection_compatible(self):
        now = timezone.now()
        health_component = {
            "component": "database",
            "label": "Database Connectivity",
            "status": "ok",
            "message": "Database connection is healthy.",
            "reason_code": "DB_CONN_OK",
            "duration_ms": 1.25,
            "checked_at": now.isoformat(),
        }
        health = HealthProjectionSchema(
            status="ok",
            component_count=1,
            failed_count=0,
            warning_count=0,
            components=[health_component],
        )
        self.assertEqual(health.components[0].component, "database")
        release = ReleaseMetadataSchema(
            environment="testing",
            release={"version": "release-1", "build_id": "build-1", "configured": True},
        )
        self.assertTrue(release.release.configured)

        environment = EnvironmentSummarySchema(
            environment="testing",
            deployment_class="non_deployment",
            release={"version": "release-1", "build_id": "build-1", "configured": True},
            components={
                "cache_backend": "locmem_or_other",
                "protected_storage_backend": "local",
                "backup_worker_enabled": False,
                "notification_worker_enabled": False,
            },
            maintenance={"active": False},
        )
        self.assertEqual(environment.components.protected_storage_backend, "local")

        catalog = OperationalCommandCatalogSchema(
            items=[{"key": "verify_health", "label": "Verify health", "mode": "read-only"}],
        )
        self.assertEqual(catalog.items[0].key, "verify_health")

        window = SimpleNamespace(
            pk="maintenance-1",
            status="scheduled",
            starts_at=now,
            ends_at=now,
            safe_public_message="Planned maintenance.",
            internal_reason_code="DB_UPGRADE",
            is_expired=False,
            created_at=now,
            updated_at=now,
        )
        maintenance = maintenance_projection(window)
        MaintenanceProjectionSchema(**maintenance)
        MaintenancePageSchema(items=[maintenance], page=1, page_size=25, total=1)

        run = operational_command_run_projection(SimpleNamespace(
            pk="run-1",
            command_key="verify_health",
            mode="execute",
            environment="testing",
            reason_code="operator_requested",
            configuration_identifier="config-1",
            started_at=now,
            finished_at=now,
            outcome="success",
            outcome_reason_code=None,
            release_version="release-1",
            build_id="build-1",
        ))
        OperationalRunPageSchema(items=[run], page=1, page_size=25, total=1)

    def test_diagnostic_output_schema_keeps_nested_context_explicit(self):
        now = timezone.now()
        projection = {
            "error_id": "ERR-2026-000099",
            "created_at": now.isoformat(),
            "request_id": "REQ-2026-000099",
            "trace_id": "trace-1",
            "severity": "error",
            "category": "database",
            "environment": "testing",
            "release_version": "release-1",
            "build_id": "build-1",
            "app_label": "system",
            "route_name": "api:v1:system_health",
            "view_name": "apps.system.api.health",
            "http_method": "GET",
            "path_template": "/api/v1/system/health/",
            "status_code": 500,
            "exception_class": "DatabaseError",
            "safe_message": "A database error occurred.",
            "fingerprint_version": "error-fingerprint-v1",
            "fingerprint": "a" * 64,
            "diagnostic_context": {
                "state": "available",
                "values": {"service_name": "database", "retryable": False, "status_code": 500},
            },
            "remediation": {"code": "CHECK_DATABASE", "hint": "Check database health."},
            "is_resolved": False,
            "resolved_at": None,
        }
        schema = ApplicationErrorProjectionSchema(**projection)
        self.assertEqual(schema.diagnostic_context.values.service_name, "database")
        SystemErrorPageSchema(items=[projection], page=1, page_size=25, total=1)


class RobotsTxtTests(TestCase):
    def test_robots_txt_is_static_non_indexable_and_safe(self):
        response = Client().get("/robots.txt")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/plain; charset=utf-8")
        self.assertEqual(response["Cache-Control"], "public, max-age=3600")
        self.assertEqual(response["X-Robots-Tag"], "noindex, nofollow, noarchive")
        self.assertTrue(response["X-Request-ID"].startswith("REQ-"))
        body = response.content.decode()
        for directive in (
            "User-agent: *",
            "Disallow: /",
            "Disallow: /api/",
            "Disallow: /admin/",
            "Disallow: /docs/",
            "Disallow: /openapi.json",
        ):
            self.assertIn(directive, body)
        self.assertNotIn("Sitemap:", body)
        self.assertNotIn("SECRET_KEY", body)

    def test_robots_txt_rejects_mutations_with_standard_headers(self):
        response = Client().post("/robots.txt")

        self.assertEqual(response.status_code, 405)
        self.assertEqual(response["Allow"], "GET, HEAD")
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertEqual(response["X-Robots-Tag"], "noindex, nofollow, noarchive")

    @override_settings(COMPASS_ACCESS_MODE="health_only")
    def test_robots_txt_remains_available_during_health_only_mode(self):
        response = Client().get("/robots.txt")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Disallow: /", response.content.decode())


class OperatingDemoSeedSmokeTests(TestCase):
    def test_seed_dry_run_loads_validated_answer_set_from_common_values(self):
        output = StringIO()

        call_command("seed_operating_demo", dry_run=True, stdout=output)

        self.assertIn("[DRY-RUN] Operating demo seed validation passed", output.getvalue())
        self.assertIn("[DRY-RUN] No changes written", output.getvalue())


class ApplicationErrorProjectionTests(TestCase):
    def setUp(self):
        self.it_admin = _user("projection-it@example.test", RoleChoices.IT_ADMIN)
        self.actor = _user("projection-student@example.test", RoleChoices.STUDENT)
        self.event = ApplicationErrorEvent.objects.create(
            error_id="ERR-2026-000002",
            request_id="request-1",
            trace_id="trace-1",
            severity="error",
            category=ErrorCategoryChoices.DATABASE,
            environment="testing",
            release_version="release-1",
            build_id="build-1",
            app_label="accounts",
            route_name="api:v1:test",
            view_name="apps.example.views.test",
            http_method="POST",
            path_template="api/v1/example/",
            status_code=500,
            actor_user=self.actor,
            actor_role=RoleChoices.STUDENT,
            actor_ip_hash="ip-hash",
            user_agent_hash="ua-hash",
            related_reference_code="SES-AY2526-000001",
            related_object_type="counseling.CounselingSession",
            related_object_id="123",
            exception_class="DatabaseError",
            safe_message="A database error occurred.",
            redacted_stack_trace="raw stack trace must never be projected",
            metadata_json={
                "service_name": "database",
                "reason_code": "connection_failed",
                "unknown_future_key": "must not appear",
                "email": "student@example.test",
            },
        )

    def test_projection_has_only_json_ready_safe_fields(self):
        projection = project_application_error_event(self.it_admin, self.event)

        self.assertIsNotNone(projection)
        json.dumps(projection)
        self.assertEqual(
            set(projection),
            {
                "error_id",
                "created_at",
                "request_id",
                "trace_id",
                "severity",
                "category",
                "environment",
                "release_version",
                "build_id",
                "app_label",
                "route_name",
                "view_name",
                "http_method",
                "path_template",
                "status_code",
                "exception_class",
                "safe_message",
                "fingerprint_version",
                "fingerprint",
                "diagnostic_context",
                "remediation",
                "is_resolved",
                "resolved_at",
            },
        )
        serialized = json.dumps(projection)
        for forbidden in (
            "raw stack trace must never be projected",
            "ip-hash",
            "ua-hash",
            "SES-AY2526-000001",
            "counseling.CounselingSession",
            "must not appear",
            "student@example.test",
        ):
            self.assertNotIn(forbidden, serialized)
        self.assertEqual(
            projection["diagnostic_context"],
            {
                "state": "available",
                "values": {
                    "service_name": "database",
                    "reason_code": "connection_failed",
                },
            },
        )
        self.assertEqual(projection["remediation"]["code"], "CHECK_DATABASE")

    def test_unauthorized_projection_is_none(self):
        self.assertIsNone(project_application_error_event(self.actor, self.event))

    def test_fingerprint_is_stable_for_non_identity_changes(self):
        equivalent = ApplicationErrorEvent.objects.create(
            error_id="ERR-2026-000003",
            category=self.event.category,
            environment="production",
            release_version="release-2",
            build_id="build-2",
            app_label=self.event.app_label,
            route_name=self.event.route_name,
            view_name=self.event.view_name,
            http_method=self.event.http_method,
            path_template=self.event.path_template,
            status_code=self.event.status_code,
            exception_class=self.event.exception_class,
            safe_message=self.event.safe_message,
        )
        first = project_application_error_event(self.it_admin, self.event)
        second = project_application_error_event(self.it_admin, equivalent)
        self.assertEqual(first["fingerprint_version"], "error-fingerprint-v1")
        self.assertEqual(first["fingerprint"], second["fingerprint"])

        equivalent.route_name = "api:v1:different"
        equivalent.save(update_fields=["route_name", "updated_at"])
        changed = project_application_error_event(self.it_admin, equivalent)
        self.assertNotEqual(first["fingerprint"], changed["fingerprint"])

    def test_empty_diagnostic_context_is_explicitly_not_captured(self):
        event = ApplicationErrorEvent.objects.create(
            error_id="ERR-2026-000004",
            safe_message="An unexpected error occurred.",
            metadata_json={"future_key": {"private": "value"}},
        )
        projection = project_application_error_event(self.it_admin, event)
        self.assertEqual(
            projection["diagnostic_context"],
            {"state": "not_captured", "values": {}},
        )


class ApplicationErrorServiceBoundaryTests(TestCase):
    def setUp(self):
        self.it_admin = _user("service-it@example.test", RoleChoices.IT_ADMIN)
        self.student = _user("service-student@example.test", RoleChoices.STUDENT)
        self.event = ApplicationErrorEvent.objects.create(
            error_id="ERR-2026-000005",
            safe_message="An unexpected error occurred.",
            exception_class="ValueError",
        )

    def test_list_and_detail_services_return_projections_only(self):
        listed = get_application_error_diagnostics_visible_to(self.it_admin)
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]["error_id"], self.event.error_id)
        self.assertNotIsInstance(listed[0], ApplicationErrorEvent)
        self.assertEqual(get_application_error_diagnostics_visible_to(self.student), [])
        self.assertIsNone(
            get_application_error_diagnostic_by_error_id(
                self.student,
                self.event.error_id,
            )
        )

    @patch("apps.system.diagnostic_services.audit_log")
    def test_detail_access_is_audited_with_safe_identity(self, audit_log):
        projection = get_application_error_diagnostic_by_error_id(
            self.it_admin,
            self.event.error_id,
        )
        self.assertEqual(projection["error_id"], self.event.error_id)
        audit_log.assert_called_once()
        metadata = audit_log.call_args.kwargs["metadata"]
        self.assertEqual(set(metadata), {"error_id", "fingerprint"})
        self.assertNotIn("exception_class", metadata)

    def test_capture_records_validated_trace_id_but_no_trace(self):
        request = RequestFactory().get(
            "/api/v1/failure?token=must-not-persist",
            HTTP_X_REQUEST_ID="request-2",
            HTTP_X_TRACE_ID="trace-2",
            HTTP_USER_AGENT="Chrome on macOS",
            REMOTE_ADDR="192.0.2.10",
        )
        attach_request_correlation(request)
        event = capture_application_error_event(
            request=request,
            exception=ValueError("raw exception message must not persist"),
            metadata={"service_name": "payments", "password": "secret-value"},
        )
        self.assertTrue(event.request_id.startswith("REQ-"))
        self.assertEqual(event.trace_id, "trace-2")
        self.assertIsNone(event.redacted_stack_trace)
        serialized = json.dumps(event.metadata_json)
        self.assertNotIn("raw exception message", serialized)
        self.assertNotIn("secret-value", serialized)

    def test_invalid_correlation_ids_are_not_persisted(self):
        request = RequestFactory().get(
            "/failure",
            HTTP_X_REQUEST_ID="contains whitespace",
            HTTP_X_TRACE_ID="x" * 101,
        )
        attach_request_correlation(request)
        event = capture_application_error_event(request=request)
        self.assertTrue(event.request_id.startswith("REQ-"))
        self.assertIsNone(event.trace_id)

    def test_public_500_contains_only_generic_detail_and_safe_error_id(self):
        request = RequestFactory().get("/failure")
        request._compass_error_id = self.event.error_id
        attach_request_correlation(request)
        response = api_internal_server_error(request)
        payload = json.loads(response.content)
        self.assertEqual(payload["detail"], "Internal server error.")
        self.assertEqual(payload["code"], "internal_error")
        self.assertEqual(payload["error_id"], self.event.error_id)
        self.assertTrue(payload["request_id"].startswith("REQ-"))
        self.assertEqual(payload["field_errors"], {})
        self.assertNotIn("exception_class", payload)
        self.assertNotIn("fingerprint", payload)
        fallback = json.loads(api_internal_server_error(RequestFactory().get("/failure")).content)
        self.assertEqual(fallback["detail"], "Internal server error.")
        self.assertIsNone(fallback["error_id"])
        self.assertTrue(fallback["request_id"].startswith("REQ-"))
