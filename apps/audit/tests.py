"""Focused contract tests for the read-only Audit Viewer boundary."""

from datetime import timedelta
from dataclasses import FrozenInstanceError

from django.test import Client, TestCase
from django.utils import timezone

from apps.accounts.models import RoleChoices, User
from apps.account_security.api_tokens import issue_token_pair
from apps.audit.api import (
    AuditEntryProjectionSchema,
    AuditPageSchema,
    AuditSafeContextSchema,
)
from apps.audit.models import AuditLogEntry
from apps.audit.policies import AuditPlane, authorized_planes, can_view_audit_entry, viewer_planes
from apps.audit.projections import audit_entry_projection
from apps.audit.queries import AuditQuery, audit_detail, audit_page
from apps.access_control.capabilities import Capability
from apps.common.contracts import PageRequest
from apps.common.exceptions import PermissionDeniedError, ValidationError
from apps.governance.models import DPOAppointment
from apps.profiles.models import CounselorProfile


def _user(email: str, role: str, *, active: bool = True, legacy: bool = False) -> User:
    actor = User.objects.create_user(
        email=email,
        password="correct-horse-battery-staple",
        first_name="Audit",
        last_name="Viewer",
        role=role,
        is_active=active,
    )
    if legacy:
        actor.is_superuser = True
        actor.save(update_fields=["is_superuser"])
    return actor


class AuditViewerTestCase(TestCase):
    def setUp(self):
        self.head = _user("audit-head@example.test", RoleChoices.COUNSELOR)
        CounselorProfile.objects.create(user=self.head, is_head_guidance=True)
        self.it = _user("audit-it@example.test", RoleChoices.IT_ADMIN)
        self.dpo = _user("audit-dpo@example.test", RoleChoices.COUNSELOR)
        self.counselor = _user("audit-counselor@example.test", RoleChoices.COUNSELOR)
        self.student = _user("audit-student@example.test", RoleChoices.STUDENT)
        self.staff = _user("audit-staff@example.test", RoleChoices.GCO_STAFF)

        now = timezone.now()
        DPOAppointment.objects.create(
            holder=self.dpo,
            valid_from=now - timedelta(days=1),
            valid_until=now + timedelta(days=1),
            appointment_reference="DPO-AUDIT-001",
            contact_email="dpo@example.test",
            appointed_by=self.head,
        )

    def _entry(self, *, actor, category, action, target_model="system.Health", target_id="42", reference=None, metadata=None):
        return AuditLogEntry.objects.create(
            actor_user=actor,
            actor_role=actor.role if actor else "",
            action_type=action,
            event_category=category,
            severity="INFO",
            target_model=target_model,
            target_object_id=target_id,
            reference_code=reference,
            request_id="REQ-20260825-000001",
            trace_id="TRACE-20260825-000001",
            source_app="apps.audit",
            safe_metadata=metadata or {},
        )

    def test_authority_planes_are_fixed_and_dpo_is_appointment_based(self):
        self.assertEqual(viewer_planes(self.it), frozenset({AuditPlane.TECHNICAL}))
        self.assertEqual(viewer_planes(self.head), frozenset({AuditPlane.BUSINESS}))
        self.assertEqual(viewer_planes(self.dpo), frozenset({AuditPlane.PRIVACY}))
        for actor in (self.counselor, self.staff, self.student):
            self.assertEqual(viewer_planes(actor), frozenset())

    def test_expired_dpo_and_legacy_accounts_fail_closed(self):
        appointment = DPOAppointment.objects.get(holder=self.dpo)
        appointment.valid_until = timezone.now() - timedelta(seconds=1)
        appointment.save(update_fields=["valid_until", "updated_at"])
        self.assertEqual(viewer_planes(self.dpo), frozenset())
        legacy = _user("audit-legacy@example.test", RoleChoices.IT_ADMIN, legacy=True)
        self.assertEqual(viewer_planes(legacy), frozenset())
        inactive = _user("audit-inactive@example.test", RoleChoices.IT_ADMIN, active=False)
        self.assertEqual(viewer_planes(inactive), frozenset())

    def test_plane_scoping_contains_business_privacy_and_technical_events(self):
        technical = self._entry(
            actor=self.it,
            category="SYSTEM",
            action="SYSTEM_HEALTH_CHECK",
            target_model="system.Health",
        )
        business = self._entry(
            actor=self.head,
            category="WORKFLOW",
            action="APPOINTMENT_CREATED",
            target_model="appointments.Appointment",
            target_id="student-42",
            reference="APT-2026-000001",
        )
        privacy = self._entry(
            actor=self.dpo,
            category="PRIVACY",
            action="PRIVACY_REQUEST_CREATED",
            target_model="privacy.DataSubjectRequest",
            target_id="subject-42",
            reference="PRV-2026-000001",
        )
        dpo_governance = self._entry(
            actor=self.head,
            category="GOVERNANCE",
            action="DPO_APPOINTMENT_CREATED",
            target_model="governance.DPOAppointment",
        )

        self.assertTrue(can_view_audit_entry(self.it, technical))
        self.assertFalse(can_view_audit_entry(self.it, business))
        self.assertTrue(can_view_audit_entry(self.head, business))
        self.assertFalse(can_view_audit_entry(self.head, privacy))
        self.assertTrue(can_view_audit_entry(self.dpo, privacy))
        self.assertTrue(can_view_audit_entry(self.dpo, dpo_governance))
        self.assertFalse(can_view_audit_entry(self.head, dpo_governance))

    def test_projection_is_allowlisted_and_fingerprints_are_opaque(self):
        entry = self._entry(
            actor=self.head,
            category="WORKFLOW",
            action="WORKFLOW_UPDATED",
            target_model="profiles.StudentProfile",
            target_id="student-raw-42",
            reference="STU-2026-000001",
            metadata={
                "reason_code": "VALIDATED",
                "status": "ACTIVE",
                "student_profile_id": 42,
                "email": "student@example.test",
                "narrative": "private narrative",
            },
        )
        projection = audit_entry_projection(entry)
        self.assertEqual(projection["target_reference"], "STU-2026-000001")
        self.assertNotEqual(projection["target_fingerprint"], "student-raw-42")
        self.assertNotEqual(projection["actor_fingerprint"], str(self.head.pk))
        self.assertEqual(projection["safe_context"], {"reason_code": "VALIDATED", "status": "ACTIVE"})
        for forbidden in (
            "safe_metadata",
            "target_object_id",
            "email",
            "narrative",
            "actor_user",
            "actor_ip_hash",
            "user_agent_hash",
        ):
            self.assertNotIn(forbidden, projection)

    def test_query_is_frozen_bounded_and_paginated(self):
        with self.assertRaises(FrozenInstanceError):
            query = AuditQuery(event_category="WORKFLOW")
            query.event_category = "SYSTEM"
        with self.assertRaises(ValidationError):
            AuditQuery(action_type="not safe value")
        with self.assertRaises(ValidationError):
            AuditQuery(created_from=timezone.now(), created_until=timezone.now() - timedelta(days=1))

        for index in range(3):
            self._entry(
                actor=self.head,
                category="WORKFLOW",
                action="WORKFLOW_PAGE",
                target_id=str(index + 1),
            )
        result = audit_page(self.head, PageRequest(page=1, page_size=2), AuditQuery(event_category="WORKFLOW"))
        self.assertEqual(result.page, 1)
        self.assertEqual(result.page_size, 2)
        self.assertEqual(result.total, 3)
        self.assertEqual(len(result.items), 2)

    def test_api_list_and_detail_match_explicit_redacted_schemas(self):
        entry = self._entry(
            actor=self.head,
            category="WORKFLOW",
            action="WORKFLOW_TYPED_RESPONSE",
            target_model="profiles.StudentProfile",
            target_id="student-raw-42",
            reference="STU-2026-000001",
            metadata={
                "status": "ACTIVE",
                "success": True,
                "count": 2,
                "email": "student@example.test",
                "narrative": "private narrative",
            },
        )
        token = issue_token_pair(self.head, assurance_verified=True).access_token
        headers = {"HTTP_AUTHORIZATION": f"Bearer {token}"}
        client = Client()

        listing = client.get("/api/v1/audit/", **headers)
        self.assertEqual(listing.status_code, 200)
        page = AuditPageSchema(**listing.json())
        matching = next(item for item in page.items if item.id == entry.id)
        self.assertEqual(matching.target_reference, "STU-2026-000001")
        self.assertEqual(matching.safe_context.status, "ACTIVE")
        self.assertTrue(matching.safe_context.success)
        self.assertEqual(matching.safe_context.count, 2)

        detail = client.get(f"/api/v1/audit/{entry.pk}/", **headers)
        self.assertEqual(detail.status_code, 200)
        validated = AuditEntryProjectionSchema(**detail.json())
        self.assertEqual(validated.id, entry.id)
        self.assertEqual(validated.safe_context.status, "ACTIVE")
        AuditSafeContextSchema(**detail.json()["safe_context"])

        serialized = detail.content.decode()
        for forbidden in (
            "target_object_id",
            "student-raw-42",
            "safe_metadata",
            "student@example.test",
            "private narrative",
            "actor_user",
            "actor_ip_hash",
            "user_agent_hash",
            "source_view",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_api_plane_scoping_and_denial_remain_unchanged(self):
        technical = self._entry(
            actor=self.it,
            category="SYSTEM",
            action="SYSTEM_TYPED_RESPONSE",
        )
        business = self._entry(
            actor=self.head,
            category="WORKFLOW",
            action="BUSINESS_TYPED_RESPONSE",
        )
        privacy = self._entry(
            actor=self.dpo,
            category="PRIVACY",
            action="PRIVACY_TYPED_RESPONSE",
        )
        client = Client()

        for actor, visible, hidden in (
            (self.it, technical, business),
            (self.head, business, privacy),
            (self.dpo, privacy, business),
        ):
            token = issue_token_pair(actor, assurance_verified=True).access_token
            headers = {"HTTP_AUTHORIZATION": f"Bearer {token}"}
            listing = client.get("/api/v1/audit/", **headers)
            self.assertEqual(listing.status_code, 200)
            ids = {item["id"] for item in listing.json()["items"]}
            self.assertIn(visible.id, ids)
            self.assertNotIn(hidden.id, ids)
            self.assertEqual(
                client.get(f"/api/v1/audit/{visible.pk}/", **headers).status_code,
                200,
            )
            self.assertEqual(
                client.get(f"/api/v1/audit/{hidden.pk}/", **headers).status_code,
                404,
            )

        for actor in (self.counselor, self.staff, self.student):
            token = issue_token_pair(actor, assurance_verified=True).access_token
            response = client.get(
                "/api/v1/audit/",
                HTTP_AUTHORIZATION=f"Bearer {token}",
            )
            self.assertEqual(response.status_code, 403)

    def test_requested_plane_is_authorized_and_applied_before_pagination(self):
        appointment = DPOAppointment.objects.get(holder=self.dpo)
        appointment.holder = self.it
        appointment.save(update_fields=["holder", "updated_at"])
        technical = self._entry(actor=self.it, category="SYSTEM", action="SYSTEM_FIRST")
        privacy = self._entry(actor=self.dpo, category="PRIVACY", action="PRIVACY_FIRST")
        business = self._entry(actor=self.head, category="WORKFLOW", action="WORKFLOW_FIRST")

        self.assertEqual(
            authorized_planes(self.it),
            frozenset({AuditPlane.TECHNICAL, AuditPlane.PRIVACY}),
        )
        page = audit_page(
            self.it,
            PageRequest(page=1, page_size=1),
            AuditQuery(),
            plane=AuditPlane.TECHNICAL,
        )
        self.assertEqual(page.total, 1)
        self.assertEqual([item["id"] for item in page.items], [technical.id])
        self.assertEqual(
            audit_page(
                self.it,
                PageRequest(page=1, page_size=25),
                AuditQuery(),
                plane=AuditPlane.PRIVACY,
            ).total,
            1,
        )
        narrowed = audit_page(
            self.it,
            PageRequest(page=1, page_size=25),
            AuditQuery(),
            plane="technical",
        )
        self.assertEqual(narrowed.items[0]["id"], technical.id)
        self.assertNotEqual(technical.id, privacy.id)
        self.assertNotEqual(technical.id, business.id)
        self.assertIsNone(audit_detail(self.it, privacy.id, plane=AuditPlane.TECHNICAL))
        self.assertIsNotNone(audit_detail(self.it, privacy.id, plane=AuditPlane.PRIVACY))
        with self.assertRaises(PermissionDeniedError):
            authorized_planes(self.it, AuditPlane.BUSINESS)

    def test_api_plane_filters_and_openapi_parameters_are_explicit(self):
        entry = self._entry(actor=self.it, category="SYSTEM", action="SYSTEM_FILTERED")
        token = issue_token_pair(self.it, assurance_verified=True).access_token
        headers = {"HTTP_AUTHORIZATION": f"Bearer {token}"}
        client = Client()

        response = client.get(
            "/api/v1/audit/?plane=technical&page=1&page_size=1&event_category=SYSTEM&action_type=SYSTEM_FILTERED&severity=INFO&source_app=apps.audit&target_model=system.Health&request_id=REQ-20260825-000001&trace_id=TRACE-20260825-000001&created_from=2026-01-01&created_until=2026-12-31",
            **headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["total"], 1)
        self.assertEqual(response.json()["items"][0]["id"], entry.id)

        from config.api.v1 import api_v1

        schema = api_v1.get_openapi_schema()
        list_parameters = {
            parameter["name"]
            for parameter in schema["paths"]["/api/v1/audit/"]["get"]["parameters"]
        }
        self.assertTrue({
            "plane", "event_category", "action_type", "severity", "source_app",
            "target_model", "created_from", "created_until", "request_id", "trace_id",
        }.issubset(list_parameters))
        detail_parameters = {
            parameter["name"]
            for parameter in schema["paths"]["/api/v1/audit/{entry_id}/"]["get"]["parameters"]
        }
        self.assertIn("plane", detail_parameters)

        self.assertEqual(client.get(f"/api/v1/audit/{entry.pk}/?plane=technical", **headers).status_code, 200)
        self.assertEqual(client.get(f"/api/v1/audit/{entry.pk}/?plane=business", **headers).status_code, 403)

    def test_unauthenticated_api_has_standard_boundary_and_no_mutations(self):
        response = Client().get("/api/v1/audit/")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertTrue(response["X-Request-ID"])

        from config.api.v1 import api_v1

        schema = api_v1.get_openapi_schema()
        self.assertIn("/api/v1/audit/", schema["paths"])
        self.assertIn("/api/v1/audit/{entry_id}/", schema["paths"])
        operation_ids = {
            operation.get("operationId")
            for path in schema["paths"].values()
            for operation in path.values()
            if isinstance(operation, dict)
        }
        self.assertIn("audit_entries_list", operation_ids)
        self.assertIn("audit_entry_detail", operation_ids)
        self.assertNotIn("audit_entries_create", operation_ids)
