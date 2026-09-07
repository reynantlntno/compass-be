import os
import uuid
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.fernet import Fernet
from apps.common.exceptions import PermissionDeniedError, ValidationError
from django.core.exceptions import ValidationError as DjangoValidationError
from django.test import Client, SimpleTestCase, TestCase
from django.utils import timezone

from apps.account_security.api_tokens import issue_token_pair
from apps.accounts.models import RoleChoices, User
from apps.governance.dpo_services import create_dpo_appointment
from apps.profiles.models import CounselorProfile
from apps.security.models import EncryptionKeyVersion, KeyPurposeChoices, KeyStatusChoices

from . import projections
from .api import (
    PrivacyAcceptancePageSchema,
    PrivacyAcceptanceProjectionSchema,
    PrivacyIncidentPageSchema,
    PrivacyIncidentProjectionSchema,
    PrivacyIncidentSafeEvidenceSchema,
    PrivacyIncidentTransitionSchema,
    PrivacyLegalHoldPageSchema,
    PrivacyLegalHoldSchema,
    PrivacyNoticeSchema,
    PrivacyRequestPageSchema,
    PrivacyRequestProjectionSchema,
    PrivacyRequestSensitiveSchema,
    PrivacyRetentionEvaluationPageSchema,
    PrivacyRetentionEvaluationResultSchema,
    PrivacyRetentionEvaluationSchema,
    PrivacyRetentionPolicyPageSchema,
    PrivacyRetentionPolicySchema,
)
from .choices import (
    PrivacyIncidentCategoryChoices,
    PrivacyIncidentNotificationDecisionChoices,
    PrivacyIncidentSeverityChoices,
    PrivacyIncidentStatusChoices,
    PrivacyRequestTypeChoices,
    ReviewerAuthorizationStatusChoices,
)
from .commands import (
    PrivacyNoticeAcceptanceCommand,
    PrivacyNoticeRevisionApprovalCommand,
    PrivacyNoticeRevisionCommand,
    PrivacyWorkflowBindingCommand,
)
from .models import (
    DataSubjectRequest,
    PrivacyIncident,
    PrivacyIncidentTransition,
    PrivacyReviewerAuthorization,
)
from .services import (
    can_view_request,
    contain_privacy_incident,
    create_data_subject_request,
    create_privacy_incident,
    approve_privacy_notice_revision_command,
    bind_privacy_notice_command,
    create_privacy_notice_revision_command,
    has_reviewer_scope,
    privacy_incidents_visible_to,
    privacy_requests_visible_to,
    record_notice_acceptance_command,
    resolve_current_notice,
    resolve_retention_policy,
    transition_privacy_incident,
    withdraw_data_subject_request,
)


def _build_user(email, role, *, is_active=True, is_superuser=False):
    actor = User.objects.create_user(
        email=email,
        password="correct-horse-battery-staple",
        first_name="Test",
        last_name="User",
        role=role,
        is_active=is_active,
    )
    if is_superuser:
        actor.is_superuser = True
        actor.save(update_fields=["is_superuser"])
    return actor


def _head_guidance(email="head@example.test", *, is_active=True, is_superuser=False):
    actor = _build_user(
        email,
        RoleChoices.COUNSELOR,
        is_active=is_active,
        is_superuser=is_superuser,
    )
    CounselorProfile.objects.create(user=actor, is_head_guidance=True)
    return actor


class PrivacyResponseContractTests(SimpleTestCase):
    def setUp(self):
        self.now = timezone.now()
        self.notice = SimpleNamespace(
            notice_identifier="student-privacy",
            purpose_workflow="student_privacy",
            version="2026.1",
            locale="en",
            body_markdown="## Privacy notice\n\nThis notice explains how information is handled.",
            effective_at=self.now,
            revision_hash="a" * 64,
        )
        self.acceptance = SimpleNamespace(
            pk=uuid.uuid4(),
            purpose_workflow="student_privacy",
            decision="ACCEPTED",
            notice_revision=SimpleNamespace(version="2026.1"),
            decided_at=self.now,
        )
        self.request = SimpleNamespace(
            pk=uuid.uuid4(),
            reference_code="PRV-2026-000001",
            request_type="ACCESS",
            target_category="cases",
            status="SUBMITTED",
            submitted_at=self.now,
            identity_verified_at=None,
            assigned_reviewer_id=None,
            fulfilled_at=None,
            protected_fulfillment_file_id=None,
            withdrawn_at=None,
            closed_at=None,
            description_encrypted="private request narrative",
            decision_notes_encrypted="private decision notes",
            decision_reason_code="",
            subject_reference_hash="b" * 64,
            target_record_reference_hash="c" * 64,
            requester_id=uuid.uuid4(),
            source_route="/private/internal",
            request_correlation_id="correlation-secret",
        )
        self.incident = SimpleNamespace(
            pk=uuid.uuid4(),
            incident_code="INC-2026-000001",
            category="UNAUTHORIZED_ACCESS",
            severity="HIGH",
            affected_workflow="records",
            affected_record_category="cases",
            status="OPEN",
            discovered_at=self.now,
            containment_code="ACCESS_REVOKED",
            safe_summary_code="DISCLOSURE_RECALLED",
            notification_decision="PENDING",
            action_metadata={"raw": "must not cross the boundary"},
            related_event_ids=["d" * 64],
            reporter_id=uuid.uuid4(),
            owner_id=uuid.uuid4(),
        )
        self.transition = SimpleNamespace(
            from_status="",
            to_status="OPEN",
            reason_code="recorded",
            occurred_at=self.now,
            safe_evidence={"metadata_only": True, "affected_count": 0},
            actor_user_id=uuid.uuid4(),
        )
        self.hold = SimpleNamespace(
            pk=uuid.uuid4(),
            record_category="cases",
            record_reference_hash="e" * 64,
            reason_code="LITIGATION_HOLD",
            status="ACTIVE",
            safe_reference="f" * 64,
            placed_at=self.now,
            released_at=None,
            placed_by_id=uuid.uuid4(),
            released_by_id=None,
        )
        self.policy = SimpleNamespace(
            pk=uuid.uuid4(),
            target_reference="cases",
            configuration_json={
                "record_category": "cases",
                "retention_trigger": "SUBMISSION",
                "retention_period_days": 365,
                "review_due_at": self.now.isoformat(),
                "legal_basis": "institutional-policy",
                "owner_role": "DPO",
                "legal_hold_behavior": "pause-disposal",
                "disposal_method": "approved-destruction",
                "evidence_requirement": "retention-log",
                "exception_status": "none",
                "raw_metadata": "must not cross the boundary",
            },
            effective_from=self.now,
            effective_until=None,
            source_reference="RETENTION-POLICY-001",
        )
        self.evaluation = SimpleNamespace(
            pk=uuid.uuid4(),
            environment="test",
            evaluated_at=self.now,
            record_category="cases",
            candidate_count=0,
            hold_count=1,
            result_code="LEGAL_HOLD",
            safe_metadata={"policy_id": str(self.policy.pk), "metadata_only": True},
        )

    def test_all_projection_families_match_exact_output_schemas(self):
        notice = projections.notice_projection(self.notice)
        self.assertEqual(
            set(notice),
            {"version", "effective_at", "body_html"},
        )
        PrivacyNoticeSchema(**notice)

        acceptance = projections.acceptance_projection(self.acceptance)
        self.assertEqual(
            set(acceptance),
            {"id", "purpose_workflow", "decision", "notice_version", "decided_at"},
        )
        PrivacyAcceptanceProjectionSchema(**acceptance)

        request = projections.request_projection(self.request)
        self.assertEqual(
            set(request),
            {
                "reference_code", "request_type", "target_category", "status", "submitted_at",
                "identity_verified", "assigned", "fulfilled", "withdrawn_at", "closed_at",
            },
        )
        PrivacyRequestProjectionSchema(**request)

        sensitive = projections.request_sensitive_projection(self.request)
        self.assertEqual(
            set(sensitive), {"reference_code", "description", "decision_notes", "decision_reason_code"}
        )
        PrivacyRequestSensitiveSchema(**sensitive)

        incident = projections.incident_projection(self.incident)
        self.assertEqual(
            set(incident),
            {
                "incident_code", "category", "severity", "affected_workflow",
                "affected_record_category", "status", "discovered_at", "containment_code",
                "safe_summary_code", "notification_decision",
            },
        )
        PrivacyIncidentProjectionSchema(**incident)
        timeline = projections.incident_transition_projection(self.transition)
        self.assertEqual(set(timeline), {"from_status", "to_status", "reason_code", "occurred_at", "safe_evidence"})
        PrivacyIncidentTransitionSchema(**timeline)
        PrivacyIncidentSafeEvidenceSchema(**timeline["safe_evidence"])
        detail = {**incident, "timeline": [timeline]}
        PrivacyIncidentProjectionSchema(**detail)
        technical = projections.incident_projection(self.incident, technical_only=True)

        self.assertNotIn("notification_decision", technical)
        technical_timeline = projections.incident_transition_projection(self.transition, technical_only=True)
        self.assertNotIn("safe_evidence", technical_timeline)
        PrivacyIncidentProjectionSchema(**technical)
        PrivacyIncidentTransitionSchema(**technical_timeline)

        hold = projections.legal_hold_projection(self.hold)
        self.assertEqual(
            set(hold),
            {"id", "record_category", "status", "reason_code", "safe_reference_present", "placed_at", "released_at"},
        )
        PrivacyLegalHoldSchema(**hold)

        policy = projections.retention_policy_projection(self.policy)
        self.assertEqual(
            set(policy),
            {
                "policy_id", "record_category", "retention_trigger", "retention_period_days",
                "review_due_at", "legal_basis", "owner_role", "legal_hold_behavior", "disposal_method",
                "evidence_requirement", "exception_status", "effective_from", "effective_until", "source_reference",
            },
        )
        PrivacyRetentionPolicySchema(**policy)

        evaluation = projections.retention_evaluation_projection(self.evaluation)
        self.assertEqual(
            set(evaluation),
            {"id", "environment", "evaluated_at", "record_category", "candidate_count", "hold_count", "result_code", "metadata_only", "policy_id"},
        )
        PrivacyRetentionEvaluationSchema(**evaluation)

    def test_public_notice_projection_fails_closed_for_unsupported_source(self):
        for source in (
            "<p>x</p>",
            "## [link](https://example.test)",
            "- list",
            "### h3",
        ):
            with self.subTest(source=source):
                notice = SimpleNamespace(**vars(self.notice))
                notice.body_markdown = source
                self.assertIsNone(projections.notice_projection(notice))

    def test_pages_and_batch_results_have_typed_items(self):
        acceptance = projections.acceptance_projection(self.acceptance)
        request = projections.request_projection(self.request)
        incident = projections.incident_projection(self.incident)
        hold = projections.legal_hold_projection(self.hold)
        policy = projections.retention_policy_projection(self.policy)
        evaluation = projections.retention_evaluation_projection(self.evaluation)

        self.assertEqual(PrivacyAcceptancePageSchema(items=[acceptance], page=1, page_size=25, total=1).items[0].id, acceptance["id"])
        self.assertEqual(PrivacyRequestPageSchema(items=[request], page=1, page_size=25, total=1).items[0].reference_code, request["reference_code"])
        self.assertEqual(PrivacyIncidentPageSchema(items=[incident], page=1, page_size=25, total=1).items[0].incident_code, incident["incident_code"])
        self.assertEqual(PrivacyLegalHoldPageSchema(items=[hold], page=1, page_size=25, total=1).items[0].id, hold["id"])
        self.assertEqual(PrivacyRetentionPolicyPageSchema(items=[policy], page=1, page_size=25, total=1).items[0].policy_id, policy["policy_id"])
        self.assertEqual(PrivacyRetentionEvaluationPageSchema(items=[evaluation], page=1, page_size=25, total=1).items[0].id, evaluation["id"])
        self.assertEqual(PrivacyRetentionEvaluationResultSchema(items=[evaluation]).items[0].id, evaluation["id"])

    def test_sensitive_and_internal_fields_do_not_cross_projection_boundaries(self):
        outputs = (
            projections.notice_projection(self.notice),
            projections.acceptance_projection(self.acceptance),
            projections.request_projection(self.request),
            projections.request_sensitive_projection(self.request),
            projections.incident_projection(self.incident),
            projections.incident_transition_projection(self.transition),
            projections.legal_hold_projection(self.hold),
            projections.retention_policy_projection(self.policy),
            projections.retention_evaluation_projection(self.evaluation),
        )
        forbidden = {
            "subject_reference_hash", "target_record_reference_hash", "token", "token_hash",
            "token_session_hash", "requester_id", "assigned_reviewer_id", "reviewed_by_id",
            "reporter_id", "owner_id", "actor_user_id", "placed_by_id", "released_by_id",
            "related_event_ids", "action_metadata", "raw_metadata", "request_correlation_id",
            "source_route", "description_encrypted", "decision_notes_encrypted", "protected_file_id",
            "expected_updated_at", "reason", "metadata_json",
        }
        for output in outputs:
            with self.subTest(output=output):
                self.assertTrue(forbidden.isdisjoint(output))

        self.assertNotIn("description", projections.request_projection(self.request))
        self.assertEqual(projections.request_sensitive_projection(self.request)["description"], "private request narrative")


class PrivacyApiResponseContractTests(TestCase):
    def setUp(self):
        self._encryption_key_patcher = patch.dict(
            os.environ,
            {"COMPASS_TEST_FIELD_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii")},
        )
        self._encryption_key_patcher.start()
        self.addCleanup(self._encryption_key_patcher.stop)
        EncryptionKeyVersion.objects.create(
            key_version="privacy-contract-v1",
            key_purpose=KeyPurposeChoices.FIELD_ENCRYPTION,
            status=KeyStatusChoices.ACTIVE,
            source_alias="env",
            secret_reference="COMPASS_TEST_FIELD_ENCRYPTION_KEY",
            algorithm="Fernet",
        )
        self.client = Client()
        self.student = _build_user("privacy-contract-student@example.test", RoleChoices.STUDENT)
        self.student_token = issue_token_pair(self.student, assurance_verified=True).access_token

    def _headers(self, token=None):
        return {"HTTP_AUTHORIZATION": f"Bearer {token or self.student_token}"}

    def test_empty_resource_pages_validate_against_their_explicit_schemas(self):
        pages = (
            ("/api/v1/privacy/acceptances/", PrivacyAcceptancePageSchema),
            ("/api/v1/privacy/requests/", PrivacyRequestPageSchema),
            ("/api/v1/privacy/retention/policies/", PrivacyRetentionPolicyPageSchema),
            ("/api/v1/privacy/retention/evaluations/", PrivacyRetentionEvaluationPageSchema),
            ("/api/v1/privacy/legal-holds/", PrivacyLegalHoldPageSchema),
            ("/api/v1/privacy/incidents/", PrivacyIncidentPageSchema),
        )
        for path, schema in pages:
            with self.subTest(path=path):
                response = self.client.get(path, **self._headers())
                self.assertEqual(response.status_code, 200, response.content)
                validated = schema(**response.json())
                self.assertEqual(validated.items, [])

    def test_request_create_and_idempotent_replay_use_the_safe_projection(self):
        payload = {
            "request_type": PrivacyRequestTypeChoices.ACCESS,
            "description": "private request narrative",
            "target_category": "cases",
            "target_record_reference": "control-number-must-not-escape",
        }
        first = self.client.post(
            "/api/v1/privacy/requests/",
            data=payload,
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="privacy-request-contract-1",
            **self._headers(),
        )
        self.assertEqual(first.status_code, 200, first.content)
        first_payload = first.json()
        PrivacyRequestProjectionSchema(**first_payload)
        self.assertNotIn("description", first_payload)
        self.assertNotIn("target_record_reference", first_payload)
        self.assertNotIn("expected_updated_at", first_payload)

        replay = self.client.post(
            "/api/v1/privacy/requests/",
            data=payload,
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="privacy-request-contract-1",
            **self._headers(),
        )
        self.assertEqual(replay.status_code, 200, replay.content)
        self.assertEqual(replay.json(), first_payload)

    def test_student_request_detail_is_safe_and_sensitive_detail_is_reviewer_only(self):
        request = create_data_subject_request(
            actor=self.student,
            request_type=PrivacyRequestTypeChoices.ACCESS,
            description="student private narrative",
            target_category="cases",
            target_record_reference="student-control-secret",
            source_route="test",
        )
        reviewer = _build_user("privacy-contract-reviewer@example.test", RoleChoices.COUNSELOR)
        PrivacyReviewerAuthorization.objects.create(
            authorized_user=reviewer,
            scopes={"scopes": ["request_review", "request_sensitive"], "categories": ["cases"]},
            source_reference="privacy-contract-test",
        )
        reviewer_token = issue_token_pair(reviewer, assurance_verified=True).access_token

        metadata_response = self.client.get(
            f"/api/v1/privacy/requests/{request.reference_code}/",
            **self._headers(),
        )
        self.assertEqual(metadata_response.status_code, 200, metadata_response.content)
        metadata = metadata_response.json()
        PrivacyRequestProjectionSchema(**metadata)
        self.assertNotIn("description", metadata)
        self.assertNotIn("target_record_reference", metadata)
        self.assertNotIn("subject_reference_hash", metadata)

        student_sensitive = self.client.get(
            f"/api/v1/privacy/requests/{request.reference_code}/sensitive/",
            **self._headers(),
        )
        self.assertEqual(student_sensitive.status_code, 404, student_sensitive.content)

        sensitive_response = self.client.get(
            f"/api/v1/privacy/requests/{request.reference_code}/sensitive/",
            **self._headers(reviewer_token),
        )
        self.assertEqual(sensitive_response.status_code, 200, sensitive_response.content)
        sensitive = PrivacyRequestSensitiveSchema(**sensitive_response.json())
        self.assertEqual(sensitive.description, "student private narrative")

    def test_it_incident_detail_uses_the_technical_projection(self):
        it_admin = _build_user("privacy-contract-it@example.test", RoleChoices.IT_ADMIN)
        token = issue_token_pair(it_admin, assurance_verified=True).access_token
        incident = PrivacyIncident.objects.create(
            incident_code="INC-CONTRACT-0001",
            category=PrivacyIncidentCategoryChoices.UNAUTHORIZED_ACCESS,
            severity=PrivacyIncidentSeverityChoices.HIGH,
            affected_workflow="records",
            affected_record_category="cases",
            notification_decision=PrivacyIncidentNotificationDecisionChoices.REQUIRED,
            action_metadata={"affected_count": 2},
            related_event_ids=["a" * 64],
        )
        PrivacyIncidentTransition.objects.create(
            incident=incident,
            from_status="",
            to_status=PrivacyIncidentStatusChoices.OPEN,
            reason_code="recorded",
            safe_evidence={"metadata_only": True},
        )

        response = self.client.get(
            f"/api/v1/privacy/incidents/{incident.incident_code}/",
            **self._headers(token),
        )
        self.assertEqual(response.status_code, 200, response.content)
        payload = response.json()
        PrivacyIncidentProjectionSchema(**payload)
        self.assertNotIn("notification_decision", payload)
        self.assertNotIn("action_metadata", payload)
        self.assertNotIn("related_event_ids", payload)
        self.assertNotIn("safe_evidence", payload["timeline"][0])


class PrivacyReviewerAuthorizationTests(TestCase):
    def setUp(self):
        self.counselor = _build_user("counselor@example.test", RoleChoices.COUNSELOR)
        self.staff = _build_user("staff@example.test", RoleChoices.GCO_STAFF)
        self.head = _head_guidance()
        self.student = _build_user("student@example.test", RoleChoices.STUDENT)
        self.it_admin = _build_user("it@example.test", RoleChoices.IT_ADMIN)

    def authorize(self, actor, scopes, **kwargs):
        return PrivacyReviewerAuthorization.objects.create(
            authorized_user=actor,
            scopes=scopes,
            source_reference="policy-test",
            **kwargs,
        )

    def test_head_guidance_requires_active_scoped_authorization(self):
        self.assertFalse(has_reviewer_scope(self.head, "request_decision", target_category="cases"))
        self.authorize(self.head, {"scopes": ["request_decision"], "categories": ["cases"]})
        self.assertTrue(has_reviewer_scope(self.head, "request_decision", target_category="cases"))
        self.assertFalse(has_reviewer_scope(self.head, "request_decision", target_category="records"))

    def test_active_authorization_requires_matching_action_and_category(self):
        self.authorize(self.counselor, {"scopes": ["request_review"], "categories": ["cases"]})
        self.assertTrue(has_reviewer_scope(self.counselor, "request_review", target_category="cases"))
        self.assertFalse(has_reviewer_scope(self.counselor, "request_decision", target_category="cases"))
        self.assertFalse(has_reviewer_scope(self.counselor, "request_review", target_category="records"))
        self.assertFalse(has_reviewer_scope(self.counselor, "request_review"))

    def test_action_only_authorization_without_category_scope_fails_closed(self):
        self.authorize(self.staff, ["request_review"])
        self.assertFalse(has_reviewer_scope(self.staff, "request_review", target_category="any-category"))
        DataSubjectRequest.objects.create(
            reference_code="PRV-UNSCOPED-1",
            subject_reference_hash="a" * 64,
            request_type=PrivacyRequestTypeChoices.ACCESS,
            target_category="any-category",
            source_route="test",
        )
        self.assertFalse(privacy_requests_visible_to(self.staff).exists())

        self.authorize(self.staff, {"scopes": ["request_review"], "categories": ["*"]})
        self.assertTrue(has_reviewer_scope(self.staff, "request_review", target_category="any-category"))
        self.assertTrue(privacy_requests_visible_to(self.staff).exists())

    def test_authorized_selectors_preserve_category_scope(self):
        DataSubjectRequest.objects.create(
            reference_code="PRV-CASES-1",
            subject_reference_hash="a" * 64,
            request_type=PrivacyRequestTypeChoices.ACCESS,
            target_category="cases",
            source_route="test",
        )
        DataSubjectRequest.objects.create(
            reference_code="PRV-RECORDS-1",
            subject_reference_hash="b" * 64,
            request_type=PrivacyRequestTypeChoices.ACCESS,
            target_category="records",
            source_route="test",
        )
        PrivacyIncident.objects.create(
            incident_code="INC-CASES-1",
            category=PrivacyIncidentCategoryChoices.UNAUTHORIZED_ACCESS,
            severity=PrivacyIncidentSeverityChoices.LOW,
            affected_record_category="cases",
        )
        PrivacyIncident.objects.create(
            incident_code="INC-RECORDS-1",
            category=PrivacyIncidentCategoryChoices.UNAUTHORIZED_ACCESS,
            severity=PrivacyIncidentSeverityChoices.LOW,
            affected_record_category="records",
        )
        self.authorize(self.head, {"scopes": ["request_review", "incident_record"], "categories": ["cases"]})
        self.assertEqual(list(privacy_requests_visible_to(self.head).values_list("reference_code", flat=True)), ["PRV-CASES-1"])
        self.assertEqual(list(privacy_incidents_visible_to(self.head).values_list("incident_code", flat=True)), ["INC-CASES-1"])

    def test_future_expired_revoked_and_legacy_authorizations_fail_closed(self):
        now = timezone.now()
        cases = (
            {"valid_from": now + timedelta(minutes=1)},
            {"valid_until": now - timedelta(minutes=1)},
            {"status": ReviewerAuthorizationStatusChoices.REVOKED},
            {"revoked_at": now},
        )
        for index, kwargs in enumerate(cases):
            actor = _build_user(f"invalid-{index}@example.test", RoleChoices.COUNSELOR)
            self.authorize(actor, ["request_review"], **kwargs)
            self.assertFalse(has_reviewer_scope(actor, "request_review", target_category="cases"))

        inactive = _build_user("inactive@example.test", RoleChoices.COUNSELOR, is_active=False)
        self.authorize(inactive, ["request_review"])
        self.assertFalse(has_reviewer_scope(inactive, "request_review", target_category="cases"))

        legacy = _build_user("legacy@example.test", RoleChoices.COUNSELOR, is_superuser=True)
        self.authorize(legacy, ["request_review"])
        self.assertFalse(has_reviewer_scope(legacy, "request_review", target_category="cases"))

    def test_unauthorized_head_and_it_selectors_are_empty(self):
        DataSubjectRequest.objects.create(
            reference_code="PRV-SELECTOR-1",
            subject_reference_hash="a" * 64,
            request_type=PrivacyRequestTypeChoices.ACCESS,
            target_category="cases",
            source_route="test",
        )
        PrivacyIncident.objects.create(
            incident_code="INC-SELECTOR-1",
            category=PrivacyIncidentCategoryChoices.UNAUTHORIZED_ACCESS,
            severity=PrivacyIncidentSeverityChoices.LOW,
            affected_record_category="cases",
        )
        self.assertFalse(privacy_requests_visible_to(self.head).exists())
        self.assertFalse(privacy_incidents_visible_to(self.head).exists())
        self.assertTrue(privacy_incidents_visible_to(self.it_admin).exists())


class PrivacySelfServiceAndIncidentTests(TestCase):
    def setUp(self):
        self.student = _build_user("student@example.test", RoleChoices.STUDENT)
        self.other_student = _build_user("other-student@example.test", RoleChoices.STUDENT)
        self.it_admin = _build_user("it@example.test", RoleChoices.IT_ADMIN)
        self.reviewer = _build_user("reviewer@example.test", RoleChoices.COUNSELOR)
        PrivacyReviewerAuthorization.objects.create(
            authorized_user=self.reviewer,
            scopes={"scopes": ["incident_record", "incident_decision"], "categories": ["cases"]},
            source_reference="policy-test",
        )

    def test_student_can_self_submit_view_and_withdraw_own_request(self):
        request = create_data_subject_request(
            actor=self.student,
            request_type=PrivacyRequestTypeChoices.ACCESS,
            target_category="cases",
            source_route="student-self-service",
        )
        self.assertTrue(can_view_request(self.student, request))
        self.assertFalse(can_view_request(self.other_student, request))
        withdrawn = withdraw_data_subject_request(actor=self.student, request=request)
        self.assertEqual(withdrawn.status, "WITHDRAWN")

    def test_it_admin_can_contain_but_cannot_make_privacy_decisions(self):
        incident = create_privacy_incident(
            actor=self.it_admin,
            category=PrivacyIncidentCategoryChoices.UNAUTHORIZED_ACCESS,
            severity=PrivacyIncidentSeverityChoices.HIGH,
            affected_record_category="cases",
            containment_code="ACCESS_REVOKED",
        )
        contained = contain_privacy_incident(actor=self.it_admin, incident=incident, reason_code="technical_containment")
        self.assertEqual(contained.status, PrivacyIncidentStatusChoices.CONTAINED)
        with self.assertRaises(PermissionDeniedError):
            transition_privacy_incident(
                actor=self.it_admin,
                incident=contained,
                to_status=PrivacyIncidentStatusChoices.RESOLVED,
                reason_code="privacy_resolution",
            )
        with self.assertRaises(PermissionDeniedError):
            create_privacy_incident(
                actor=self.it_admin,
                category=PrivacyIncidentCategoryChoices.UNAUTHORIZED_ACCESS,
                severity=PrivacyIncidentSeverityChoices.HIGH,
                affected_record_category="cases",
                notification_decision=PrivacyIncidentNotificationDecisionChoices.REQUIRED,
            )

    def test_it_admin_with_explicit_reviewer_authorization_can_make_privacy_decisions(self):
        PrivacyReviewerAuthorization.objects.create(
            authorized_user=self.it_admin,
            scopes={"scopes": ["incident_record", "incident_decision"], "categories": ["cases"]},
            source_reference="dpo-appointment-test",
        )
        incident = create_privacy_incident(
            actor=self.it_admin,
            category=PrivacyIncidentCategoryChoices.UNAUTHORIZED_ACCESS,
            severity=PrivacyIncidentSeverityChoices.HIGH,
            affected_record_category="cases",
            notification_decision=PrivacyIncidentNotificationDecisionChoices.REQUIRED,
        )
        updated = transition_privacy_incident(
            actor=self.it_admin,
            incident=incident,
            to_status=PrivacyIncidentStatusChoices.INVESTIGATING,
            reason_code="dpo_review_started",
        )
        self.assertEqual(updated.status, PrivacyIncidentStatusChoices.INVESTIGATING)

    def test_authorized_reviewer_can_make_incident_decision(self):
        incident = create_privacy_incident(
            actor=self.reviewer,
            category=PrivacyIncidentCategoryChoices.UNAUTHORIZED_ACCESS,
            severity=PrivacyIncidentSeverityChoices.HIGH,
            affected_record_category="cases",
        )
        updated = transition_privacy_incident(
            actor=self.reviewer,
            incident=incident,
            to_status=PrivacyIncidentStatusChoices.INVESTIGATING,
            reason_code="review_started",
        )
        self.assertEqual(updated.status, PrivacyIncidentStatusChoices.INVESTIGATING)

    def test_student_self_service_requires_active_nonlegacy_account(self):
        inactive = _build_user("inactive-student@example.test", RoleChoices.STUDENT, is_active=False)
        with self.assertRaises(PermissionDeniedError):
            create_data_subject_request(
                actor=inactive,
                request_type=PrivacyRequestTypeChoices.ACCESS,
                source_route="student-self-service",
            )

    def test_student_cannot_submit_a_request_for_another_subject(self):
        with self.assertRaises(PermissionDeniedError):
            create_data_subject_request(
                actor=self.student,
                request_type=PrivacyRequestTypeChoices.ACCESS,
                subject_reference=f"user:{self.other_student.pk}",
                source_route="student-self-service",
            )

    def test_request_view_requires_a_concrete_target(self):
        self.assertFalse(can_view_request(self.student, None))


class PrivacyNoticeAndRetentionBoundaryTests(TestCase):
    def setUp(self):
        now = timezone.now()
        self.head = _head_guidance("notice-head@example.test")
        self.dpo = _build_user("notice-dpo@example.test", RoleChoices.GCO_STAFF)
        self.student = _build_user("notice-student@example.test", RoleChoices.STUDENT)
        create_dpo_appointment(
            actor=self.head,
            holder=self.dpo,
            valid_from=now - timedelta(minutes=1),
            valid_until=now + timedelta(days=365),
            appointment_reference="DPO-NOTICE-001",
            contact_email="dpo-notice@example.test",
        )

    def _revision(self):
        return create_privacy_notice_revision_command(
            actor=self.dpo,
            command=PrivacyNoticeRevisionCommand(
                notice_identifier="student-privacy",
                version="2026.1",
                body_markdown="# Student privacy notice",
                source_reference="DPO-NOTICE-SOURCE-001",
                purpose_workflow="student_privacy",
            ),
        )

    def test_notice_requires_approval_and_binding_before_acceptance(self):
        with patch("apps.privacy.services.is_policy_active", return_value=True):
            revision = self._revision()
            with self.assertRaises(ValidationError):
                bind_privacy_notice_command(
                    actor=self.dpo,
                    command=PrivacyWorkflowBindingCommand(
                        purpose_workflow="student_privacy",
                        notice_revision_id=str(revision.pk),
                        status="PUBLISHED",
                    ),
                )
            approve_privacy_notice_revision_command(
                actor=self.dpo,
                revision_id=revision.pk,
                command=PrivacyNoticeRevisionApprovalCommand(
                    approval_reference="DPO-APPROVAL-001",
                ),
            )
            binding = bind_privacy_notice_command(
                actor=self.dpo,
                command=PrivacyWorkflowBindingCommand(
                    purpose_workflow="student_privacy",
                    notice_revision_id=str(revision.pk),
                    status="PUBLISHED",
                    source_reference="DPO-BINDING-001",
                ),
            )
            self.assertEqual(binding.notice_revision_id, revision.pk)
            self.assertEqual(resolve_current_notice("student-privacy", "student_privacy").pk, revision.pk)
            event = record_notice_acceptance_command(
                actor=self.student,
                command=PrivacyNoticeAcceptanceCommand(
                    notice_identifier="student-privacy",
                    purpose_workflow="student_privacy",
                    subject_reference=f"user:{self.student.pk}",
                ),
                source_route="test",
            )
            self.assertEqual(event.notice_revision_id, revision.pk)

    def test_notice_content_is_immutable_and_projection_has_no_session_secret(self):
        with patch("apps.privacy.services.is_policy_active", return_value=True):
            revision = self._revision()
            with self.assertRaises(DjangoValidationError):
                revision.body_markdown = "tampered"
                revision.save()

    def test_retention_resolution_requires_an_exact_target_reference(self):
        with patch("apps.governance.selectors.resolve_effective_policy", return_value=None) as resolver:
            self.assertIsNone(resolve_retention_policy(""))
            self.assertIsNone(resolve_retention_policy("student_records"))
            resolver.assert_called_once_with(
                "privacy.retention",
                target_type="privacy.RetentionRule",
                target_reference="student_records",
                at=None,
            )

    def test_openapi_keeps_dpo_governance_under_policies(self):
        schema = Client().get("/api/v1/openapi.json").json()
        self.assertIn("/api/v1/privacy/notices/{notice_identifier}/", schema["paths"])
        self.assertIn("/api/v1/privacy/notice-revisions/", schema["paths"])
        self.assertIn("/api/v1/privacy/notice-bindings/", schema["paths"])
        self.assertNotIn("/api/v1/policies/privacy-notice-revisions/", schema["paths"])
        self.assertNotIn("/api/v1/policies/privacy-notice-bindings/", schema["paths"])
        self.assertFalse(any(path.startswith("/api/v1/privacy/dpo") for path in schema["paths"]))
