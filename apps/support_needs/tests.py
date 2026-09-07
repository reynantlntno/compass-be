# Project: COMPASS
# File: apps/support_needs/tests.py
# Module: apps.support_needs
# Purpose: Focused tests for the support-support_need aggregate suppression
#          boundary (contract boundary).  Small verified counts are suppressed with the
#          canonical SUPPRESSION_LABEL, unverified records are excluded, and
#          non-counselors are denied.

import json

from apps.access_control.capabilities import Capability
from apps.access_control.choices import GrantReasonCode, ScopeMode
from apps.access_control.models import WorkflowAuthorityGrant
from apps.account_security.api_tokens import issue_token_pair
from apps.common.exceptions import PermissionDeniedError, ValidationError
from django.test import Client, TestCase
from django.utils import timezone

from apps.accounts.models import RoleChoices, User
from apps.access_control.models import CounselorCoverage
from apps.profiles.models import CounselorProfile, StudentProfile
from apps.reports.suppression import MIN_SUPPRESSION_THRESHOLD, SUPPRESSION_LABEL
from apps.support_needs.choices import (
    SupportNeedCategory,
    SupportNeedSourceType,
    SupportNeedStatus,
)
from apps.support_needs.api import (
    SupportNeedMutationResponseSchema,
    SupportNeedPageSchema,
    SupportNeedProjectionSchema,
    SupportNeedTypePageSchema,
    SupportNeedTypeSchema,
)
from apps.support_needs.commands import (
    SupportNeedCreateCommand,
    SupportNeedReasonCommand,
    SupportNeedUpdateCommand,
)
from apps.support_needs.models import StudentSupportNeed, SupportNeedType
from apps.support_needs.services import (
    archive_support_need,
    create_support_need,
    mark_support_need_needs_review,
    update_support_need,
    verify_support_need,
)
from apps.support_needs.queries import support_need_aggregate_dataset
from apps.support_needs.projections import (
    project_support_need,
    project_support_need_type,
    replay_support_need,
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


def _verified_support_need(student, support_need_type):
    return StudentSupportNeed.objects.create(
        student_profile=student,
        support_need_type=support_need_type,
        status=SupportNeedStatus.VERIFIED,
        source_type=SupportNeedSourceType.COUNSELOR_STAFF_VERIFICATION,
    )


class SupportNeedAggregateSuppressionTests(TestCase):
    """1..4 verified counts suppress; 5+ stays integer; drafts are excluded."""

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

        self.financial_type = SupportNeedType.objects.create(
            key="financial-aid",
            label="Financial Aid",
            category=SupportNeedCategory.FINANCIAL_CONTEXT,
            is_active=True,
        )
        self.disability_type = SupportNeedType.objects.create(
            key="disability-support",
            label="Disability Support",
            category=SupportNeedCategory.DISABILITY_SUPPORT,
            is_active=True,
        )

        # (student, support_need_type) is DB-unique for non-inventory records, so
        # one support_need per student yields distinct, in-scope group sizes.
        self.small_students = [
            _build_student(email=f"ccms-{index}@example.test", college="CCMS")
            for index in range(MIN_SUPPRESSION_THRESHOLD - 1)
        ]
        self.large_students = [
            _build_student(email=f"ccms-large-{index}@example.test", college="CCMS")
            for index in range(MIN_SUPPRESSION_THRESHOLD)
        ]

        for student in self.small_students:
            _verified_support_need(student, self.financial_type)
        for student in self.large_students:
            _verified_support_need(student, self.disability_type)

    def _counts_by_key(self, rows):
        return {row["support_need_key"]: row["count"] for row in rows}

    def test_small_nonzero_group_is_suppressed_not_zero(self):
        rows = support_need_aggregate_dataset(self.counselor)
        counts = self._counts_by_key(rows)
        self.assertEqual(counts[self.financial_type.key], SUPPRESSION_LABEL)

    def test_threshold_group_remains_integer_count(self):
        rows = support_need_aggregate_dataset(self.counselor)
        counts = self._counts_by_key(rows)
        self.assertEqual(counts[self.disability_type.key], MIN_SUPPRESSION_THRESHOLD)
        self.assertIsInstance(counts[self.disability_type.key], int)

    def test_unverified_records_are_excluded(self):
        # A draft support_need for another (student, type) pair is excluded
        # entirely: the aggregate is verified-only, so no draft group exists.
        draft_student = _build_student(email="ccms-draft@example.test", college="CCMS")
        StudentSupportNeed.objects.create(
            student_profile=draft_student,
            support_need_type=self.disability_type,
            status=SupportNeedStatus.DRAFT,
            source_type=SupportNeedSourceType.COUNSELOR_STAFF_VERIFICATION,
        )
        rows = support_need_aggregate_dataset(self.counselor)
        counts = self._counts_by_key(rows)
        self.assertEqual(counts[self.disability_type.key], MIN_SUPPRESSION_THRESHOLD)

    def test_out_of_scope_records_never_inflate_scope_counts(self):
        # Distinct out-of-scope students keep (student, type) DB-unique while
        # proving a Biology cohort never enters the CCMS coverage slice.
        for index in range(MIN_SUPPRESSION_THRESHOLD):
            out_of_scope = _build_student(
                email=f"bio-large-{index}@example.test", college="Biology"
            )
            _verified_support_need(out_of_scope, self.disability_type)
        rows = support_need_aggregate_dataset(self.counselor)
        counts = self._counts_by_key(rows)
        self.assertEqual(counts[self.disability_type.key], MIN_SUPPRESSION_THRESHOLD)

    def test_no_scope_counselor_is_denied(self):
        # Student support needs require an explicit scope: a counselor without
        # live coverage has no visible students and is denied the aggregate.
        with self.assertRaises(PermissionDeniedError):
            support_need_aggregate_dataset(self.no_scope_counselor)

    def test_gco_staff_is_denied(self):
        # support_needs.scope grants no Student Support Needs workflow scope to GCO Staff.
        with self.assertRaises(PermissionDeniedError):
            support_need_aggregate_dataset(self.staff)


class SupportNeedServiceLifecycleTests(TestCase):
    def setUp(self):
        from apps.inventory.tests import _enable_test_field_encryption

        _enable_test_field_encryption()
        from datetime import timedelta

        self.head = _build_user(email="sn-head@example.test", role=RoleChoices.COUNSELOR)
        CounselorProfile.objects.create(user=self.head, is_head_guidance=True)
        self.counselor = _build_user(
            email="sn-counselor@example.test", role=RoleChoices.COUNSELOR
        )
        CounselorCoverage.objects.create(
            counselor=self.counselor,
            college="CCMS",
            starts_at=timezone.localdate(),
        )
        for actor, capability in (
            (self.counselor, Capability.SUPPORT_NEEDS_VERIFY),
            (self.counselor, Capability.SUPPORT_NEEDS_DISPUTE),
            (self.counselor, Capability.SUPPORT_NEEDS_ARCHIVE),
        ):
            WorkflowAuthorityGrant.objects.create(
                grantee=actor,
                capability=capability.value,
                scope_mode=ScopeMode.COUNSELOR_COVERAGE.value,
                college="CCMS",
                valid_from=timezone.localdate(),
                valid_until=timezone.localdate() + timedelta(days=30),
                granted_by=self.head,
                grant_reason_code=GrantReasonCode.LOCAL_WORKFLOW,
            )
        self.student = _build_student(email="sn-student@example.test", college="CCMS")
        self.type = SupportNeedType.objects.create(
            key="financial-aid-lc",
            label="Financial Aid",
            category=SupportNeedCategory.FINANCIAL_CONTEXT,
            is_active=True,
        )

    def _create(self, actor=None):
        return create_support_need(
            actor or self.counselor,
            SupportNeedCreateCommand(
                student_profile_id=str(self.student.pk),
                support_need_type_key=self.type.key,
                source_type=SupportNeedSourceType.COUNSELOR_STAFF_VERIFICATION,
                source_snapshot_label="Intake interview",
            ),
        )

    def test_scoped_counselor_create_update_verify_archive_flow(self):
        record = self._create()
        self.assertEqual(record.status, SupportNeedStatus.DRAFT)

        updated = update_support_need(
            self.counselor,
            str(record.pk),
            SupportNeedUpdateCommand(source_snapshot_label="Updated intake"),
        )
        self.assertEqual(updated.source_snapshot_label, "Updated intake")

        verified = verify_support_need(
            self.counselor, str(record.pk), SupportNeedReasonCommand("routine_review")
        )
        self.assertEqual(verified.status, SupportNeedStatus.VERIFIED)
        self.assertEqual(verified.metadata_json.get("review_code"), "routine_review")

        archived = archive_support_need(
            self.counselor, str(record.pk), SupportNeedReasonCommand("retired")
        )
        self.assertEqual(archived.status, SupportNeedStatus.ARCHIVED)

    def test_students_gco_staff_it_and_legacy_are_denied(self):
        student_user = self.student.user
        staff = _build_user(email="sn-staff2@example.test", role=RoleChoices.GCO_STAFF)
        it_admin = _build_user(email="sn-it@example.test", role=RoleChoices.IT_ADMIN)
        legacy = User.objects.create_user(
            email="sn-legacy@example.test",
            password="correct-horse-battery-staple",
            role=RoleChoices.STUDENT,
            is_active=True,
        )
        legacy.is_superuser = True
        legacy.save(update_fields=["is_superuser"])
        for actor in (student_user, staff, it_admin, legacy):
            with self.assertRaises((PermissionDeniedError, ValidationError)):
                self._create(actor)

    def test_manual_creation_cannot_inject_inventory_provenance(self):
        with self.assertRaises(ValidationError):
            create_support_need(
                self.counselor,
                SupportNeedCreateCommand(
                    student_profile_id=str(self.student.pk),
                    support_need_type_key=self.type.key,
                    source_type=SupportNeedSourceType.INDIVIDUAL_INVENTORY,
                ),
            )

    def test_update_command_has_no_reassignment_or_metadata_fields(self):
        with self.assertRaises(TypeError):
            SupportNeedUpdateCommand(student_profile=self.student)
        with self.assertRaises(TypeError):
            SupportNeedUpdateCommand(metadata={"arbitrary": "payload"})
        with self.assertRaises(TypeError):
            SupportNeedUpdateCommand(source_type=SupportNeedSourceType.STUDENT_PROVIDED)

    def test_invalid_reason_codes_fail_closed(self):
        record = self._create()
        with self.assertRaises(ValidationError):
            mark_support_need_needs_review(
                self.counselor,
                str(record.pk),
                SupportNeedReasonCommand("free text excuse"),
            )

    def test_invalid_status_transitions_return_conflicts(self):
        record = self._create()
        archive_support_need(
            self.counselor, str(record.pk), SupportNeedReasonCommand("archived")
        )
        with self.assertRaises(ValidationError):
            update_support_need(
                self.counselor, str(record.pk), SupportNeedUpdateCommand()
            )
        with self.assertRaises(ValidationError):
            archive_support_need(
                self.counselor, str(record.pk), SupportNeedReasonCommand("archived")
            )


class SupportNeedResponseSchemaContractTests(TestCase):
    def setUp(self):
        self.student = _build_student(
            email="sn-contract-student@example.test", college="CCMS"
        )
        self.type = SupportNeedType.objects.create(
            key="contract-financial-aid",
            label="Financial Aid",
            category=SupportNeedCategory.FINANCIAL_CONTEXT,
            is_active=True,
        )
        self.record = StudentSupportNeed.objects.create(
            student_profile=self.student,
            support_need_type=self.type,
            status=SupportNeedStatus.NEEDS_REVIEW,
            source_type=SupportNeedSourceType.COUNSELOR_STAFF_VERIFICATION,
            source_snapshot_label="Contract fixture",
            metadata_json={
                "review_code": "routine_review",
                "needs_review_reason": "inventory_reopened",
                "dispute_reason": "student_disputed",
            },
        )

    def test_type_and_record_projections_match_explicit_schemas(self):
        type_projection = project_support_need_type(self.type)
        self.assertEqual(set(type_projection), {"key", "label", "category", "is_active"})
        self.assertEqual(SupportNeedTypeSchema(**type_projection).key, self.type.key)

        projection = project_support_need(self.record)
        self.assertEqual(
            set(projection),
            {
                "support_need_id",
                "student_profile_id",
                "type_key",
                "type_label",
                "type_category",
                "status",
                "source_type",
                "source_snapshot_label",
                "effective_from",
                "effective_until",
                "review_due_at",
                "verified_at",
                "disputed_at",
                "archived_at",
                "review_code",
                "needs_review_reason",
                "dispute_reason",
            },
        )
        validated = SupportNeedProjectionSchema(**projection)
        self.assertEqual(validated.type_key, self.type.key)
        self.assertEqual(validated.review_code, "routine_review")
        self.assertEqual(validated.needs_review_reason, "inventory_reopened")
        self.assertEqual(validated.dispute_reason, "student_disputed")

        for forbidden in (
            "student_number",
            "control_number",
            "email",
            "phone",
            "actor_user_id",
            "source_app_label",
            "source_model_name",
            "source_object_id",
            "source_inventory_snapshot_id",
            "source_submission_history_id",
            "evidence_summary_json",
            "metadata_json",
            "deactivation_reason",
            "archival_reason",
        ):
            self.assertNotIn(forbidden, projection)

    def test_replay_is_a_bounded_mutation_schema(self):
        replay = replay_support_need(self.record.pk)
        self.assertEqual(set(replay), {"support_need_id", "type_key", "status"})
        validated = SupportNeedMutationResponseSchema(**replay)
        self.assertEqual(validated.support_need_id, str(self.record.pk))
        self.assertIsNone(validated.student_profile_id)

        page = {
            "items": [project_support_need(self.record)],
            "page": 1,
            "page_size": 25,
            "total": 1,
        }
        self.assertEqual(SupportNeedPageSchema(**page).items[0].status, "needs_review")
        type_page = {
            "items": [project_support_need_type(self.type)],
            "page": 1,
            "page_size": 25,
            "total": 1,
        }
        self.assertEqual(SupportNeedTypePageSchema(**type_page).items[0].key, self.type.key)


class SupportNeedApiResponseRuntimeTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.head = _build_user(
            email="sn-api-head@example.test", role=RoleChoices.COUNSELOR
        )
        CounselorProfile.objects.create(user=self.head, is_head_guidance=True)
        self.student = _build_student(
            email="sn-api-student@example.test", college="CCMS"
        )
        self.type = SupportNeedType.objects.create(
            key="api-financial-aid",
            label="Financial Aid",
            category=SupportNeedCategory.FINANCIAL_CONTEXT,
            is_active=True,
        )
        self.head_token = issue_token_pair(
            self.head, assurance_verified=True
        ).access_token

    @staticmethod
    def _json(value):
        return json.dumps(value)

    def _headers(self, token=None, key=None):
        return {
            "HTTP_AUTHORIZATION": f"Bearer {token or self.head_token}",
            "HTTP_IDEMPOTENCY_KEY": key or "support-needs-api-default",
        }

    def test_pages_detail_mutations_and_replay_use_bounded_schemas(self):
        create_response = self.client.post(
            "/api/v1/support-needs/",
            data=self._json(
                {
                    "student_profile_id": str(self.student.pk),
                    "support_need_type_key": self.type.key,
                    "source_type": SupportNeedSourceType.COUNSELOR_STAFF_VERIFICATION,
                    "source_snapshot_label": "API intake",
                    "evidence_summary": {"source_field": "financial_context"},
                }
            ),
            content_type="application/json",
            **self._headers(key="support-needs-api-create"),
        )
        self.assertEqual(create_response.status_code, 200)
        created = create_response.json()
        created_schema = SupportNeedMutationResponseSchema(**created)
        self.assertEqual(created_schema.type_key, self.type.key)
        self.assertNotIn("evidence_summary", created)
        self.assertNotIn("metadata_json", created)
        self.assertNotIn("reason_code", created)

        replay_response = self.client.post(
            "/api/v1/support-needs/",
            data=self._json(
                {
                    "student_profile_id": str(self.student.pk),
                    "support_need_type_key": self.type.key,
                    "source_type": SupportNeedSourceType.COUNSELOR_STAFF_VERIFICATION,
                    "source_snapshot_label": "API intake",
                    "evidence_summary": {"source_field": "financial_context"},
                }
            ),
            content_type="application/json",
            **self._headers(key="support-needs-api-create"),
        )
        self.assertEqual(replay_response.status_code, 200)
        replay = replay_response.json()
        SupportNeedMutationResponseSchema(**replay)
        self.assertEqual(set(replay), {"support_need_id", "type_key", "status"})

        record_id = created_schema.support_need_id
        detail_response = self.client.get(
            f"/api/v1/support-needs/{record_id}/",
            **self._headers(key="support-needs-api-detail"),
        )
        self.assertEqual(detail_response.status_code, 200)
        detail = SupportNeedProjectionSchema(**detail_response.json())
        self.assertEqual(detail.source_snapshot_label, "API intake")

        type_page_response = self.client.get(
            "/api/v1/support-needs/types/",
            **self._headers(key="support-needs-api-types"),
        )
        self.assertEqual(type_page_response.status_code, 200)
        self.assertEqual(
            SupportNeedTypePageSchema(**type_page_response.json()).items[0].key,
            self.type.key,
        )

        list_response = self.client.get(
            "/api/v1/support-needs/",
            **self._headers(key="support-needs-api-list"),
        )
        self.assertEqual(list_response.status_code, 200)
        self.assertTrue(SupportNeedPageSchema(**list_response.json()).items)

        update_response = self.client.patch(
            f"/api/v1/support-needs/{record_id}/",
            data=self._json({"source_snapshot_label": "Updated API intake"}),
            content_type="application/json",
            **self._headers(key="support-needs-api-update"),
        )
        self.assertEqual(update_response.status_code, 200)
        self.assertEqual(
            SupportNeedMutationResponseSchema(**update_response.json()).source_snapshot_label,
            "Updated API intake",
        )

        verify_response = self.client.post(
            f"/api/v1/support-needs/{record_id}/verify/",
            data=self._json({"reason_code": "routine_review"}),
            content_type="application/json",
            **self._headers(key="support-needs-api-verify"),
        )
        self.assertEqual(verify_response.status_code, 200)
        verified = SupportNeedMutationResponseSchema(**verify_response.json())
        self.assertEqual(verified.status, SupportNeedStatus.VERIFIED)
        self.assertEqual(verified.review_code, "routine_review")

        review_response = self.client.post(
            f"/api/v1/support-needs/{record_id}/needs-review/",
            data=self._json({"reason_code": "inventory_reopened"}),
            content_type="application/json",
            **self._headers(key="support-needs-api-review"),
        )
        self.assertEqual(review_response.status_code, 200)
        review = SupportNeedMutationResponseSchema(**review_response.json())
        self.assertEqual(review.status, SupportNeedStatus.NEEDS_REVIEW)
        self.assertEqual(review.needs_review_reason, "inventory_reopened")

        queue_response = self.client.get(
            "/api/v1/support-needs/review-queue/",
            **self._headers(key="support-needs-api-queue"),
        )
        self.assertEqual(queue_response.status_code, 200)
        queue = SupportNeedPageSchema(**queue_response.json())
        self.assertEqual(queue.total, 1)
        self.assertEqual(queue.items[0].support_need_id, record_id)

        dispute_response = self.client.post(
            f"/api/v1/support-needs/{record_id}/dispute/",
            data=self._json({"reason_code": "student_disputed"}),
            content_type="application/json",
            **self._headers(key="support-needs-api-dispute"),
        )
        self.assertEqual(dispute_response.status_code, 200)
        dispute = SupportNeedMutationResponseSchema(**dispute_response.json())
        self.assertEqual(dispute.status, SupportNeedStatus.DISPUTED)
        self.assertEqual(dispute.dispute_reason, "student_disputed")

        archive_response = self.client.post(
            f"/api/v1/support-needs/{record_id}/archive/",
            data=self._json({"reason_code": "retired"}),
            content_type="application/json",
            **self._headers(key="support-needs-api-archive"),
        )
        self.assertEqual(archive_response.status_code, 200)
        archived = SupportNeedMutationResponseSchema(**archive_response.json())
        self.assertEqual(archived.status, SupportNeedStatus.ARCHIVED)
        self.assertNotIn("archival_reason", archive_response.json())

    def test_non_counselor_roles_cannot_read_support_need_payloads(self):
        record = StudentSupportNeed.objects.create(
            student_profile=self.student,
            support_need_type=self.type,
            status=SupportNeedStatus.VERIFIED,
            source_type=SupportNeedSourceType.COUNSELOR_STAFF_VERIFICATION,
        )
        actors = (
            _build_user(email="sn-api-student-reader@example.test", role=RoleChoices.STUDENT),
            _build_user(email="sn-api-staff-reader@example.test", role=RoleChoices.GCO_STAFF),
            _build_user(email="sn-api-it-reader@example.test", role=RoleChoices.IT_ADMIN),
        )
        for actor in actors:
            token = issue_token_pair(actor, assurance_verified=True).access_token
            with self.subTest(role=actor.role):
                response = self.client.get(
                    f"/api/v1/support-needs/{record.pk}/",
                    **self._headers(token=token, key=f"support-needs-denied-{actor.pk}"),
                )
                self.assertEqual(response.status_code, 404)
                self.assertNotIn(self.student.user.email, response.content.decode())


class SupportNeedMaterializationTests(TestCase):
    """Inventory-derived records: idempotent, bounded, orchestration-only."""

    def setUp(self):
        from apps.inventory.tests import _enable_test_field_encryption

        _enable_test_field_encryption()
        self.owner = User.objects.create_user(
            email="sn-mat-owner@example.test",
            password="correct-horse-battery-staple",
            role=RoleChoices.STUDENT,
            is_active=True,
        )
        from apps.profiles.models import StudentProfile as SP

        self.student = SP.objects.create(
            user=self.owner, campus="Main Campus", college="CCMS"
        )
        self.pwd_type = SupportNeedType.objects.create(
            key="pwd_disability",
            label="Disability Support",
            category=SupportNeedCategory.DISABILITY_SUPPORT,
            is_active=True,
        )
        answers = {
            "support_context": {
                "mapping_version": "support-needs-v1",
                "pwd_status": "YES",
                "indigenous_peoples_status": "NO",
            }
        }
        from apps.inventory.models import (
            InventoryStatusChoices,
            StudentInventorySnapshot,
            StudentInventoryStatusHistory,
        )

        self.snapshot = StudentInventorySnapshot.objects.create(
            student_profile=self.student,
            academic_year="2025-2026",
            status=InventoryStatusChoices.SUBMITTED,
            data=answers,
            data_encrypted=answers,
            reopen_reason="",
            reopen_reason_encrypted="",
            correction_notes="",
            correction_notes_encrypted="",
        )
        StudentInventoryStatusHistory.objects.create(
            snapshot=self.snapshot,
            from_status="",
            to_status=InventoryStatusChoices.SUBMITTED,
            actor=self.owner,
            submission_sequence=1,
            is_baseline=True,
            submitted_data_encrypted=answers,
        )

    def _materialize(self):
        from apps.orchestration.commands import InventorySupportNeedsCommand
        from apps.orchestration.use_cases import materialize_support_needs_for_inventory

        return materialize_support_needs_for_inventory(
            self.owner,
            InventorySupportNeedsCommand(str(self.snapshot.pk))
        )

    def test_materialization_is_idempotent_per_snapshot_and_type(self):
        self._materialize()
        self._materialize()
        records = StudentSupportNeed.objects.filter(
            source_inventory_snapshot_id=self.snapshot.pk
        )
        self.assertEqual(records.count(), 1)
        record = records.get()
        self.assertEqual(record.support_need_type_id, self.pwd_type.pk)
        self.assertEqual(record.status, SupportNeedStatus.DRAFT)
        # Bounded evidence only; no raw answer payloads.
        evidence = record.evidence_summary_json or {}
        self.assertEqual(evidence.get("source_section"), "SUPPORT_CONTEXT")
        self.assertNotIn("support_context", evidence)
        self.assertEqual(
            set(record.metadata_json or {}), set()
        )  # system-derived records stay metadata-free

    def test_reopen_marks_derived_records_for_review(self):
        from apps.orchestration.use_cases import mark_inventory_support_needs_for_review

        self._materialize()
        counselor = User.objects.create_user(
            email="sn-mat-counselor@example.test",
            password="correct-horse-battery-staple",
            role=RoleChoices.COUNSELOR,
            is_active=True,
        )
        from apps.access_control.choices import ScopeMode, GrantReasonCode
        from apps.access_control.capabilities import Capability
        from datetime import timedelta

        WorkflowAuthorityGrant.objects.create(
            grantee=counselor,
            capability=Capability.SUPPORT_NEEDS_DISPUTE.value,
            scope_mode=ScopeMode.COUNSELOR_COVERAGE.value,
            college="CCMS",
            valid_from=timezone.localdate(),
            valid_until=timezone.localdate() + timedelta(days=30),
            granted_by=counselor,
            grant_reason_code=GrantReasonCode.LOCAL_WORKFLOW,
        )
        head = User.objects.create_user(
            email="sn-mat-head@example.test",
            password="correct-horse-battery-staple",
            role=RoleChoices.COUNSELOR,
            is_active=True,
        )
        CounselorProfile.objects.create(user=head, is_head_guidance=True)
        from apps.orchestration.commands import InventoryReviewCommand

        updated = mark_inventory_support_needs_for_review(
            head, InventoryReviewCommand(str(self.snapshot.pk))
        )
        self.assertEqual(len(updated), 1)
        self.assertEqual(updated[0].status, SupportNeedStatus.NEEDS_REVIEW)
        self.assertEqual(
            (updated[0].metadata_json or {}).get("needs_review_reason"),
            "inventory_reopened",
        )
