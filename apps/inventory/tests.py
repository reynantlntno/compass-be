from datetime import timedelta
import json
from types import MappingProxyType, SimpleNamespace

from django.test import Client, SimpleTestCase, TestCase
from django.utils import timezone as dj_timezone

from apps.access_control.capabilities import Capability
from apps.access_control.choices import GrantReasonCode, ScopeMode
from apps.access_control.models import CounselorCoverage, WorkflowAuthorityGrant
from apps.accounts.models import RoleChoices, User
from apps.account_security.api_tokens import issue_token_pair
from apps.common.exceptions import (
    PermissionDeniedError,
    StaleStateError,
    ValidationError,
    WorkflowError,
)
from apps.inventory import queries as inventory_queries
from apps.inventory.commands import (
    InventoryDraftCommand,
    InventoryDraftCreateCommand,
    InventoryReopenCommand,
    InventorySubmitCommand,
)
from apps.inventory.models import (
    InventoryStatusChoices,
    StudentInventorySnapshot,
)
from apps.inventory.projections import project_history_event, project_staff_snapshot
from apps.inventory.selectors import (
    get_current_inventory_snapshot,
    get_latest_guidance_inventory,
    get_latest_submitted_inventory,
)
from apps.inventory.services import (
    get_or_create_current_inventory_draft,
    reopen_inventory_for_correction,
    save_inventory_draft,
    submit_inventory_snapshot,
)
from apps.profiles.models import CounselorProfile, StudentProfile


def _student(email, *, active=True, superuser=False):
    actor = User.objects.create_user(
        email=email,
        password="correct-horse-battery-staple",
        role=RoleChoices.STUDENT,
        is_active=active,
    )
    if superuser:
        actor.is_superuser = True
        actor.save(update_fields=["is_superuser"])
    return actor


class InventoryOwnerSelectorTests(TestCase):
    def setUp(self):
        self.owner = _student("inventory-owner@example.test")
        self.owner_profile = StudentProfile.objects.create(
            user=self.owner,
            campus="Main Campus",
            college="CCMS",
        )
        self.other = _student("inventory-other@example.test")
        self.other_profile = StudentProfile.objects.create(
            user=self.other,
            campus="Main Campus",
            college="CCMS",
        )
        self.snapshot = StudentInventorySnapshot.objects.create(
            student_profile=self.owner_profile,
            academic_year="2025-2026",
            status=InventoryStatusChoices.SUBMITTED,
            data={"safe": True},
        )

    def test_status_selectors_require_active_exact_owner(self):
        self.assertEqual(
            get_current_inventory_snapshot(
                self.owner, self.owner_profile, "2025-2026"
            ).pk,
            self.snapshot.pk,
        )
        self.assertEqual(
            get_latest_submitted_inventory(self.owner, self.owner_profile).pk,
            self.snapshot.pk,
        )
        self.assertEqual(
            get_latest_guidance_inventory(self.owner, self.owner_profile).pk,
            self.snapshot.pk,
        )
        self.assertIsNone(
            get_current_inventory_snapshot(
                self.other, self.owner_profile, "2025-2026"
            )
        )
        self.assertIsNone(get_latest_submitted_inventory(self.other, self.owner_profile))

    def test_inactive_and_legacy_self_access_fail_closed(self):
        inactive = _student("inventory-inactive@example.test", active=False)
        inactive_profile = StudentProfile.objects.create(user=inactive)
        legacy = _student("inventory-legacy@example.test", superuser=True)
        legacy_profile = StudentProfile.objects.create(user=legacy)
        self.assertIsNone(
            get_current_inventory_snapshot(inactive, inactive_profile, "2025-2026")
        )
        self.assertIsNone(get_latest_submitted_inventory(legacy, legacy_profile))


_ANSWERS = {"personal_data": {"completed": True}}


def _enable_test_field_encryption():
    """Point the env key source at the container's FIELD_ENCRYPTION_KEY."""

    from apps.security.models import EncryptionKeyVersion, KeyPurposeChoices, KeyStatusChoices

    exists = EncryptionKeyVersion.objects.filter(
        key_purpose=KeyPurposeChoices.FIELD_ENCRYPTION,
        status=KeyStatusChoices.ACTIVE,
    ).exists()
    if not exists:
        EncryptionKeyVersion.objects.create(
            key_version="test-vertical-v1",
            key_purpose=KeyPurposeChoices.FIELD_ENCRYPTION,
            status=KeyStatusChoices.ACTIVE,
            source_alias="env",
            secret_reference="FIELD_ENCRYPTION_KEY",
            algorithm="Fernet",
        )


class InventoryServiceLifecycleTests(TestCase):
    def setUp(self):
        _enable_test_field_encryption()
        self.owner = _student("inventory-owner2@example.test")
        self.owner_profile = StudentProfile.objects.create(
            user=self.owner, campus="Main Campus", college="CCMS"
        )
        self.other = _student("inventory-other2@example.test")
        StudentProfile.objects.create(user=self.other, campus="Main Campus", college="CCMS")

    def _draft(self):
        return get_or_create_current_inventory_draft(
            self.owner, InventoryDraftCreateCommand("2025-2026")
        )

    def test_owner_can_create_save_and_submit_own_inventory(self):
        draft = self._draft()
        saved = save_inventory_draft(
            self.owner, str(draft.pk), InventoryDraftCommand(_ANSWERS)
        )
        self.assertEqual(saved.data, _ANSWERS)
        submitted = submit_inventory_snapshot(
            self.owner, str(draft.pk), InventorySubmitCommand(privacy_acknowledged=True)
        )
        self.assertEqual(submitted.status, InventoryStatusChoices.SUBMITTED)

    def test_duplicate_draft_creation_is_idempotent(self):
        first = self._draft()
        second = self._draft()
        self.assertEqual(first.pk, second.pk)

    def test_submission_requires_explicit_privacy_acknowledgement(self):
        draft = self._draft()
        with self.assertRaises(ValidationError):
            submit_inventory_snapshot(
                self.owner,
                str(draft.pk),
                InventorySubmitCommand(privacy_acknowledged=False),
            )

    def test_draft_save_rejects_submitted_snapshot(self):
        draft = self._draft()
        submit_inventory_snapshot(self.owner, str(draft.pk), InventorySubmitCommand(True))
        with self.assertRaises(WorkflowError):
            save_inventory_draft(
                self.owner, str(draft.pk), InventoryDraftCommand(_ANSWERS)
            )

    def test_stale_expected_updated_at_is_rejected(self):
        draft = self._draft()
        with self.assertRaises(StaleStateError):
            submit_inventory_snapshot(
                self.owner,
                str(draft.pk),
                InventorySubmitCommand(True, expected_updated_at="2000-01-01T00:00:00+00:00"),
            )

    def test_non_owner_student_receives_no_data(self):
        draft = self._draft()
        with self.assertRaises(PermissionDeniedError):
            save_inventory_draft(
                self.other, str(draft.pk), InventoryDraftCommand(_ANSWERS)
            )
        with self.assertRaises(PermissionDeniedError):
            submit_inventory_snapshot(self.other, str(draft.pk), InventorySubmitCommand(True))

    def test_inactive_and_legacy_superusers_fail_closed(self):
        inactive = _student("inventory-inactive2@example.test", active=False)
        StudentProfile.objects.create(user=inactive)
        legacy = _student("inventory-legacy2@example.test", superuser=True)
        StudentProfile.objects.create(user=legacy)
        for actor in (inactive, legacy):
            with self.assertRaises(PermissionDeniedError):
                get_or_create_current_inventory_draft(
                    actor, InventoryDraftCreateCommand("2025-2026")
                )


class InventoryApiContractTests(TestCase):
    def setUp(self):
        _enable_test_field_encryption()
        self.client = Client()
        self.student = _student("inventory-api-owner@example.test")
        self.profile = StudentProfile.objects.create(
            user=self.student,
            campus="Main Campus",
            college="CCMS",
        )
        self.token = issue_token_pair(self.student, assurance_verified=True).access_token

    def _headers(self, key=None):
        return {
            "HTTP_AUTHORIZATION": f"Bearer {self.token}",
            "HTTP_IDEMPOTENCY_KEY": key or "inventory-api-draft-1",
        }

    def test_draft_route_uses_shared_contract_and_replays_safely(self):
        response = self.client.post(
            "/api/v1/inventory/drafts/",
            data=json.dumps({"academic_year": "2025-2026"}),
            content_type="application/json",
            **self._headers(),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertIsNotNone(response["X-Request-ID"])
        payload = response.json()
        self.assertEqual(set(payload), {"snapshot_id", "academic_year", "status"})
        self.assertEqual(payload["academic_year"], "2025-2026")
        self.assertNotIn("data", payload)
        self.assertNotIn("data_encrypted", payload)
        self.assertNotIn("expected_updated_at", payload)

        replay = self.client.post(
            "/api/v1/inventory/drafts/",
            data=json.dumps({"academic_year": "2025-2026"}),
            content_type="application/json",
            **self._headers(),
        )
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.json(), payload)

    def test_mutation_without_idempotency_key_is_validation_error(self):
        response = self.client.post(
            "/api/v1/inventory/drafts/",
            data=json.dumps({"academic_year": "2025-2026"}),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()["code"], "validation")

    def test_detail_and_history_routes_return_typed_projection_pages(self):
        created = self.client.post(
            "/api/v1/inventory/drafts/",
            data=json.dumps({"academic_year": "2025-2026"}),
            content_type="application/json",
            **self._headers("inventory-api-detail-1"),
        )
        self.assertEqual(created.status_code, 200)
        snapshot_id = created.json()["snapshot_id"]

        auth_headers = {"HTTP_AUTHORIZATION": f"Bearer {self.token}"}
        detail = self.client.get(
            f"/api/v1/inventory/{snapshot_id}/",
            **auth_headers,
        )
        self.assertEqual(detail.status_code, 200)
        detail_payload = detail.json()
        self.assertEqual(detail_payload["snapshot_id"], snapshot_id)
        self.assertEqual(detail_payload["answers"], {})
        self.assertNotIn("data_encrypted", detail_payload)
        self.assertNotIn("expected_updated_at", detail_payload)

        history = self.client.get(
            f"/api/v1/inventory/{snapshot_id}/history/",
            **auth_headers,
        )
        self.assertEqual(history.status_code, 200)
        self.assertEqual(
            set(history.json()),
            {"items", "page", "page_size", "total"},
        )
        self.assertEqual(history.json()["items"], [])


class InventoryCommandValidationTests(SimpleTestCase):
    def test_answer_object_must_be_exact_dict(self):
        with self.assertRaises(ValidationError):
            InventoryDraftCommand(MappingProxyType({"personal_data": {}}))
        with self.assertRaises(ValidationError):
            InventoryDraftCommand([("personal_data", {})])
        with self.assertRaises(ValidationError):
            InventoryDraftCommand("personal_data")

    def test_unknown_sections_models_and_cycles_are_rejected(self):
        with self.assertRaises(ValidationError):
            InventoryDraftCommand({"unknown_section": {"a": 1}})
        with self.assertRaises(ValidationError):
            InventoryDraftCommand({"personal_data": SimpleNamespace(bad=True)})
        cyclic = {}
        cyclic["personal_data"] = cyclic
        with self.assertRaises(ValidationError):
            InventoryDraftCommand(cyclic)

    def test_commands_are_frozen_and_reject_unknown_fields(self):
        command = InventoryDraftCreateCommand(" 2025-2026 ")
        self.assertEqual(command.academic_year, "2025-2026")
        with self.assertRaises(TypeError):
            InventoryDraftCreateCommand("2025-2026", student_profile_id="1")
        with self.assertRaises(ValidationError):
            InventoryReopenCommand(reason="short")


class InventoryConfidentialityAccessTests(TestCase):
    def setUp(self):
        _enable_test_field_encryption()
        self.owner = _student("inventory-conf-owner@example.test")
        self.owner_profile = StudentProfile.objects.create(
            user=self.owner, campus="Main Campus", college="CCMS"
        )
        answers = {"personal_data": {"safe": "value"}}
        self.submitted = StudentInventorySnapshot.objects.create(
            student_profile=self.owner_profile,
            academic_year="2025-2026",
            status=InventoryStatusChoices.SUBMITTED,
            data=answers,
            data_encrypted=answers,
            reopen_reason="",
            reopen_reason_encrypted="",
            correction_notes="",
            correction_notes_encrypted="",
        )
        self.draft = StudentInventorySnapshot.objects.create(
            student_profile=self.owner_profile,
            academic_year="2024-2025",
            status=InventoryStatusChoices.DRAFT,
            data=answers,
            data_encrypted=answers,
            reopen_reason="",
            reopen_reason_encrypted="",
            correction_notes="",
            correction_notes_encrypted="",
        )
        self.counselor = User.objects.create_user(
            email="inventory-counselor@example.test",
            password="correct-horse-battery-staple",
            role=RoleChoices.COUNSELOR,
            is_active=True,
        )
        CounselorCoverage.objects.create(
            counselor=self.counselor, college="CCMS", starts_at=dj_timezone.localdate()
        )
        self.out_of_scope = User.objects.create_user(
            email="inventory-outside@example.test",
            password="correct-horse-battery-staple",
            role=RoleChoices.COUNSELOR,
            is_active=True,
        )
        CounselorCoverage.objects.create(
            counselor=self.out_of_scope, college="Biology", starts_at=dj_timezone.localdate()
        )

    def test_owner_detail_includes_current_answers(self):
        detail = inventory_queries.snapshot_detail(self.owner, str(self.submitted.pk))
        self.assertEqual(detail["snapshot_id"], str(self.submitted.pk))
        self.assertIn("answers", detail)
        self.assertEqual(detail["answers"], {"personal_data": {"safe": "value"}})

    def test_scoped_counselor_sees_submitted_answers_only(self):
        detail = inventory_queries.snapshot_detail(self.counselor, str(self.submitted.pk))
        self.assertEqual(detail["snapshot_id"], str(self.submitted.pk))
        self.assertIn("answers", detail)
        draft_detail = inventory_queries.snapshot_detail(self.counselor, str(self.draft.pk))
        self.assertNotIn("answers", draft_detail)
        page = inventory_queries.scoped_snapshot_page(self.counselor)
        self.assertEqual(page["total"], 1)
        self.assertEqual(page["items"][0]["status"], InventoryStatusChoices.SUBMITTED)

    def test_out_of_scope_counselor_is_denied_everywhere(self):
        self.assertIsNone(
            inventory_queries.snapshot_detail(self.out_of_scope, str(self.submitted.pk))
        )
        page = inventory_queries.scoped_snapshot_page(self.out_of_scope)
        self.assertEqual(page["total"], 0)

    def test_gco_staff_it_admin_and_legacy_users_get_nothing(self):
        staff = User.objects.create_user(
            email="inventory-gco@example.test",
            password="correct-horse-battery-staple",
            role=RoleChoices.GCO_STAFF,
        )
        it_admin = User.objects.create_user(
            email="inventory-it@example.test",
            password="correct-horse-battery-staple",
            role=RoleChoices.IT_ADMIN,
        )
        legacy = _student("inventory-conf-legacy@example.test", superuser=True)
        for actor in (staff, it_admin, legacy):
            self.assertEqual(inventory_queries.scoped_snapshot_page(actor)["total"], 0)
            self.assertIsNone(
                inventory_queries.snapshot_detail(actor, str(self.submitted.pk))
            )

    def test_history_projection_never_carries_payloads_or_narratives(self):
        from apps.inventory.models import StudentInventoryStatusHistory

        sample = StudentInventoryStatusHistory(
            id=42,
            snapshot=self.submitted,
            from_status="",
            to_status=InventoryStatusChoices.SUBMITTED,
            submission_sequence=1,
            is_baseline=True,
            schema_version="2.1.0",
        )
        projected = project_history_event(sample)
        self.assertEqual(
            set(projected),
            {
                "history_id",
                "status_from",
                "status_to",
                "transitioned_at",
                "submission_sequence",
                "is_baseline",
                "schema_version",
            },
        )
        self.assertEqual(projected["history_id"], "42")
        self.assertNotIn("reason_encrypted", projected)
        self.assertNotIn("submitted_data_encrypted", projected)

    def test_staff_projection_keys_exclude_secret_fields(self):
        payload = project_staff_snapshot(self.draft)
        for forbidden in (
            "data",
            "data_encrypted",
            "reopen_reason",
            "reopen_reason_encrypted",
            "correction_notes_encrypted",
            "answers",
        ):
            self.assertNotIn(forbidden, payload)


class InventoryReopenAuthorityTests(TestCase):
    def setUp(self):
        _enable_test_field_encryption()
        self.owner = _student("inventory-reopen-owner@example.test")
        self.owner_profile = StudentProfile.objects.create(
            user=self.owner, campus="Main Campus", college="CCMS"
        )
        answers = {"personal_data": {"safe": "value"}}
        self.snapshot = StudentInventorySnapshot.objects.create(
            student_profile=self.owner_profile,
            academic_year="2025-2026",
            status=InventoryStatusChoices.SUBMITTED,
            data=answers,
            data_encrypted=answers,
            reopen_reason="",
            reopen_reason_encrypted="",
            correction_notes="",
            correction_notes_encrypted="",
        )
        self.head = User.objects.create_user(
            email="inventory-reopen-head@example.test",
            password="correct-horse-battery-staple",
            role=RoleChoices.COUNSELOR,
            is_active=True,
        )
        CounselorProfile.objects.create(user=self.head, is_head_guidance=True)
        self.counselor = User.objects.create_user(
            email="inventory-reopen-counselor@example.test",
            password="correct-horse-battery-staple",
            role=RoleChoices.COUNSELOR,
            is_active=True,
        )
        CounselorCoverage.objects.create(
            counselor=self.counselor, college="CCMS", starts_at=dj_timezone.localdate()
        )
        WorkflowAuthorityGrant.objects.create(
            grantee=self.counselor,
            capability=Capability.INVENTORY_CORRECTION_REVIEW.value,
            scope_mode=ScopeMode.COUNSELOR_COVERAGE.value,
            college="CCMS",
            valid_from=dj_timezone.localdate(),
            valid_until=dj_timezone.localdate() + timedelta(days=30),
            granted_by=self.head,
            grant_reason_code=GrantReasonCode.LOCAL_WORKFLOW,
        )

    def test_head_guidance_fixed_authority_can_reopen(self):
        reason = "Please clarify the household income section before finalizing."
        reopened = reopen_inventory_for_correction(
            self.head,
            str(self.snapshot.pk),
            InventoryReopenCommand(reason=reason),
        )
        self.assertEqual(reopened.status, InventoryStatusChoices.REOPENED_FOR_CORRECTION)
        correction_rows = list(reopened.status_history.all())
        # Legacy submitted snapshots without a baseline history receive the
        # immutable baseline before the correction transition is recorded.
        self.assertEqual(len(correction_rows), 2)
        correction_row = next(
            row for row in correction_rows
            if row.to_status == InventoryStatusChoices.REOPENED_FOR_CORRECTION
        )
        # The operational reason is stored encrypted on the history row only.
        self.assertEqual(correction_row.reason_encrypted, reason)
        # Reopened answer bodies remain owner-only for staff readers.
        detail = inventory_queries.snapshot_detail(self.counselor, str(self.snapshot.pk))
        self.assertNotIn("answers", detail)

    def test_scoped_counselor_with_grant_can_reopen(self):
        reopened = reopen_inventory_for_correction(
            self.counselor,
            str(self.snapshot.pk),
            InventoryReopenCommand(reason="Please verify the disability support response."),
        )
        self.assertEqual(reopened.status, InventoryStatusChoices.REOPENED_FOR_CORRECTION)

    def test_counselor_without_grant_is_denied(self):
        no_grant = User.objects.create_user(
            email="inventory-nogrant@example.test",
            password="correct-horse-battery-staple",
            role=RoleChoices.COUNSELOR,
            is_active=True,
        )
        CounselorCoverage.objects.create(
            counselor=no_grant, college="CCMS", starts_at=dj_timezone.localdate()
        )
        with self.assertRaises(PermissionDeniedError):
            reopen_inventory_for_correction(
                no_grant,
                str(self.snapshot.pk),
                InventoryReopenCommand(reason="Please confirm the living conditions entry."),
            )

    def test_student_cannot_reopen(self):
        with self.assertRaises(PermissionDeniedError):
            reopen_inventory_for_correction(
                self.owner,
                str(self.snapshot.pk),
                InventoryReopenCommand(reason="Student requested reopening of the record."),
            )
