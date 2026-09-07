"""Focused authority tests for the separated Good Moral workflow."""

import uuid
from datetime import date, timedelta
from decimal import Decimal
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth.models import AnonymousUser
from django.test import Client, SimpleTestCase, TestCase
from django.utils import timezone

from apps.account_security.api_tokens import issue_token_pair
from apps.accounts.models import RoleChoices, User
from apps.access_control.capabilities import Capability
from apps.access_control.choices import GrantReasonCode, ScopeMode
from apps.access_control.models import CounselorCoverage, WorkflowAuthorityGrant
from apps.good_moral.models import (
    GoodMoralRequest,
    GoodMoralStatusChoices,
    RequestTypeChoices,
    ReceiptStatusChoices,
    DrySealStatusChoices,
    DrySealConfirmationMethodChoices,
)
from apps.documents.workflow_api import GeneratedDocumentMetadataSchema
from apps.good_moral import projections
from apps.good_moral.api import (
    GoodMoralMutationResponseSchema,
    GoodMoralPageResultSchema,
    GoodMoralRequestSchema,
)
from apps.good_moral.policies import (
    can_create_request,
    can_cancel_request,
    can_encode_receipt_metadata,
    can_verify_receipt_metadata,
    can_submit_request,
    can_approve_request,
    can_assign_reviewer,
    can_generate_request_document,
    can_confirm_dry_seal,
    can_mark_printed,
    can_read_generated_certificate_content,
    can_release_request,
    can_reject_request,
    can_start_review,
    can_view_request,
    can_view_review_queue,
    can_void_request,
)
from apps.good_moral.document_services import GoodMoralGenerationError, _good_moral_template_key
from apps.good_moral.lifecycle import GoodMoralVariantError, derive_request_type, validate_request_variant
from apps.good_moral.exit_prerequisite import NOT_APPLICABLE, evaluate_exit_prerequisite
from apps.common.policy import PolicyChangeRequest
from apps.governance.policy_lifecycle import ensure_active_policy_for_target
from apps.good_moral.services import (
    GoodMoralPolicyError,
    GoodMoralServiceError,
    _approve_request as approve_request,
    _assign_reviewer as assign_reviewer,
    _generate_certificate_document as generate_certificate_document,
    _release_certificate as release_certificate,
    _start_review as start_review,
    _confirm_dry_seal as confirm_dry_seal,
    _update_receipt_metadata as update_receipt_metadata,
    _verify_receipt_metadata as verify_receipt_metadata,
    _create_draft as create_draft,
)
from apps.profiles.models import CounselorProfile, StudentLifecycleChoices, StudentProfile


def _build_user(email, role, *, is_active=True, is_superuser=False):
    return User.objects.create_user(
        email=email,
        password="correct-horse-battery-staple",
        first_name="Test",
        last_name="User",
        role=role,
        is_active=is_active,
    )


def _counselor(email, *, is_active=True, is_head=False, is_superuser=False):
    actor = _build_user(
        email,
        RoleChoices.COUNSELOR,
        is_active=is_active,
    )
    if is_superuser:
        actor.is_superuser = True
        actor.save(update_fields=["is_superuser"])
    CounselorProfile.objects.create(user=actor, is_head_guidance=is_head)
    return actor


class GoodMoralResponseContractTests(SimpleTestCase):
    def setUp(self):
        self.today = timezone.localdate()
        self.now = timezone.now()
        self.document = SimpleNamespace(
            reference_code="GMC-2026-000001",
            document_status="RELEASED",
            generated_at=self.now,
            released_at=self.now,
            protected_file=SimpleNamespace(content_type="application/pdf"),
            template_version=SimpleNamespace(
                version_label="v1",
                output_format="PDF",
                template=SimpleNamespace(stable_key="good_moral_certificate"),
            ),
        )
        self.request = SimpleNamespace(
            reference_code="GMC-2026-000001",
            request_type="STUDENT",
            status="RELEASED",
            requester_user_id=uuid.uuid4(),
            student_profile_id=uuid.uuid4(),
            applicant_display_name="Test Student",
            applicant_lifecycle_status="GRADUATED",
            applicant_campus="Main Campus",
            applicant_college="CCMS",
            applicant_department="Guidance",
            applicant_program_degree="BS Psychology",
            applicant_year_level="4",
            applicant_academic_year="2025-2026",
            applicant_graduation_date=self.today,
            applicant_major="must not be projected",
            applicant_semester="must not be projected",
            purpose_text="Employment application",
            receipt_status="VERIFIED",
            official_receipt_number="OR-SECRET",
            official_receipt_date=self.today,
            official_receipt_amount=Decimal("100.00"),
            receipt_encoded_by_id=uuid.uuid4(),
            receipt_verified_by_id=uuid.uuid4(),
            receipt_rejection_code="must not be projected",
            ossd_verification_status="VERIFIED",
            assigned_reviewer_id=uuid.uuid4(),
            reviewed_by_id=uuid.uuid4(),
            approved_by_id=uuid.uuid4(),
            approval_signatory_name="must not be projected",
            approval_signatory_title="must not be projected",
            approved_at=self.now,
            generated_at=self.now,
            generated_by_id=uuid.uuid4(),
            generation_failure_code="must not be projected",
            printed_at=self.now,
            printed_by_id=uuid.uuid4(),
            released_at=self.now,
            released_by_id=uuid.uuid4(),
            dry_seal_status="SEALED",
            dry_seal_confirmation_method="STUDENT_ATTESTED",
            dry_seal_confirmed_by_id=uuid.uuid4(),
            office_only_note="must not be projected",
            hold_rejection_reason_code="must not be projected",
            generated_document=self.document,
            created_at=self.now,
            updated_at=self.now,
            metadata_json={"must_not": "projected"},
            reason_code="must not be projected",
            note="must not be projected",
            expected_updated_at="must not be projected",
        )

    def test_student_and_staff_projections_match_one_explicit_output_superset(self):
        student = projections.student_request_projection(
            SimpleNamespace(**{**vars(self.request), "generated_document": None})
        )
        self.assertEqual(
            set(student),
            {
                "reference_code",
                "request_type",
                "status",
                "applicant_lifecycle_status",
                "applicant_academic_year",
                "applicant_graduation_date",
                "purpose_text",
                "receipt_status",
                "dry_seal_status",
                "dry_seal_confirmation_method",
                "generated_document",
                "created_at",
                "updated_at",
            },
        )
        student_schema = GoodMoralRequestSchema(**student)
        self.assertEqual(student_schema.purpose_text, "Employment application")
        self.assertNotIn("applicant_display_name", student)
        self.assertNotIn("ossd_verification_status", student)

        staff = projections.staff_request_projection(self.request)
        self.assertEqual(
            set(staff),
            {
                "reference_code",
                "request_type",
                "status",
                "applicant_display_name",
                "applicant_lifecycle_status",
                "applicant_campus",
                "applicant_college",
                "applicant_department",
                "applicant_program_degree",
                "applicant_year_level",
                "applicant_academic_year",
                "applicant_graduation_date",
                "receipt_status",
                "ossd_verification_status",
                "approved_at",
                "generated_at",
                "printed_at",
                "released_at",
                "dry_seal_status",
                "dry_seal_confirmation_method",
                "generated_document",
                "created_at",
                "updated_at",
            },
        )
        staff_schema = GoodMoralRequestSchema(**staff)
        self.assertEqual(staff_schema.applicant_display_name, "Test Student")
        self.assertIsNotNone(staff_schema.generated_document)

        GoodMoralPageResultSchema(items=[student, staff], page=1, page_size=25, total=2)
        self.assertEqual(
            GeneratedDocumentMetadataSchema(**staff["generated_document"]).template_key,
            "good_moral_certificate",
        )

    def test_mutation_projection_is_bounded_and_replay_safe(self):
        mutation = projections.mutation_result(self.request)
        self.assertEqual(
            set(mutation),
            {
                "reference_code",
                "status",
                "receipt_status",
                "dry_seal_status",
                "updated_at",
            },
        )
        result = GoodMoralMutationResponseSchema(**mutation)
        self.assertEqual(result.reference_code, "GMC-2026-000001")

    def test_outputs_exclude_receipt_actor_office_and_request_fields(self):
        outputs = (
            projections.student_request_projection(
                SimpleNamespace(**{**vars(self.request), "generated_document": None})
            ),
            projections.staff_request_projection(self.request),
            projections.mutation_result(self.request),
            projections.document_projection(self.document),
        )
        forbidden = {
            "official_receipt_number",
            "official_receipt_date",
            "official_receipt_amount",
            "receipt_encoded_by",
            "receipt_encoded_by_id",
            "receipt_verified_by",
            "receipt_verified_by_id",
            "receipt_rejection_code",
            "assigned_reviewer",
            "assigned_reviewer_id",
            "reviewed_by",
            "reviewed_by_id",
            "approved_by",
            "approved_by_id",
            "approval_signatory_name",
            "approval_signatory_title",
            "generated_by",
            "generated_by_id",
            "generation_failure_code",
            "printed_by",
            "printed_by_id",
            "released_by",
            "released_by_id",
            "dry_seal_confirmed_by",
            "dry_seal_confirmed_by_id",
            "office_only_note",
            "hold_rejection_reason_code",
            "metadata_json",
            "reason_code",
            "note",
            "expected_updated_at",
            "requester_user_id",
            "student_profile_id",
        }
        for output in outputs:
            with self.subTest(output=output):
                self.assertTrue(forbidden.isdisjoint(output))


class GoodMoralApiResponseTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = _build_user("good-moral-contract-student@example.test", RoleChoices.STUDENT)
        StudentProfile.objects.create(
            user=self.user,
            lifecycle_status=StudentLifecycleChoices.ACTIVE,
            campus="Main Campus",
            college="CCMS",
            program="BS Psychology",
        )
        self.token = issue_token_pair(self.user, assurance_verified=True).access_token

    def test_empty_student_page_validates_at_api_boundary(self):
        response = self.client.get(
            "/api/v1/good-moral/",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )
        self.assertEqual(response.status_code, 200, response.content)
        GoodMoralPageResultSchema(**response.json())


class GoodMoralAuthorityTests(TestCase):
    """A reviewer can validate; issuance remains explicitly operational."""

    def setUp(self):
        self.today = timezone.localdate()
        self.student = _build_user("good-moral-student@example.test", RoleChoices.STUDENT)
        self.student_profile = StudentProfile.objects.create(
            user=self.student,
            campus="Main Campus",
            college="CCMS",
            department="Guidance",
            program="BS Psychology",
        )
        self.counselor = _counselor("good-moral-counselor@example.test")
        CounselorCoverage.objects.create(
            counselor=self.counselor,
            campus="Main Campus",
            college="CCMS",
            starts_at=self.today,
        )
        self.outside_counselor = _counselor("good-moral-outside@example.test")
        self.head = _counselor("good-moral-head@example.test", is_head=True)
        self.gco_staff = _build_user("good-moral-gco@example.test", RoleChoices.GCO_STAFF)
        self.it_admin = _build_user("good-moral-it@example.test", RoleChoices.IT_ADMIN)
        self.inactive_counselor = _counselor(
            "good-moral-inactive@example.test", is_active=False
        )
        self.legacy_counselor = _counselor(
            "good-moral-legacy@example.test", is_superuser=True
        )
        self.gco_grants = [WorkflowAuthorityGrant.objects.create(
            grantee=self.gco_staff, capability=capability.value,
            scope_mode=ScopeMode.EXPLICIT_ORGANIZATION.value,
            campus="Main Campus", college="CCMS", valid_from=self.today,
            valid_until=self.today + timedelta(days=365),
            granted_by=self.head, grant_reason_code=GrantReasonCode.LOCAL_WORKFLOW.value,
        ) for capability in (
            Capability.GOOD_MORAL_DOCUMENT_GENERATE,
            Capability.GOOD_MORAL_PRINT,
            Capability.GOOD_MORAL_REGISTRAR_SEAL_CONFIRM,
            Capability.GOOD_MORAL_RELEASE,
            Capability.GOOD_MORAL_RECEIPT_ENCODE,
            Capability.GOOD_MORAL_RECEIPT_VERIFY,
        )]
        self.request = self._request()

    def _request(self, *, reference_code="GMC-TEST-000001", status=None):
        return GoodMoralRequest.objects.create(
            reference_code=reference_code,
            request_type=RequestTypeChoices.STUDENT,
            requester_user=self.student,
            student_profile=self.student_profile,
            applicant_display_name="Test User",
            applicant_lifecycle_status="ACTIVE",
            applicant_campus="Main Campus",
            applicant_college="CCMS",
            applicant_department="Guidance",
            applicant_program_degree="BS Psychology",
            applicant_year_level="4",
            applicant_academic_year="2025-2026",
            purpose_text="Employment application",
            status=status or GoodMoralStatusChoices.PAYMENT_ENCODED,
            receipt_status=ReceiptStatusChoices.VERIFIED,
        )

    def test_student_owns_visibility_but_not_office_actions(self):
        self.assertTrue(can_view_request(self.student, self.request))
        self.assertFalse(can_approve_request(self.student, self.request))
        self.assertFalse(can_generate_request_document(self.student, self.request))
        self.request.status = GoodMoralStatusChoices.PRINTED
        self.request.generated_document_id = uuid.uuid4()
        self.assertFalse(can_release_request(self.student, self.request))

    def test_creation_is_target_scoped_not_role_only(self):
        self.assertTrue(
            can_create_request(
                self.counselor,
                self.student_profile,
                requester_user=self.student,
            )
        )
        self.assertFalse(
            can_create_request(
                self.outside_counselor,
                self.student_profile,
                requester_user=self.student,
            )
        )
        unassigned_staff = _build_user(
            "good-moral-create-unassigned@example.test", RoleChoices.GCO_STAFF
        )
        self.assertFalse(
            can_create_request(
                unassigned_staff,
                self.student_profile,
                requester_user=self.student,
            )
        )

        other_student = _build_user(
            "good-moral-other-student@example.test", RoleChoices.STUDENT
        )
        other_profile = StudentProfile.objects.create(
            user=other_student,
            campus="Main Campus",
            college="CCMS",
        )
        self.assertFalse(
            can_create_request(
                self.student,
                other_profile,
                requester_user=self.student,
            )
        )

    def test_submission_is_target_scoped_for_counselors(self):
        self.request.status = GoodMoralStatusChoices.DRAFT
        self.assertTrue(can_submit_request(self.counselor, self.request))
        self.assertFalse(can_submit_request(self.outside_counselor, self.request))

    def test_unassigned_counselor_cannot_self_claim_or_issue(self):
        self.assertFalse(can_view_request(self.counselor, self.request))
        self.assertFalse(can_start_review(self.counselor, self.request))
        self.assertFalse(can_approve_request(self.counselor, self.request))
        self.assertFalse(can_generate_request_document(self.counselor, self.request))
        self.assertFalse(can_release_request(self.counselor, self.request))

    def test_cancellation_requires_the_named_operational_authority(self):
        self.assertFalse(can_cancel_request(self.counselor, self.request))
        self.assertFalse(can_cancel_request(self.gco_staff, self.request))

    def test_head_assigns_reviewer_and_reviewer_is_scoped_to_coverage(self):
        assigned = assign_reviewer(self.head, self.request, self.counselor)
        self.assertEqual(assigned.assigned_reviewer_id, self.counselor.pk)
        self.request.refresh_from_db()
        self.assertTrue(can_view_request(self.counselor, self.request))
        self.assertTrue(can_start_review(self.counselor, self.request))
        self.assertTrue(can_reject_request(self.counselor, self.request))
        self.assertFalse(can_approve_request(self.counselor, self.request))
        self.assertFalse(can_generate_request_document(self.counselor, self.request))
        self.assertFalse(can_mark_printed(self.counselor, self.request))
        self.assertFalse(can_confirm_dry_seal(self.counselor, self.request))
        self.assertFalse(can_release_request(self.counselor, self.request))

    def test_reviewer_assignment_rejects_out_of_scope_regular_counselor(self):
        self.assertFalse(can_assign_reviewer(self.head, self.request, self.outside_counselor))
        with self.assertRaises(GoodMoralPolicyError):
            assign_reviewer(self.head, self.request, self.outside_counselor)

    def test_head_has_fixed_approval_and_document_fallback_authority(self):
        self.request.status = GoodMoralStatusChoices.FOR_APPROVAL
        self.assertTrue(can_approve_request(self.head, self.request))
        self.request.status = GoodMoralStatusChoices.GENERATED
        self.assertTrue(can_void_request(self.head, self.request))
        self.assertTrue(can_mark_printed(self.head, self.request))
        self.request.status = GoodMoralStatusChoices.PRINTED
        self.request.generated_document_id = uuid.uuid4()
        self.assertTrue(can_release_request(self.head, self.request))

    def test_gco_document_assignment_is_the_only_issuance_path(self):
        self.request.status = GoodMoralStatusChoices.APPROVED_FOR_GENERATION
        self.assertTrue(can_generate_request_document(self.gco_staff, self.request))
        self.request.status = GoodMoralStatusChoices.GENERATED
        self.assertTrue(can_mark_printed(self.gco_staff, self.request))
        self.request.status = GoodMoralStatusChoices.PRINTED
        self.assertFalse(can_confirm_dry_seal(self.gco_staff, self.request))
        self.request.status = GoodMoralStatusChoices.PRINTED
        self.request.generated_document_id = uuid.uuid4()
        self.assertTrue(can_release_request(self.gco_staff, self.request))

        unassigned = _build_user("good-moral-gco-unassigned@example.test", RoleChoices.GCO_STAFF)
        self.assertFalse(can_generate_request_document(unassigned, self.request))
        self.assertFalse(can_release_request(unassigned, self.request))

    def test_linked_gco_staff_does_not_inherit_head_or_counselor_authority(self):
        WorkflowAuthorityGrant.objects.create(
            grantee=self.gco_staff, capability=Capability.GOOD_MORAL_DOCUMENT_GENERATE.value,
            scope_mode=ScopeMode.EXPLICIT_ORGANIZATION.value, campus="Main Campus", college="CCMS",
            valid_from=self.today, valid_until=self.today + timedelta(days=365),
            granted_by=self.head,
            grant_reason_code=GrantReasonCode.LOCAL_WORKFLOW.value,
        )
        self.request.status = GoodMoralStatusChoices.FOR_APPROVAL
        self.assertFalse(can_approve_request(self.gco_staff, self.request))
        self.assertFalse(can_start_review(self.gco_staff, self.request))

    def test_it_admin_has_no_good_moral_business_authority(self):
        actions = (
            can_view_request,
            can_start_review,
            can_approve_request,
            can_generate_request_document,
            can_release_request,
        )
        for action in actions:
            with self.subTest(action=action.__name__):
                self.assertFalse(action(self.it_admin, self.request))
        self.assertFalse(can_view_review_queue(self.it_admin))

    def test_inactive_and_legacy_superuser_accounts_fail_closed(self):
        for actor in (
            AnonymousUser(),
            self.inactive_counselor,
            self.legacy_counselor,
        ):
            with self.subTest(actor=repr(actor)):
                self.assertFalse(can_view_request(actor, self.request))
                self.assertFalse(can_start_review(actor, self.request))
                self.assertFalse(can_approve_request(actor, self.request))
                self.assertFalse(can_generate_request_document(actor, self.request))
                self.assertFalse(can_release_request(actor, self.request))

    def test_assigned_reviewer_cannot_approve_or_release_by_direct_service_call(self):
        assign_reviewer(self.head, self.request, self.counselor)
        self.request.status = GoodMoralStatusChoices.FOR_APPROVAL
        self.request.save(update_fields=["status", "updated_at"])
        with self.assertRaises(GoodMoralPolicyError):
            approve_request(
                self.counselor,
                self.request,
                signatory_name="Test Signatory",
                signatory_title="Head Guidance",
            )

        self.request.status = GoodMoralStatusChoices.PRINTED
        self.request.save(update_fields=["status", "updated_at"])
        with self.assertRaises(GoodMoralPolicyError):
            release_certificate(self.counselor, self.request)

    def test_generation_service_denies_counselor_before_rendering(self):
        assign_reviewer(self.head, self.request, self.counselor)
        self.request.status = GoodMoralStatusChoices.APPROVED_FOR_GENERATION
        self.request.save(update_fields=["status", "updated_at"])
        with self.assertRaises(GoodMoralGenerationError):
            generate_certificate_document(self.counselor, self.request)

    def test_permitted_gco_release_path_reaches_document_service(self):
        request = self._request(
            reference_code="GMC-TEST-000002",
            status=GoodMoralStatusChoices.PRINTED,
        )
        request.generated_document_id = uuid.uuid4()

        # The policy is the authority gate; the downstream document and
        # notification effects are isolated here to prove the permitted
        # operational assignment is what allows the service to proceed.
        request_proxy = mock.Mock()
        request_proxy.pk = request.pk
        request_proxy.reference_code = request.reference_code
        request_proxy.status = GoodMoralStatusChoices.PRINTED
        request_proxy.generated_document_id = request.generated_document_id
        request_proxy.generated_document = mock.Mock()
        request_proxy.student_profile = self.student_profile
        request_proxy.assigned_reviewer = None
        request_proxy.request_type = RequestTypeChoices.STUDENT
        request_proxy.applicant_lifecycle_status = "ACTIVE"
        request_proxy.receipt_status = ReceiptStatusChoices.VERIFIED
        request_proxy.dry_seal_status = "PENDING"
        request_proxy.dry_seal_confirmation_method = ""
        request_proxy.dry_seal_confirmed_by_id = None
        request_proxy.dry_seal_confirmed_at = None
        request_proxy.ossd_verification_status = "NOT_REQUIRED"
        request_proxy.save = mock.Mock()

        with (
            mock.patch("apps.good_moral.services.GoodMoralRequest.objects.select_for_update") as lock,
            mock.patch("apps.good_moral.services.release_document_for_composition"),
            mock.patch("apps.good_moral.services._audit_transition"),
            mock.patch("apps.good_moral.services.issue_feedback_invitation_for_completed_source"),
            mock.patch("apps.good_moral.notification_services.enqueue_good_moral_event"),
            mock.patch("apps.good_moral.exit_prerequisite.enforce_exit_prerequisite"),
        ):
            lock.return_value.get.return_value = request_proxy
            result = release_certificate(self.gco_staff, request)

        self.assertIs(result, request_proxy)
        self.assertEqual(request_proxy.status, GoodMoralStatusChoices.RELEASED)
        request_proxy.save.assert_called_once()

    def test_receipt_encoding_and_verification_are_separate_authorities(self):
        self.request.status = GoodMoralStatusChoices.FOR_PAYMENT
        self.request.receipt_status = ReceiptStatusChoices.PENDING
        self.request.save(update_fields=["status", "receipt_status", "updated_at"])

        self.assertTrue(can_encode_receipt_metadata(self.head, self.request))
        self.assertFalse(can_verify_receipt_metadata(self.head, self.request))

        verification_only = _build_user(
            "good-moral-verify-only@example.test", RoleChoices.GCO_STAFF
        )
        WorkflowAuthorityGrant.objects.create(
            grantee=verification_only,
            capability=Capability.GOOD_MORAL_RECEIPT_VERIFY.value,
            scope_mode=ScopeMode.EXPLICIT_ORGANIZATION.value,
            campus="Main Campus",
            college="CCMS",
            valid_from=self.today,
            valid_until=self.today + timedelta(days=365),
            granted_by=self.head,
            grant_reason_code=GrantReasonCode.LOCAL_WORKFLOW.value,
        )

        update_receipt_metadata(
            self.head,
            self.request,
            receipt_number="OR-123",
            receipt_date=self.today,
            receipt_amount="100.00",
        )
        self.request.refresh_from_db()
        self.assertFalse(can_encode_receipt_metadata(verification_only, self.request))
        self.assertTrue(can_verify_receipt_metadata(verification_only, self.request))

    def test_processing_actions_require_verified_receipt(self):
        self.request.receipt_status = ReceiptStatusChoices.PENDING
        self.request.status = GoodMoralStatusChoices.FOR_APPROVAL
        self.assertFalse(can_approve_request(self.head, self.request))
        self.request.status = GoodMoralStatusChoices.APPROVED_FOR_GENERATION
        self.assertFalse(can_generate_request_document(self.gco_staff, self.request))

    def test_student_confirms_external_seal_and_duplicate_preserves_provenance(self):
        self.request.status = GoodMoralStatusChoices.RELEASED
        self.request.dry_seal_status = DrySealStatusChoices.PENDING
        self.request.save(update_fields=["status", "dry_seal_status", "updated_at"])

        self.assertTrue(can_confirm_dry_seal(self.student, self.request))
        confirmed = confirm_dry_seal(self.student, self.request)
        self.assertEqual(confirmed.dry_seal_status, DrySealStatusChoices.SEALED)
        self.assertEqual(
            confirmed.dry_seal_confirmation_method,
            DrySealConfirmationMethodChoices.STUDENT_ATTESTED,
        )
        original_confirmed_at = confirmed.dry_seal_confirmed_at
        with self.assertRaises(GoodMoralServiceError):
            confirm_dry_seal(self.student, confirmed)
        confirmed.refresh_from_db()
        self.assertEqual(confirmed.dry_seal_confirmed_at, original_confirmed_at)
        self.assertEqual(confirmed.dry_seal_confirmed_by_id, self.student.pk)

    def test_scoped_counselor_and_gco_staff_can_record_external_confirmation(self):
        counselor_grant = WorkflowAuthorityGrant.objects.create(
            grantee=self.counselor,
            capability=Capability.GOOD_MORAL_REGISTRAR_SEAL_CONFIRM.value,
            scope_mode=ScopeMode.COUNSELOR_COVERAGE.value,
            valid_from=self.today,
            valid_until=self.today + timedelta(days=365),
            granted_by=self.head,
            grant_reason_code=GrantReasonCode.LOCAL_WORKFLOW.value,
        )
        self.assertIsNotNone(counselor_grant.pk)

        counselor_request = self._request(reference_code="GMC-TEST-000003", status=GoodMoralStatusChoices.RELEASED)
        self.assertTrue(can_confirm_dry_seal(self.counselor, counselor_request))
        confirm_dry_seal(self.counselor, counselor_request)
        counselor_request.refresh_from_db()
        self.assertEqual(
            counselor_request.dry_seal_confirmation_method,
            DrySealConfirmationMethodChoices.COUNSELOR_RECORDED,
        )

        gco_request = self._request(reference_code="GMC-TEST-000004", status=GoodMoralStatusChoices.RELEASED)
        self.assertTrue(can_confirm_dry_seal(self.gco_staff, gco_request))
        confirm_dry_seal(self.gco_staff, gco_request)
        gco_request.refresh_from_db()
        self.assertEqual(
            gco_request.dry_seal_confirmation_method,
            DrySealConfirmationMethodChoices.GCO_STAFF_RECORDED,
        )

    def test_confirmation_is_target_scoped_and_fails_closed(self):
        self.request.status = GoodMoralStatusChoices.RELEASED
        self.request.save(update_fields=["status", "updated_at"])
        for actor in (
            self.outside_counselor,
            self.inactive_counselor,
            self.legacy_counselor,
            self.it_admin,
            AnonymousUser(),
        ):
            with self.subTest(actor=repr(actor)):
                self.assertFalse(can_confirm_dry_seal(actor, self.request))

    def test_old_dry_seal_capability_and_lifecycle_symbols_are_absent(self):
        self.assertFalse(hasattr(Capability, "GOOD_MORAL_DRY_SEAL"))
        self.assertFalse(hasattr(__import__("apps.good_moral.policies", fromlist=["*"]), "can_mark_dry_sealed"))
        self.assertFalse(hasattr(__import__("apps.good_moral.services", fromlist=["*"]), "mark_ready_for_release"))


class GoodMoralLifecycleVariantTests(TestCase):
    def setUp(self):
        self.student = _build_user("good-moral-lifecycle@example.test", RoleChoices.STUDENT)
        self.profile = StudentProfile.objects.create(
            user=self.student,
            lifecycle_status=StudentLifecycleChoices.ACTIVE,
            campus="Main Campus",
            college="CCMS",
        )

    def _request(self, *, lifecycle, request_type, graduation_date=None):
        return GoodMoralRequest.objects.create(
            reference_code=f"GMC-LIFE-{uuid.uuid4().hex[:8]}",
            request_type=request_type,
            requester_user=self.student,
            student_profile=self.profile,
            applicant_display_name="Lifecycle Student",
            applicant_lifecycle_status=lifecycle,
            applicant_campus="Main Campus",
            applicant_college="CCMS",
            applicant_academic_year="2025-2026",
            applicant_graduation_date=graduation_date,
            purpose_text="Employment",
        )

    def test_lifecycle_derives_student_and_graduate_variants(self):
        self.assertEqual(derive_request_type(self.profile), RequestTypeChoices.STUDENT)
        self.profile.lifecycle_status = StudentLifecycleChoices.GRADUATING
        self.assertEqual(derive_request_type(self.profile), RequestTypeChoices.STUDENT)
        self.profile.lifecycle_status = StudentLifecycleChoices.GRADUATED
        self.assertEqual(derive_request_type(self.profile), RequestTypeChoices.GRADUATE)
        self.profile.lifecycle_status = StudentLifecycleChoices.ALUMNI
        self.assertEqual(derive_request_type(self.profile), RequestTypeChoices.GRADUATE)

    def test_invalid_lifecycle_cannot_derive_a_new_request_variant(self):
        self.profile.lifecycle_status = StudentLifecycleChoices.TRANSFERRED
        with self.assertRaises(GoodMoralVariantError):
            derive_request_type(self.profile)

    def test_persisted_mismatch_fails_closed_without_rewriting_the_snapshot(self):
        request = self._request(
            lifecycle=StudentLifecycleChoices.GRADUATED,
            request_type=RequestTypeChoices.STUDENT,
            graduation_date=timezone.localdate(),
        )
        with self.assertRaises(GoodMoralVariantError):
            validate_request_variant(request)
        with self.assertRaises(GoodMoralGenerationError):
            _good_moral_template_key(request)
        request.refresh_from_db()
        self.assertEqual(request.request_type, RequestTypeChoices.STUDENT)

    def test_graduate_variant_requires_a_graduation_date(self):
        request = self._request(
            lifecycle=StudentLifecycleChoices.ALUMNI,
            request_type=RequestTypeChoices.GRADUATE,
        )
        with self.assertRaises(GoodMoralVariantError):
            validate_request_variant(request)

    @mock.patch("apps.good_moral.services.generate_good_moral_reference_code", return_value="GMC-LIFE-CREATED")
    def test_create_draft_derives_variant_and_rejects_missing_graduation_date(self, _reference):
        request = create_draft(
            actor=self.student,
            requester_user=self.student,
            purpose_text="Employment",
            student_profile=self.profile,
            academic_year="2025-2026",
        )
        self.assertEqual(request.request_type, RequestTypeChoices.STUDENT)
        self.profile.lifecycle_status = StudentLifecycleChoices.ALUMNI
        with self.assertRaises(GoodMoralServiceError):
            create_draft(
                actor=self.student,
                requester_user=self.student,
                purpose_text="Employment",
                student_profile=self.profile,
                academic_year="2026-2027",
            )


class GoodMoralExitPrerequisiteScopeTests(TestCase):
    def setUp(self):
        self.student = _build_user("good-moral-exit-scope@example.test", RoleChoices.STUDENT)
        self.profile = StudentProfile.objects.create(
            user=self.student,
            lifecycle_status=StudentLifecycleChoices.GRADUATING,
            campus="Main Campus",
            college="CCMS",
        )
        ensure_active_policy_for_target(
            None,
            PolicyChangeRequest(
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
                    "decision_record_reference": "GCO-EXIT-2026",
                },
                effective_from=timezone.now(),
                source_reference="GCO-EXIT-2026",
            ),
            system_context=True,
        )

    def _request(self, *, lifecycle, request_type, year):
        return GoodMoralRequest.objects.create(
            reference_code=f"GMC-EXIT-{uuid.uuid4().hex[:8]}",
            request_type=request_type,
            requester_user=self.student,
            student_profile=self.profile,
            applicant_display_name="Exit Student",
            applicant_lifecycle_status=lifecycle,
            applicant_campus="Main Campus",
            applicant_college="CCMS",
            applicant_academic_year="2025-2026",
            applicant_graduation_date=date(year, 5, 1),
            purpose_text="Employment",
        )

    def test_only_current_graduating_cohort_is_subject_to_the_gate(self):
        current = self._request(
            lifecycle=StudentLifecycleChoices.GRADUATING,
            request_type=RequestTypeChoices.STUDENT,
            year=2026,
        )
        self.assertNotEqual(evaluate_exit_prerequisite(current).status, NOT_APPLICABLE)

        older = self._request(
            lifecycle=StudentLifecycleChoices.GRADUATING,
            request_type=RequestTypeChoices.STUDENT,
            year=2025,
        )
        self.assertEqual(evaluate_exit_prerequisite(older).status, NOT_APPLICABLE)

        graduate = self._request(
            lifecycle=StudentLifecycleChoices.GRADUATED,
            request_type=RequestTypeChoices.GRADUATE,
            year=2026,
        )
        self.assertEqual(evaluate_exit_prerequisite(graduate).status, NOT_APPLICABLE)
