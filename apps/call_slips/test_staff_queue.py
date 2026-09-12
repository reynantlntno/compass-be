"""Staff Call Slips workspace queue tests."""

from django.test import Client, TestCase
from django.utils import timezone

from apps.account_security.api_tokens import issue_token_pair
from apps.accounts.models import RoleChoices, User


class CallSlipStaffQueueTests(TestCase):
    """Scope, allowlists, filters, HTTP contract for the Call Slips queue."""

    def setUp(self):
        from apps.access_control.models import CounselorCoverage
        from apps.profiles.models import StudentProfile

        self.client = Client()
        self.student = User.objects.create_user(
            email="call-slip-queue-student@example.test",
            password="correct-horse-battery-staple",
            first_name="Slip",
            last_name="Student",
            role=RoleChoices.STUDENT,
            is_active=True,
        )
        StudentProfile.objects.create(
            user=self.student,
            student_number="2026-0100",
            college="CCMS",
            campus="Main Campus",
        )
        self.counselor = User.objects.create_user(
            email="call-slip-queue-counselor@example.test",
            password="correct-horse-battery-staple",
            role=RoleChoices.COUNSELOR,
            is_active=True,
        )
        CounselorCoverage.objects.create(
            counselor=self.counselor, college="CCMS", starts_at=timezone.localdate()
        )
        self.out_of_scope = User.objects.create_user(
            email="call-slip-queue-outside@example.test",
            password="correct-horse-battery-staple",
            role=RoleChoices.COUNSELOR,
            is_active=True,
        )
        CounselorCoverage.objects.create(
            counselor=self.out_of_scope, college="Biology", starts_at=timezone.localdate()
        )

        from apps.call_slips.models import (
            CallSlip,
            CallSlipDestinationChoices,
            CallSlipPurposeCodeChoices,
            CallSlipSourceTypeChoices,
            CallSlipStatusChoices,
        )
        from apps.referrals.models import (
            Referral,
            ReferralReasonCategoryChoices,
            ReferralSourceTypeChoices,
            ReferralStatusChoices,
        )

        self.referral = Referral.objects.create(
            reference_code="REF-AY2526-000200",
            student=self.student,
            source_type=ReferralSourceTypeChoices.FACULTY,
            reason_text="Private referral narrative",
            reason_category_code=ReferralReasonCategoryChoices.PERSONAL_OR_SOCIAL,
            course_snapshot="BS Information Technology",
            year_level_snapshot="2",
            block_snapshot="B",
            submitted_at=timezone.now(),
            submitted_by=self.counselor,
            received_at=timezone.now(),
            received_by=self.counselor,
            status=ReferralStatusChoices.RECEIVED,
            created_by=self.counselor,
            updated_by=self.counselor,
            creation_request_key="call-slip-queue-referral-1",
        )
        self.slip = CallSlip.objects.create(
            reference_code="CSL-AY2526-000001",
            student=self.student,
            referral=self.referral,
            source_type=CallSlipSourceTypeChoices.REFERRAL,
            purpose_code=CallSlipPurposeCodeChoices.GUIDANCE_INTERVIEW,
            destination_code=CallSlipDestinationChoices.GUIDANCE_OFFICE,
            report_to_destination="Guidance Office",
            mode="ONSITE",
            status=CallSlipStatusChoices.DRAFT,
            created_by=self.counselor,
            updated_by=self.counselor,
            creation_request_key="call-slip-queue-create-1",
        )
        self.headers = {
            "HTTP_AUTHORIZATION": f"Bearer {issue_token_pair(self.counselor, assurance_verified=True).access_token}"
        }

    def test_queue_rows_are_scoped_and_projection_is_allowlisted(self):
        from apps.call_slips import queue as call_slips_queue
        from apps.common.contracts import PageRequest

        page = call_slips_queue.queue_page(
            self.counselor, PageRequest(page=1, page_size=20)
        )
        self.assertEqual(page["total"], 1)
        row = page["items"][0]
        self.assertEqual(
            set(row),
            {
                "reference_code",
                "student_display_name",
                "student_number",
                "source_type",
                "source_type_label",
                "purpose_code",
                "purpose_label",
                "mode_code",
                "mode_label",
                "destination_code",
                "destination_label",
                "status",
                "status_label",
                "assignment_state",
                "schedule_bucket",
                "scheduled_start_at",
                "scheduled_end_at",
                "referral_reference",
                "appointment_reference",
                "issued_at",
                "acknowledged_at",
                "created_at",
                "updated_at",
            },
        )
        for forbidden in (
            "id",
            "office_only_remarks",
            "office_only_remarks_encrypted",
            "student_safe_instructions",
            "email",
            "cancellation_detail",
            "no_show_detail",
        ):
            self.assertNotIn(forbidden, row)
        self.assertEqual(row["referral_reference"], "REF-AY2526-000200")
        self.assertIsNone(row["appointment_reference"])
        self.assertEqual(
            call_slips_queue.queue_page(
                self.out_of_scope, PageRequest(page=1, page_size=20)
            )["total"],
            0,
        )

    def test_queue_filters_and_student_is_empty(self):
        from apps.call_slips import queue as call_slips_queue
        from apps.common.contracts import PageRequest
        from apps.common.exceptions import ValidationError

        self.assertEqual(
            call_slips_queue.queue_page(
                self.counselor, PageRequest(page=1, page_size=20), query="2026-0100"
            )["total"],
            1,
        )
        self.assertEqual(
            call_slips_queue.queue_page(
                self.counselor, PageRequest(page=1, page_size=20),
                academic_year="2025-2026",
            )["total"],
            1,
        )
        self.assertEqual(
            call_slips_queue.queue_page(
                self.counselor, PageRequest(page=1, page_size=20),
                purpose_codes="GUIDANCE_INTERVIEW",
            )["total"],
            1,
        )
        self.assertEqual(
            call_slips_queue.queue_page(
                self.counselor, PageRequest(page=1, page_size=20),
                mode_codes="ONLINE",
            )["total"],
            0,
        )
        with self.assertRaises(ValidationError):
            call_slips_queue.queue_page(
                self.counselor, PageRequest(page=1, page_size=20), statuses="UNKNOWN_STATUS"
            )

        student_page = self.client.get(
            "/api/v1/call-slips/queue/",
            HTTP_AUTHORIZATION=f"Bearer {issue_token_pair(self.student, assurance_verified=True).access_token}",
        )
        self.assertEqual(student_page.status_code, 200, student_page.content[:2000])
        self.assertEqual(student_page.json()["total"], 0)

    def test_queue_http_endpoint_returns_typed_staff_page(self):
        response = self.client.get("/api/v1/call-slips/queue/", **self.headers)
        self.assertEqual(response.status_code, 200, response.content)
        payload = response.json()
        self.assertEqual(set(payload), {"items", "page", "page_size", "total"})
        self.assertEqual(payload["total"], 1)
        self.assertEqual(payload["items"][0]["referral_reference"], "REF-AY2526-000200")