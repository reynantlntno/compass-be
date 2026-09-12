"""Staff Referrals workspace queue and intake-search tests."""

from django.test import Client, TestCase
from django.utils import timezone

from apps.account_security.api_tokens import issue_token_pair
from apps.accounts.models import RoleChoices, User


class ReferralStaffQueueTests(TestCase):
    """Scope, allowlists, filters, HTTP contract, and intake search."""

    def setUp(self):
        from apps.access_control.models import CounselorCoverage
        from apps.profiles.models import StudentProfile

        self.client = Client()
        self.student = User.objects.create_user(
            email="referral-queue-student@example.test",
            password="correct-horse-battery-staple",
            first_name="Queue",
            last_name="Student",
            role=RoleChoices.STUDENT,
            is_active=True,
        )
        StudentProfile.objects.create(
            user=self.student,
            student_number="2026-0099",
            college="CCMS",
            campus="Main Campus",
        )
        self.counselor = User.objects.create_user(
            email="referral-queue-counselor@example.test",
            password="correct-horse-battery-staple",
            role=RoleChoices.COUNSELOR,
            is_active=True,
        )
        CounselorCoverage.objects.create(
            counselor=self.counselor, college="CCMS", starts_at=timezone.localdate()
        )
        self.out_of_scope = User.objects.create_user(
            email="referral-queue-outside@example.test",
            password="correct-horse-battery-staple",
            role=RoleChoices.COUNSELOR,
            is_active=True,
        )
        CounselorCoverage.objects.create(
            counselor=self.out_of_scope, college="Biology", starts_at=timezone.localdate()
        )

        from apps.referrals.models import (
            Referral,
            ReferralReasonCategoryChoices,
            ReferralSourceTypeChoices,
            ReferralStatusChoices,
        )

        self.referral = Referral.objects.create(
            reference_code="REF-AY2526-000123",
            student=self.student,
            source_type=ReferralSourceTypeChoices.FACULTY,
            reason_text="Private referral narrative",
            reason_category_code=ReferralReasonCategoryChoices.ACADEMIC,
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
            creation_request_key="referral-queue-create-1",
        )
        self.headers = {
            "HTTP_AUTHORIZATION": f"Bearer {issue_token_pair(self.counselor, assurance_verified=True).access_token}"
        }

    def test_queue_rows_are_scoped_and_projection_is_allowlisted(self):
        from apps.access_control.models import CounselorCoverage
        from apps.common.contracts import PageRequest
        from apps.referrals import queue as referrals_queue

        page = referrals_queue.queue_page(
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
                "student_block_snapshot",
                "source_type",
                "source_type_label",
                "reason_category",
                "reason_category_label",
                "status",
                "status_label",
                "assignment_state",
                "age_bucket",
                "received_at",
                "created_at",
                "updated_at",
                "has_active_call_slip",
                "active_call_slip_reference",
                "can_prepare_call_slip",
                "is_terminal",
            },
        )
        for forbidden in (
            "id",
            "reason_text",
            "reason_text_encrypted",
            "email",
            "referrer_display_snapshot",
        ):
            self.assertNotIn(forbidden, row)
        self.assertTrue(row["can_prepare_call_slip"])
        self.assertFalse(row["has_active_call_slip"])

        out_of_scope_counselor = User.objects.create_user(
            email="referral-queue-outside2@example.test",
            password="correct-horse-battery-staple",
            role=RoleChoices.COUNSELOR,
            is_active=True,
        )
        CounselorCoverage.objects.create(
            counselor=out_of_scope_counselor, college="CCMS Other", starts_at=timezone.localdate()
        )
        self.assertEqual(
            referrals_queue.queue_page(out_of_scope_counselor, PageRequest(page=1, page_size=20))["total"],
            0,
        )

    def test_queue_filters_and_search_never_match_sensitive_fields(self):
        from apps.common.contracts import PageRequest
        from apps.common.exceptions import ValidationError
        from apps.referrals import queue as referrals_queue
        from apps.referrals.models import ReferralStatusChoices

        self.assertEqual(
            referrals_queue.queue_page(
                self.counselor, PageRequest(page=1, page_size=20), query="2026-0099"
            )["total"],
            1,
        )
        self.assertEqual(
            referrals_queue.queue_page(
                self.counselor,
                PageRequest(page=1, page_size=20),
                query="referral-queue-student@example.test",
            )["total"],
            0,
        )
        self.assertEqual(
            referrals_queue.queue_page(
                self.counselor,
                PageRequest(page=1, page_size=20),
                query="Private referral narrative",
            )["total"],
            0,
        )
        self.assertEqual(
            referrals_queue.queue_page(
                self.counselor, PageRequest(page=1, page_size=20),
                academic_year="2025-2026",
            )["total"],
            1,
        )
        self.assertEqual(
            referrals_queue.queue_page(
                self.counselor,
                PageRequest(page=1, page_size=20),
                statuses=ReferralStatusChoices.DRAFT,
            )["total"],
            0,
        )
        self.assertEqual(
            referrals_queue.queue_page(
                self.counselor, PageRequest(page=1, page_size=20), assignment="mine"
            )["total"],
            0,
        )
        self.assertEqual(
            referrals_queue.queue_page(
                self.counselor, PageRequest(page=1, page_size=20), assignment="unassigned"
            )["total"],
            1,
        )
        with self.assertRaises(ValidationError):
            referrals_queue.queue_page(
                self.counselor, PageRequest(page=1, page_size=20), academic_year="not-a-year"
            )

    def test_queue_http_endpoint_returns_typed_staff_page(self):
        response = self.client.get("/api/v1/referrals/queue/", **self.headers)
        self.assertEqual(response.status_code, 200, response.content)
        payload = response.json()
        self.assertEqual(set(payload), {"items", "page", "page_size", "total"})
        self.assertEqual(payload["total"], 1)

    def test_staff_intake_student_search_is_scoped(self):
        from apps.profiles.selectors import select_staff_intake_students

        self.assertEqual(select_staff_intake_students(self.counselor).count(), 1)
        self.assertEqual(select_staff_intake_students(self.out_of_scope).count(), 0)
        student_token = issue_token_pair(self.student, assurance_verified=True).access_token
        student_page = self.client.get(
            "/api/v1/profiles/staff-students/",
            HTTP_AUTHORIZATION=f"Bearer {student_token}",
        )
        self.assertEqual(student_page.status_code, 200)
        self.assertEqual(student_page.json()["total"], 0)