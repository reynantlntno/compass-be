"""Focused command and API-contract tests for the Referral vertical."""

from dataclasses import FrozenInstanceError
from datetime import timedelta
from types import SimpleNamespace
from unittest import mock

from django.test import Client, SimpleTestCase, TestCase
from django.utils import timezone

from apps.call_slips.commands import CallSlipDraftCommand
from apps.account_security.api_tokens import issue_token_pair
from apps.accounts.models import RoleChoices, User
from apps.common.api.idempotency import ApiMutationOutcome
from apps.common.api.operations import get_operation_spec, validate_operation_registry
from apps.common.exceptions import ValidationError
from apps.orchestration.commands import ReferralCallSlipCommand

from .commands import ReferralDraftCommand, ReferralTransitionCommand


class ReferralCommandBoundaryTests(SimpleTestCase):
    def test_commands_are_frozen_and_reject_arbitrary_mappings(self):
        command = ReferralDraftCommand(source_type="FACULTY")
        with self.assertRaises(FrozenInstanceError):
            command.source_type = "OTHER"
        with self.assertRaises(ValidationError):
            ReferralTransitionCommand(reason_code={"unsafe": True})
        with self.assertRaises(ValidationError):
            CallSlipDraftCommand(
                student_id="1",
                source_type="OFFICE_INITIATED",
                purpose_code="OTHER_APPROVED",
                destination_code="GUIDANCE_OFFICE",
                office_only_remarks={"raw": "mapping"},
            )

    def test_cross_domain_command_contains_only_stable_references(self):
        command = ReferralCallSlipCommand(referral_reference="REF-2026-0001")
        self.assertEqual(command.referral_reference, "REF-2026-0001")
        self.assertFalse(hasattr(command, "referral"))

    def test_vertical_operations_are_registered_and_no_store(self):
        self.assertEqual(validate_operation_registry(), [])
        self.assertTrue(get_operation_spec("referrals_create").idempotency_required)
        self.assertTrue(get_operation_spec("call_slips_from_referral").idempotency_required)
        self.assertTrue(get_operation_spec("call_slips_acknowledge").idempotency_required)


class ReferralResponseContractTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.actor = User.objects.create_user(
            email="referral-response@example.test",
            password="correct-horse-battery-staple",
            role=RoleChoices.COUNSELOR,
            is_active=True,
        )
        self.token = issue_token_pair(self.actor, assurance_verified=True).access_token
        self.headers = {"HTTP_AUTHORIZATION": f"Bearer {self.token}"}
        self.now = timezone.now()

    def test_queue_and_detail_keep_nested_output_contracts(self):
        queue = {
            "items": [{
                "reference_code": "REF-2026-0001",
                "status_code": "UNDER_REVIEW",
                "status_label": "Under review",
                "age_bucket": "Today",
                "assignment_state": "Assigned",
                "updated_at": self.now,
            }],
            "page": 1,
            "page_size": 20,
            "total": 1,
        }
        detail = {
            "reference_code": "REF-2026-0001",
            "status": "Under review",
            "student_label": "Student A",
            "source_type": "Faculty",
            "reason_text": "Needs a guidance interview.",
            "reason_category": "Academic",
            "course_snapshot": "BSN",
            "year_level_snapshot": "2",
            "block_snapshot": "B",
            "occurred_at": self.now,
            "source_signed_on": self.now.date(),
            "assignment_state": "Assigned",
            "actions": [{
                "action_code": "INTERVIEW_SCHEDULING_NEEDED",
                "outcome_code": "PENDING",
                "remarks": "Schedule a meeting.",
                "performed_at": self.now,
            }],
            "linked_call_slips": [{
                "reference_code": "CS-2026-0001",
                "status_code": "ISSUED",
                "status_label": "Issued",
                "scheduled_start_at": self.now,
                "scheduled_end_at": self.now + timedelta(minutes=60),
                "issued_at": self.now,
                "acknowledged_at": None,
                "is_issued": True,
                "is_acknowledged": False,
                "is_terminal": False,
                "reissued_from_reference": "",
                "successor_reference": "",
                "permissions": {
                    "update": False,
                    "issue": False,
                    "attendance": True,
                    "no_show": True,
                    "expire": True,
                    "cancel": False,
                    "reissue": False,
                    "print": True,
                },
                "has_successor": False,
            }],
            "field_group_codes": ["REFERRAL-SUBMISSION", "REFERRAL-ACTION"],
        }
        with mock.patch("apps.referrals.queries.scoped_referral_page", return_value=SimpleNamespace(as_dict=lambda: queue)):
            listed = self.client.get("/api/v1/referrals/?page=1&page_size=20", **self.headers)
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(set(listed.json()), set(queue))

        with mock.patch("apps.referrals.queries.referral_detail", return_value=detail):
            response = self.client.get("/api/v1/referrals/REF-2026-0001/", **self.headers)
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(set(payload), set(detail))
        self.assertEqual(set(payload["linked_call_slips"][0]["permissions"]), {
            "update", "issue", "attendance", "no_show", "expire", "cancel", "reissue", "print",
        })
        self.assertNotIn("reason_text_encrypted", payload)
        self.assertNotIn("request_detail", payload)
        self.assertNotIn("referrer_display_snapshot", payload)

    def test_reassignment_detail_keeps_safe_metadata_only(self):
        detail = {
            "id": 11,
            "reference_code": "REF-2026-0002",
            "status": "Pending",
            "request_reason_code": "WORKFLOW_PROGRESSION",
            "has_proposed_counselor": True,
            "created_at": self.now,
        }
        with mock.patch("apps.referrals.queries.reassignment_request_detail", return_value=detail):
            response = self.client.get("/api/v1/referrals/reassignment/11/", **self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.json()), set(detail))
        self.assertNotIn("request_detail", response.json())

    def test_mutation_response_and_idempotent_replay_have_only_stable_fields(self):
        mutation = {
            "reference_code": "REF-2026-0003",
            "status": "CLOSED",
        }
        outcome = ApiMutationOutcome(
            value=mutation,
            related_object=SimpleNamespace(pk="referral-related-1"),
        )
        headers = {
            **self.headers,
            "HTTP_IDEMPOTENCY_KEY": "referral-response-replay-1",
        }
        with (
            mock.patch(
                "apps.referrals.api.close_referral",
                return_value=SimpleNamespace(
                    reference_code=mutation["reference_code"],
                    status=mutation["status"],
                ),
            ) as service,
            mock.patch("apps.referrals.api._outcome", return_value=outcome),
            mock.patch("apps.referrals.queries.replay_by_id", return_value=mutation),
        ):
            response = self.client.post(
                "/api/v1/referrals/REF-2026-0003/close/",
                data={
                    "reason_code": "WORK_COMPLETED",
                    "reason_detail": "Completed",
                },
                content_type="application/json",
                **headers,
            )
            replay = self.client.post(
                "/api/v1/referrals/REF-2026-0003/close/",
                data={
                    "reason_code": "WORK_COMPLETED",
                    "reason_detail": "Completed",
                },
                content_type="application/json",
                **headers,
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(response.json(), mutation)
        self.assertEqual(replay.json(), mutation)
        self.assertEqual(set(response.json()), {"reference_code", "status"})
        service.assert_called_once()
