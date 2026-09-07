"""Focused owner-boundary tests for Call Slip student actions."""

from datetime import timedelta
from types import SimpleNamespace
from unittest import mock

from django.test import Client, TestCase
from django.utils import timezone

from apps.accounts.models import RoleChoices, User
from apps.account_security.api_tokens import issue_token_pair
from apps.common.api.idempotency import ApiMutationOutcome

from .models import CallSlipStatusChoices
from .policies import (
    can_acknowledge_call_slip,
    can_request_reschedule,
    can_student_view_call_slip,
)


def _user(email, *, active=True, superuser=False):
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


class CallSlipStudentOwnerBoundaryTests(TestCase):
    def setUp(self):
        self.owner = _user("call-slip-owner@example.test")
        self.other = _user("call-slip-other@example.test")
        self.slip = SimpleNamespace(
            student_id=self.owner.pk,
            status=CallSlipStatusChoices.ISSUED,
            issued_at=object(),
        )

    def test_student_actions_require_exact_active_owner(self):
        self.assertTrue(can_student_view_call_slip(self.owner, self.slip))
        self.assertTrue(can_acknowledge_call_slip(self.owner, self.slip))
        self.assertTrue(can_request_reschedule(self.owner, self.slip))
        self.assertFalse(can_student_view_call_slip(self.other, self.slip))
        self.assertFalse(can_acknowledge_call_slip(self.other, self.slip))
        self.assertFalse(can_request_reschedule(self.other, self.slip))

    def test_inactive_and_legacy_student_owners_fail_closed(self):
        inactive = _user("call-slip-inactive@example.test", active=False)
        legacy = _user("call-slip-legacy@example.test", superuser=True)
        for actor in (inactive, legacy):
            target = SimpleNamespace(
                student_id=actor.pk,
                status=CallSlipStatusChoices.ISSUED,
                issued_at=object(),
            )
            self.assertFalse(can_student_view_call_slip(actor, target))
            self.assertFalse(can_acknowledge_call_slip(actor, target))
            self.assertFalse(can_request_reschedule(actor, target))


class CallSlipResponseContractTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.actor = _user("call-slip-response@example.test")
        self.token = issue_token_pair(self.actor, assurance_verified=True).access_token
        self.headers = {"HTTP_AUTHORIZATION": f"Bearer {self.token}"}
        self.now = timezone.now()

    def test_queue_and_student_detail_preserve_explicit_output_shapes(self):
        queue = {
            "items": [{
                "reference_code": "CS-2026-0001",
                "status_code": "ISSUED",
                "status_label": "Issued",
                "schedule_bucket": "Today",
                "assignment_state": "Assigned",
                "updated_at": self.now,
            }],
            "page": 1,
            "page_size": 20,
            "total": 1,
        }
        student_detail = {
            "reference_code": "CS-2026-0001",
            "issued_date": self.now.date(),
            "scheduled_start_at": self.now,
            "scheduled_end_at": self.now + timedelta(minutes=60),
            "expected_duration_minutes": 60,
            "mode_label": "On-site",
            "safe_destination": "Guidance Office",
            "purpose_label": "Guidance Interview",
            "student_safe_instructions": "Report to the front desk.",
            "status_label": "Issued",
            "can_acknowledge": True,
            "can_reschedule": True,
        }
        with mock.patch("apps.call_slips.queries.scoped_call_slip_page", return_value=SimpleNamespace(as_dict=lambda: queue)):
            listed = self.client.get("/api/v1/call-slips/?page=1&page_size=20", **self.headers)
        self.assertEqual(listed.status_code, 200)
        listed_payload = listed.json()
        self.assertEqual(set(listed_payload), set(queue))
        self.assertEqual(set(listed_payload["items"][0]), set(queue["items"][0]))
        self.assertTrue(listed_payload["items"][0]["updated_at"].endswith("Z"))

        with mock.patch("apps.call_slips.queries.student_call_slip_detail", return_value=student_detail):
            detail = self.client.get("/api/v1/call-slips/CS-2026-0001/student-detail/", **self.headers)
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(set(detail.json()), set(student_detail))
        self.assertNotIn("office_only_remarks", detail.json())
        self.assertNotIn("student_label", detail.json())

    def test_operational_superset_omits_student_only_fields(self):
        operational = {
            "reference_code": "CS-2026-0002",
            "scheduled_start_at": None,
            "scheduled_end_at": None,
            "expected_duration_minutes": 60,
            "mode_label": "On-site",
            "purpose_label": "General Office Reporting",
            "student_safe_instructions": "Report to the office.",
            "status_label": "Draft",
            "status_code": "DRAFT",
            "student_label": "Student A",
            "source_type_label": "Office Initiated",
            "assignment_state": "Unassigned",
            "destination_label": "Guidance Office",
            "report_to_destination": "Guidance Office",
            "student_safe_location": "Guidance Office",
            "office_only_remarks": "Internal note",
            "has_referral_link": False,
            "referral_reference": "",
            "has_appointment_link": False,
            "created_at": self.now,
            "updated_at": self.now,
            "source_form_code": "CNSC-OP-GTA-01F8",
            "source_form_revision": 0,
            "is_printable": False,
        }
        with mock.patch("apps.call_slips.queries.call_slip_detail", return_value=operational):
            response = self.client.get("/api/v1/call-slips/CS-2026-0002/", **self.headers)
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(set(payload), set(operational))
        self.assertNotIn("safe_destination", payload)
        self.assertNotIn("can_acknowledge", payload)
        self.assertNotIn("can_reschedule", payload)

    def test_printable_and_reschedule_details_are_typed_outputs(self):
        printable = {
            "reference_code": "CS-2026-0003",
            "issued_date": self.now.date(),
            "scheduled_start_at": self.now,
            "scheduled_end_at": self.now + timedelta(minutes=60),
            "expected_duration_minutes": 60,
            "mode_label": "On-site",
            "safe_destination": "Guidance Office",
            "purpose_label": "Guidance Interview",
            "student_safe_instructions": "Report to the front desk.",
            "status_label": "Issued",
            "source_form_code": "CNSC-OP-GTA-01F8",
            "source_form_revision": 0,
            "source_form_family": "call_slip",
        }
        with mock.patch("apps.call_slips.queries.printable_call_slip", return_value=printable):
            response = self.client.get("/api/v1/call-slips/CS-2026-0003/printable/", **self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.json()), set(printable))

        reschedule = {
            "id": 7,
            "reference_code": "CS-2026-0003",
            "status": "PENDING",
            "previous_start_at": self.now,
            "previous_end_at": self.now + timedelta(minutes=60),
            "proposed_start_at": self.now + timedelta(days=1),
            "proposed_end_at": self.now + timedelta(days=1, minutes=60),
            "student_reason": "Unavailable at the original time.",
            "decision_code": "",
            "decision_detail": "[REDACTED]",
        }
        with mock.patch("apps.call_slips.queries.reschedule_request_detail", return_value=reschedule):
            response = self.client.get("/api/v1/call-slips/reschedule/7/", **self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.json()), set(reschedule))

    def test_mutation_response_and_idempotent_replay_are_typed(self):
        mutation = {"reference_code": "CS-2026-0004", "status": "ACKNOWLEDGED"}
        outcome = ApiMutationOutcome(
            value=mutation,
            related_object=SimpleNamespace(pk="call-slip-related-1"),
        )
        headers = {
            **self.headers,
            "HTTP_IDEMPOTENCY_KEY": "call-slip-response-replay-1",
        }
        with (
            mock.patch(
                "apps.call_slips.api.acknowledge_call_slip",
                return_value=SimpleNamespace(reference_code=mutation["reference_code"], status=mutation["status"]),
            ) as service,
            mock.patch("apps.call_slips.api._outcome", return_value=outcome),
            mock.patch("apps.call_slips.queries.replay_by_id", return_value=mutation),
        ):
            first = self.client.post(
                "/api/v1/call-slips/CS-2026-0004/acknowledge/",
                **headers,
            )
            replay = self.client.post(
                "/api/v1/call-slips/CS-2026-0004/acknowledge/",
                **headers,
            )
        self.assertEqual(first.status_code, 200)
        self.assertEqual(replay.status_code, 200, replay.content)
        self.assertEqual(first.json(), mutation)
        self.assertEqual(replay.json(), mutation)
        service.assert_called_once()
