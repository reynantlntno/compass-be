from datetime import date
from decimal import Decimal
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from apps.common.exceptions import ValidationError
from apps.good_moral.api import DraftSchema, create_request
from apps.good_moral.commands import (
    GoodMoralDraftCommand,
    GoodMoralReceiptEncodeCommand,
    GoodMoralReceiptVerificationCommand,
)


class GoodMoralCommandContractTests(SimpleTestCase):
    def test_commands_are_frozen_and_reject_arbitrary_mappings(self):
        command = GoodMoralDraftCommand(
            requester_user_id="1",
            student_profile_id="2",
            purpose_text="Employment",
        )
        with self.assertRaises((AttributeError, TypeError)):
            command.purpose_text = "changed"
        with self.assertRaises(ValidationError):
            GoodMoralDraftCommand(
                requester_user_id="1",
                student_profile_id="2",
                purpose_text={"unexpected": "field"},
            )

    def test_receipt_commands_bound_amount_and_verification_decision(self):
        command = GoodMoralReceiptEncodeCommand(
            receipt_number="OR-001",
            receipt_date=date(2026, 8, 24),
            receipt_amount=Decimal("100.00"),
        )
        self.assertEqual(command.receipt_amount, Decimal("100.00"))
        with self.assertRaises(ValidationError):
            GoodMoralReceiptVerificationCommand(approved=False)


class GoodMoralApiWiringTests(SimpleTestCase):
    def test_create_route_builds_typed_command_and_uses_shared_adapter(self):
        actor = SimpleNamespace(pk=10)
        request = SimpleNamespace(auth=SimpleNamespace(user=actor))
        payload = DraftSchema(
            requester_user_id="10",
            student_profile_id="20",
            purpose_text="Employment",
        )
        result = SimpleNamespace(
            reference_code="GMC-TEST-1",
            status="DRAFT",
            receipt_status="PENDING",
            dry_seal_status="PENDING",
            updated_at=None,
        )

        def execute(_request, _operation_id, _payload, operation):
            return operation()

        with (
            mock.patch("apps.good_moral.api._run", side_effect=execute),
            mock.patch("apps.good_moral.api.service_create_draft", return_value=result) as service,
        ):
            response = create_request(request, payload)

        service.assert_called_once()
        command = service.call_args.kwargs["command"]
        self.assertIsInstance(command, GoodMoralDraftCommand)
        self.assertEqual(command.student_profile_id, "20")
        self.assertEqual(response.value["reference_code"], "GMC-TEST-1")
