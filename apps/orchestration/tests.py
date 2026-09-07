"""Focused tests for the typed cross-domain composition boundary."""

from dataclasses import FrozenInstanceError

from django.test import SimpleTestCase

from apps.common.exceptions import ValidationError
from apps.orchestration.boundary import DomainEvent, require_serializable_event
from apps.orchestration.commands import (
    FeedbackInvitationCommand,
    FormInvitationLifecycleCommand,
    InventoryReviewCommand,
)


class OrchestrationCommandTests(SimpleTestCase):
    def test_commands_are_frozen_and_require_stable_ids(self):
        command = FormInvitationLifecycleCommand(" invitation-1 ")
        self.assertEqual(command.invitation_id, "invitation-1")
        with self.assertRaises(FrozenInstanceError):
            command.invitation_id = "other"
        with self.assertRaises(ValidationError):
            InventoryReviewCommand("bad\nidentifier")
        with self.assertRaises(ValidationError):
            FeedbackInvitationCommand("unsupported", "source-1")

    def test_commands_do_not_accept_arbitrary_payload_objects(self):
        with self.assertRaises(ValidationError):
            FeedbackInvitationCommand("good_moral", object())


class OrchestrationEventTests(SimpleTestCase):
    def test_registered_event_is_json_safe_and_accepted(self):
        event = DomainEvent(
            event_type="feedback.csm_invitation",
            event_key="feedback:invitation:1",
            payload={"invitation_id": "1", "count": 1},
        )
        self.assertEqual(require_serializable_event(event), event)

    def test_event_rejects_unregistered_type_and_protected_payload_keys(self):
        with self.assertRaises(ValidationError):
            require_serializable_event(
                DomainEvent(
                    event_type="not.registered",
                    event_key="event:1",
                    payload={"value": "ok"},
                )
            )
        with self.assertRaises(ValidationError):
            DomainEvent(
                event_type="feedback.csm_invitation",
                event_key="feedback:invitation:2",
                payload={"raw_token": "never"},
            )

    def test_event_rejects_models_and_invalid_identity(self):
        with self.assertRaises(ValidationError):
            DomainEvent(
                event_type="feedback.csm_invitation",
                event_key="feedback:invitation:3",
                payload={"value": object()},
            )
        with self.assertRaises(ValidationError):
            DomainEvent(
                event_type="Bad Event",
                event_key="event:4",
                payload={},
            )


class OrchestrationSupportNeedsMappingTests(SimpleTestCase):
    def test_candidates_are_bounded_and_never_carry_raw_answers(self):
        from apps.orchestration.support_needs_mapping import build_support_need_candidates

        answers = {
            "support_context": {
                "mapping_version": "support-needs-v1",
                "pwd_status": "YES",
                "indigenous_peoples_status": "DECLINE_TO_ANSWER",
            },
            "family_data": {"secret": "raw-value"},
        }
        candidates = build_support_need_candidates(answers)
        self.assertEqual(len(candidates), 2)
        positive = [c for c in candidates if c.is_positive]
        changed = [c for c in candidates if c.is_source_changed]
        self.assertEqual(positive[0].support_need_key, "pwd_disability")
        self.assertEqual(changed[0].response, "DECLINE_TO_ANSWER")
        # DTO fields only: no raw answer content crosses the boundary.
        for candidate in candidates:
            self.assertFalse(hasattr(candidate, "answers"))
            self.assertNotIn("secret", repr(candidate))

    def test_unmapped_context_is_rejected(self):
        from apps.orchestration.support_needs_mapping import build_support_need_candidates

        with self.assertRaises(ValidationError):
            build_support_need_candidates(
                {"support_context": {"mapping_version": "unknown-v9"}}
            )

    def test_workflow_commands_validate_stable_ids_and_reasons(self):
        from apps.orchestration.commands import (
            InventoryReopenWorkflowCommand,
            InventorySubmitWorkflowCommand,
        )

        submit = InventorySubmitWorkflowCommand(
            " snapshot-1 ",
            True,
            "2026-08-24T00:00:00+00:00",
        )
        self.assertEqual(submit.snapshot_id, "snapshot-1")
        self.assertEqual(submit.expected_updated_at, "2026-08-24T00:00:00+00:00")
        reopen = InventoryReopenWorkflowCommand(
            "snapshot-1", "Please clarify the household income section."
        )
        self.assertIn("household", reopen.reason)
        with self.assertRaises(ValidationError):
            InventoryReopenWorkflowCommand("snapshot-1", "short")
        with self.assertRaises(ValidationError):
            InventorySubmitWorkflowCommand("bad\nid", True)
