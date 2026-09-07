from types import SimpleNamespace
from unittest import TestCase

from django.utils import timezone

from apps.common.exceptions import ValidationError
from apps.form_collection.api import (
    FormCollectionPageSchema,
    FormCollectionSchema,
    InvitationBatchIssueReceiptSchema,
    InvitationBatchPageSchema,
    InvitationBatchSchema,
    InvitationMetadataPageSchema,
    InvitationMetadataSchema,
    ManualMatchPageSchema,
    ManualMatchSchema,
    VerifiedAccessSchema,
    _batch_issue_receipt,
)
from apps.form_collection import projections
from apps.form_collection.commands import (
    FormCollectionCreateCommand,
    InvitationRecipient,
    InvitationVerificationCommand,
)
from apps.common.form_values import ValidatedAnswerSet


class FormCollectionCommandContractTests(TestCase):
    def test_commands_are_frozen_and_answers_are_json_safe(self):
        command = FormCollectionCreateCommand(
            name="Exit batch",
            start_at=__import__("datetime").datetime(2026, 8, 24),
            end_at=__import__("datetime").datetime(2026, 8, 25),
            form_type="exit_interview",
        )
        with self.assertRaises(AttributeError):
            command.name = "changed"
        answers = ValidatedAnswerSet(values={"rating": 5}, form_revision_id="revision-1")
        self.assertEqual(dict(answers.values), {"rating": 5})
        with self.assertRaises(ValidationError):
            ValidatedAnswerSet(values={"bad": object()}, form_revision_id="revision-1")

    def test_verification_command_rejects_unbounded_values(self):
        with self.assertRaises(ValidationError):
            InvitationVerificationCommand(selector="x", verifier="y" * 129)
        with self.assertRaises(ValidationError):
            InvitationRecipient()

    def test_invitation_projection_contains_no_secret_fields(self):
        value = SimpleNamespace(
            pk="invitation-1",
            selector="safe-selector",
            collection_id="collection-1",
            invitation_batch_id=None,
            target_form_key="exit_interview",
            intended_recipient_name="Student",
            status="ISSUED",
            expires_at=None,
            max_uses=1,
            used_count=0,
            verified_at=None,
            submitted_at=None,
            linked_student_id=None,
            created_at=None,
            token_hash="must-not-project",
            control_number_hash="must-not-project",
        )
        projected = projections.invitation_metadata(value)
        self.assertNotIn("token_hash", projected)
        self.assertNotIn("control_number_hash", projected)
        self.assertNotIn("verifier", projected)


class FormCollectionResponseSchemaContractTests(TestCase):
    @staticmethod
    def _collection():
        now = timezone.now()
        return SimpleNamespace(
            pk="collection-1",
            name="Exit interview collection",
            description="Graduating students",
            audience="GRADUATING",
            status="ACTIVE",
            start_at=now,
            end_at=now,
            form_type="exit_interview",
            form_family_id="family-1",
            form_revision_id="revision-1",
            created_at=now,
            launched_at=now,
            closed_at=None,
            metadata_json={"internal": "must not project"},
        )

    @staticmethod
    def _batch():
        now = timezone.now()
        return SimpleNamespace(
            pk="batch-1",
            collection_id="collection-1",
            invitation_batch_name="Graduating students",
            source_type="MANUAL",
            status="ISSUED",
            total_requested=2,
            total_issued=1,
            total_failed=1,
            issued_at=now,
            created_at=now,
            metadata_json={"internal": "must not project"},
        )

    @staticmethod
    def _invitation():
        now = timezone.now()
        return SimpleNamespace(
            pk="invitation-1",
            selector="safe-selector",
            collection_id="collection-1",
            invitation_batch_id="batch-1",
            target_form_key="exit_interview",
            intended_recipient_name="Student Example",
            status="ISSUED",
            expires_at=now,
            max_uses=1,
            used_count=0,
            verified_at=None,
            submitted_at=None,
            linked_student_id=None,
            created_at=now,
            token_hash="must-not-project",
            control_number_hash="must-not-project",
            student_number_hash="must-not-project",
            metadata_json={"verification_otp": "must-not-project"},
        )

    @staticmethod
    def _manual_match():
        now = timezone.now()
        return SimpleNamespace(
            pk="record-1",
            source_collection_id="collection-1",
            source_invitation_id="invitation-1",
            name_snapshot="Student Example",
            program_snapshot="BS Computer Science",
            student_match_status="NEEDS_MANUAL_REVIEW",
            matched_at=None,
            linked_at=None,
            reviewed_at=now,
            control_number_hash="must-not-project",
            student_number_hash="must-not-project",
            email_hash="must-not-project",
            metadata_json={"internal": "must-not-project"},
        )

    def test_collection_batch_and_page_outputs_are_typed(self):
        collection = projections.collection(self._collection())
        batch = projections.invitation_batch(self._batch())

        self.assertEqual(FormCollectionSchema(**collection).status, "ACTIVE")
        self.assertEqual(InvitationBatchSchema(**batch).total_issued, 1)
        self.assertEqual(
            FormCollectionPageSchema(items=[collection], page=1, page_size=25, total=1).items[0].id,
            "collection-1",
        )
        self.assertEqual(
            InvitationBatchPageSchema(items=[batch], page=1, page_size=25, total=1).items[0].id,
            "batch-1",
        )

    def test_invitation_and_verified_access_outputs_are_secret_free(self):
        invitation = projections.invitation_metadata(self._invitation())
        self.assertEqual(
            InvitationMetadataSchema(**invitation).selector,
            "safe-selector",
        )
        self.assertTrue(
            {
                "token_hash",
                "control_number_hash",
                "student_number_hash",
                "metadata_json",
                "verifier",
            }.isdisjoint(invitation),
        )
        self.assertEqual(
            InvitationMetadataPageSchema(
                items=[invitation], page=1, page_size=25, total=1
            ).items[0].id,
            "invitation-1",
        )

        collection = self._collection()
        verified = projections.verified_access(
            SimpleNamespace(
                pk="invitation-1",
                collection_id="collection-1",
                target_form_key="exit_interview",
                collection=collection,
                intended_recipient_name="Student Example",
                status="VERIFIED",
                expires_at=collection.end_at,
                token_hash="must-not-project",
            )
        )
        self.assertEqual(VerifiedAccessSchema(**verified).form_type, "exit_interview")
        self.assertNotIn("token_hash", verified)

    def test_issue_receipt_and_manual_match_outputs_are_bounded(self):
        batch = self._batch()
        receipt = _batch_issue_receipt(batch)
        self.assertEqual(InvitationBatchIssueReceiptSchema(**receipt).batch_id, "batch-1")
        self.assertEqual(
            set(receipt),
            {
                "batch_id",
                "status",
                "total_requested",
                "total_issued",
                "total_failed",
                "issued_at",
            },
        )

        manual_match = projections.manual_match(self._manual_match())
        self.assertEqual(
            ManualMatchSchema(**manual_match).student_match_status,
            "NEEDS_MANUAL_REVIEW",
        )
        self.assertTrue(
            {
                "control_number_hash",
                "student_number_hash",
                "email_hash",
                "metadata_json",
            }.isdisjoint(manual_match),
        )
        self.assertEqual(
            ManualMatchPageSchema(
                items=[manual_match], page=1, page_size=25, total=1
            ).items[0].id,
            "record-1",
        )
