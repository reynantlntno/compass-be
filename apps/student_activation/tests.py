"""Focused tests for shared account activation mechanics and student onboarding."""

import importlib
import uuid
from datetime import timedelta

from django.apps import apps as django_apps
from django.db import connection
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.account_security.activation import (
    ActivationPurpose,
    activation_url_for_token,
    hash_activation_token,
    decode_activation_reference,
    issue_activation_token,
)
from apps.accounts.models import RoleChoices, StaffAccountInvitation, User
from apps.common.exceptions import ValidationError
from apps.notifications.models import EmailDelivery
from apps.student_activation.models import StudentActivationInvitation
from apps.student_activation.services import (
    create_activation_invitation,
    execute_student_activation,
)


@override_settings(
    ACCOUNT_ACTIVATION_TOKEN_SECRET="activation-test-secret-value",
    COMPASS_CLIENT_BASE_URL="http://localhost:3000",
    COMPASS_ENVIRONMENT="test",
)
class SharedActivationMechanicsTests(TestCase):
    def test_token_profiles_are_purpose_bound_and_hash_only(self):
        reference = uuid.uuid4()
        student_token = issue_activation_token(reference, ActivationPurpose.STUDENT)
        staff_token = issue_activation_token(reference, ActivationPurpose.STAFF)

        self.assertNotEqual(student_token, staff_token)
        self.assertEqual(decode_activation_reference(student_token, ActivationPurpose.STUDENT), reference)
        self.assertEqual(decode_activation_reference(staff_token, ActivationPurpose.STAFF), reference)
        self.assertIsNone(decode_activation_reference(student_token, ActivationPurpose.STAFF))
        self.assertIsNone(decode_activation_reference(staff_token, ActivationPurpose.STUDENT))
        self.assertEqual(hash_activation_token(student_token), hash_activation_token(student_token))
        self.assertNotEqual(student_token, hash_activation_token(student_token))

    def test_malformed_and_oversized_tokens_fail_closed(self):
        self.assertIsNone(decode_activation_reference("not-a-token", ActivationPurpose.STUDENT))
        self.assertIsNone(decode_activation_reference("x" * 513, ActivationPurpose.STAFF))
        with self.assertRaises(ValidationError):
            hash_activation_token("x" * 513)

    def test_activation_urls_use_separate_client_paths(self):
        reference = uuid.uuid4()
        student_token = issue_activation_token(reference, ActivationPurpose.STUDENT)
        staff_token = issue_activation_token(reference, ActivationPurpose.STAFF)

        self.assertIn("/activate/?token=", activation_url_for_token(student_token, ActivationPurpose.STUDENT))
        self.assertIn("/staff-activate/?token=", activation_url_for_token(staff_token, ActivationPurpose.STAFF))


class StudentActivationServiceTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="student-activation@example.test",
            password=None,
            first_name="Student",
            last_name="Activation",
            role=RoleChoices.STUDENT,
            is_active=False,
        )

    @override_settings(ACCOUNT_ACTIVATION_TOKEN_SECRET="activation-test-secret-value")
    def test_new_student_invitation_uses_canonical_profile_and_replay_is_denied(self):
        invitation, raw_token = create_activation_invitation(self.user)

        self.assertEqual(invitation.token_version, "account-activation-student-v1")
        self.assertNotEqual(invitation.token_hash, raw_token)
        self.assertNotIn(raw_token, invitation.token_hash)

        activated = execute_student_activation(
            raw_token,
            "correct-horse-battery-staple",
            "correct-horse-battery-staple",
        )
        self.assertEqual(activated.pk, self.user.pk)
        self.user.refresh_from_db()
        invitation.refresh_from_db()
        self.assertTrue(self.user.is_active)
        self.assertIsNotNone(invitation.used_at)

        with self.assertRaises(ValidationError):
            execute_student_activation(
                raw_token,
                "correct-horse-battery-staple",
                "correct-horse-battery-staple",
            )

    @override_settings(ACCOUNT_ACTIVATION_TOKEN_SECRET="activation-test-secret-value")
    def test_student_activation_rejects_non_student_invitation_target(self):
        self.user.role = RoleChoices.COUNSELOR
        self.user.save(update_fields=["role"])
        with self.assertRaises(ValidationError):
            create_activation_invitation(self.user)


class ActivationCutoverMigrationTests(TestCase):
    def test_pending_invitations_are_revoked_and_unsent_deliveries_cancelled(self):
        student = User.objects.create_user(
            email="pending-student@example.test",
            password=None,
            first_name="Pending",
            last_name="Student",
            role=RoleChoices.STUDENT,
            is_active=False,
        )
        staff = User.objects.create_user(
            email="pending-staff@example.test",
            password=None,
            first_name="Pending",
            last_name="Staff",
            role=RoleChoices.GCO_STAFF,
            is_active=False,
        )
        student_invitation = StudentActivationInvitation.objects.create(
            user=student,
            token_hash="a" * 64,
            token_version="account-activation-student-v1",
            delivery_email_hash="b" * 64,
            expires_at=timezone.now() + timedelta(days=1),
        )
        staff_invitation = StaffAccountInvitation.objects.create(
            user=staff,
            role_snapshot=RoleChoices.GCO_STAFF,
            profile_type=RoleChoices.GCO_STAFF,
            token_hash="c" * 64,
            delivery_email_hash="d" * 64,
            expires_at=timezone.now() + timedelta(days=1),
        )
        for template_key, user, invitation in (
            ("student_activation", student, student_invitation),
            ("staff_activation", staff, staff_invitation),
        ):
            EmailDelivery.objects.create(
                delivery_key=uuid.uuid4().hex,
                recipient_user=user,
                recipient_email=user.email,
                template_key=template_key,
                subject="Activation",
                context_json={"invitation_id": str(invitation.pk)},
                next_retry_at=timezone.now(),
                related_object_id=str(invitation.pk),
            )

        migration = importlib.import_module(
            "apps.account_security.migrations.0004_activation_mechanics_cutover"
        )
        with connection.schema_editor() as schema_editor:
            migration.revoke_pending_activation_invitations(django_apps, schema_editor)

        student_invitation.refresh_from_db()
        staff_invitation.refresh_from_db()
        self.assertEqual(student_invitation.revocation_reason, "activation_mechanics_cutover")
        self.assertEqual(staff_invitation.revocation_reason, "activation_mechanics_cutover")
        self.assertTrue(student_invitation.revoked_at)
        self.assertTrue(staff_invitation.revoked_at)
        self.assertFalse(EmailDelivery.objects.filter(delivery_state="queued").exists())
