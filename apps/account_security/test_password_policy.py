"""Focused coverage for the shared password policy boundary."""

import uuid
from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from apps.account_security.activation import validate_activation_password
from apps.account_security.api_tokens import issue_token_pair
from apps.account_security.application_services import change_password, reset_password
from apps.account_security.commands import PasswordChangeCommand, RecoveryResetCommand
from apps.account_security.models import (
    AccountRecoveryRequest,
    ApiSession,
    ApiSessionStatusChoices,
)
from apps.account_security.password_policy import validate_new_password
from apps.account_security.tokens import build_recovery_token, hash_identifier, hash_token
from apps.accounts.models import RoleChoices, User
from apps.common.exceptions import ValidationError


class PasswordPolicyHelperTests(TestCase):
    def setUp(self):
        self.old_password = "Ridge-lantern-2026!"
        self.user = User.objects.create_user(
            email="policy-owner@example.test",
            password=self.old_password,
            first_name="Morgan",
            last_name="Reed",
            role=RoleChoices.STUDENT,
            is_active=True,
        )

    def assert_rejected(self, password, **kwargs):
        with self.assertRaises(ValidationError) as context:
            validate_new_password(password, **kwargs)
        self.assertNotIn(password, str(context.exception))

    def test_configured_policy_rejects_short_numeric_common_and_oversized_values(self):
        self.assert_rejected("short")
        self.assert_rejected("12345678")
        self.assert_rejected("password")
        self.assert_rejected("x" * 513)

    def test_user_similarity_and_reuse_are_checked_only_with_the_user(self):
        self.assert_rejected("Morgan123", user=self.user)
        self.assert_rejected(
            self.old_password,
            user=self.user,
            reject_reuse=True,
        )
        validate_new_password(
            "Harbor-lantern-2026!",
            user=self.user,
            reject_reuse=True,
        )

    def test_activation_uses_the_shared_user_aware_policy(self):
        with self.assertRaises(ValidationError):
            validate_activation_password("12345678", "12345678", self.user)
        with self.assertRaises(ValidationError):
            validate_activation_password("Morgan123", "Morgan123", self.user)


class PasswordChangePolicyTests(TestCase):
    def setUp(self):
        self.old_password = "Ridge-lantern-2026!"
        self.user = User.objects.create_user(
            email="change-owner@example.test",
            password=self.old_password,
            first_name="Morgan",
            last_name="Reed",
            role=RoleChoices.STUDENT,
            is_active=True,
        )

    def test_reuse_is_rejected_before_security_state_changes(self):
        pair = issue_token_pair(self.user)
        with self.assertRaises(ValidationError):
            change_password(
                actor=self.user,
                command=PasswordChangeCommand(
                    current_password=self.old_password,
                    new_password=self.old_password,
                    password_confirmation=self.old_password,
                ),
            )

        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.old_password))
        self.assertEqual(
            ApiSession.objects.get(id=pair.session_id).status,
            ApiSessionStatusChoices.ACTIVE,
        )


class RecoveryResetPolicyTests(TestCase):
    def _recovery_request(self, user):
        request = AccountRecoveryRequest.objects.create(
            id=uuid.uuid4(),
            user=user,
            identifier_hash=hash_identifier(user.email),
            delivery_email_hash=hash_identifier(user.email),
            token_hash="pending-token-hash",
            status="pending",
            expires_at=timezone.now() + timedelta(minutes=30),
        )
        token = build_recovery_token(request.id)
        request.token_hash = hash_token(token)
        request.save(update_fields=["token_hash", "updated_at"])
        return request, token

    def test_recovery_rejects_reuse_after_token_resolves_the_user(self):
        old_password = "Ridge-lantern-2026!"
        user = User.objects.create_user(
            email="recovery-owner@example.test",
            password=old_password,
            first_name="Morgan",
            last_name="Reed",
            role=RoleChoices.STUDENT,
            is_active=True,
        )
        request, token = self._recovery_request(user)

        with self.assertRaises(ValidationError):
            reset_password(
                command=RecoveryResetCommand(
                    token=token,
                    new_password=old_password,
                    password_confirmation=old_password,
                )
            )

        user.refresh_from_db()
        request.refresh_from_db()
        self.assertTrue(user.check_password(old_password))
        self.assertEqual(request.status, "pending")

    def test_recovery_rejects_user_similar_password_after_token_resolution(self):
        old_password = "Ridge-lantern-2026!"
        user = User.objects.create_user(
            email="recovery-similarity@example.test",
            password=old_password,
            first_name="Morgan",
            last_name="Reed",
            role=RoleChoices.STUDENT,
            is_active=True,
        )
        request, token = self._recovery_request(user)

        with self.assertRaises(ValidationError):
            reset_password(
                command=RecoveryResetCommand(
                    token=token,
                    new_password="Morgan123",
                    password_confirmation="Morgan123",
                )
            )

        user.refresh_from_db()
        request.refresh_from_db()
        self.assertTrue(user.check_password(old_password))
        self.assertEqual(request.status, "pending")
