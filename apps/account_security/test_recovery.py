"""Focused tests for governed internal account recovery boundaries."""

import json
import uuid
from dataclasses import FrozenInstanceError
from datetime import timedelta
from io import StringIO
from unittest.mock import patch

from django.core.management import CommandError, call_command
from django.test import Client, TestCase, override_settings
from django.utils import timezone

from apps.account_security.api_tokens import issue_token_pair
from apps.account_security.commands import (
    ITAdminRecoveryCommand,
    StaffAssistedRecoveryCommand,
)
from apps.account_security.email_evidence import record_verified_email_evidence
from apps.account_security.models import (
    AccountRecoveryRequest,
    ApiSession,
    ApiSessionStatusChoices,
    ApiToken,
    ApiTokenStatusChoices,
    TrustedDevice,
)
from apps.account_security.application_services import request_staff_account_recovery
from apps.account_security.tokens import hash_identifier, hash_token
from apps.accounts.models import RoleChoices, User
from apps.audit.models import AuditLogEntry
from apps.common.exceptions import AssuranceRequiredError, PermissionDeniedError, ValidationError
from apps.profiles.models import CounselorProfile
from apps.workflow.models import OutboxEvent


def make_user(email, role, *, password="correct-horse-battery-staple", active=True, superuser=False):
    user = User.objects.create_user(
        email=email,
        password=password,
        first_name="Test",
        last_name="User",
        role=role,
        is_active=active,
    )
    if superuser:
        user.is_superuser = True
        user.save(update_fields=["is_superuser"])
    return user


class ITAdminRecoveryCommandTests(TestCase):
    @override_settings(COMPASS_ACCESS_MODE="health_only")
    def test_command_recovers_it_admin_and_invalidates_prior_security_state(self):
        old_password = "correct-horse-battery-staple"
        new_password = "new-operator-password-2026!"
        user = make_user("operator@example.test", RoleChoices.IT_ADMIN, password=old_password)
        pair = issue_token_pair(user, assurance_verified=True)
        trusted_device = TrustedDevice.objects.create(
            user=user,
            device_hash="device-hash-operator",
            label="Test device",
            trusted_until=timezone.now() + timedelta(days=2),
            assurance_policy_version="internal-2fa-v1",
            assurance_context="internal_required",
        )
        recovery_request = AccountRecoveryRequest.objects.create(
            id=uuid.uuid4(),
            user=user,
            identifier_hash=hash_identifier(user.email),
            delivery_email_hash=hash_identifier(user.email),
            token_hash=hash_token("pending-recovery-token"),
            status="pending",
            expires_at=timezone.now() + timedelta(minutes=30),
        )

        output = StringIO()
        with patch(
            "sys.stdin",
            StringIO(f"{new_password}\n{new_password}\n"),
        ):
            call_command(
                "bootstrap_it_admin_recovery",
                "--email",
                user.email,
                "--password-stdin",
                "--confirm",
                stdout=output,
            )

        user.refresh_from_db()
        trusted_device.refresh_from_db()
        recovery_request.refresh_from_db()
        self.assertTrue(user.check_password(new_password))
        self.assertFalse(user.check_password(old_password))
        self.assertFalse(ApiToken.objects.filter(
            user=user,
            status=ApiTokenStatusChoices.ACTIVE,
        ).exists())
        self.assertEqual(
            ApiSession.objects.filter(
                id=pair.session_id,
                status=ApiSessionStatusChoices.REVOKED,
            ).count(),
            1,
        )
        self.assertEqual(trusted_device.status, "revoked")
        self.assertEqual(recovery_request.status, "revoked")
        self.assertEqual(output.getvalue().strip(), "IT_ADMIN_RECOVERY_STATUS=completed")
        self.assertNotIn(old_password, output.getvalue())
        self.assertNotIn(new_password, output.getvalue())
        self.assertNotIn(user.email, output.getvalue())
        self.assertTrue(AuditLogEntry.objects.filter(
            action_type="it_admin_password_recovered",
            target_object_id=str(user.pk),
        ).exists())

    def test_command_dto_is_frozen_and_redacts_password(self):
        command = ITAdminRecoveryCommand(
            email="operator@example.test",
            new_password="new-operator-password-2026!",
        )
        with self.assertRaises(FrozenInstanceError):
            command.email = "changed@example.test"
        self.assertNotIn(command.new_password, repr(command))
        with self.assertRaises(ValidationError):
            ITAdminRecoveryCommand(
                email={"email": "operator@example.test"},
                new_password="new-operator-password-2026!",
            )

    @override_settings(COMPASS_ACCESS_MODE="active")
    def test_command_rejects_active_mode_without_changing_password(self):
        user = make_user("operator@example.test", RoleChoices.IT_ADMIN)
        output = StringIO()
        with patch("sys.stdin", StringIO("new-operator-password-2026!\nnew-operator-password-2026!\n")):
            with self.assertRaises(CommandError) as error:
                call_command(
                    "bootstrap_it_admin_recovery",
                    "--email",
                    user.email,
                    "--password-stdin",
                    "--confirm",
                    stdout=output,
                )
        self.assertEqual(str(error.exception), "it_admin_recovery_failed:permission")
        user.refresh_from_db()
        self.assertTrue(user.check_password("correct-horse-battery-staple"))

    @override_settings(COMPASS_ACCESS_MODE="health_only")
    def test_service_rejects_non_it_admin_or_legacy_targets(self):
        counselor = make_user("counselor@example.test", RoleChoices.COUNSELOR)
        with self.assertRaises(PermissionDeniedError):
            from apps.account_security.application_services import recover_it_admin_password

            recover_it_admin_password(
                command=ITAdminRecoveryCommand(
                    email=counselor.email,
                    new_password="new-operator-password-2026!",
                )
            )


class StaffAssistedRecoveryApiTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.it_admin = make_user("it-admin@example.test", RoleChoices.IT_ADMIN)
        self.target = make_user("staff@example.test", RoleChoices.GCO_STAFF)
        record_verified_email_evidence(
            self.target,
            verification_method="staff_out_of_band",
            verified_by=self.it_admin,
            reason_category="internal_role_policy",
        )
        self.access_token = issue_token_pair(
            self.it_admin,
            assurance_verified=True,
        ).access_token

    def _headers(self, key="staff-recovery-1"):
        return {
            "HTTP_AUTHORIZATION": f"Bearer {self.access_token}",
            "HTTP_IDEMPOTENCY_KEY": key,
        }

    def _payload(self, *, target_id=None, reason="internal_role_policy", attested=False):
        return {
            "target_account_id": target_id or self.target.pk,
            "reason_category": reason,
            "email_ownership_attested": attested,
        }

    def test_it_admin_can_queue_staff_recovery_without_disclosing_token_or_email(self):
        response = self.client.post(
            "/api/v1/auth/staff-recovery/request/",
            data=json.dumps(self._payload()),
            content_type="application/json",
            **self._headers(),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.json()), {"accepted", "detail"})
        self.assertTrue(response.json()["accepted"])
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertNotIn(self.target.email, response.content.decode())
        self.assertNotIn("token", response.content.decode().lower())
        self.assertEqual(
            OutboxEvent.objects.filter(event_type="account_security.recovery_requested").count(),
            1,
        )
        recovery_request = AccountRecoveryRequest.objects.get(user=self.target, status="pending")
        event = OutboxEvent.objects.get(event_type="account_security.recovery_requested")
        self.assertEqual(event.payload_json, {"recovery_request_id": str(recovery_request.id)})
        self.assertNotIn(recovery_request.token_hash, response.content.decode())

    def test_idempotency_replays_safe_receipt_and_rejects_changed_payload(self):
        payload = self._payload()
        first = self.client.post(
            "/api/v1/auth/staff-recovery/request/",
            data=json.dumps(payload),
            content_type="application/json",
            **self._headers("staff-recovery-replay"),
        )
        replay = self.client.post(
            "/api/v1/auth/staff-recovery/request/",
            data=json.dumps(payload),
            content_type="application/json",
            **self._headers("staff-recovery-replay"),
        )
        conflict = self.client.post(
            "/api/v1/auth/staff-recovery/request/",
            data=json.dumps(self._payload(attested=True)),
            content_type="application/json",
            **self._headers("staff-recovery-replay"),
        )

        self.assertEqual(first.status_code, 200)
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.json(), first.json())
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(
            OutboxEvent.objects.filter(event_type="account_security.recovery_requested").count(),
            1,
        )

    def test_staff_recovery_requires_verified_email_or_explicit_attestation(self):
        target = make_user("unverified@example.test", RoleChoices.COUNSELOR)
        denied = self.client.post(
            "/api/v1/auth/staff-recovery/request/",
            data=json.dumps(self._payload(target_id=target.pk)),
            content_type="application/json",
            **self._headers("staff-recovery-unverified"),
        )
        self.assertEqual(denied.status_code, 422)
        self.assertEqual(denied.json()["code"], "validation")

        accepted = self.client.post(
            "/api/v1/auth/staff-recovery/request/",
            data=json.dumps(self._payload(target_id=target.pk, attested=True)),
            content_type="application/json",
            **self._headers("staff-recovery-attested"),
        )
        self.assertEqual(accepted.status_code, 200)

    def test_non_it_admin_and_non_regular_staff_targets_are_denied(self):
        head = make_user("head@example.test", RoleChoices.COUNSELOR)
        CounselorProfile.objects.create(user=head, is_head_guidance=True)
        head_token = issue_token_pair(head, assurance_verified=True).access_token
        denied_actor = self.client.post(
            "/api/v1/auth/staff-recovery/request/",
            data=json.dumps(self._payload()),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {head_token}",
            HTTP_IDEMPOTENCY_KEY="staff-recovery-head-denied",
        )
        self.assertEqual(denied_actor.status_code, 403)

        student = make_user("student@example.test", RoleChoices.STUDENT)
        denied_target = self.client.post(
            "/api/v1/auth/staff-recovery/request/",
            data=json.dumps(self._payload(target_id=student.pk)),
            content_type="application/json",
            **self._headers("staff-recovery-student-denied"),
        )
        self.assertEqual(denied_target.status_code, 403)

        self_target = self.client.post(
            "/api/v1/auth/staff-recovery/request/",
            data=json.dumps(self._payload(target_id=self.it_admin.pk)),
            content_type="application/json",
            **self._headers("staff-recovery-self-denied"),
        )
        self.assertEqual(self_target.status_code, 403)

        inactive_target = make_user(
            "inactive-staff@example.test",
            RoleChoices.GCO_STAFF,
            active=False,
        )
        denied_inactive = self.client.post(
            "/api/v1/auth/staff-recovery/request/",
            data=json.dumps(self._payload(target_id=inactive_target.pk)),
            content_type="application/json",
            **self._headers("staff-recovery-inactive-denied"),
        )
        self.assertEqual(denied_inactive.status_code, 403)

        legacy_target = make_user(
            "legacy-staff@example.test",
            RoleChoices.GCO_STAFF,
            superuser=True,
        )
        denied_legacy = self.client.post(
            "/api/v1/auth/staff-recovery/request/",
            data=json.dumps(self._payload(target_id=legacy_target.pk)),
            content_type="application/json",
            **self._headers("staff-recovery-legacy-denied"),
        )
        self.assertEqual(denied_legacy.status_code, 403)

    def test_it_admin_can_queue_recovery_for_designated_head_guidance(self):
        designated_head = make_user("designated-head@example.test", RoleChoices.COUNSELOR)
        CounselorProfile.objects.create(user=designated_head, is_head_guidance=True)

        response = self.client.post(
            "/api/v1/auth/staff-recovery/request/",
            data=json.dumps(
                self._payload(
                    target_id=designated_head.pk,
                    attested=True,
                )
            ),
            content_type="application/json",
            **self._headers("staff-recovery-designated-head"),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.json()), {"accepted", "detail"})
        self.assertTrue(response.json()["accepted"])
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertNotIn(designated_head.email, response.content.decode())
        self.assertNotIn("token", response.content.decode().lower())
        recovery_request = AccountRecoveryRequest.objects.get(
            user=designated_head,
            status="pending",
        )
        self.assertEqual(recovery_request.request_source, "staff_assisted")
        self.assertEqual(
            OutboxEvent.objects.filter(event_type="account_security.recovery_requested").count(),
            1,
        )

    def test_command_and_api_operation_are_registered(self):
        response = self.client.get("/api/v1/openapi.json")
        self.assertEqual(response.status_code, 200)
        operation = response.json()["paths"]["/api/v1/auth/staff-recovery/request/"]["post"]
        self.assertEqual(operation["operationId"], "auth_staff_recovery_request")

    def test_staff_recovery_dto_rejects_mapping_and_unknown_reason(self):
        with self.assertRaises(ValidationError):
            StaffAssistedRecoveryCommand(
                target_account_id={"id": self.target.pk},
                reason_category="internal_role_policy",
            )
        with self.assertRaises(ValidationError):
            StaffAssistedRecoveryCommand(
                target_account_id=self.target.pk,
                reason_category="unbounded-reason",
            )
        with self.assertRaises(ValidationError):
            ITAdminRecoveryCommand(
                email="operator@example.test",
                new_password="password\nwith-newline",
            )

    def test_application_service_requires_fresh_api_session_assurance(self):
        command = StaffAssistedRecoveryCommand(
            target_account_id=self.target.pk,
            reason_category="internal_role_policy",
        )
        with self.assertRaises(AssuranceRequiredError):
            request_staff_account_recovery(
                actor=self.it_admin,
                command=command,
                assurance_token=None,
            )

    def test_api_token_assurance_allows_recovery_without_session_marker(self):
        response = self.client.post(
            "/api/v1/auth/staff-recovery/request/",
            data=json.dumps(self._payload()),
            content_type="application/json",
            **self._headers("staff-recovery-token-assurance"),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            "accepted": True,
            "detail": "Recovery instructions were queued for the selected staff account.",
        })

    def test_api_token_assurance_rejects_stale_token(self):
        from apps.account_security.models import ApiTokenTypeChoices

        stale = ApiToken.objects.get(
            user=self.it_admin,
            token_type=ApiTokenTypeChoices.ACCESS,
        )
        ApiSession.objects.filter(id=stale.session_id).update(
            last_otp_verified_at=timezone.now() - timedelta(minutes=11),
        )

        response = self.client.post(
            "/api/v1/auth/staff-recovery/request/",
            data=json.dumps(self._payload()),
            content_type="application/json",
            **self._headers("staff-recovery-stale-token"),
        )

        self.assertEqual(response.status_code, 403)
