"""Focused tests for staff provisioning, invitations, and Head designation."""

from dataclasses import FrozenInstanceError
from datetime import timedelta
from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.test import Client, TestCase, override_settings
from django.utils import timezone

from apps.accounts.commands import (
    ITAdminBootstrapCommand,
    InitialHeadGuidanceBootstrapCommand,
    StaffAccountCreateCommand,
    StaffInvitationActivationCommand,
)
from apps.accounts.api import HeadGuidanceProjectionSchema
from apps.accounts.models import RoleChoices, StaffAccountInvitation, User
from apps.accounts.projections import project_head_designation
from apps.accounts.services import (
    activate_staff_invitation,
    assign_head_guidance,
    bootstrap_initial_head_guidance,
    bootstrap_it_admin,
    deactivate_staff_account,
    provision_staff_account,
    reissue_staff_invitation,
    revoke_staff_invitation,
)
from apps.account_security.activation import ActivationPurpose, issue_activation_token
from apps.access_control.authority import has_capability
from apps.access_control.capabilities import Capability
from apps.access_control.rules import is_head_guidance
from apps.common.exceptions import LifecycleConflictError, PermissionDeniedError, ValidationError
from apps.profiles.models import CounselorProfile, GCOStaffProfile
from apps.account_security.api_tokens import issue_token_pair
from apps.workflow.models import OutboxEvent
from apps.notifications.models import EmailDelivery, NotificationTemplate
from apps.orchestration.notification_outbox_handlers import handle_staff_account_invitation_event


def make_user(email, role, *, active=True, superuser=False):
    user = User.objects.create_user(
        email=email,
        password="correct-horse-battery-staple",
        first_name="Test",
        last_name="User",
        role=role,
        is_active=active,
    )
    if superuser:
        user.is_superuser = True
        user.save(update_fields=["is_superuser"])
    return user


class StaffProvisioningTests(TestCase):
    def setUp(self):
        self.head = make_user("head@example.test", RoleChoices.COUNSELOR)
        CounselorProfile.objects.create(user=self.head, is_head_guidance=True)

    def command(self, role=RoleChoices.COUNSELOR, email="new@example.test"):
        return StaffAccountCreateCommand(
            email=email,
            first_name="New",
            last_name="Staff",
            role=role,
            source_reference="institutional-onboarding-2026",
        )

    def test_head_provisions_inactive_counselor_and_gco_with_matching_profiles(self):
        counselor, invitation = provision_staff_account(self.head, self.command())
        staff, staff_invitation = provision_staff_account(
            self.head, self.command(RoleChoices.GCO_STAFF, "staff@example.test"),
        )
        self.assertFalse(counselor.is_active)
        self.assertFalse(staff.is_active)
        self.assertIsNotNone(invitation)
        self.assertIsNotNone(staff_invitation)
        self.assertTrue(CounselorProfile.objects.filter(user=counselor).exists())
        self.assertTrue(GCOStaffProfile.objects.filter(user=staff).exists())
        self.assertFalse(has_capability(staff, Capability.GOOD_MORAL_RELEASE))
        self.assertTrue(OutboxEvent.objects.filter(
            event_type="staff_account.invitation_requested",
            payload_json={"invitation_id": str(invitation.token_reference)},
        ).exists())
        outbox_event = OutboxEvent.objects.get(
            event_type="staff_account.invitation_requested",
            payload_json={"invitation_id": str(invitation.token_reference)},
        )
        self.assertTrue(NotificationTemplate.objects.filter(stable_key="staff_activation", status="active").exists())
        handle_staff_account_invitation_event(
            {"invitation_id": str(invitation.token_reference)}, outbox_event,
        )
        self.assertTrue(EmailDelivery.objects.filter(
            template_key="staff_activation", related_object_id=str(invitation.pk),
        ).exists())

    def test_non_head_roles_and_legacy_accounts_cannot_provision(self):
        actors = [
            make_user("regular@example.test", RoleChoices.COUNSELOR),
            make_user("gco@example.test", RoleChoices.GCO_STAFF),
            make_user("student@example.test", RoleChoices.STUDENT),
            make_user("it@example.test", RoleChoices.IT_ADMIN),
            make_user("inactive-head@example.test", RoleChoices.COUNSELOR, active=False),
            make_user("legacy-head@example.test", RoleChoices.COUNSELOR, superuser=True),
        ]
        for index, actor in enumerate(actors):
            with self.subTest(actor=actor.email):
                with self.assertRaises(PermissionDeniedError):
                    provision_staff_account(actor, self.command(email=f"blocked-{index}@example.test"))

    def test_it_admin_is_bootstrap_only_and_has_no_profile(self):
        with self.assertRaises(PermissionDeniedError):
            provision_staff_account(self.head, self.command(RoleChoices.IT_ADMIN, "it@example.test"))
        with override_settings(
            COMPASS_ACCESS_MODE="health_only",
            ACCOUNT_ACTIVATION_TOKEN_SECRET="test-bootstrap-secret",
        ):
            it_admin = bootstrap_it_admin(ITAdminBootstrapCommand(
                email="bootstrap-it@example.test",
                first_name="Bootstrap",
                last_name="Admin",
                password="A-valid-long-password-123!",
            ))
        self.assertTrue(it_admin.is_active)
        self.assertFalse(hasattr(it_admin, "counselor_profile"))
        self.assertFalse(hasattr(it_admin, "staff_profile"))
        self.assertFalse(StaffAccountInvitation.objects.filter(user=it_admin).exists())

    def test_duplicate_email_is_atomic(self):
        existing = make_user("duplicate@example.test", RoleChoices.STUDENT)
        with self.assertRaises(ValidationError):
            provision_staff_account(self.head, self.command(email=existing.email))
        self.assertFalse(User.objects.filter(email="duplicate@example.test", role=RoleChoices.COUNSELOR).exists())

    def test_initial_head_is_bootstrap_only_and_multiple_heads_fail_closed(self):
        make_user("bootstrap-it@example.test", RoleChoices.IT_ADMIN)
        with self.assertRaises(LifecycleConflictError):
            with override_settings(
                COMPASS_ACCESS_MODE="health_only",
                ACCOUNT_ACTIVATION_TOKEN_SECRET="test-bootstrap-secret",
                COMPASS_CLIENT_BASE_URL="http://localhost:3000",
            ):
                bootstrap_initial_head_guidance(InitialHeadGuidanceBootstrapCommand(
                    email="initial-head@example.test",
                    first_name="Initial",
                    last_name="Head",
                ))

    def test_head_cannot_self_designate(self):
        with self.assertRaises(PermissionDeniedError):
            assign_head_guidance(self.head, self.head)


class InstitutionalBootstrapTests(TestCase):
    bootstrap_settings = override_settings(
        COMPASS_ACCESS_MODE="health_only",
        ACCOUNT_ACTIVATION_TOKEN_SECRET="test-bootstrap-secret",
        COMPASS_CLIENT_BASE_URL="http://localhost:3000",
    )

    def it_admin_command(self, email="it-admin@example.test"):
        return ITAdminBootstrapCommand(
            email=email,
            first_name="Institutional",
            last_name="Admin",
            password="A-valid-long-password-123!",
        )

    def head_command(self, email="initial-head@example.test"):
        return InitialHeadGuidanceBootstrapCommand(
            email=email,
            first_name="Initial",
            last_name="Head",
            license_number="LIC-001",
        )

    def test_bootstrap_commands_are_frozen_and_password_is_redacted(self):
        command = self.it_admin_command()
        with self.assertRaises(FrozenInstanceError):
            command.email = "changed@example.test"
        self.assertNotIn(command.password, repr(command))
        with self.assertRaises(ValidationError):
            ITAdminBootstrapCommand(
                email={"email": "model-or-mapping"},
                first_name="Initial",
                last_name="Admin",
                password="A-valid-long-password-123!",
            )

    @bootstrap_settings
    def test_it_admin_bootstrap_is_login_ready_and_has_no_profile_or_invitation(self):
        user = bootstrap_it_admin(self.it_admin_command())
        self.assertTrue(user.is_active)
        self.assertTrue(user.check_password("A-valid-long-password-123!"))
        self.assertEqual(user.role, RoleChoices.IT_ADMIN)
        self.assertFalse(CounselorProfile.objects.filter(user=user).exists())
        self.assertFalse(GCOStaffProfile.objects.filter(user=user).exists())
        self.assertFalse(StaffAccountInvitation.objects.filter(user=user).exists())

        with self.assertRaises(LifecycleConflictError):
            bootstrap_it_admin(self.it_admin_command(email="second-it@example.test"))

    def test_it_admin_bootstrap_requires_health_only_mode(self):
        with override_settings(COMPASS_ACCESS_MODE="active"):
            with self.assertRaises(PermissionDeniedError):
                bootstrap_it_admin(self.it_admin_command())
        self.assertFalse(User.objects.filter(email="it-admin@example.test").exists())

    @bootstrap_settings
    def test_initial_head_requires_active_it_admin_and_is_inactive_until_activation(self):
        with self.assertRaises(LifecycleConflictError):
            bootstrap_initial_head_guidance(self.head_command())

        it_admin = bootstrap_it_admin(self.it_admin_command())
        head, invitation = bootstrap_initial_head_guidance(self.head_command())
        head.refresh_from_db()
        self.assertFalse(head.is_active)
        self.assertEqual(head.role, RoleChoices.COUNSELOR)
        self.assertTrue(CounselorProfile.objects.get(user=head).is_head_guidance)
        self.assertEqual(invitation.created_by_id, it_admin.pk)
        self.assertTrue(OutboxEvent.objects.filter(
            event_type="staff_account.invitation_requested",
            payload_json={"invitation_id": str(invitation.token_reference)},
        ).exists())

        raw_token = issue_activation_token(invitation, ActivationPurpose.STAFF)
        activated = activate_staff_invitation(StaffInvitationActivationCommand(
            token=raw_token,
            password="A-valid-long-password-123!",
            password_confirmation="A-valid-long-password-123!",
        ))
        activated.refresh_from_db()
        self.assertTrue(activated.is_active)
        self.assertTrue(is_head_guidance(activated))

    @bootstrap_settings
    def test_initial_head_rolls_back_when_activation_configuration_is_missing(self):
        bootstrap_it_admin(self.it_admin_command())
        with override_settings(COMPASS_CLIENT_BASE_URL=""):
            with self.assertRaises(ValidationError):
                bootstrap_initial_head_guidance(self.head_command())
        self.assertFalse(User.objects.filter(email="initial-head@example.test").exists())
        self.assertFalse(StaffAccountInvitation.objects.exists())

    @bootstrap_settings
    def test_bootstrap_management_commands_emit_only_safe_receipts(self):
        output = StringIO()
        with patch("sys.stdin", StringIO("A-valid-long-password-123!\nA-valid-long-password-123!\n")):
            call_command(
                "bootstrap_it_admin",
                email="command-it@example.test",
                first_name="Command",
                last_name="Admin",
                password_stdin=True,
                confirm=True,
                stdout=output,
            )
        rendered = output.getvalue()
        self.assertIn("IT_ADMIN_BOOTSTRAP_STATUS=created", rendered)
        self.assertNotIn("A-valid-long-password-123!", rendered)

        output = StringIO()
        call_command(
            "bootstrap_initial_head_guidance",
            email="command-head@example.test",
            first_name="Command",
            last_name="Head",
            confirm=True,
            stdout=output,
        )
        rendered = output.getvalue()
        invitation = StaffAccountInvitation.objects.get(user__email="command-head@example.test")
        raw_token = issue_activation_token(invitation, ActivationPurpose.STAFF)
        self.assertIn("INITIAL_HEAD_GUIDANCE_BOOTSTRAP_STATUS=created", rendered)
        self.assertIn("invitation=queued", rendered)
        self.assertNotIn(raw_token, rendered)


class StaffInvitationLifecycleTests(TestCase):
    def setUp(self):
        self.head = make_user("head@example.test", RoleChoices.COUNSELOR)
        CounselorProfile.objects.create(user=self.head, is_head_guidance=True)
        self.user, self.invitation = provision_staff_account(
            self.head,
            StaffAccountCreateCommand(
                email="invitee@example.test", first_name="Invite", last_name="E", role=RoleChoices.COUNSELOR,
            ),
        )

    def test_invitation_is_hash_only_single_use_and_activation_verifies_email(self):
        raw_token = issue_activation_token(self.invitation, ActivationPurpose.STAFF)
        self.assertNotEqual(raw_token, self.invitation.token_hash)
        self.assertNotIn(raw_token, self.invitation.token_hash)
        activated = activate_staff_invitation(StaffInvitationActivationCommand(
            token=raw_token,
            password="A-valid-long-password-123!",
            password_confirmation="A-valid-long-password-123!",
        ))
        self.assertEqual(activated.pk, self.user.pk)
        activated.refresh_from_db()
        self.invitation.refresh_from_db()
        self.assertTrue(activated.is_active)
        self.assertIsNotNone(self.invitation.used_at)
        with self.assertRaises(ValidationError):
            activate_staff_invitation(StaffInvitationActivationCommand(
                token=raw_token,
                password="A-valid-long-password-123!",
                password_confirmation="A-valid-long-password-123!",
            ))

    def test_reissue_revokes_previous_and_revoke_cancels_current(self):
        replacement = reissue_staff_invitation(self.head, self.user)
        self.invitation.refresh_from_db()
        self.assertIsNotNone(self.invitation.revoked_at)
        self.assertIsNone(replacement.used_at)
        revoked = revoke_staff_invitation(self.head, replacement)
        self.assertIsNotNone(revoked.revoked_at)

    def test_expired_or_mismatched_invitation_denies_activation(self):
        self.invitation.expires_at = timezone.now() - timedelta(minutes=1)
        self.invitation.save(update_fields=["expires_at"])
        with self.assertRaises(ValidationError):
            activate_staff_invitation(StaffInvitationActivationCommand(
                token=issue_activation_token(self.invitation, ActivationPurpose.STAFF),
                password="A-valid-long-password-123!",
                password_confirmation="A-valid-long-password-123!",
            ))

    def test_deactivation_revokes_pending_invitation_and_prevents_head_deactivation(self):
        deactivated = deactivate_staff_account(self.head, self.user)
        self.assertFalse(deactivated.is_active)
        self.invitation.refresh_from_db()
        self.assertIsNotNone(self.invitation.revoked_at)
        with self.assertRaises(LifecycleConflictError):
            deactivate_staff_account(self.head, self.head)


class StaffAccountApiTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.head = make_user("api-head@example.test", RoleChoices.COUNSELOR)
        CounselorProfile.objects.create(user=self.head, is_head_guidance=True)
        self.access_token = issue_token_pair(self.head, assurance_verified=True).access_token

    def headers(self):
        return {"HTTP_AUTHORIZATION": f"Bearer {self.access_token}"}

    def test_authenticated_head_can_create_and_list_staff_without_secrets(self):
        response = self.client.post(
            "/api/v1/staff-accounts/",
            data={
                "email": "api-created@example.test",
                "first_name": "API",
                "last_name": "Created",
                "role": RoleChoices.GCO_STAFF,
            },
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="staff-create-001",
            **self.headers(),
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertFalse(payload["is_active"])
        serialized = response.content.decode()
        self.assertNotIn("token_hash", serialized)
        self.assertNotIn("password", serialized)
        listing = self.client.get("/api/v1/staff-accounts/", **self.headers())
        self.assertEqual(listing.status_code, 200)
        self.assertTrue(any(item["email"] == "api-created@example.test" for item in listing.json()["items"]))

    def test_staff_accounts_api_cannot_create_it_admin(self):
        response = self.client.post(
            "/api/v1/staff-accounts/",
            data={
                "email": "api-it-admin@example.test",
                "first_name": "API",
                "last_name": "IT",
                "role": RoleChoices.IT_ADMIN,
            },
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="staff-create-it-admin-001",
            **self.headers(),
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(User.objects.filter(email="api-it-admin@example.test").exists())

    def test_staff_activation_endpoint_consumes_invitation(self):
        user, invitation = provision_staff_account(
            self.head,
            StaffAccountCreateCommand(
                email="api-activation@example.test", first_name="Activation", last_name="User",
                role=RoleChoices.COUNSELOR,
            ),
        )
        raw_token = issue_activation_token(invitation, ActivationPurpose.STAFF)
        response = self.client.post(
            "/api/v1/auth/staff-activation/",
            data={
                "token": raw_token,
                "password": "A-valid-long-password-123!",
                "password_confirmation": "A-valid-long-password-123!",
            },
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        user.refresh_from_db()
        self.assertTrue(user.is_active)

    def test_static_head_guidance_route_is_not_captured_as_user_id(self):
        target = make_user("target-counselor@example.test", RoleChoices.COUNSELOR)
        CounselorProfile.objects.create(user=target)
        response = self.client.post(
            "/api/v1/staff-accounts/head-guidance/assign/",
            data={"user_id": target.pk},
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="head-assign-001",
            **self.headers(),
        )
        # A current Head cannot create a second active Head; 409 also proves
        # the static route resolved to the designation service rather than the
        # integer user-id route.
        self.assertEqual(response.status_code, 409)

    def test_staff_mutation_requires_and_replays_idempotency_key(self):
        payload = {
            "email": "idempotent-staff@example.test",
            "first_name": "Idempotent",
            "last_name": "Staff",
            "role": RoleChoices.GCO_STAFF,
        }
        missing = self.client.post(
            "/api/v1/staff-accounts/",
            data=payload,
            content_type="application/json",
            **self.headers(),
        )
        self.assertEqual(missing.status_code, 422)
        self.assertEqual(missing.json()["code"], "validation")

        first = self.client.post(
            "/api/v1/staff-accounts/",
            data=payload,
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="staff-replay-001",
            **self.headers(),
        )
        replay = self.client.post(
            "/api/v1/staff-accounts/",
            data=payload,
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="staff-replay-001",
            **self.headers(),
        )
        self.assertEqual(first.status_code, 200)
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.json()["id"], first.json()["id"])

        conflict = self.client.post(
            "/api/v1/staff-accounts/",
            data={**payload, "email": "different-staff@example.test"},
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="staff-replay-001",
            **self.headers(),
        )
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json()["code"], "lifecycle_conflict")


class HeadGuidanceResponseSchemaContractTests(TestCase):
    def setUp(self):
        self.head = make_user("schema-head@example.test", RoleChoices.COUNSELOR)
        self.profile = CounselorProfile.objects.create(
            user=self.head,
            is_head_guidance=True,
        )

    def test_designation_projection_and_replay_match_output_schema(self):
        projection = project_head_designation(self.profile)
        self.assertEqual(
            set(projection),
            {"user_id", "is_head_guidance", "designated_at"},
        )
        validated = HeadGuidanceProjectionSchema(**projection)
        self.assertEqual(validated.user_id, self.head.pk)
        self.assertTrue(validated.is_head_guidance)

        replay = project_head_designation(
            CounselorProfile.objects.get(pk=self.profile.pk),
        )
        self.assertEqual(replay, projection)
        self.assertEqual(
            HeadGuidanceProjectionSchema(**replay).user_id,
            self.head.pk,
        )
        for forbidden in (
            "token",
            "token_hash",
            "password",
            "employee_number",
            "license_number",
            "actor_user_id",
            "expected_updated_at",
        ):
            self.assertNotIn(forbidden, projection)
