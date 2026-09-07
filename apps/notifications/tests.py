from datetime import timedelta
from dataclasses import FrozenInstanceError
from io import StringIO
from unittest.mock import patch

from django.core.management import call_command, get_commands
from django.test import Client, TestCase
from django.utils import timezone

from apps.account_security.api_tokens import issue_token_pair
from apps.accounts.models import RoleChoices, User
from apps.common.exceptions import LifecycleConflictError, NotFoundError, PermissionDeniedError, ValidationError
from apps.notifications.commands import (
    DeadLetterReason,
    EmailDeliveryDeadLetterCommand,
    EmailDeliveryRetryCommand,
    NotificationArchiveCommand,
    NotificationPreferenceUpdateCommand,
    NotificationReadCommand,
)
from apps.notifications.models import Notification, NotificationPreference
from apps.notifications.policies import can_manage_preferences, can_read_notification
from apps.notifications.selectors import get_user_notifications, get_user_preferences
from apps.notifications.services import (
    archive_notification,
    mark_email_delivery_dead,
    mark_notification_read,
    retry_email_delivery,
    update_notification_preference,
)
from apps.notifications.email_adapters import DjangoEmailAdapter


def _user(email, *, active=True, superuser=False):
    user = User.objects.create_user(
        email=email,
        password="correct-horse-battery-staple",
        role=RoleChoices.STUDENT,
        is_active=active,
    )
    if superuser:
        user.is_superuser = True
        user.save(update_fields=["is_superuser"])
    return user


class NotificationOwnerBoundaryTests(TestCase):
    def test_active_owner_can_read_only_owned_notifications_and_preferences(self):
        owner = _user("notification-owner@example.test")
        other = _user("notification-other@example.test")
        notification = Notification.objects.create(
            dedupe_key="notification-owner-1",
            recipient_user=owner,
            notification_type="TEST",
            title="Test",
            body_preview="Safe preview",
        )
        NotificationPreference.objects.create(
            user=owner,
            notification_type="TEST",
        )

        self.assertTrue(can_read_notification(owner, notification))
        self.assertFalse(can_read_notification(other, notification))
        self.assertEqual(get_user_notifications(owner).count(), 1)
        self.assertEqual(get_user_notifications(other).count(), 0)
        self.assertEqual(get_user_preferences(owner).count(), 1)

    def test_inactive_and_legacy_owners_fail_closed_even_for_self(self):
        inactive = _user("notification-inactive@example.test", active=False)
        legacy = _user("notification-legacy@example.test", superuser=True)
        for actor, key in ((inactive, "inactive"), (legacy, "legacy")):
            notification = Notification.objects.create(
                dedupe_key=f"notification-{key}",
                recipient_user=actor,
                notification_type="TEST",
                title="Test",
                body_preview="Safe preview",
            )
            self.assertFalse(can_read_notification(actor, notification))
            self.assertFalse(can_manage_preferences(actor, actor))
            self.assertEqual(get_user_notifications(actor).count(), 0)
            self.assertEqual(get_user_preferences(actor).count(), 0)


class EmailAdapterTests(TestCase):
    def test_sends_using_the_explicit_django_connection(self):
        class FakeConnection:
            timeout = None

            def __init__(self):
                self.messages = []

            def send_messages(self, messages):
                self.messages.extend(messages)
                return len(messages)

        connection = FakeConnection()
        with (
            patch("apps.notifications.email_adapters.get_connection", return_value=connection),
            patch("apps.notifications.email_adapters.resolve_runtime_setting", return_value=10),
        ):
            message_id = DjangoEmailAdapter().send_email(
                recipient_email="recipient@example.test",
                subject="Test subject",
                text_content="Test body",
            )

        self.assertTrue(message_id.startswith("msg_"))
        self.assertEqual(len(connection.messages), 1)
        self.assertEqual(connection.messages[0].subject, "Test subject")


class NotificationCommandAndServiceTests(TestCase):
    def setUp(self):
        self.owner = _user("notification-service-owner@example.test")
        self.other = _user("notification-service-other@example.test")
        self.notification = Notification.objects.create(
            dedupe_key="notification-service-1",
            recipient_user=self.owner,
            notification_type="appointment_scheduled",
            title="Appointment update",
            body_preview="Your appointment is ready.",
        )

    def test_notification_worker_stays_idle_when_policy_disables_delivery(self):
        output = StringIO()
        values = {
            "NOTIFICATION_WORKER_ENABLED": False,
            "NOTIFICATION_WORKER_BATCH_SIZE": 20,
            "NOTIFICATION_WORKER_LOCK_TIMEOUT_SECONDS": 300,
            "NOTIFICATION_WORKER_INTERVAL_SECONDS": 5,
        }

        def runtime_value(_policy_key, setting_key):
            return values[setting_key]

        with (
            patch(
                "apps.notifications.management.commands.process_notification_queue.resolve_runtime_setting",
                side_effect=runtime_value,
            ),
            patch("apps.notifications.management.commands.process_notification_queue.process_outbox_batch") as outbox,
            patch("apps.notifications.management.commands.process_notification_queue.process_email_delivery_batch") as email,
        ):
            call_command("process_notification_queue", once=True, stdout=output)

        outbox.assert_not_called()
        email.assert_not_called()
        self.assertIn("NOTIFICATION_WORKER=DISABLED", output.getvalue())

    def test_notification_worker_processes_both_queues_when_policy_enables_delivery(self):
        output = StringIO()
        values = {
            "NOTIFICATION_WORKER_ENABLED": True,
            "NOTIFICATION_WORKER_BATCH_SIZE": 20,
            "NOTIFICATION_WORKER_LOCK_TIMEOUT_SECONDS": 300,
            "NOTIFICATION_WORKER_INTERVAL_SECONDS": 5,
        }

        def runtime_value(_policy_key, setting_key):
            return values[setting_key]

        with (
            patch(
                "apps.notifications.management.commands.process_notification_queue.resolve_runtime_setting",
                side_effect=runtime_value,
            ),
            patch(
                "apps.notifications.management.commands.process_notification_queue.process_outbox_batch",
                return_value=3,
            ) as outbox,
            patch(
                "apps.notifications.management.commands.process_notification_queue.process_email_delivery_batch",
                return_value=4,
            ) as email,
        ):
            call_command(
                "process_notification_queue",
                once=True,
                batch_size=7,
                lock_timeout=11,
                stdout=output,
            )

        outbox.assert_called_once()
        email.assert_called_once()
        self.assertEqual(outbox.call_args.kwargs["batch_size"], 7)
        self.assertEqual(email.call_args.kwargs["batch_size"], 7)
        self.assertEqual(outbox.call_args.kwargs["lock_timeout_seconds"], 11)
        self.assertEqual(email.call_args.kwargs["lock_timeout_seconds"], 11)
        self.assertEqual(
            outbox.call_args.kwargs["worker_id"],
            email.call_args.kwargs["worker_id"],
        )
        self.assertIn("Processed outbox=3 email=4", output.getvalue())

    def test_deprecated_queue_entrypoints_are_not_registered(self):
        commands = get_commands()
        self.assertNotIn("process_email_deliveries", commands)
        self.assertNotIn("process_outbox_events", commands)

    def test_commands_are_frozen_and_service_rejects_untyped_inputs(self):
        command = NotificationReadCommand(expected_status="unread")
        with self.assertRaises(FrozenInstanceError):
            command.expected_status = "read"
        with self.assertRaises(ValidationError):
            mark_notification_read(
                actor=self.owner,
                notification_id=self.notification.pk,
                command={"expected_status": "unread"},
            )
        with self.assertRaises(ValidationError):
            NotificationPreferenceUpdateCommand(
                notification_type="appointment_scheduled",
                in_app_enabled="yes",
                email_enabled=True,
            )

    def test_owner_mutations_reload_and_lock_and_non_owner_cannot_mutate(self):
        updated = mark_notification_read(
            actor=self.owner,
            notification_id=self.notification.pk,
            command=NotificationReadCommand(expected_status="unread"),
        )
        self.assertEqual(updated.status, "read")
        with self.assertRaises(NotFoundError):
            archive_notification(
                actor=self.other,
                notification_id=self.notification.pk,
                command=NotificationArchiveCommand(),
            )
        archived = archive_notification(
            actor=self.owner,
            notification_id=self.notification.pk,
            command=NotificationArchiveCommand(expected_status="read"),
        )
        self.assertEqual(archived.status, "archived")
        with self.assertRaises(LifecycleConflictError):
            mark_notification_read(
                actor=self.owner,
                notification_id=self.notification.pk,
                command=NotificationReadCommand(expected_status="unread"),
            )

    def test_preferences_are_catalog_bound_and_mandatory_security_cannot_be_disabled(self):
        preference = update_notification_preference(
            actor=self.owner,
            command=NotificationPreferenceUpdateCommand(
                notification_type="appointment_scheduled",
                in_app_enabled=False,
                email_enabled=True,
            ),
        )
        self.assertFalse(preference.in_app_enabled)
        with self.assertRaises(ValidationError):
            update_notification_preference(
                actor=self.owner,
                command=NotificationPreferenceUpdateCommand(
                    notification_type="password_changed",
                    in_app_enabled=False,
                    email_enabled=True,
                ),
            )
        with self.assertRaises(ValidationError):
            update_notification_preference(
                actor=self.owner,
                command=NotificationPreferenceUpdateCommand(
                    notification_type="not-in-catalog",
                    in_app_enabled=True,
                    email_enabled=True,
                ),
            )


class NotificationApiTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.student = _user("notification-api-student@example.test")
        self.other = _user("notification-api-other@example.test")
        self.it_admin = _user("notification-api-it@example.test")
        self.it_admin.role = RoleChoices.IT_ADMIN
        self.it_admin.save(update_fields=["role"])
        self.student_token = issue_token_pair(self.student, assurance_verified=True).access_token
        self.other_token = issue_token_pair(self.other, assurance_verified=True).access_token
        self.it_token = issue_token_pair(self.it_admin, assurance_verified=True).access_token
        self.notification = Notification.objects.create(
            dedupe_key="notification-api-1",
            recipient_user=self.student,
            notification_type="appointment_scheduled",
            title="Appointment update",
            body_preview="Your appointment is ready.",
            metadata_json={"safe": "value", "student_number": "must-not-leak"},
        )

    @staticmethod
    def headers(token, key=None):
        value = {"HTTP_AUTHORIZATION": f"Bearer {token}"}
        if key:
            value["HTTP_IDEMPOTENCY_KEY"] = key
        return value

    def test_owner_inbox_and_mutations_use_safe_projection_and_idempotency(self):
        response = self.client.get("/api/v1/notifications/?page=1&page_size=100", **self.headers(self.student_token))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["items"][0]["id"], str(self.notification.pk))
        body = response.content.decode()
        self.assertNotIn("student_number", body)
        self.assertNotIn("recipient_user", body)
        self.assertTrue(response["X-Request-ID"].startswith("REQ-"))
        self.assertEqual(response["Cache-Control"], "no-store")

        read = self.client.post(
            f"/api/v1/notifications/{self.notification.pk}/read/",
            data={"expected_status": "unread"},
            content_type="application/json",
            **self.headers(self.student_token, "notification-read-1"),
        )
        replay = self.client.post(
            f"/api/v1/notifications/{self.notification.pk}/read/",
            data={"expected_status": "unread"},
            content_type="application/json",
            **self.headers(self.student_token, "notification-read-1"),
        )
        self.assertEqual(read.status_code, 200)
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.json()["status"], "read")

        archive = self.client.post(
            f"/api/v1/notifications/{self.notification.pk}/archive/",
            data={"expected_status": "read"},
            content_type="application/json",
            **self.headers(self.student_token, "notification-archive-1"),
        )
        self.assertEqual(archive.status_code, 200)
        self.assertEqual(archive.json()["status"], "archived")

    def test_non_owner_and_inactive_access_fail_closed(self):
        response = self.client.get(
            f"/api/v1/notifications/{self.notification.pk}/",
            **self.headers(self.other_token),
        )
        self.assertEqual(response.status_code, 404)

        self.student.is_active = False
        self.student.save(update_fields=["is_active"])
        response = self.client.get("/api/v1/notifications/", **self.headers(self.student_token))
        self.assertIn(response.status_code, {401, 403})

    def test_preferences_expose_catalog_and_reject_mandatory_disable(self):
        catalog = self.client.get(
            "/api/v1/notifications/preferences/catalog/?page=1&page_size=100",
            **self.headers(self.student_token),
        )
        self.assertEqual(catalog.status_code, 200)
        self.assertTrue(any(item["notification_type"] == "password_changed" for item in catalog.json()["items"]))

        update = self.client.put(
            "/api/v1/notifications/preferences/appointment_scheduled/",
            data={"in_app_enabled": False, "email_enabled": True},
            content_type="application/json",
            **self.headers(self.student_token, "notification-preference-1"),
        )
        self.assertEqual(update.status_code, 200)
        self.assertFalse(update.json()["in_app_enabled"])

        forbidden = self.client.put(
            "/api/v1/notifications/preferences/password_changed/",
            data={"in_app_enabled": False, "email_enabled": False},
            content_type="application/json",
            **self.headers(self.student_token, "notification-preference-2"),
        )
        self.assertEqual(forbidden.status_code, 422)
        self.assertEqual(forbidden.json()["code"], "validation")

    def test_it_delivery_projection_and_lifecycle_are_technical_only(self):
        delivery = Notification.objects.get(pk=self.notification.pk)
        from apps.notifications.models import EmailDelivery
        email_delivery = EmailDelivery.objects.create(
            delivery_key="notification-delivery-api-1",
            recipient_user=self.student,
            recipient_email="student-secret@example.test",
            notification=delivery,
            template_key="appointment_update",
            subject="Sensitive subject must not be exposed",
            context_json={"student_number": "must-not-leak"},
            status="failed",
            delivery_state="delayed",
            next_retry_at=timezone.now(),
            provider_message_id="provider-secret",
            related_object_id="related-secret",
            last_error_code="PROVIDER_INTERNAL_EMAIL",
            last_error_safe_summary="Provider failed for secret@example.test; see https://provider.test/token=secret-token.",
        )
        listing = self.client.get(
            "/api/v1/notifications/delivery/?page=1&page_size=100",
            **self.headers(self.it_token),
        )
        self.assertEqual(listing.status_code, 200)
        body = listing.content.decode()
        self.assertIn(str(email_delivery.pk), body)
        for forbidden in (
            "student-secret@example.test",
            "Sensitive subject",
            "provider-secret",
            "related-secret",
            "student_number",
            "secret@example.test",
            "secret-token",
            "provider.test",
        ):
            self.assertNotIn(forbidden, body)

        student_denied = self.client.get(
            "/api/v1/notifications/delivery/?page=1&page_size=100",
            **self.headers(self.student_token),
        )
        self.assertEqual(student_denied.status_code, 403)

        retry = self.client.post(
            f"/api/v1/notifications/delivery/{email_delivery.pk}/retry/",
            content_type="application/json",
            **self.headers(self.it_token, "notification-delivery-retry-1"),
        )
        self.assertEqual(retry.status_code, 200)
        self.assertEqual(retry.json()["delivery_state"], "queued")

        dead = self.client.post(
            f"/api/v1/notifications/delivery/{email_delivery.pk}/dead-letter/",
            data={"reason": DeadLetterReason.MANUAL_OPERATIONAL_REVIEW.value},
            content_type="application/json",
            **self.headers(self.it_token, "notification-delivery-dead-1"),
        )
        self.assertEqual(dead.status_code, 200)
        self.assertEqual(dead.json()["status"], "dead")
        self.assertNotIn(DeadLetterReason.MANUAL_OPERATIONAL_REVIEW.value, dead.content.decode())
