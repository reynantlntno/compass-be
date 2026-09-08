"""Focused API foundation tests for bearer auth and versioned routing."""

import io
import json
import uuid
from datetime import timedelta
from unittest.mock import patch

from django.http import HttpResponse
from django.test import Client, RequestFactory, TestCase, override_settings
from django.utils import timezone

from apps.account_security.assurance import ASSURANCE_CONTEXT, ASSURANCE_POLICY_VERSION
from apps.account_security.api_tokens import issue_token_pair
from apps.account_security.models import (
    ApiSession,
    ApiSessionStatusChoices,
    ApiToken,
    ApiTokenStatusChoices,
    TrustedDevice,
    TwoStepChallenge,
)
from apps.account_security.commands import (
    PasswordChangeCommand,
    RecoveryResetCommand,
)
from apps.accounts.models import RoleChoices, User
from apps.account_security.tokens import hash_identifier, hash_token
from apps.account_security.audit import log_security_event
from apps.account_security.network import classify_network_class
from apps.account_security.selectors import get_active_sessions, get_user_activity_logs
from apps.common.contracts import PageRequest
from apps.audit.models import AuditLogEntry
from django.contrib.auth.models import AnonymousUser


class ApiFoundationTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.password = "correct-horse-battery-staple"
        self.user = User.objects.create_user(
            email="student@example.test",
            password=self.password,
            first_name="Test",
            last_name="Student",
            role=RoleChoices.STUDENT,
            is_active=True,
        )

    def _login(self, email=None, password=None):
        response = self.client.post(
            "/api/v1/auth/login/",
            data=json.dumps(
                {
                    "email": email or self.user.email,
                    "password": password or self.password,
                }
            ),
            content_type="application/json",
        )
        return response

    def test_versioned_routes_docs_and_health(self):
        health = self.client.get("/health/")
        docs = self.client.get("/api/v1/docs/")
        schema = self.client.get("/api/v1/openapi.json")
        old_file_route = self.client.get(f"/api/files/{uuid.uuid4()}/download/")

        self.assertEqual(health.status_code, 200)
        self.assertEqual(health["X-Robots-Tag"], "noindex, nofollow, noarchive")
        self.assertEqual(docs.status_code, 200)
        self.assertEqual(docs["X-Robots-Tag"], "noindex, nofollow, noarchive")
        self.assertEqual(schema.status_code, 200)
        self.assertEqual(schema["X-Robots-Tag"], "noindex, nofollow, noarchive")
        self.assertEqual(old_file_route.status_code, 404)

        document = schema.json()
        self.assertEqual(document["info"]["version"], "1.0.0")
        self.assertIn("/api/v1/auth/login/", document["paths"])
        self.assertIn("/api/v1/files/{file_id}/download/", document["paths"])
        self.assertIn("204", document["paths"]["/api/v1/auth/logout/"]["post"]["responses"])
        security_schemes = document["components"]["securitySchemes"]
        self.assertIn("CompassBearerAuthentication", security_schemes)
        self.assertEqual(security_schemes["CompassBearerAuthentication"]["scheme"], "bearer")

    def test_anonymous_api_request_is_rejected(self):
        response = self.client.get("/api/v1/auth/me/")

        self.assertEqual(response.status_code, 401)
        payload = response.json()
        self.assertEqual(payload["code"], "unauthenticated")
        self.assertEqual(payload["detail"], "Authentication is required.")
        self.assertTrue(payload["request_id"].startswith("REQ-"))

    def test_student_login_and_authenticated_me(self):
        response = self._login()

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["token_type"], "Bearer")
        self.assertTrue(payload["access_token"])
        self.assertTrue(payload["refresh_token"])
        self.assertEqual(ApiToken.objects.count(), 2)
        self.assertFalse(
            ApiToken.objects.filter(token_hash=payload["access_token"]).exists()
        )

        me = self.client.get(
            "/api/v1/auth/me/",
            HTTP_AUTHORIZATION=f"Bearer {payload['access_token']}",
        )

        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.json()["email"], self.user.email)
        self.assertEqual(me.json()["role"], RoleChoices.STUDENT)

    def test_invalid_credentials_have_same_safe_response(self):
        wrong_password = self._login(password="wrong-password")
        unknown_email = self._login(email="unknown@example.test")

        self.assertEqual(wrong_password.status_code, 401)
        self.assertEqual(unknown_email.status_code, 401)
        wrong_payload = wrong_password.json()
        unknown_payload = unknown_email.json()
        self.assertEqual(wrong_payload["detail"], "Invalid credentials.")
        self.assertEqual(wrong_payload["code"], "unauthenticated")
        self.assertEqual(wrong_payload["field_errors"], {})
        self.assertEqual(wrong_payload["detail"], unknown_payload["detail"])
        self.assertEqual(wrong_payload["code"], unknown_payload["code"])
        self.assertNotEqual(wrong_payload["request_id"], unknown_payload["request_id"])

    def test_refresh_rotation_and_reuse_revokes_family(self):
        initial = self._login().json()
        rotated = self.client.post(
            "/api/v1/auth/token/refresh/",
            data=json.dumps({"refresh_token": initial["refresh_token"]}),
            content_type="application/json",
        )

        self.assertEqual(rotated.status_code, 200)
        rotated_payload = rotated.json()
        self.assertNotEqual(rotated_payload["refresh_token"], initial["refresh_token"])

        reuse = self.client.post(
            "/api/v1/auth/token/refresh/",
            data=json.dumps({"refresh_token": initial["refresh_token"]}),
            content_type="application/json",
        )

        self.assertEqual(reuse.status_code, 401)
        self.assertEqual(
            ApiToken.objects.filter(status=ApiTokenStatusChoices.ACTIVE).count(),
            0,
        )

    def test_logout_revokes_token_family(self):
        pair = self._login().json()
        logout = self.client.post(
            "/api/v1/auth/logout/",
            HTTP_AUTHORIZATION=f"Bearer {pair['access_token']}",
        )
        me = self.client.get(
            "/api/v1/auth/me/",
            HTTP_AUTHORIZATION=f"Bearer {pair['access_token']}",
        )

        self.assertEqual(logout.status_code, 204)
        self.assertEqual(me.status_code, 401)

    def test_security_stamp_invalidates_existing_access_token(self):
        pair = self._login().json()
        self.user.rotate_auth_security_stamp()

        response = self.client.get(
            "/api/v1/auth/me/",
            HTTP_AUTHORIZATION=f"Bearer {pair['access_token']}",
        )

        self.assertEqual(response.status_code, 401)

    def test_password_change_revokes_active_api_tokens(self):
        self._login()

        self.user.set_password("new-password")
        self.user.save(update_fields=["password"])

        self.assertEqual(
            ApiToken.objects.filter(status=ApiTokenStatusChoices.ACTIVE).count(),
            0,
        )

    def test_role_change_and_deactivation_revoke_active_api_tokens(self):
        self._login()
        self.user.role = RoleChoices.COUNSELOR
        self.user.save(update_fields=["role"])
        self.assertEqual(
            ApiToken.objects.filter(status=ApiTokenStatusChoices.ACTIVE).count(),
            0,
        )

        second_user = User.objects.create_user(
            email="inactive-student@example.test",
            password=self.password,
            role=RoleChoices.STUDENT,
            is_active=True,
        )
        issue_token_pair(second_user)
        second_user.is_active = False
        second_user.save(update_fields=["is_active"])
        self.assertEqual(
            ApiToken.objects.filter(
                user=second_user,
                status=ApiTokenStatusChoices.ACTIVE,
            ).count(),
            0,
        )

    @patch("apps.account_security.api_tokens.create_twostep_challenge")
    def test_internal_login_stops_at_two_step_challenge(self, create_challenge):
        internal = User.objects.create_user(
            email="it-admin@example.test",
            password=self.password,
            first_name="IT",
            last_name="Admin",
            role=RoleChoices.IT_ADMIN,
            is_active=True,
        )
        challenge = TwoStepChallenge(
            id=uuid.uuid4(),
            user=internal,
            purpose="login",
            expires_at=timezone.now() + timedelta(minutes=5),
        )
        create_challenge.return_value = (challenge, None)

        response = self._login(
            email=internal.email,
            password=self.password,
        )

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()["requires_verification"], True)
        self.assertEqual(ApiToken.objects.filter(user=internal).count(), 0)

    @patch("apps.account_security.api_tokens.create_twostep_challenge")
    def test_internal_login_verification_issues_tokens_and_replay_is_rejected(
        self, create_challenge
    ):
        internal = User.objects.create_user(
            email="verified-it-admin@example.test",
            password=self.password,
            role=RoleChoices.IT_ADMIN,
            is_active=True,
        )

        def create_login_challenge(user, **kwargs):
            pending_nonce = kwargs["pending_nonce"]
            challenge = TwoStepChallenge.objects.create(
                user=user,
                purpose="login",
                otp_hash=hash_token("123456"),
                status="pending",
                delivery_email_hash=hash_identifier(user.email),
                expires_at=timezone.now() + timedelta(minutes=5),
                security_stamp=user.auth_security_stamp,
                assurance_policy_version=ASSURANCE_POLICY_VERSION,
                assurance_context=ASSURANCE_CONTEXT,
                metadata_json={"pending_nonce_hash": hash_token(pending_nonce)},
            )
            return challenge, None

        create_challenge.side_effect = create_login_challenge
        challenged = self._login(email=internal.email, password=self.password)
        verify_payload = {
            "challenge_id": challenged.json()["challenge_id"],
            "pending_nonce": challenged.json()["pending_nonce"],
            "otp": "123456",
        }

        verified = self.client.post(
            "/api/v1/auth/login/verify/",
            data=json.dumps(verify_payload),
            content_type="application/json",
        )
        replay = self.client.post(
            "/api/v1/auth/login/verify/",
            data=json.dumps(verify_payload),
            content_type="application/json",
        )

        self.assertEqual(challenged.status_code, 202)
        self.assertEqual(verified.status_code, 200)
        self.assertTrue(verified.json()["access_token"])
        self.assertEqual(replay.status_code, 401)
        self.assertEqual(ApiToken.objects.filter(user=internal).count(), 2)

    @patch("apps.account_security.api_tokens.create_twostep_challenge")
    def test_expired_internal_login_challenge_is_rejected(self, create_challenge):
        internal = User.objects.create_user(
            email="expired-it-admin@example.test",
            password=self.password,
            role=RoleChoices.IT_ADMIN,
            is_active=True,
        )

        def create_expired_challenge(user, **kwargs):
            pending_nonce = kwargs["pending_nonce"]
            challenge = TwoStepChallenge.objects.create(
                user=user,
                purpose="login",
                otp_hash=hash_token("123456"),
                status="pending",
                delivery_email_hash=hash_identifier(user.email),
                expires_at=timezone.now() - timedelta(seconds=1),
                security_stamp=user.auth_security_stamp,
                assurance_policy_version=ASSURANCE_POLICY_VERSION,
                assurance_context=ASSURANCE_CONTEXT,
                metadata_json={"pending_nonce_hash": hash_token(pending_nonce)},
            )
            return challenge, None

        create_challenge.side_effect = create_expired_challenge
        challenged = self._login(email=internal.email, password=self.password)
        verify_payload = {
            "challenge_id": challenged.json()["challenge_id"],
            "pending_nonce": challenged.json()["pending_nonce"],
            "otp": "123456",
        }
        response = self.client.post(
            "/api/v1/auth/login/verify/",
            data=json.dumps(verify_payload),
            content_type="application/json",
        )

        challenge = TwoStepChallenge.objects.get(id=verify_payload["challenge_id"])
        self.assertEqual(challenged.status_code, 202)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(challenge.status, "expired")
        self.assertEqual(ApiToken.objects.filter(user=internal).count(), 0)

    def test_new_file_route_requires_bearer_authentication(self):
        response = self.client.get(f"/api/v1/files/{uuid.uuid4()}/download/")

        self.assertEqual(response.status_code, 401)

    def test_authorized_file_download_preserves_no_store_and_audit(self):
        pair = self._login().json()
        protected_file = type("ProtectedFileStub", (), {"content_type": "application/pdf"})()
        with patch(
            "apps.security.downloads.open_protected_file_stream",
            return_value=(io.BytesIO(b"pdf-bytes"), 9, protected_file),
        ) as open_file, patch(
            "apps.security.downloads.audit_proxy_download_served"
        ) as audit_download:
            response = self.client.get(
                f"/api/v1/files/{uuid.uuid4()}/download/",
                HTTP_AUTHORIZATION=f"Bearer {pair['access_token']}",
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(b"".join(response.streaming_content), b"pdf-bytes")
        self.assertEqual(response["Cache-Control"], "no-store, private")
        self.assertEqual(response["X-Robots-Tag"], "noindex, nofollow, noarchive")
        self.assertEqual(response["X-Content-Type-Options"], "nosniff")
        open_file.assert_called_once()
        audit_download.assert_called_once()

    def test_state_changing_bearer_endpoint_is_not_cookie_csrf_authenticated(self):
        csrf_client = Client(enforce_csrf_checks=True)
        response = csrf_client.post(
            "/api/v1/auth/token/refresh/",
            data=json.dumps({"refresh_token": "invalid"}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 401)


class BearerDocsProtectionTests(TestCase):
    def test_docs_decorator_hides_schema_without_it_admin_bearer(self):
        from config.api.docs import bearer_it_admin_docs

        def protected_view(request):
            return HttpResponse("schema")

        protected = bearer_it_admin_docs(protected_view)
        response = protected(RequestFactory().get("/api/v1/openapi.json"))

        self.assertEqual(response.status_code, 404)

    def test_docs_decorator_allows_active_it_admin_bearer(self):
        from config.api.docs import bearer_it_admin_docs

        admin = User.objects.create_user(
            email="docs-admin@example.test",
            password="correct-horse-battery-staple",
            role=RoleChoices.IT_ADMIN,
            is_active=True,
        )
        # The docs boundary requires an explicitly OTP-assured API session;
        # it must not depend on a seeded Governance row being present in the
        # test database.
        pair = issue_token_pair(admin, assurance_verified=True)

        protected = bearer_it_admin_docs(lambda request: HttpResponse("schema"))
        response = protected(
            RequestFactory().get(
                "/api/v1/openapi.json",
                HTTP_AUTHORIZATION=f"Bearer {pair.access_token}",
            )
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"schema")


@override_settings(CAMPUS_NETWORK_CIDRS=["10.20.0.0/16", "172.16.0.0/12"])
class NetworkClassTests(TestCase):
    """Bounded coarse-network classification boundaries (contract boundary)."""

    def test_configured_campus_range_is_campus(self):
        self.assertEqual(classify_network_class("10.20.5.5"), "campus_network")
        self.assertEqual(classify_network_class("172.16.3.9"), "campus_network")

    def test_rfc_private_not_configured_is_private(self):
        self.assertEqual(classify_network_class("192.168.1.5"), "private_network")
        self.assertEqual(classify_network_class("10.99.1.1"), "private_network")

    def test_global_address_is_public(self):
        self.assertEqual(classify_network_class("8.8.8.8"), "public_network")
        self.assertEqual(classify_network_class("1.1.1.1"), "public_network")

    def test_loopback_is_unknown(self):
        self.assertEqual(classify_network_class("127.0.0.1"), "unknown")

    def test_link_local_is_unknown(self):
        self.assertEqual(classify_network_class("169.254.10.10"), "unknown")

    def test_unspecified_is_unknown(self):
        self.assertEqual(classify_network_class("0.0.0.0"), "unknown")

    def test_reserved_is_unknown(self):
        self.assertEqual(classify_network_class("240.0.0.1"), "unknown")

    def test_missing_and_unparseable_are_unknown(self):
        self.assertEqual(classify_network_class(""), "unknown")
        self.assertEqual(classify_network_class(None), "unknown")
        self.assertEqual(classify_network_class("not-an-ip"), "unknown")

    def test_global_outside_configured_ranges_is_not_campus(self):
        # A valid address outside every configured range is public, never campus.
        self.assertEqual(classify_network_class("8.8.8.8"), "public_network")

    def test_invalid_configured_entry_never_broadens(self):
        with override_settings(CAMPUS_NETWORK_CIDRS=["not-a-cidr"]):
            self.assertEqual(classify_network_class("192.168.1.5"), "private_network")


class ActivityProjectionTests(TestCase):
    """Account-activity display-state contract (contract boundary)."""

    def setUp(self):
        self.user = User.objects.create_user(
            email="owner@example.test",
            password="correct-horse-battery-staple",
            role=RoleChoices.STUDENT,
            is_active=True,
        )

    def _entry(self, action="login_success", severity="INFO", safe_metadata=None):
        return AuditLogEntry.objects.create(
            actor_user=self.user,
            action_type=action,
            event_category="SECURITY",
            severity=severity,
            target_model="accounts.User",
            target_object_id=str(self.user.pk),
            safe_metadata=safe_metadata or {},
        )

    def test_available_and_approximate_states(self):
        self._entry(safe_metadata={"device_label": "Chrome on macOS", "network_class": "campus_network"})
        row = get_user_activity_logs(self.user)[0]
        self.assertEqual(row["device"]["state"], "available")
        self.assertEqual(row["device"]["label"], "Chrome on macOS")
        self.assertEqual(row["network"]["state"], "approximate")

    def test_missing_metadata_is_not_captured(self):
        self._entry(safe_metadata={})
        row = get_user_activity_logs(self.user)[0]
        self.assertEqual(row["device"]["state"], "not_captured")
        self.assertEqual(row["network"]["state"], "not_captured")

    def test_unknown_device_is_not_captured(self):
        self._entry(safe_metadata={"device_label": "Unknown Device"})
        row = get_user_activity_logs(self.user)[0]
        self.assertEqual(row["device"]["state"], "not_captured")

    def test_unknown_browser_on_unknown_os_is_not_captured(self):
        self._entry(safe_metadata={"device_label": "Unknown Browser on Unknown OS"})
        row = get_user_activity_logs(self.user)[0]
        self.assertEqual(row["device"]["state"], "not_captured")

    def test_invalid_present_metadata_is_unavailable(self):
        self._entry(safe_metadata={"network_class": "totally-made-up"})
        row = get_user_activity_logs(self.user)[0]
        self.assertEqual(row["network"]["state"], "unavailable")

    def test_arbitrary_non_empty_device_summary_is_unavailable(self):
        # Regression: arbitrary non-empty stored strings must NOT project as
        # available. Only bounded browser/OS summaries may be available.
        self._entry(safe_metadata={"device_label": "Chrome on macOS <script>"})
        row = get_user_activity_logs(self.user)[0]
        self.assertEqual(row["device"]["state"], "unavailable")

    def test_partial_unknown_device_summary_is_unavailable(self):
        self._entry(safe_metadata={"device_label": "Chrome on Unknown OS"})
        row = get_user_activity_logs(self.user)[0]
        self.assertEqual(row["device"]["state"], "unavailable")

    def test_unknown_network_class_is_not_captured_not_unavailable(self):
        # Regression: the bounded "unknown" class (missing/unparseable IP
        # metadata) is a capture gap, not a decoder failure.
        self._entry(
            safe_metadata={
                "device_label": "Chrome on macOS",
                "network_class": "unknown",
            }
        )
        row = get_user_activity_logs(self.user)[0]
        self.assertEqual(row["network"]["state"], "not_captured")
        self.assertEqual(row["device"]["state"], "available")

    def test_degraded_metadata_is_unavailable(self):
        self._entry(
            safe_metadata={
                "redacted": True,
                "reason_code": "metadata_sanitization_failed",
            }
        )
        row = get_user_activity_logs(self.user)[0]
        self.assertEqual(row["device"]["state"], "unavailable")
        self.assertEqual(row["network"]["state"], "unavailable")

    def test_timestamps_are_consistent_iso_strings(self):
        from django.utils.dateparse import parse_datetime

        self._entry(safe_metadata={"device_label": "Chrome on macOS", "network_class": "public_network"})
        row = get_user_activity_logs(self.user)[0]
        self.assertIsNotNone(parse_datetime(row["created_at"]))

    def test_no_raw_values_leak(self):
        self._entry(safe_metadata={"device_label": "Chrome on macOS", "network_class": "campus_network"})
        dumped = json.dumps(get_user_activity_logs(self.user))
        self.assertNotIn("10.20.", dumped)
        self.assertNotIn("Mozilla", dumped)


class ActivitySelectorAuthTests(TestCase):
    """Account activity requires an active, non-legacy owner boundary."""

    def setUp(self):
        self.user = User.objects.create_user(
            email="owner@example.test",
            password="correct-horse-battery-staple",
            role=RoleChoices.STUDENT,
            is_active=True,
        )
        self.other = User.objects.create_user(
            email="other@example.test",
            password="correct-horse-battery-staple",
            role=RoleChoices.STUDENT,
            is_active=True,
        )

    def _entry(self, user, action="login_success", safe_metadata=None):
        return AuditLogEntry.objects.create(
            actor_user=user,
            action_type=action,
            event_category="SECURITY",
            severity="INFO",
            target_model="accounts.User",
            target_object_id=str(user.pk),
            safe_metadata=safe_metadata or {},
        )

    def test_unauthenticated_and_none_return_empty(self):
        self.assertEqual(get_user_activity_logs(None), [])
        self.assertEqual(get_user_activity_logs(AnonymousUser()), [])

    def test_owner_scoping_excludes_other_user_rows(self):
        self._entry(self.user, safe_metadata={"device_label": "Chrome on macOS"})
        self._entry(self.other, safe_metadata={"device_label": "Firefox on Linux"})
        rows = get_user_activity_logs(self.user)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["device"]["label"], "Chrome on macOS")

    def test_inactive_owner_is_denied_even_for_own_logs(self):
        inactive = User.objects.create_user(
            email="inactive@example.test",
            password="correct-horse-battery-staple",
            role=RoleChoices.STUDENT,
            is_active=False,
        )
        self._entry(inactive)
        self.assertEqual(get_user_activity_logs(inactive), [])

    def test_legacy_superuser_is_denied_even_for_own_logs(self):
        legacy = User.objects.create_user(
            email="legacy@example.test",
            password="correct-horse-battery-staple",
            role=RoleChoices.STUDENT,
            is_active=True,
        )
        legacy.is_superuser = True
        legacy.save(update_fields=["is_superuser"])
        self._entry(legacy)
        self.assertEqual(get_user_activity_logs(legacy), [])

    def test_action_filter_excludes_other_categories(self):
        self._entry(self.user, action="password_changed")
        self._entry(self.user, action="login_success")
        rows = get_user_activity_logs(self.user, days=90, action_filter="login")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["label"], "Sign-in completed")


@override_settings(CAMPUS_NETWORK_CIDRS=["10.20.0.0/16"])
class ActiveSessionsTests(TestCase):
    """Active-session projection contract (contract boundary)."""

    def setUp(self):
        self.user = User.objects.create_user(
            email="owner@example.test",
            password="correct-horse-battery-staple",
            role=RoleChoices.STUDENT,
            is_active=True,
        )
        self.other = User.objects.create_user(
            email="other@example.test",
            password="correct-horse-battery-staple",
            role=RoleChoices.STUDENT,
            is_active=True,
        )

    def _create_session(self, user, device="Chrome on macOS", network="campus_network"):
        ip = "10.20.1.1" if network == "campus_network" else "8.8.8.8"
        pair = issue_token_pair(user, ip=ip, user_agent=device)
        session = ApiSession.objects.get(id=pair.session_id)
        session.device_summary = device.lower()
        session.network_class = network
        session.save(update_fields=["device_summary", "network_class", "updated_at"])
        return session

    def test_anonymous_returns_not_authorized(self):
        result = get_active_sessions(AnonymousUser())
        self.assertEqual(result["sessions"], [])
        self.assertNotIn("decode", result)
        self.assertNotIn("decode", get_active_sessions(None))

    def test_returns_own_session_and_excludes_other_user(self):
        mine = self._create_session(self.user, network="campus_network")
        self._create_session(self.other, device="Firefox on Linux", network="public_network")
        result = get_active_sessions(self.user, current_session_id=mine.id)
        self.assertEqual(len(result["sessions"]), 1)
        row = result["sessions"][0]
        self.assertTrue(row["is_current"])
        self.assertEqual(row["device"]["state"], "available")
        self.assertEqual(row["network"]["state"], "approximate")
        # raw session key and decoded internals never exposed
        dumped = json.dumps(result)
        self.assertNotIn(str(mine.id), dumped)
        self.assertNotIn("_auth_user_id", dumped)

    def test_inactive_and_legacy_accounts_cannot_read_own_sessions(self):
        inactive = User.objects.create_user(
            email="inactive-session@example.test",
            password="correct-horse-battery-staple",
            role=RoleChoices.STUDENT,
            is_active=False,
        )
        legacy = User.objects.create_user(
            email="legacy-session@example.test",
            password="correct-horse-battery-staple",
            role=RoleChoices.STUDENT,
            is_active=True,
        )
        legacy.is_superuser = True
        legacy.save(update_fields=["is_superuser"])
        for actor in (inactive, legacy):
            result = get_active_sessions(actor)
            self.assertEqual(result["sessions"], [])
            self.assertNotIn("decode", result)

    def test_django_sessions_are_not_projected_as_api_sessions(self):
        result = get_active_sessions(self.user)
        self.assertEqual(result["sessions"], [])
        self.assertNotIn("decode", json.dumps(result))


@override_settings(CAMPUS_NETWORK_CIDRS=["10.20.0.0/16"])
class EventBoundaryTests(TestCase):
    """device_label/network_class derived from transient values only (contract boundary)."""

    def setUp(self):
        self.user = User.objects.create_user(
            email="owner@example.test",
            password="correct-horse-battery-staple",
            role=RoleChoices.STUDENT,
            is_active=True,
        )

    def test_device_and_network_derived_and_override_resistant(self):
        log = log_security_event(
            action_type="login_success",
            target_model="accounts.User",
            target_object_id=str(self.user.pk),
            actor_user=self.user,
            ip_address="10.20.1.2",
            user_agent=(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"
            ),
            metadata={
                "device_label": "spoofed-device",
                "network_class": "spoofed-network",
                "reason": "keepme",
            },
        )
        self.assertEqual(log.safe_metadata["device_label"], "Chrome on macOS")
        self.assertEqual(log.safe_metadata["network_class"], "campus_network")
        self.assertEqual(log.safe_metadata["reason"], "keepme")
        self.assertNotIn("spoofed", json.dumps(log.safe_metadata))

    def test_raw_ip_and_user_agent_never_persisted(self):
        user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121 Safari/537.36"
        )
        log = log_security_event(
            action_type="login_success",
            target_model="accounts.User",
            target_object_id=str(self.user.pk),
            actor_user=self.user,
            ip_address="10.20.99.99",
            user_agent=user_agent,
        )
        dumped = json.dumps(log.safe_metadata)
        self.assertNotIn("10.20.99.99", dumped)
        self.assertNotIn("Windows NT", dumped)
        self.assertNotIn("Mozilla", dumped)
        self.assertEqual(log.safe_metadata["device_label"], "Chrome on Windows")
        self.assertEqual(log.safe_metadata["network_class"], "campus_network")

    def test_unknown_transient_yields_not_captured_device(self):
        log = log_security_event(
            action_type="login_success",
            target_model="accounts.User",
            target_object_id=str(self.user.pk),
            actor_user=self.user,
        )
        self.assertEqual(log.safe_metadata["device_label"], "Unknown Device")
        self.assertEqual(log.safe_metadata["network_class"], "unknown")


class AccountSecurityApiParityTests(TestCase):
    """Focused tests for the new user-owned account-security API boundary."""

    def setUp(self):
        self.password = "correct-horse-battery-staple"
        self.user = User.objects.create_user(
            email="api-owner@example.test",
            password=self.password,
            role=RoleChoices.STUDENT,
            is_active=True,
        )
        self.other = User.objects.create_user(
            email="api-other@example.test",
            password=self.password,
            role=RoleChoices.STUDENT,
            is_active=True,
        )
        self.client = Client()
        self.access_token = issue_token_pair(self.user).access_token
        AuditLogEntry.objects.filter(actor_user=self.user).delete()

    def _token(self, user=None):
        if user is None:
            return self.access_token
        return issue_token_pair(user).access_token

    def _headers(self, user=None, key=None):
        headers = {"HTTP_AUTHORIZATION": f"Bearer {self._token(user)}"}
        if key:
            headers["HTTP_IDEMPOTENCY_KEY"] = key
        return headers

    def _entry(self, user, *, action, category, reference="SAFE-001", metadata=None):
        return AuditLogEntry.objects.create(
            actor_user=user,
            actor_role=user.role,
            action_type=action,
            event_category=category,
            severity="INFO",
            target_model="workflow.Record",
            target_object_id="sensitive-object-id",
            reference_code=reference,
            safe_metadata=metadata or {},
        )

    def test_activity_is_owner_scoped_and_category_bounded(self):
        self._entry(
            self.user,
            action="login_success",
            category="SECURITY",
            metadata={"device_label": "Chrome on macOS", "network_class": "public_network"},
        )
        self._entry(self.user, action="APPOINTMENT_SUBMITTED", category="WORKFLOW")
        self._entry(self.other, action="OTHER_USER_ACTION", category="WORKFLOW")

        from apps.account_security.queries import get_activity_page
        try:
            get_activity_page(self.user, PageRequest(page=1, page_size=100), category="all")
        except Exception as exc:
            self.fail(f"activity query failed: {type(exc).__name__}: {exc}")

        response = self.client.get(
            "/api/v1/me/activity/?category=all&page=1&page_size=100",
            **self._headers(),
        )

        self.assertEqual(response.status_code, 200, response.content)
        payload = response.json()
        self.assertEqual(payload["total"], 2)
        dumped = json.dumps(payload)
        self.assertNotIn("sensitive-object-id", dumped)
        self.assertNotIn("api-owner@example.test", dumped)
        self.assertEqual(response["Cache-Control"], "no-store")

        activity_by_type = {
            item["activity_type"]: item for item in payload["items"]
        }
        self.assertEqual(
            set(activity_by_type["login_success"]),
            {
                "activity_type",
                "category",
                "label",
                "created_at",
                "status_label",
                "status_tone",
                "reference_code",
                "device",
                "network",
            },
        )
        self.assertEqual(
            set(activity_by_type["APPOINTMENT_SUBMITTED"]),
            {
                "activity_type",
                "category",
                "label",
                "created_at",
                "status_label",
                "status_tone",
                "reference_code",
            },
        )
        self.assertNotIn("device", activity_by_type["APPOINTMENT_SUBMITTED"])
        self.assertNotIn("network", activity_by_type["APPOINTMENT_SUBMITTED"])

        security = self.client.get(
            "/api/v1/me/activity/?category=security",
            **self._headers(),
        )
        self.assertEqual(security.status_code, 200)
        self.assertEqual(security.json()["total"], 1)
        self.assertEqual(security.json()["items"][0]["device"]["state"], "available")

    def test_sessions_and_trusted_devices_never_expose_raw_verifiers(self):
        device = TrustedDevice.objects.create(
            user=self.user,
            device_hash=hash_token("raw-device-verifier"),
            label="Safari on macOS",
            status="active",
            trusted_until=timezone.now() + timedelta(days=1),
        )

        sessions = self.client.get("/api/v1/me/sessions/", **self._headers())
        devices = self.client.get("/api/v1/me/trusted-devices/", **self._headers())

        self.assertEqual(sessions.status_code, 200)
        self.assertEqual(devices.status_code, 200)
        dumped = json.dumps({"sessions": sessions.json(), "devices": devices.json()})
        self.assertNotIn("raw-device-verifier", dumped)
        self.assertNotIn("device_hash", dumped)
        self.assertEqual(
            set(sessions.json()["items"][0]),
            {
                "session_token",
                "is_current",
                "device",
                "network",
                "started_at",
                "last_activity_at",
                "expires_at",
                "authentication_method",
            },
        )
        self.assertEqual(
            set(devices.json()["items"][0]),
            {
                "id",
                "device",
                "status",
                "trusted_until",
                "last_used_at",
                "revoked_at",
                "is_current",
            },
        )
        self.assertEqual(devices.json()["items"][0]["id"], str(device.id))

    def test_empty_account_security_pages_are_bounded(self):
        activity = self.client.get("/api/v1/me/activity/", **self._headers())
        sessions = self.client.get("/api/v1/me/sessions/", **self._headers())
        devices = self.client.get("/api/v1/me/trusted-devices/", **self._headers())

        self.assertEqual(activity.status_code, 200)
        self.assertEqual(sessions.status_code, 200)
        self.assertEqual(devices.status_code, 200)
        self.assertEqual(activity.json()["items"], [])
        self.assertEqual(len(sessions.json()["items"]), 1)
        self.assertEqual(devices.json()["items"], [])
        for payload, expected_total in (
            (activity.json(), 0),
            (sessions.json(), 1),
            (devices.json(), 0),
        ):
            self.assertEqual(payload["page"], 1)
            self.assertEqual(payload["page_size"], 25)
            self.assertEqual(payload["total"], expected_total)

    def test_session_and_device_mutations_are_owner_bound_and_idempotent(self):
        second_session_id = issue_token_pair(self.user).session_id
        action_token = hash_identifier(f"account-session:{second_session_id}")
        from apps.account_security.tokens import get_session_action_token
        response = self.client.post(
            f"/api/v1/me/sessions/{action_token}/revoke/",
            **self._headers(key="session-revoke-1"),
        )
        replay = self.client.post(
            f"/api/v1/me/sessions/{action_token}/revoke/",
            **self._headers(key="session-revoke-1"),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"revoked": True})
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.json(), {"revoked": True})
        self.assertEqual(
            ApiSession.objects.get(id=second_session_id).status,
            ApiSessionStatusChoices.REVOKED,
        )

    def test_password_change_rotates_security_state_and_rejects_raw_command_repr(self):
        command = PasswordChangeCommand(
            current_password=self.password,
            new_password="new-correct-horse-battery-staple",
            password_confirmation="new-correct-horse-battery-staple",
        )
        self.assertNotIn(self.password, repr(command))
        response = self.client.post(
            "/api/v1/me/password/change/",
            data=json.dumps({
                "current_password": self.password,
                "new_password": "new-correct-horse-battery-staple",
                "password_confirmation": "new-correct-horse-battery-staple",
            }),
            content_type="application/json",
            **self._headers(key="password-change-1"),
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["changed"])
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("new-correct-horse-battery-staple"))
        self.assertFalse(ApiToken.objects.filter(user=self.user, status=ApiTokenStatusChoices.ACTIVE).exists())

    def test_recovery_reset_command_is_immutable_and_mismatches_are_validation_errors(self):
        command = RecoveryResetCommand(
            token="opaque-recovery-token",
            new_password="new-correct-horse-battery-staple",
            password_confirmation="new-correct-horse-battery-staple",
        )
        self.assertNotIn("opaque-recovery-token", repr(command))
        self.assertNotIn("new-correct-horse-battery-staple", repr(command))

    def test_recovery_request_is_generic_and_reset_rejects_invalid_token(self):
        response = self.client.post(
            "/api/v1/auth/recovery/request/",
            data=json.dumps({"email": "unknown@example.test"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("If an account exists", response.json()["detail"])
        self.assertNotIn("unknown@example.test", response.content.decode())
        self.assertEqual(response["Cache-Control"], "no-store")

        reset = self.client.post(
            "/api/v1/auth/recovery/reset/",
            data=json.dumps({
                "token": "malformed-token",
                "new_password": "new-correct-horse-battery-staple",
                "password_confirmation": "new-correct-horse-battery-staple",
            }),
            content_type="application/json",
        )
        self.assertEqual(reset.status_code, 401)
        self.assertEqual(reset.json()["code"], "unauthenticated")

    def test_invalid_activity_category_and_inactive_account_fail_closed(self):
        invalid = self.client.get(
            "/api/v1/me/activity/?category=unrestricted",
            **self._headers(),
        )
        self.assertEqual(invalid.status_code, 422)
        self.assertEqual(invalid.json()["code"], "validation")

        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        denied = self.client.get(
            "/api/v1/me/activity/",
            HTTP_AUTHORIZATION=f"Bearer {self.access_token}",
        )
        self.assertEqual(denied.status_code, 401)
