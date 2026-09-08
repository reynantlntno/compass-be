"""Targeted regression coverage for API sessions, assurance, and remembered devices."""

import json
import uuid
from datetime import timedelta
from unittest.mock import patch

from django.http import HttpResponse
from django.test import Client, TestCase, override_settings
from django.utils import timezone

from apps.account_security.api_tokens import (
    ApiTokenPair,
    LoginChallenge,
    begin_password_login,
    issue_token_pair,
    rotate_refresh_token,
)
from apps.account_security.assurance import (
    ASSURANCE_CONTEXT,
    ASSURANCE_POLICY_VERSION,
    validate_api_token_assurance,
)
from apps.account_security.models import (
    ApiSession,
    ApiSessionAuthenticationMethodChoices,
    ApiSessionStatusChoices,
    ApiToken,
    StudentTwoFactorEnrollment,
    TrustedDevice,
    TwoStepChallenge,
)
from apps.account_security.network import classify_network_class
from apps.account_security.session_cookies import (
    SESSION_MEDIA_TYPE,
    session_cookie_names,
    set_session_cookies,
    trusted_device_cookie_name,
)
from apps.account_security.services import (
    consume_trusted_device_for_login,
    issue_trusted_device_after_otp,
)
from apps.account_security.tokens import hash_identifier, hash_token
from apps.account_security.two_factor import (
    request_assurance_challenge,
    request_student_two_factor_change,
    verify_assurance_challenge,
    verify_student_two_factor_change,
)
from apps.accounts.models import RoleChoices, User
from apps.common.contracts import RequestMetadata


UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"
)


class AccountSecuritySessionAndTrustedDeviceTests(TestCase):
    def setUp(self):
        self.password = "correct-horse-battery-staple"
        self.student = User.objects.create_user(
            email="security-student@example.test",
            password=self.password,
            first_name="Security",
            last_name="Student",
            role=RoleChoices.STUDENT,
            is_active=True,
        )
        self.enrollment = StudentTwoFactorEnrollment.objects.create(
            user=self.student,
            enabled=True,
            enabled_at=timezone.now(),
        )

    def _verified_login_challenge(self, *, verified_at=None):
        verified_at = verified_at or timezone.now()
        return TwoStepChallenge.objects.create(
            user=self.student,
            purpose="login",
            otp_hash=hash_token("123456"),
            status="verified",
            delivery_email_hash=hash_identifier(self.student.email),
            expires_at=verified_at + timedelta(minutes=5),
            verified_at=verified_at,
            security_stamp=self.student.auth_security_stamp,
            assurance_policy_version=ASSURANCE_POLICY_VERSION,
            assurance_context=ASSURANCE_CONTEXT,
            metadata_json={"pending_nonce_hash": hash_token("nonce")},
        )

    def test_refresh_preserves_otp_provenance_and_absolute_session_deadline(self):
        verified_at = timezone.now() - timedelta(minutes=2)
        pair = issue_token_pair(
            self.student,
            user_agent=UA,
            assurance_verified=True,
            authentication_method=ApiSessionAuthenticationMethodChoices.OTP,
            otp_verified_at=verified_at,
        )
        session = ApiSession.objects.get(pk=pair.session_id)
        absolute_deadline = timezone.now() + timedelta(days=2)
        session.absolute_expires_at = absolute_deadline
        session.save(update_fields=["absolute_expires_at", "updated_at"])

        rotated = rotate_refresh_token(pair.refresh_token, user_agent=UA)
        session.refresh_from_db()

        self.assertEqual(session.absolute_expires_at, absolute_deadline)
        self.assertEqual(session.last_otp_verified_at, verified_at)
        self.assertLessEqual(rotated.refresh_expires_at, absolute_deadline)

    def test_trusted_device_is_hash_only_rotates_and_preserves_expiry(self):
        challenge = self._verified_login_challenge()
        raw_token, expiry, device_id = issue_trusted_device_after_otp(
            challenge,
            user_agent=UA,
            ip="8.8.8.8",
        )
        device = TrustedDevice.objects.get(pk=device_id)

        self.assertTrue(raw_token)
        self.assertEqual(len(device.device_hash), 64)
        self.assertNotEqual(device.device_hash, raw_token)
        self.assertEqual(device.network_class, classify_network_class("8.8.8.8"))

        rotated = consume_trusted_device_for_login(
            self.student,
            raw_token,
            user_agent=UA,
            ip="192.168.1.20",
        )
        self.assertIsNotNone(rotated)
        rotated_token, rotated_expiry, rotated_device_id = rotated
        device.refresh_from_db()
        self.assertEqual(rotated_device_id, device.id)
        self.assertNotEqual(rotated_token, raw_token)
        self.assertEqual(rotated_expiry, expiry)
        self.assertEqual(device.trusted_until, expiry)
        self.assertEqual(
            consume_trusted_device_for_login(
                self.student,
                raw_token,
                user_agent=UA,
            ),
            None,
        )

    def test_trusted_login_requires_password_and_skips_only_otp(self):
        challenge = self._verified_login_challenge()
        raw_token, _expiry, _device_id = issue_trusted_device_after_otp(
            challenge,
            user_agent=UA,
        )
        context = RequestMetadata(ip_address="8.8.8.8", user_agent=UA)

        pair = begin_password_login(
            self.student.email,
            self.password,
            context,
            trusted_device_token=raw_token,
        )

        self.assertIsInstance(pair, ApiTokenPair)
        self.assertTrue(pair.trusted_device_token)
        self.assertNotEqual(pair.trusted_device_token, raw_token)
        session = ApiSession.objects.get(pk=pair.session_id)
        self.assertEqual(
            session.authentication_method,
            ApiSessionAuthenticationMethodChoices.TRUSTED_DEVICE,
        )
        self.assertFalse(validate_api_token_assurance(self.student, ApiToken.objects.get(
            token_hash=hash_token(pair.access_token)
        ))[0])

    def test_cookie_profile_reads_and_rotates_trusted_device_cookie(self):
        challenge = self._verified_login_challenge()
        raw_token, _expiry, _device_id = issue_trusted_device_after_otp(
            challenge,
            user_agent=UA,
        )
        client = Client()
        response = client.post(
            "/api/v1/auth/login/",
            data=json.dumps({"email": self.student.email, "password": self.password}),
            content_type="application/json",
            HTTP_ACCEPT=SESSION_MEDIA_TYPE,
            HTTP_X_COMPASS_AUTH_TRANSPORT="cookie",
            HTTP_COOKIE=f"{trusted_device_cookie_name()}={raw_token}",
            HTTP_USER_AGENT=UA,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"authenticated": True})
        self.assertIn(trusted_device_cookie_name(), response.cookies)
        self.assertNotEqual(
            response.cookies[trusted_device_cookie_name()].value,
            raw_token,
        )

    @override_settings(COMPASS_ENVIRONMENT="staging")
    def test_staging_trusted_device_cookie_is_secure_and_auth_scoped(self):
        challenge = self._verified_login_challenge()
        raw_token, expiry, _device_id = issue_trusted_device_after_otp(
            challenge,
            user_agent=UA,
        )
        pair = issue_token_pair(
            self.student,
            assurance_verified=True,
            authentication_method=ApiSessionAuthenticationMethodChoices.OTP,
            trusted_device_token=raw_token,
            trusted_device_expires_at=expiry,
        )
        response = HttpResponse()
        set_session_cookies(response, pair)
        cookie = response.cookies["__Secure-compass-trusted-device"]

        self.assertTrue(cookie["secure"])
        self.assertTrue(cookie["httponly"])
        self.assertEqual(cookie["samesite"], "Lax")
        self.assertEqual(cookie["path"], "/api/v1/auth/")
        self.assertEqual(cookie["domain"], "")

    def test_student_two_factor_status_is_explicit_and_authenticated(self):
        pair = issue_token_pair(
            self.student,
            assurance_verified=True,
            authentication_method=ApiSessionAuthenticationMethodChoices.OTP,
        )
        response = self.client.get(
            "/api/v1/me/two-factor/",
            HTTP_AUTHORIZATION=f"Bearer {pair.access_token}",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"enabled": True, "required": False, "can_change": True},
        )

    def test_logout_is_idempotent_for_expired_access_and_revokes_family(self):
        pair = issue_token_pair(
            self.student,
            assurance_verified=True,
            authentication_method=ApiSessionAuthenticationMethodChoices.OTP,
        )
        ApiToken.objects.filter(token_hash=hash_token(pair.access_token)).update(
            expires_at=timezone.now() - timedelta(seconds=1),
        )
        response = self.client.post(
            "/api/v1/auth/logout/",
            data=json.dumps({"refresh_token": pair.refresh_token}),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {pair.access_token}",
        )

        self.assertEqual(response.status_code, 204)
        cookie_names = session_cookie_names()
        self.assertIn(cookie_names.access, response.cookies)
        self.assertIn(cookie_names.refresh, response.cookies)
        self.assertEqual(
            ApiSession.objects.get(pk=pair.session_id).status,
            ApiSessionStatusChoices.REVOKED,
        )
        self.assertEqual(
            ApiToken.objects.filter(session_id=pair.session_id, status="ACTIVE").count(),
            0,
        )

    def test_invalid_trusted_device_falls_back_to_otp_challenge_without_reason(self):
        pending = TwoStepChallenge(
            id=uuid.uuid4(),
            user=self.student,
            purpose="login",
            expires_at=timezone.now() + timedelta(minutes=5),
        )
        context = RequestMetadata(ip_address="8.8.8.8", user_agent=UA)
        with patch(
            "apps.account_security.api_tokens.create_twostep_challenge",
            return_value=(pending, None),
        ):
            outcome = begin_password_login(
                self.student.email,
                self.password,
                context,
                trusted_device_token="invalid-remembered-device",
            )

        self.assertIsInstance(outcome, LoginChallenge)
        self.assertTrue(outcome.pending_nonce)

    @patch("apps.account_security.services.send_security_email", return_value="mail-id")
    def test_trusted_login_requires_fresh_step_up_otp(self, _send):
        challenge = self._verified_login_challenge()
        raw_token, _expiry, _device_id = issue_trusted_device_after_otp(
            challenge,
            user_agent=UA,
        )
        trusted_pair = begin_password_login(
            self.student.email,
            self.password,
            RequestMetadata(ip_address="8.8.8.8", user_agent=UA),
            trusted_device_token=raw_token,
        )
        trusted_access = ApiToken.objects.get(
            token_hash=hash_token(trusted_pair.access_token),
        )
        self.assertFalse(validate_api_token_assurance(self.student, trusted_access)[0])

        step_up = request_assurance_challenge(
            self.student,
            session_id=trusted_pair.session_id,
            ip="8.8.8.8",
            user_agent=UA,
        )
        step_up_challenge = TwoStepChallenge.objects.get(pk=step_up["challenge_id"])
        step_up_challenge.otp_hash = hash_token("654321")
        step_up_challenge.save(update_fields=["otp_hash", "updated_at"])
        self.assertEqual(
            verify_assurance_challenge(
                self.student,
                session_id=trusted_pair.session_id,
                challenge_id=step_up_challenge.id,
                pending_nonce=step_up["pending_nonce"],
                otp="654321",
                ip="8.8.8.8",
                user_agent=UA,
            ),
            {"verified": True},
        )
        trusted_access.refresh_from_db()
        self.assertTrue(validate_api_token_assurance(self.student, trusted_access)[0])

    def test_sixth_device_revokes_oldest_and_it_admin_never_gets_one(self):
        created = []
        for index in range(5):
            challenge = self._verified_login_challenge()
            raw, _expiry, device_id = issue_trusted_device_after_otp(
                challenge,
                user_agent=UA,
            )
            created.append((raw, device_id))
            TrustedDevice.objects.filter(pk=device_id).update(
                created_at=timezone.now() - timedelta(days=10 - index),
            )

        sixth_challenge = self._verified_login_challenge()
        _sixth_raw, _sixth_expiry, sixth_id = issue_trusted_device_after_otp(
            sixth_challenge,
            user_agent=UA,
        )
        self.assertEqual(
            TrustedDevice.objects.filter(
                user=self.student,
                status="active",
                trusted_until__gt=timezone.now(),
            ).count(),
            5,
        )
        self.assertEqual(
            TrustedDevice.objects.get(pk=created[0][1]).revoked_reason,
            "active_device_limit",
        )
        self.assertTrue(sixth_id)

        admin = User.objects.create_user(
            email="security-it@example.test",
            password=self.password,
            role=RoleChoices.IT_ADMIN,
            is_active=True,
        )
        admin_challenge = TwoStepChallenge.objects.create(
            user=admin,
            purpose="login",
            otp_hash=hash_token("123456"),
            status="verified",
            delivery_email_hash=hash_identifier(admin.email),
            expires_at=timezone.now() + timedelta(minutes=5),
            verified_at=timezone.now(),
            security_stamp=admin.auth_security_stamp,
            assurance_policy_version=ASSURANCE_POLICY_VERSION,
            assurance_context=ASSURANCE_CONTEXT,
        )
        receipt = issue_trusted_device_after_otp(admin_challenge, user_agent=UA)
        self.assertEqual(receipt, (None, None, None))
        self.assertFalse(TrustedDevice.objects.filter(user=admin).exists())

    @patch("apps.account_security.services.send_security_email", return_value="mail-id")
    def test_student_two_factor_change_revokes_old_sessions_and_reissues_one(self, _send):
        old_pair = issue_token_pair(
            self.student,
            user_agent=UA,
            assurance_verified=True,
            authentication_method=ApiSessionAuthenticationMethodChoices.OTP,
        )
        challenge_data = request_student_two_factor_change(
            self.student,
            current_password=self.password,
            enabled=False,
            ip="8.8.8.8",
            user_agent=UA,
        )
        # The fixture starts enabled; use the real challenge row with a known
        # verifier so the email adapter remains outside this regression test.
        challenge = TwoStepChallenge.objects.get(pk=challenge_data["challenge_id"])
        challenge.otp_hash = hash_token("123456")
        challenge.save(update_fields=["otp_hash", "updated_at"])

        enabled, replacement = verify_student_two_factor_change(
            self.student,
            challenge_id=challenge.id,
            pending_nonce=challenge_data["pending_nonce"],
            otp="123456",
            ip="8.8.8.8",
            user_agent=UA,
        )
        self.assertFalse(enabled)
        self.assertTrue(replacement.access_token)
        self.assertFalse(ApiSession.objects.get(pk=old_pair.session_id).status == ApiSessionStatusChoices.ACTIVE)
        self.assertEqual(
            StudentTwoFactorEnrollment.objects.get(user=self.student).enabled,
            False,
        )

    @patch("apps.account_security.services.send_security_email", return_value="mail-id")
    def test_student_two_factor_change_api_returns_replacement_bearer_pair(self, _send):
        pair = issue_token_pair(
            self.student,
            user_agent=UA,
            assurance_verified=True,
            authentication_method=ApiSessionAuthenticationMethodChoices.OTP,
        )
        client = Client()
        requested = client.post(
            "/api/v1/me/two-factor/change/request/",
            data=json.dumps({"current_password": self.password, "enabled": False}),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {pair.access_token}",
            HTTP_USER_AGENT=UA,
        )
        self.assertEqual(requested.status_code, 200)
        challenge_data = requested.json()
        challenge = TwoStepChallenge.objects.get(pk=challenge_data["challenge_id"])
        challenge.otp_hash = hash_token("123456")
        challenge.save(update_fields=["otp_hash", "updated_at"])

        verified = client.post(
            "/api/v1/me/two-factor/change/verify/",
            data=json.dumps({
                "challenge_id": challenge_data["challenge_id"],
                "pending_nonce": challenge_data["pending_nonce"],
                "otp": "123456",
            }),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {pair.access_token}",
            HTTP_USER_AGENT=UA,
        )

        self.assertEqual(verified.status_code, 200)
        payload = verified.json()
        self.assertFalse(payload["enabled"])
        self.assertTrue(payload["access_token"])
        self.assertNotEqual(payload["access_token"], pair.access_token)
