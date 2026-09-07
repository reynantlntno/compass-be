"""Focused tests for the explicit HttpOnly-cookie authentication profile."""

import json
import uuid
from datetime import timedelta
from unittest.mock import patch

from django.test import Client, TestCase, override_settings
from django.utils import timezone

from apps.account_security.api_tokens import issue_token_pair
from apps.account_security.assurance import ASSURANCE_CONTEXT, ASSURANCE_POLICY_VERSION
from apps.account_security.session_cookies import (
    SESSION_MEDIA_TYPE,
    session_cookie_names,
    set_session_cookies,
)
from apps.account_security.models import ApiToken, ApiTokenStatusChoices, TwoStepChallenge
from apps.account_security.tokens import hash_identifier, hash_token
from apps.accounts.models import RoleChoices, User


@override_settings(
    COMPASS_ENVIRONMENT="testing",
    COMPASS_ACCESS_MODE="active",
    CSRF_TRUSTED_ORIGINS=["http://testserver"],
)
class SessionTransportTests(TestCase):
    def setUp(self):
        self.password = "correct-horse-battery-staple"
        self.user = User.objects.create_user(
            email="session-student@example.test",
            password=self.password,
            first_name="Session",
            last_name="Student",
            role=RoleChoices.STUDENT,
            is_active=True,
        )
        self.client = Client(enforce_csrf_checks=True)
        self.session_headers = {
            "HTTP_ACCEPT": SESSION_MEDIA_TYPE,
            "HTTP_X_COMPASS_AUTH_TRANSPORT": "cookie",
        }

    def _csrf(self):
        response = self.client.get("/api/v1/auth/csrf/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.json()), {"csrf_token"})
        self.assertNotIn("access_token", response.content.decode())
        self.assertIn("csrftoken", response.cookies)
        return response.json()["csrf_token"]

    def _post_session(self, path, payload=None, *, csrf=None, **headers):
        request_headers = dict(self.session_headers)
        if csrf is not None:
            request_headers["HTTP_X_CSRFTOKEN"] = csrf
        request_headers.update(headers)
        return self.client.post(
            path,
            data=json.dumps({} if payload is None else payload),
            content_type="application/json",
            **request_headers,
        )

    def test_login_sets_safe_session_cookies_without_returning_tokens(self):
        csrf = self._csrf()
        response = self._post_session(
            "/api/v1/auth/login/",
            {"email": self.user.email, "password": self.password},
            csrf=csrf,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"authenticated": True})
        body = response.content.decode()
        self.assertNotIn("access_token", body)
        self.assertNotIn("refresh_token", body)

        names = session_cookie_names()
        access_cookie = response.cookies[names.access]
        refresh_cookie = response.cookies[names.refresh]
        self.assertTrue(access_cookie["httponly"])
        self.assertTrue(refresh_cookie["httponly"])
        self.assertEqual(access_cookie["samesite"], "Lax")
        self.assertEqual(refresh_cookie["samesite"], "Lax")
        self.assertEqual(access_cookie["path"], "/")
        self.assertEqual(refresh_cookie["path"], "/api/v1/auth/")
        self.assertEqual(access_cookie["domain"], "")
        self.assertEqual(refresh_cookie["domain"], "")
        self.assertFalse(access_cookie["secure"])
        self.assertFalse(refresh_cookie["secure"])

    def test_cookie_auth_requires_explicit_profile_and_supports_me(self):
        csrf = self._csrf()
        login = self._post_session(
            "/api/v1/auth/login/",
            {"email": self.user.email, "password": self.password},
            csrf=csrf,
        )
        self.assertEqual(login.status_code, 200)

        without_marker = self.client.get("/api/v1/auth/me/")
        self.assertEqual(without_marker.status_code, 401)

        me = self.client.get("/api/v1/auth/me/", **self.session_headers)
        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.json()["email"], self.user.email)
        self.assertEqual(me.json()["role"], RoleChoices.STUDENT)

    @patch("apps.account_security.api_tokens.create_twostep_challenge")
    def test_internal_otp_session_profile_returns_only_receipt(self, create_challenge):
        internal = User.objects.create_user(
            email="session-it-admin@example.test",
            password=self.password,
            first_name="Session",
            last_name="Admin",
            role=RoleChoices.IT_ADMIN,
            is_active=True,
        )

        def create_login_challenge(user, **kwargs):
            pending_nonce = kwargs["pending_nonce"]
            challenge = TwoStepChallenge.objects.create(
                id=uuid.uuid4(),
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
        csrf = self._csrf()
        challenged = self._post_session(
            "/api/v1/auth/login/",
            {"email": internal.email, "password": self.password},
            csrf=csrf,
        )

        self.assertEqual(challenged.status_code, 202)
        challenge = challenged.json()
        self.assertTrue(challenge["requires_verification"])
        self.assertNotIn("access_token", challenged.content.decode())
        self.assertNotIn("refresh_token", challenged.content.decode())

        verified = self._post_session(
            "/api/v1/auth/login/verify/",
            {
                "challenge_id": challenge["challenge_id"],
                "pending_nonce": challenge["pending_nonce"],
                "otp": "123456",
            },
            csrf=csrf,
        )

        self.assertEqual(verified.status_code, 200)
        self.assertEqual(verified.json(), {"authenticated": True})
        self.assertNotIn("access_token", verified.content.decode())
        self.assertNotIn("refresh_token", verified.content.decode())
        names = session_cookie_names()
        self.assertIn(names.access, verified.cookies)
        self.assertIn(names.refresh, verified.cookies)

    def test_refresh_rotates_cookie_and_logout_clears_both(self):
        csrf = self._csrf()
        login = self._post_session(
            "/api/v1/auth/login/",
            {"email": self.user.email, "password": self.password},
            csrf=csrf,
        )
        self.assertEqual(login.status_code, 200)
        names = session_cookie_names()
        previous_refresh = self.client.cookies[names.refresh].value

        refreshed = self._post_session("/api/v1/auth/token/refresh/", csrf=csrf)
        self.assertEqual(refreshed.status_code, 200)
        self.assertEqual(refreshed.json(), {"authenticated": True})
        self.assertNotEqual(self.client.cookies[names.refresh].value, previous_refresh)
        self.assertEqual(ApiToken.objects.filter(status=ApiTokenStatusChoices.ACTIVE).count(), 3)

        logout = self._post_session("/api/v1/auth/logout/", csrf=csrf)
        self.assertEqual(logout.status_code, 204)
        self.assertEqual(self.client.cookies[names.access].value, "")
        self.assertEqual(self.client.cookies[names.refresh].value, "")
        self.assertEqual(ApiToken.objects.filter(status=ApiTokenStatusChoices.ACTIVE).count(), 0)

    def test_cookie_profile_requires_csrf_and_rejects_conflicting_bearer(self):
        csrf = self._csrf()
        missing_csrf = self._post_session(
            "/api/v1/auth/login/",
            {"email": self.user.email, "password": self.password},
        )
        self.assertEqual(missing_csrf.status_code, 403)
        self.assertEqual(missing_csrf.json()["code"], "permission")

        login = self._post_session(
            "/api/v1/auth/login/",
            {"email": self.user.email, "password": self.password},
            csrf=csrf,
        )
        self.assertEqual(login.status_code, 200)
        bearer = issue_token_pair(self.user).access_token
        conflicting = self.client.get(
            "/api/v1/auth/me/",
            **self.session_headers,
            HTTP_AUTHORIZATION=f"Bearer {bearer}",
        )
        self.assertEqual(conflicting.status_code, 401)

    def test_bearer_profile_remains_compatible(self):
        bearer = issue_token_pair(self.user).access_token
        response = self.client.get(
            "/api/v1/auth/me/",
            HTTP_AUTHORIZATION=f"Bearer {bearer}",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["email"], self.user.email)

    @override_settings(COMPASS_ENVIRONMENT="staging")
    def test_staging_session_cookies_use_secure_prefixes(self):
        pair = issue_token_pair(self.user)
        response = self.client.get("/api/v1/auth/csrf/")
        set_session_cookies(response, pair)

        names = session_cookie_names()
        self.assertEqual(names.access, "__Host-compass-access")
        self.assertEqual(names.refresh, "__Secure-compass-refresh")
        self.assertTrue(response.cookies[names.access]["secure"])
        self.assertTrue(response.cookies[names.refresh]["secure"])
        self.assertEqual(response.cookies[names.access]["path"], "/")
        self.assertEqual(response.cookies[names.refresh]["path"], "/api/v1/auth/")
        self.assertEqual(response.cookies[names.access]["domain"], "")
        self.assertEqual(response.cookies[names.refresh]["domain"], "")
