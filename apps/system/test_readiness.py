from django.test import SimpleTestCase, override_settings

from apps.system.management.commands.verify_health import (
    _email_external_evidence_check,
    _safe_configuration_presence,
)
from apps.system.readiness_services import build_report


class AutomatedReadinessContractTests(SimpleTestCase):
    def test_external_acceptance_is_visible_but_does_not_block_strict_automation(self):
        check = _email_external_evidence_check(
            "email_real_inbox",
            "EMAIL_INBOX_DELIVERY_PENDING",
            "Manual evidence remains pending.",
        )

        report = build_report(
            "verify_health",
            [check],
            strict=True,
            probe_external=True,
        )

        self.assertFalse(check.required)
        self.assertTrue(report["passed"])
        self.assertEqual(report["release_claim"], "NOT_CLAIMED")
        self.assertEqual(report["summary"]["counts"]["PENDING"], 1)

    @override_settings(
        COMPASS_ENVIRONMENT="staging",
        COMPASS_ACCESS_MODE="active",
        ECOUNSELING_PROVIDER="DAILY",
        SECRET_KEY="sensitive-value-that-must-not-appear",
        ECOUNSELING_DAILY_API_KEY="provider-value-that-must-not-appear",
        ECOUNSELING_DAILY_DOMAIN="demo-compass.daily.co",
    )
    def test_configuration_presence_never_serializes_values(self):
        entries = _safe_configuration_presence()
        serialized = str(entries)

        self.assertNotIn("sensitive-value-that-must-not-appear", serialized)
        self.assertNotIn("provider-value-that-must-not-appear", serialized)
        by_name = {entry["name"]: entry for entry in entries}
        self.assertTrue(by_name["SECRET_KEY"]["present"])
        self.assertEqual(by_name["SECRET_KEY"]["classification"], "secret")
        self.assertEqual(
            by_name["SECRET_KEY"]["declared_source"],
            "podman_secret_wrapper",
        )
        self.assertTrue(by_name["ECOUNSELING_DAILY_API_KEY"]["required"])

    @override_settings(
        COMPASS_ENVIRONMENT="staging",
        COMPASS_ACCESS_MODE="health_only",
        ECOUNSELING_PROVIDER="disabled",
        EMAIL_HOST_PASSWORD="",
        ECOUNSELING_DAILY_API_KEY="",
    )
    def test_optional_inactive_configuration_is_reported_not_configured(self):
        by_name = {entry["name"]: entry for entry in _safe_configuration_presence()}

        self.assertFalse(by_name["EMAIL_HOST_PASSWORD"]["required"])
        self.assertEqual(by_name["EMAIL_HOST_PASSWORD"]["validity"], "NOT_CONFIGURED")
        self.assertFalse(by_name["ECOUNSELING_DAILY_API_KEY"]["required"])
        self.assertEqual(by_name["ECOUNSELING_DAILY_API_KEY"]["validity"], "NOT_CONFIGURED")
