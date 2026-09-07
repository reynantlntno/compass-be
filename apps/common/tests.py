"""Architecture and contract regression tests for the API-readiness boundary."""

from dataclasses import FrozenInstanceError
from pathlib import Path
import re

from django.test import SimpleTestCase

from apps.common.contracts import (
    MAX_PAGE_SIZE,
    ContractValidationError,
    PageRequest,
    PageResult,
    to_json_object,
    to_json_value,
)
from apps.common.exceptions import ValidationError
from apps.common.references import (
    CANONICAL_REFERENCE_SPECS,
    format_reference_code,
    validate_reference_code,
)
from apps.common.request_dedup import (
    build_request_fingerprint,
    hash_request_key,
    normalize_request_key,
)


class ContractTests(SimpleTestCase):
    def test_page_request_is_positive_and_bounded(self):
        self.assertEqual(PageRequest(page=2, page_size=100).offset, 100)
        with self.assertRaises(ContractValidationError):
            PageRequest(page=0)
        with self.assertRaises(ContractValidationError):
            PageRequest(page_size=MAX_PAGE_SIZE + 1)

    def test_page_result_is_immutable_and_json_ready(self):
        result = PageResult(items=[{"created_at": "2026-08-22T00:00:00+00:00"}], page=1, page_size=25, total=1)
        self.assertEqual(result.as_dict()["items"][0]["created_at"], "2026-08-22T00:00:00+00:00")
        with self.assertRaises(FrozenInstanceError):
            result.page = 2

    def test_projection_serializer_rejects_unknown_objects(self):
        with self.assertRaises(TypeError):
            to_json_value(object())
        self.assertEqual(to_json_object({"value": 1}), {"value": 1})


class SharedMechanicsTests(SimpleTestCase):
    def test_reference_registry_contains_every_canonical_workflow_prefix(self):
        self.assertEqual(
            set(CANONICAL_REFERENCE_SPECS),
            {"APT", "REF", "CSL", "SES", "CAS", "ECS", "ESC", "GMC", "EIT", "GTS", "FBK", "DOC", "CNT"},
        )
        self.assertEqual(format_reference_code("GMC", "2026-2027", 1), "GMC-AY2627-000001")
        self.assertTrue(validate_reference_code("ESC-AY2627-000001"))
        self.assertFalse(validate_reference_code("ESC-AY2628-000001"))

    def test_reference_format_rejects_invalid_period_and_overflow(self):
        with self.assertRaises(ValidationError):
            format_reference_code("GMC", "2026-2028", 1)
        with self.assertRaises(ValidationError):
            format_reference_code("GMC", "2026-2027", 1_000_000)

    def test_request_key_mechanics_are_bounded_and_purpose_separated(self):
        self.assertEqual(normalize_request_key("  request-1  "), "request-1")
        with self.assertRaises(ValidationError):
            normalize_request_key("bad\nkey")
        self.assertNotEqual(
            hash_request_key("request-1", purpose="one"),
            hash_request_key("request-1", purpose="two"),
        )
        self.assertEqual(
            hash_request_key("request-1"),
            hash_request_key("request-1"),
        )

    def test_request_fingerprint_excludes_sensitive_and_volatile_values(self):
        base = build_request_fingerprint(
            "POST", "/api/v1/test/", {"name": "A", "password": "one", "request_id": "x"}
        )
        changed_secret = build_request_fingerprint(
            "POST", "/api/v1/test/", {"name": "A", "password": "two", "request_id": "y"}
        )
        self.assertEqual(base, changed_secret)


class ArchitectureBoundaryTests(SimpleTestCase):
    ROOT = Path(__file__).resolve().parents[2]
    APPLICATION_ROOT = ROOT / "apps"
    CLIENT_DOMAINS = {
        "accounts", "profiles", "inventory", "appointments", "counseling",
        "referrals", "call_slips", "assessments", "support_needs", "good_moral",
        "content", "form_collection", "feedback", "exit_interviews",
        "graduate_tracer", "reports", "documents", "organizations",
        "student_activation", "imports", "privacy", "notifications", "backups",
        "system",
        "account_security",
    }

    def test_client_domains_have_explicit_future_route_boundaries(self):
        for domain in self.CLIENT_DOMAINS:
            for module in (
                "commands.py",
                "policies.py",
                "selectors.py",
                "queries.py",
                "services.py",
                "projections.py",
            ):
                self.assertTrue(
                    (self.APPLICATION_ROOT / domain / module).is_file(),
                    f"{domain} is missing {module}",
                )

    def test_removed_http_leakage_is_not_reintroduced(self):
        forbidden = re.compile(
            r"django\.shortcuts|get_object_or_404|Http404|request\.(?:GET|POST)"
        )
        checked = (
            self.APPLICATION_ROOT / "content" / "selectors.py",
            self.APPLICATION_ROOT / "backups" / "selectors.py",
            self.APPLICATION_ROOT / "documents" / "preview_services.py",
            self.APPLICATION_ROOT / "counseling" / "ecounseling_services.py",
            self.APPLICATION_ROOT / "account_security" / "api_tokens.py",
            self.APPLICATION_ROOT / "account_security" / "services.py",
        )
        for path in checked:
            self.assertIsNone(forbidden.search(path.read_text()), str(path))

    def test_domain_modules_do_not_depend_on_http_request_or_404(self):
        """HTTP extraction and root error translation stay at the edge."""
        forbidden = re.compile(
            r"django\.shortcuts|get_object_or_404|Http404|request\.(?:GET|POST)"
        )
        allowed_root_handlers = {
            "apps/system/middleware.py",
            "apps/common/api/errors.py",
            "apps/common/api/middleware.py",
            "apps/reports/api.py",
        }
        violations = []
        for path in self.APPLICATION_ROOT.rglob("*.py"):
            relative = path.relative_to(self.ROOT).as_posix()
            if "migrations" in path.parts or path.name in {"tests.py", "api.py"} or relative in allowed_root_handlers:
                continue
            if forbidden.search(path.read_text()):
                violations.append(relative)
        self.assertEqual(violations, [])

    def test_domain_services_do_not_import_other_domain_mutations(self):
        """Cross-domain writes must be composed through orchestration."""
        allowed_same_domain = {"audit", "common", "workflow", "governance", "account_security"}
        violations = []
        for path in self.APPLICATION_ROOT.glob("*/services.py"):
            owner = path.parent.name
            for match in re.finditer(r"from apps\.([a-z0-9_]+)\.services import", path.read_text()):
                imported = match.group(1)
                if imported not in {owner, *allowed_same_domain}:
                    violations.append(f"{path.relative_to(self.ROOT)} -> {imported}")
        self.assertEqual(violations, [])

    def test_service_layers_use_stable_domain_errors(self):
        forbidden = re.compile(
            r"from django\.core\.exceptions import .*\b(?:PermissionDenied|ValidationError)\b"
        )
        violations = []
        for path in self.APPLICATION_ROOT.rglob("*.py"):
            if path.name == "tests.py" or "migrations" in path.parts:
                continue
            if not path.name.endswith("services.py"):
                continue
            if forbidden.search(path.read_text()):
                violations.append(path.relative_to(self.ROOT).as_posix())
        self.assertEqual(violations, [])

    def test_http_adapters_are_explicitly_limited(self):
        allowed = {
            "apps/account_security/api.py",
            "apps/account_security/api_auth.py",
            "apps/account_security/middleware.py",
            "apps/account_security/session_cookies.py",
            "apps/documents/response_adapters.py",
            "apps/organizations/response_adapters.py",
            "apps/security/downloads.py",
            "apps/system/http.py",
            "apps/system/middleware.py",
            "apps/common/api/errors.py",
            "apps/common/api/middleware.py",
            "apps/reports/api.py",
        }
        violations = []
        for path in self.APPLICATION_ROOT.rglob("*.py"):
            relative = path.relative_to(self.ROOT).as_posix()
            if relative in allowed or "/tests.py" in relative:
                continue
            content = path.read_text()
            if re.search(r"from django\.(?:http|shortcuts) import|import django\.http", content):
                violations.append(relative)
        self.assertEqual(violations, [])

    def test_canonical_authority_and_url_names_are_unique(self):
        for path in self.APPLICATION_ROOT.rglob("*.py"):
            if "migrations" in path.parts or path.name == "tests.py":
                continue
            content = path.read_text()
            self.assertNotIn("access_control.authorization", content, str(path))
            self.assertNotIn("COMPASS_APPLICATION_BASE_URL", content, str(path))
            self.assertNotIn("ACCOUNT_SECURITY_RECOVERY_BASE_URL", content, str(path))

    def test_shared_mechanics_have_no_runtime_duplicates(self):
        runtime_files = [
            path for path in self.APPLICATION_ROOT.rglob("*.py")
            if "migrations" not in path.parts and path.name != "tests.py"
        ]
        text = "\n".join(path.read_text() for path in runtime_files)
        self.assertNotIn("apps." + "account_security.rate_limits", text)
        self.assertNotIn("apps." + "organizations.reference_codes", text)
        self.assertNotIn("_join" + "_denial_rate_limited", text)
        self.assertNotIn("run_" + "idempotent_action", text)
        for path in self.APPLICATION_ROOT.glob("*/reference_codes.py"):
            self.assertNotIn("select_for_update", path.read_text(), str(path))
            self.assertNotIn("last_sequence +=", path.read_text(), str(path))

    def test_active_source_has_no_retired_project_labels(self):
        """Planning-ticket identifiers must not become runtime contracts again."""
        retired_identifier = "f" + "nd"
        planning_pattern = re.compile(
            r"(?:Related\s+Blueprint|Appendix\s+[A-Z]|Phase\s+[0-9A-Z]|"
            r"Part\s+[0-9A-Z]|blueprint\s+(?:algorithm|specification))"
        )
        violations = []
        for path in self.ROOT.rglob("*"):
            active_suffixes = {".py", ".css", ".js", ".html", ".yaml", ".yml", ".toml", ".ini"}
            if any(part in {"node_modules", ".next", "out", "build"} for part in path.parts):
                continue
            if not path.is_file() or "migrations" in path.parts or (
                path.suffix not in active_suffixes and path.name not in {".env", ".env.example"}
            ):
                continue
            if path.name == "tests.py":
                continue
            relative = path.relative_to(self.ROOT).as_posix()
            content = path.read_text(errors="replace")
            if re.search(re.escape(retired_identifier), content, re.IGNORECASE):
                violations.append(f"retired identifier: {relative}")
                continue
            # The feedback model retains official CSM form-section wording;
            # those are domain labels, not project-planning references.
            planning_content = content
            if relative == "apps/feedback/models.py":
                planning_content = "\n".join(
                    line for line in content.splitlines()
                    if not re.search(r"(?i)\bpart\s+[0-9a-z]", line)
                )
            if planning_pattern.search(planning_content):
                violations.append(f"planning label: {relative}")
        self.assertEqual(violations, [])

    def test_orchestration_is_the_only_runtime_composition_boundary(self):
        orchestration_root = self.APPLICATION_ROOT / "orchestration"
        self.assertFalse((orchestration_root / "workflows.py").exists())

        violations = []
        for path in self.APPLICATION_ROOT.rglob("*.py"):
            if "migrations" in path.parts or path.name == "tests.py":
                continue
            relative = path.relative_to(self.ROOT).as_posix()
            content = path.read_text()
            if relative != "apps/orchestration/notification_outbox_handlers.py" and re.search(
                r"def\s+_contact_alert_recipients\b", content
            ):
                violations.append(f"private contact recipient helper: {relative}")
            if relative != "apps/orchestration" and "apps.orchestration.workflows" in content:
                violations.append(f"legacy orchestration import: {relative}")
            if (
                relative.startswith("apps/orchestration/")
                and re.search(r"^\s*def\s+\w+\([^\n]*(?:\*args|\*\*kwargs)", content, re.MULTILINE)
            ):
                violations.append(f"untyped orchestration boundary: {relative}")
            if relative.startswith("apps/orchestration/") and re.search(
                r"(?:django\.http|django\.shortcuts|ninja)", content
            ):
                violations.append(f"HTTP import in orchestration: {relative}")
        self.assertEqual(violations, [])

    def test_cross_domain_feedback_mutations_are_composed(self):
        violations = []
        for path in self.APPLICATION_ROOT.rglob("*.py"):
            if "migrations" in path.parts or path.name == "tests.py":
                continue
            relative = path.relative_to(self.ROOT).as_posix()
            if relative.startswith("apps/orchestration/"):
                continue
            if "apps.feedback.invitation_services" in path.read_text():
                violations.append(relative)
        self.assertEqual(violations, [])
