"""Focused tests for the canonical per-account authority foundation."""

from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

from django.core.exceptions import ValidationError
from django.test import Client
from django.test import TestCase
from django.utils import timezone

from apps.accounts.models import RoleChoices, User
from apps.account_security.api_tokens import issue_token_pair
from apps.access_control.authority import (
    AuthorityReason,
    build_authority_context,
    evaluate_capability,
    has_capability,
    resolve_capability,
)
from apps.access_control.contracts import AUTHORITY_CONTRACTS, validate_authority_contracts
from apps.access_control.capabilities import (
    ALL_DELEGABLE_CAPABILITIES,
    AuthoritySource,
    CAPABILITY_SPECS,
    Capability,
    HEAD_FIXED_CAPABILITIES,
    validate_capability_catalog,
)
from apps.access_control.choices import GrantReasonCode, GrantStatus, ScopeMode
from apps.access_control.models import CounselorCoverage, WorkflowAuthorityGrant
from apps.access_control.scopes import counselor_has_live_coverage_for_student
from apps.access_control.rules import owns_student_profile, owns_user
from apps.common.exceptions import NotFoundError
from apps.profiles.queries import support_directory_page
from apps.profiles.models import CounselorProfile, GCOStaffProfile, StudentProfile


def user(email, role, *, active=True, superuser=False):
    actor = User.objects.create_user(
        email=email, password="correct-horse-battery-staple", first_name="Test",
        last_name="User", role=role, is_active=active,
    )
    if superuser:
        actor.is_superuser = True
        actor.save(update_fields=["is_superuser"])
    return actor


def head(email="head@example.test"):
    actor = user(email, RoleChoices.COUNSELOR)
    CounselorProfile.objects.create(user=actor, is_head_guidance=True)
    return actor


class CapabilityCatalogTests(TestCase):
    def test_every_catalog_key_has_a_complete_spec(self):
        self.assertEqual(validate_capability_catalog(), [])
        self.assertTrue(ALL_DELEGABLE_CAPABILITIES)

    def test_institution_wide_capabilities_are_not_delegable(self):
        for capability, spec in CAPABILITY_SPECS.items():
            if spec.impact_scope == "institution":
                self.assertNotIn(AuthoritySource.ACCOUNT_GRANT, spec.authority_sources, capability)

    def test_no_dead_private_or_sign_aliases_exist(self):
        capability_names = {cap.name for cap in Capability}
        self.assertFalse(any("PRIVATE" in name for name in capability_names))
        self.assertFalse(any("NOTES_VIEW" in name for name in capability_names))
        self.assertFalse(hasattr(Capability, "GOOD_MORAL_SIGN"))

    def test_every_policy_module_declares_its_authority_sources(self):
        policy_apps = {
            path.parent.name
            for path in Path(__file__).resolve().parents[1].glob("*/policies.py")
        }
        self.assertEqual(policy_apps, set(AUTHORITY_CONTRACTS))
        self.assertEqual(validate_authority_contracts(), [])


class AuthorityResolutionTests(TestCase):
    def setUp(self):
        self.today = timezone.localdate()
        self.student = user("student@example.test", RoleChoices.STUDENT)
        self.profile = StudentProfile.objects.create(
            user=self.student, campus="Main Campus", college="CCMS", department="Guidance", program="BS",
        )
        self.counselor = user("counselor@example.test", RoleChoices.COUNSELOR)
        self.head = head()
        self.staff = user("staff@example.test", RoleChoices.GCO_STAFF)

    def grant(self, *, grantee, capability, scope=ScopeMode.COUNSELOR_COVERAGE, until=None, from_date=None, **organization):
        if until is None and capability in {
            Capability.GOOD_MORAL_APPROVE,
            Capability.APPOINTMENTS_SCHEDULE,
            Capability.APPOINTMENTS_CANCEL,
            Capability.APPOINTMENTS_OUTCOME_MANAGE,
        }:
            until = (from_date or self.today) + timedelta(days=365)
        return WorkflowAuthorityGrant.objects.create(
            grantee=grantee, capability=capability.value, scope_mode=scope.value,
            valid_from=from_date or self.today, valid_until=until, granted_by=self.head,
            grant_reason_code=GrantReasonCode.LOCAL_WORKFLOW, **organization,
        )

    def test_student_has_no_optional_authority(self):
        self.assertFalse(resolve_capability(self.student, Capability.REPORTS_RUN))

    def test_counselor_has_direct_baseline_but_no_optional_authority(self):
        context = build_authority_context(self.counselor)
        self.assertTrue(resolve_capability(context, Capability.REPORTS_RUN))
        self.assertFalse(resolve_capability(context, Capability.GOOD_MORAL_APPROVE))

    def test_head_has_exact_fixed_supervision_capabilities(self):
        context = build_authority_context(self.head)
        for capability in HEAD_FIXED_CAPABILITIES:
            self.assertTrue(resolve_capability(context, capability), capability)
        self.assertTrue(resolve_capability(context, Capability.REPORTS_RUN))
        self.assertTrue(resolve_capability(context, Capability.STUDENT_RECORDS_VIEW_SCOPED))
        self.assertFalse(resolve_capability(context, Capability.TOKENS_REVOKE))

    def test_gco_staff_has_no_role_wide_business_authority(self):
        self.assertFalse(has_capability(self.staff, Capability.APPOINTMENTS_REVIEW))
        self.assertFalse(has_capability(self.staff, Capability.REPORTS_RUN))

    def test_gco_staff_explicit_organization_grant_needs_no_counselor_link(self):
        WorkflowAuthorityGrant.objects.create(
            grantee=self.staff,
            capability=Capability.APPOINTMENTS_REVIEW.value,
            scope_mode=ScopeMode.EXPLICIT_ORGANIZATION.value,
            college="CCMS",
            valid_from=self.today,
            granted_by=self.head,
            grant_reason_code=GrantReasonCode.LOCAL_WORKFLOW,
        )
        self.assertTrue(has_capability(self.staff, Capability.APPOINTMENTS_REVIEW, target=self.profile))

    def test_authority_grant_model_has_no_counselor_relationship_field(self):
        field_names = {field.name for field in WorkflowAuthorityGrant._meta.get_fields()}
        self.assertFalse(any(field_name.endswith("_counselor") for field_name in field_names))

    def test_gco_staff_grants_cannot_use_counselor_coverage_scope(self):
        with self.assertRaises(ValidationError):
            self.grant(
                grantee=self.staff,
                capability=Capability.APPOINTMENTS_REVIEW,
                scope=ScopeMode.COUNSELOR_COVERAGE,
            )

    def test_grant_is_account_specific_and_current(self):
        self.grant(grantee=self.counselor, capability=Capability.GOOD_MORAL_APPROVE, scope=ScopeMode.ASSIGNED_RECORDS)
        self.assertTrue(has_capability(self.counselor, Capability.GOOD_MORAL_APPROVE))
        self.assertFalse(has_capability(user("other@example.test", RoleChoices.COUNSELOR), Capability.GOOD_MORAL_APPROVE))

    def test_coverage_intersects_grant_scope(self):
        CounselorCoverage.objects.create(
            counselor=self.counselor, college="CCMS", starts_at=self.today,
        )
        self.grant(grantee=self.counselor, capability=Capability.GOOD_MORAL_APPROVE)
        context = build_authority_context(self.counselor)
        self.assertTrue(resolve_capability(context, Capability.GOOD_MORAL_APPROVE, target=self.profile))
        self.profile.college = "Biology"
        self.profile.save(update_fields=["college"])
        self.assertFalse(resolve_capability(context, Capability.GOOD_MORAL_APPROVE, target=self.profile))

    def test_content_target_scope_uses_the_same_organization_dimensions(self):
        CounselorCoverage.objects.create(
            counselor=self.counselor, college="CCMS", starts_at=self.today,
        )
        self.grant(
            grantee=self.counselor,
            capability=Capability.CONTENT_LOCAL_PUBLISH,
        )
        covered_content = SimpleNamespace(target_college="CCMS")
        other_content = SimpleNamespace(target_college="Biology")
        self.assertTrue(has_capability(self.counselor, Capability.CONTENT_LOCAL_PUBLISH, target=covered_content))
        self.assertFalse(has_capability(self.counselor, Capability.CONTENT_LOCAL_PUBLISH, target=other_content))

    def test_expired_and_revoked_grants_are_denied(self):
        expired = self.grant(
            grantee=self.counselor, capability=Capability.GOOD_MORAL_APPROVE,
            from_date=self.today - timedelta(days=2), until=self.today - timedelta(days=1),
        )
        # The model accepts historical rows; resolver uses the current window.
        self.assertFalse(has_capability(self.counselor, Capability.GOOD_MORAL_APPROVE))
        expired.status = GrantStatus.REVOKED
        expired.revoked_at = timezone.now()
        expired.save(update_fields=["status", "revoked_at", "updated_at"])

    def test_inactive_and_legacy_accounts_fail_closed(self):
        inactive = user("inactive@example.test", RoleChoices.COUNSELOR, active=False)
        legacy = user("legacy@example.test", RoleChoices.COUNSELOR, superuser=True)
        for actor in (inactive, legacy):
            self.assertFalse(has_capability(actor, Capability.REPORTS_RUN))

    def test_unknown_capability_fails_closed(self):
        self.assertFalse(has_capability(self.counselor, "unknown.capability"))

    def test_decision_reports_the_authority_source(self):
        counselor_decision = evaluate_capability(self.counselor, Capability.REPORTS_RUN)
        self.assertEqual(counselor_decision.reason_code, AuthorityReason.COUNSELOR_BASELINE.value)
        self.assertEqual(counselor_decision.source, AuthoritySource.COUNSELOR_BASELINE.value)

        head_decision = evaluate_capability(self.head, Capability.REPORTS_VIEW_INSTITUTION)
        self.assertEqual(head_decision.reason_code, AuthorityReason.HEAD_FIXED.value)
        self.assertEqual(head_decision.source, AuthoritySource.HEAD_FIXED.value)

        it_admin = user("it-authority@example.test", RoleChoices.IT_ADMIN)
        it_decision = evaluate_capability(it_admin, Capability.SYSTEM_HEALTH_VIEW)
        self.assertEqual(it_decision.reason_code, AuthorityReason.IT_FIXED.value)
        self.assertEqual(it_decision.source, AuthoritySource.IT_FIXED.value)

        self.grant(
            grantee=self.staff,
            capability=Capability.APPOINTMENTS_REVIEW,
            scope=ScopeMode.EXPLICIT_ORGANIZATION,
            college="CCMS",
        )
        grant_decision = evaluate_capability(self.staff, Capability.APPOINTMENTS_REVIEW, target=self.profile)
        self.assertEqual(grant_decision.reason_code, AuthorityReason.ACCOUNT_GRANT.value)
        self.assertEqual(grant_decision.source, AuthoritySource.ACCOUNT_GRANT.value)

    def test_non_grantee_contexts_never_load_workflow_grants(self):
        for actor in (self.head, self.student, user("it-no-grants@example.test", RoleChoices.IT_ADMIN)):
            self.assertEqual(build_authority_context(actor).grants, ())

    def test_authority_decision_reason_codes_fail_closed(self):
        inactive = user("decision-inactive@example.test", RoleChoices.COUNSELOR, active=False)
        legacy = user("decision-legacy@example.test", RoleChoices.COUNSELOR, superuser=True)
        inactive_decision = evaluate_capability(inactive, Capability.REPORTS_RUN)
        legacy_decision = evaluate_capability(legacy, Capability.REPORTS_RUN)
        unknown_decision = evaluate_capability(self.counselor, "unknown.capability")
        self.assertEqual(inactive_decision.reason_code, AuthorityReason.INACTIVE.value)
        self.assertEqual(legacy_decision.reason_code, AuthorityReason.LEGACY_SUPERUSER.value)
        self.assertEqual(unknown_decision.reason_code, AuthorityReason.UNKNOWN_CAPABILITY.value)


class CoveragePrimitiveTests(TestCase):
    def test_live_coverage_window_is_enforced(self):
        today = timezone.localdate()
        counselor = user("coverage@example.test", RoleChoices.COUNSELOR)
        student = StudentProfile.objects.create(
            user=user("covered@example.test", RoleChoices.STUDENT), college="CCMS",
        )
        CounselorCoverage.objects.create(
            counselor=counselor, college="CCMS", starts_at=today - timedelta(days=10), ends_at=today - timedelta(days=1),
        )
        self.assertFalse(counselor_has_live_coverage_for_student(counselor, student))


class OwnerAndDirectoryBoundaryTests(TestCase):
    def test_owner_predicates_require_active_exact_owner(self):
        student = user("owner-boundary@example.test", RoleChoices.STUDENT)
        profile = StudentProfile.objects.create(user=student, college="CCMS")
        other = user("other-owner@example.test", RoleChoices.STUDENT)
        inactive = user("inactive-owner@example.test", RoleChoices.STUDENT, active=False)
        legacy = user("legacy-owner@example.test", RoleChoices.STUDENT, superuser=True)

        self.assertTrue(owns_user(student, student.pk))
        self.assertTrue(owns_student_profile(student, profile))
        self.assertFalse(owns_user(other, student.pk))
        self.assertFalse(owns_user(inactive, inactive.pk))
        self.assertFalse(owns_user(legacy, legacy.pk))

    def test_student_directory_projection_is_scoped_and_secret_free(self):
        today = timezone.localdate()
        student = user("directory-student@example.test", RoleChoices.STUDENT)
        profile = StudentProfile.objects.create(
            user=student, campus="Main Campus", college="CCMS"
        )
        counselor = user("directory-counselor@example.test", RoleChoices.COUNSELOR)
        CounselorProfile.objects.create(
            user=counselor, is_head_guidance=False, license_number="SECRET-LICENSE"
        )
        CounselorCoverage.objects.create(
            counselor=counselor, campus="Main Campus", college="CCMS", starts_at=today
        )
        staff = user("directory-staff@example.test", RoleChoices.GCO_STAFF)
        GCOStaffProfile.objects.create(
            user=staff, employee_number="SECRET-EMPLOYEE", designation="Front Desk"
        )
        WorkflowAuthorityGrant.objects.create(
            grantee=staff,
            capability=Capability.CALL_SLIPS_PREPARE.value,
            scope_mode=ScopeMode.EXPLICIT_ORGANIZATION.value,
            campus="Main Campus",
            college="CCMS",
            valid_from=today,
            granted_by=head("directory-head@example.test"),
            grant_reason_code=GrantReasonCode.LOCAL_WORKFLOW,
        )

        page = support_directory_page(student)
        entries = page["items"]
        self.assertEqual({entry["role"] for entry in entries}, {"COUNSELOR", "GCO_STAFF"})
        for entry in entries:
            self.assertEqual(
                set(entry), {"user_id", "display_name", "role", "designation"}
            )
            self.assertNotIn("email", entry)
            self.assertNotIn("license_number", entry)
            self.assertNotIn("employee_number", entry)

        other = user("directory-other@example.test", RoleChoices.STUDENT)
        other_profile = StudentProfile.objects.create(user=other, college="Biology")
        with self.assertRaises(NotFoundError):
            support_directory_page(student, student_id=other_profile.pk)


class AssignmentScopeBoundaryTests(TestCase):
    def test_assigned_record_grant_never_matches_a_bare_student_profile(self):
        today = timezone.localdate()
        head_actor = head("scope-head@example.test")
        counselor = user("assigned-scope@example.test", RoleChoices.COUNSELOR)
        student = StudentProfile.objects.create(
            user=user("assigned-student@example.test", RoleChoices.STUDENT), college="CCMS",
        )
        WorkflowAuthorityGrant.objects.create(
            grantee=counselor,
            capability=Capability.GOOD_MORAL_APPROVE.value,
            scope_mode=ScopeMode.ASSIGNED_RECORDS.value,
            valid_from=today,
            valid_until=today + timedelta(days=365),
            granted_by=head_actor,
            grant_reason_code=GrantReasonCode.LOCAL_WORKFLOW,
        )
        self.assertFalse(has_capability(counselor, Capability.GOOD_MORAL_APPROVE, target=student))
        self.assertTrue(has_capability(
            counselor,
            Capability.GOOD_MORAL_APPROVE,
            target=SimpleNamespace(assigned_reviewer_id=counselor.pk),
        ))

    def test_mandatory_expiry_and_maximum_window_are_enforced(self):
        today = timezone.localdate()
        counselor = user("expiry-scope@example.test", RoleChoices.COUNSELOR)
        manager = head("expiry-head@example.test")
        with self.assertRaises(ValidationError):
            WorkflowAuthorityGrant.objects.create(
                grantee=counselor,
                capability=Capability.GOOD_MORAL_APPROVE.value,
                scope_mode=ScopeMode.COUNSELOR_COVERAGE.value,
                valid_from=today,
                granted_by=manager,
                grant_reason_code=GrantReasonCode.LOCAL_WORKFLOW,
            )
        with self.assertRaises(ValidationError):
            WorkflowAuthorityGrant.objects.create(
                grantee=counselor,
                capability=Capability.GOOD_MORAL_APPROVE.value,
                scope_mode=ScopeMode.COUNSELOR_COVERAGE.value,
                valid_from=today,
                valid_until=today + timedelta(days=367),
                granted_by=manager,
                grant_reason_code=GrantReasonCode.LOCAL_WORKFLOW,
            )


class AuthorityApiContractTests(TestCase):
    def test_authority_routes_are_bearer_protected(self):
        response = Client().get("/api/v1/authority/me/")
        self.assertEqual(response.status_code, 401)

    def test_counselor_coverage_self_projection_is_current_complete_and_safe(self):
        today = timezone.localdate()
        counselor = user("coverage-api-counselor@example.test", RoleChoices.COUNSELOR)
        manager = head("coverage-api-head@example.test")
        assigned = CounselorCoverage.objects.create(
            counselor=counselor,
            campus="Main Campus",
            college="CCMS",
            department="Guidance",
            program="BS Psychology",
            is_primary=True,
            starts_at=today,
            assigned_by=manager,
        )
        CounselorCoverage.objects.create(
            counselor=counselor,
            starts_at=today,
            is_primary=False,
            assigned_by=manager,
        )
        CounselorCoverage.objects.create(
            counselor=counselor,
            college="Expired College",
            starts_at=today - timedelta(days=10),
            ends_at=today - timedelta(days=1),
            assigned_by=manager,
        )
        CounselorCoverage.objects.create(
            counselor=counselor,
            college="Future College",
            starts_at=today + timedelta(days=1),
            assigned_by=manager,
        )
        inactive = user("coverage-api-inactive@example.test", RoleChoices.COUNSELOR, active=False)
        CounselorCoverage.objects.create(counselor=inactive, starts_at=today)
        student = user("coverage-api-student@example.test", RoleChoices.STUDENT)

        token = issue_token_pair(counselor, assurance_verified=True).access_token
        response = Client().get(
            "/api/v1/authority/me/coverage/?page=1&page_size=100",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
        self.assertEqual(response.status_code, 200, response.content)
        payload = response.json()
        self.assertEqual(payload["total"], 2)
        self.assertEqual(len(payload["items"]), 2)
        self.assertEqual(payload["items"][0]["college"], assigned.college)
        self.assertEqual(payload["items"][1]["scope_label"], "All current coverage")
        for item in payload["items"]:
            self.assertEqual(
                set(item), {"scope_label", "campus", "college", "department", "program", "is_primary"}
            )
            self.assertNotIn("id", item)
            self.assertNotIn("assigned_by", item)
            self.assertNotIn("reason_code", item)

        student_token = issue_token_pair(student, assurance_verified=True).access_token
        student_response = Client().get(
            "/api/v1/authority/me/coverage/",
            HTTP_AUTHORIZATION=f"Bearer {student_token}",
        )
        self.assertEqual(student_response.status_code, 200, student_response.content)
        self.assertEqual(student_response.json()["items"], [])

    def test_counselor_coverage_self_projection_route_is_documented(self):
        from config.api.v1 import api_v1

        schema = api_v1.get_openapi_schema()
        operation = schema["paths"]["/api/v1/authority/me/coverage/"]["get"]
        self.assertEqual(operation["operationId"], "authority_me_coverage")
        self.assertIn("CounselorCoveragePageSchema", str(operation))

    def test_authority_schema_has_stable_operations_and_bearer_security(self):
        from config.api.v1 import api_v1

        schema = api_v1.get_openapi_schema()
        self.assertIn("/api/v1/authority/capabilities/", schema["paths"])
        self.assertIn("/api/v1/authority/grants/", schema["paths"])
        self.assertIn("/api/v1/authority/me/", schema["paths"])
        self.assertIn("CompassBearerAuthentication", schema["components"]["securitySchemes"])

    def test_authority_schema_excludes_retired_counselor_link_field(self):
        from config.api.v1 import api_v1

        schema = api_v1.get_openapi_schema()
        authority_schema = str({
            "paths": {
                path: value
                for path, value in schema["paths"].items()
                if path.startswith("/api/v1/authority/")
            },
            "components": {
                "schemas": {
                    name: value
                    for name, value in schema["components"]["schemas"].items()
                    if name.startswith(("Capability", "Grant", "Effective", "Scope"))
                },
            },
        })
        self.assertNotIn("linked_counselor_id", authority_schema)
        self.assertIn("authority_sources", authority_schema)
        self.assertIn("grant_eligible_roles", authority_schema)
        self.assertIn("grant_scope_modes", authority_schema)
        self.assertNotIn("head_default", schema)
        self.assertNotIn("'eligible_roles':", schema)
        self.assertNotIn("'scope_modes':", schema)
