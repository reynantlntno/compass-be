"""Focused tests for the read-only Profiles vertical cutover."""

from datetime import timedelta
from pathlib import Path
from unittest import mock
from uuid import uuid4

from django.test import Client, TestCase
from django.utils import timezone

from apps.access_control.capabilities import Capability
from apps.access_control.choices import GrantReasonCode, GrantStatus, ScopeMode
from apps.access_control.models import CounselorCoverage, WorkflowAuthorityGrant
from apps.access_control import selectors as access_control_selectors
from apps.accounts.models import RoleChoices, User
from apps.account_security.api_tokens import issue_token_pair
from apps.common.contracts import PageRequest
from apps.common.exceptions import (
    NotFoundError,
    PermissionDeniedError,
    ValidationError,
)
from apps.profiles import selectors as profiles_selectors
from apps.profiles.policies import can_view_support_directory
from apps.profiles.queries import my_profile, support_directory_page
from apps.profiles.projections import (
    DIRECTORY_ENTRY_KEYS,
    SELF_PROFILE_KEYS,
    project_base_profile,
    project_counselor_directory_entry,
    project_self_counselor_profile,
    project_self_staff_profile,
    project_self_student_profile,
    project_staff_directory_entry,
)
from apps.profiles.models import CounselorProfile, GCOStaffProfile, StudentProfile


def user(email, role, *, active=True, superuser=False, **extra):
    fields = {
        "password": "correct-horse-battery-staple",
        "first_name": "Test",
        "last_name": "User",
        "role": role,
        "is_active": active,
    }
    fields.update(extra)
    actor = User.objects.create_user(email=email, **fields)
    if superuser:
        actor.is_superuser = True
        actor.save(update_fields=["is_superuser"])
    return actor


def today():
    return timezone.localdate()


def make_student(email="profile-student@example.test", **profile_fields):
    actor = user(email, RoleChoices.STUDENT)
    fields = {"campus": "Main Campus", "college": "CCMS"}
    fields.update(profile_fields)
    profile = StudentProfile.objects.create(user=actor, **fields)
    return actor, profile


def make_grant(grantee, *, capability, scope_mode=ScopeMode.EXPLICIT_ORGANIZATION,
               college="CCMS", valid_from=None, valid_until=None, status=None):
    grant = WorkflowAuthorityGrant.objects.create(
        grantee=grantee,
        capability=capability.value if hasattr(capability, "value") else str(capability),
        scope_mode=scope_mode.value if hasattr(scope_mode, "value") else str(scope_mode),
        college=college,
        valid_from=valid_from if valid_from is not None else today(),
        valid_until=valid_until,
        granted_by=user(f"grant-head-{uuid4().hex[:10]}@example.test", RoleChoices.COUNSELOR),
        grant_reason_code=GrantReasonCode.LOCAL_WORKFLOW,
    )
    if status is not None:
        WorkflowAuthorityGrant.objects.filter(pk=grant.pk).update(status=status)
        grant.refresh_from_db()
    return grant


def make_staff(email, designation="Front Desk"):
    staff = user(email, RoleChoices.GCO_STAFF)
    GCOStaffProfile.objects.create(user=staff, designation=designation)
    return staff


class SelfProjectionTests(TestCase):
    def test_self_student_projection_has_exact_owner_only_keys(self):
        _, profile = make_student(
            student_number="2026-0001", control_number="CTRL-SECRET",
            department="Guidance", program="BS Psych", year_level=2,
            lifecycle_status="ACTIVE",
        )
        projection = project_self_student_profile(profile)
        expected = {
            "user_id", "display_name", "role", "profile_type", "student_number",
            "lifecycle_status", "campus", "college", "department", "program",
            "year_level",
        }
        self.assertEqual(set(projection), expected)
        self.assertTrue(expected <= SELF_PROFILE_KEYS)
        self.assertNotIn("control_number", projection)
        self.assertNotIn("email", projection)

    def test_self_counselor_and_staff_projections_are_secret_free(self):
        counselor = user("projection-counselor@example.test", RoleChoices.COUNSELOR)
        counselor_profile = CounselorProfile.objects.create(
            user=counselor, license_number="LIC-SECRET",
        )
        counselor_projection = project_self_counselor_profile(counselor_profile)
        self.assertEqual(set(counselor_projection), {
            "user_id", "display_name", "role", "profile_type",
            "designation", "is_head_guidance",
        })
        self.assertNotIn("license_number", counselor_projection)

        staff = user("projection-staff@example.test", RoleChoices.GCO_STAFF)
        staff_profile = GCOStaffProfile.objects.create(
            user=staff, employee_number="EMP-SECRET", designation="Front Desk",
        )
        staff_projection = project_self_staff_profile(staff_profile)
        self.assertEqual(set(staff_projection), {
            "user_id", "display_name", "role", "profile_type", "designation",
        })
        self.assertNotIn("employee_number", staff_projection)

    def test_directory_entries_use_exact_allowlist_and_base_projection(self):
        counselor = user("entry-counselor@example.test", RoleChoices.COUNSELOR)
        counselor_profile = CounselorProfile.objects.create(
            user=counselor, license_number="LIC-SECRET",
        )
        entry = project_counselor_directory_entry(counselor_profile)
        self.assertEqual(set(entry), DIRECTORY_ENTRY_KEYS)
        staff = user("entry-staff@example.test", RoleChoices.GCO_STAFF)
        self.assertEqual(set(project_staff_directory_entry(
            GCOStaffProfile(user=staff, employee_number="EMP-SECRET")
        )), DIRECTORY_ENTRY_KEYS)
        self.assertNotIn("employee_number", project_staff_directory_entry(
            GCOStaffProfile(user=staff, employee_number="EMP-SECRET")
        ))
        self.assertEqual(set(project_base_profile(counselor)), {
            "user_id", "display_name", "role",
        })


class MyProfileQueryTests(TestCase):
    def test_student_owner_gets_own_profile(self):
        student, _ = make_student(student_number="2026-0002")
        projection = my_profile(student)
        self.assertEqual(projection["role"], RoleChoices.STUDENT)
        self.assertEqual(projection["student_number"], "2026-0002")

    def test_inactive_and_legacy_actors_fail_closed(self):
        inactive = user("inactive-self@example.test", RoleChoices.STUDENT, active=False)
        legacy = user("legacy-self@example.test", RoleChoices.STUDENT, superuser=True)
        for actor in (inactive, legacy):
            with self.subTest(actor=actor.email):
                with self.assertRaises(PermissionDeniedError):
                    my_profile(actor)

    def test_missing_role_profiles_fail_closed(self):
        bare_student = user("bare-student@example.test", RoleChoices.STUDENT)
        bare_counselor = user("bare-counselor@example.test", RoleChoices.COUNSELOR)
        bare_staff = user("bare-staff@example.test", RoleChoices.GCO_STAFF)
        for actor in (bare_student, bare_counselor, bare_staff):
            with self.subTest(actor=actor.email):
                with self.assertRaises(PermissionDeniedError):
                    my_profile(actor)

    def test_it_admin_receives_base_role_safe_projection(self):
        admin = user("admin-self@example.test", RoleChoices.IT_ADMIN)
        projection = my_profile(admin)
        self.assertEqual(set(projection), {"user_id", "display_name", "role"})
        self.assertEqual(projection["role"], RoleChoices.IT_ADMIN)


class SupportDirectoryPolicyTests(TestCase):
    def test_owner_matches_and_non_owner_is_denied(self):
        student, profile = make_student()
        _, other_profile = make_student("other-directory@example.test")
        self.assertTrue(can_view_support_directory(student, profile))
        self.assertFalse(can_view_support_directory(student, other_profile))
        with self.assertRaises(NotFoundError):
            support_directory_page(student, student_id=other_profile.pk)

    def test_inactive_and_legacy_actors_fail_closed(self):
        _, profile = make_student()
        inactive = user("inactive-dir@example.test", RoleChoices.COUNSELOR, active=False)
        legacy = user("legacy-dir@example.test", RoleChoices.COUNSELOR, superuser=True)
        self.assertFalse(can_view_support_directory(inactive, profile))
        self.assertFalse(can_view_support_directory(legacy, profile))

    def test_it_admin_is_always_denied(self):
        _, profile = make_student()
        admin = user("admin-dir@example.test", RoleChoices.IT_ADMIN)
        self.assertFalse(can_view_support_directory(admin, profile))
        with self.assertRaises(PermissionDeniedError):
            support_directory_page(admin, student_id=profile.pk)

    def test_counselor_requires_live_coverage_of_target(self):
        _, profile = make_student()
        covered = user("covered-counselor@example.test", RoleChoices.COUNSELOR)
        CounselorCoverage.objects.create(
            counselor=covered, campus="Main Campus", college="CCMS",
            starts_at=today() - timedelta(days=1),
        )
        self.assertTrue(can_view_support_directory(covered, profile))

        uncovered = user("uncovered-counselor@example.test", RoleChoices.COUNSELOR)
        self.assertFalse(can_view_support_directory(uncovered, profile))

        expired = user("expired-counselor@example.test", RoleChoices.COUNSELOR)
        CounselorCoverage.objects.create(
            counselor=expired, campus="Main Campus", college="CCMS",
            starts_at=today() - timedelta(days=30),
            ends_at=today() - timedelta(days=1),
        )
        self.assertFalse(can_view_support_directory(expired, profile))

    def test_blank_student_placement_does_not_match_narrow_coverage(self):
        student, profile = make_student(college="")
        narrow = user("narrow-coverage@example.test", RoleChoices.COUNSELOR)
        CounselorProfile.objects.create(user=narrow)
        CounselorCoverage.objects.create(
            counselor=narrow,
            campus="Main Campus",
            college="CCMS",
            starts_at=today() - timedelta(days=1),
        )

        self.assertFalse(can_view_support_directory(narrow, profile))
        self.assertEqual(support_directory_page(student)["items"], [])

    def test_head_access_requires_named_fixed_capability_not_role_or_flag(self):
        _, profile = make_student()
        head = user("dir-head@example.test", RoleChoices.COUNSELOR)
        CounselorProfile.objects.create(user=head, is_head_guidance=True)
        self.assertTrue(can_view_support_directory(head, profile))

        # The decision rides on the named fixed capability, never the
        # designation flag or the counselor role alone.
        with mock.patch(
            "apps.profiles.policies.has_fixed_capability", return_value=False
        ):
            self.assertFalse(can_view_support_directory(head, profile))

        regular = user("regular-capability-counselor@example.test", RoleChoices.COUNSELOR)
        CounselorProfile.objects.create(user=regular, is_head_guidance=False)
        with mock.patch(
            "apps.profiles.policies.has_fixed_capability", return_value=True
        ):
            self.assertFalse(can_view_support_directory(regular, profile))

    def test_gco_staff_grant_variants_fail_closed_except_matching_explicit_org(self):
        _, in_scope = make_student(college="CCMS")
        _, out_of_scope = make_student("elsewhere@example.test", college="Engineering")
        staff = make_staff("scoped-staff@example.test")

        # No grant at all.
        self.assertFalse(can_view_support_directory(staff, in_scope))

        # Wrong capability: powerful but not on the student-facing allowlist.
        make_grant(staff, capability=Capability.REPORTS_RUN)
        self.assertFalse(can_view_support_directory(staff, in_scope))

        # Office-wide grants never authorize the directory.
        office_wide = make_grant(
            staff,
            capability=Capability.CALL_SLIPS_PREPARE,
            scope_mode=ScopeMode.OFFICE_WIDE,
            college=None,
            valid_until=today() + timedelta(days=30),
        )
        self.assertEqual(office_wide.scope_mode, ScopeMode.OFFICE_WIDE.value)
        self.assertFalse(can_view_support_directory(staff, in_scope))

        # Assigned-records grants are workflow-record scoped, not student scope.
        make_grant(
            staff,
            capability=Capability.CALL_SLIPS_PREPARE,
            scope_mode=ScopeMode.ASSIGNED_RECORDS,
            college=None,
        )
        self.assertFalse(can_view_support_directory(staff, in_scope))

        # Expired grant.
        make_grant(
            staff,
            capability=Capability.CALL_SLIPS_PREPARE,
            valid_from=today() - timedelta(days=30),
            valid_until=today() - timedelta(days=1),
        )
        self.assertFalse(can_view_support_directory(staff, in_scope))

        # Revoked grant.
        make_grant(
            staff,
            capability=Capability.CALL_SLIPS_PREPARE,
            status=GrantStatus.REVOKED,
        )
        self.assertFalse(can_view_support_directory(staff, in_scope))

        # Mismatched organization scope.
        self.assertFalse(can_view_support_directory(staff, out_of_scope))

        # Matching explicit organization grant is honored and contained.
        make_grant(staff, capability=Capability.CALL_SLIPS_PREPARE, college="CCMS")
        self.assertTrue(can_view_support_directory(staff, in_scope))
        self.assertFalse(can_view_support_directory(staff, out_of_scope))

    def test_blank_explicit_grant_scope_fails_closed_even_if_row_is_corrupt(self):
        _, profile = make_student(college="CCMS")
        staff = make_staff("corrupt-scope-staff@example.test")
        grant = make_grant(staff, capability=Capability.CALL_SLIPS_PREPARE)
        WorkflowAuthorityGrant.objects.filter(pk=grant.pk).update(
            campus=None,
            college=None,
            department=None,
            program=None,
        )

        self.assertFalse(can_view_support_directory(staff, profile))

    def test_directory_target_must_be_an_active_student_profile(self):
        head = user("target-head@example.test", RoleChoices.COUNSELOR)
        CounselorProfile.objects.create(user=head, is_head_guidance=True)

        non_student = user("target-counselor@example.test", RoleChoices.COUNSELOR)
        non_student_profile = StudentProfile.objects.create(user=non_student)
        with self.assertRaises(NotFoundError):
            support_directory_page(head, student_id=non_student_profile.pk)

        inactive_student, inactive_profile = make_student("inactive-target@example.test")
        inactive_student.is_active = False
        inactive_student.save(update_fields=["is_active"])
        with self.assertRaises(NotFoundError):
            support_directory_page(head, student_id=inactive_profile.pk)


class SupportDirectoryQueryTests(TestCase):
    def test_directory_entries_are_ordered_deterministic_and_scoped(self):
        student, profile = make_student()
        counselor_b = user("counselor-b@example.test", RoleChoices.COUNSELOR,
                           first_name="Zed", last_name="Later")
        CounselorProfile.objects.create(user=counselor_b)
        counselor_a = user("counselor-a@example.test", RoleChoices.COUNSELOR,
                           first_name="Ada", last_name="Early")
        CounselorProfile.objects.create(user=counselor_a)
        for counselor in (counselor_b, counselor_a):
            CounselorCoverage.objects.create(
                counselor=counselor, campus="Main Campus", college="CCMS",
                starts_at=today() - timedelta(days=1),
            )
        staff = make_staff("listed-staff@example.test", designation="Front Desk")
        make_grant(staff, capability=Capability.CALL_SLIPS_PREPARE)

        page = support_directory_page(student)
        entries = page["items"]
        self.assertEqual(
            [(entry["role"], entry["display_name"]) for entry in entries],
            [
                ("COUNSELOR", "Ada Early"),
                ("COUNSELOR", "Zed Later"),
                ("GCO_STAFF", "Test User"),
            ],
        )
        for entry in entries:
            self.assertEqual(set(entry), DIRECTORY_ENTRY_KEYS)

    def test_authorized_but_empty_directory_is_successful(self):
        student, profile = make_student(college="Empty College")
        page = support_directory_page(student)
        self.assertEqual(page["items"], [])
        self.assertEqual(page["total"], 0)
        self.assertEqual(page["page"], 1)

    def test_pagination_is_bounded_and_stable(self):
        student, profile = make_student()
        names = [("Alpha", "One"), ("Beta", "Two"), ("Gamma", "Three")]
        for index, (first, last) in enumerate(names):
            counselor = user(
                f"paged-counselor-{index}@example.test", RoleChoices.COUNSELOR,
                first_name=first, last_name=last,
            )
            CounselorProfile.objects.create(user=counselor)
            CounselorCoverage.objects.create(
                counselor=counselor, campus="Main Campus", college="CCMS",
                starts_at=today() - timedelta(days=1),
            )
        first_page = support_directory_page(
            student, page=PageRequest(page=1, page_size=2)
        )
        second_page = support_directory_page(
            student, page=PageRequest(page=2, page_size=2)
        )
        self.assertEqual(len(first_page["items"]), 2)
        self.assertEqual(first_page["page_size"], 2)
        self.assertEqual(first_page["total"], 3)
        self.assertEqual(len(second_page["items"]), 1)
        all_names = [entry["display_name"] for entry in first_page["items"]] + [
            entry["display_name"] for entry in second_page["items"]
        ]
        self.assertEqual(all_names, sorted(all_names))

    def test_directory_query_count_is_bounded(self):
        student, profile = make_student()
        staff = make_staff("bounded-staff@example.test")
        make_grant(staff, capability=Capability.CALL_SLIPS_PREPARE)
        with self.assertNumQueries(4):
            support_directory_page(student)


class ProfilesApiTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.student, self.student_profile = make_student(student_number="2026-7777")
        self.student_token = issue_token_pair(
            self.student, assurance_verified=True
        ).access_token

    def headers(self, token=None):
        return {"HTTP_AUTHORIZATION": f"Bearer {token or self.student_token}"}

    def test_me_returns_owner_projection_with_correlation_and_no_store(self):
        response = self.client.get("/api/v1/profiles/me/", **self.headers())
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["role"], RoleChoices.STUDENT)
        self.assertEqual(payload["student_number"], "2026-7777")
        self.assertNotIn("control_number", payload)
        self.assertNotIn("email", payload)
        self.assertIsNotNone(response["X-Request-ID"])
        self.assertEqual(response["Cache-Control"], "no-store")

    def test_unauthenticated_request_is_denied(self):
        response = self.client.get("/api/v1/profiles/me/")
        self.assertEqual(response.status_code, 401)
        payload = response.json()
        self.assertEqual(payload["code"], "unauthenticated")
        self.assertIn("detail", payload)

    def test_student_supplying_another_student_id_gets_generic_not_found(self):
        _, other_profile = make_student("api-other@example.test")
        response = self.client.get(
            f"/api/v1/profiles/directory/?student_id={other_profile.pk}",
            **self.headers(),
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["code"], "not_found")

    def test_staff_actors_require_student_id(self):
        counselor = user("api-counselor@example.test", RoleChoices.COUNSELOR)
        token = issue_token_pair(counselor, assurance_verified=True).access_token
        response = self.client.get("/api/v1/profiles/directory/", **self.headers(token))
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()["code"], "validation")

    def test_out_of_scope_counselor_gets_generic_not_found(self):
        counselor = user("api-oos-counselor@example.test", RoleChoices.COUNSELOR)
        token = issue_token_pair(counselor, assurance_verified=True).access_token
        response = self.client.get(
            f"/api/v1/profiles/directory/?student_id={self.student_profile.pk}",
            **self.headers(token),
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["code"], "not_found")

    def test_it_admin_is_denied_on_both_routes(self):
        admin = user("api-admin@example.test", RoleChoices.IT_ADMIN)
        token = issue_token_pair(admin, assurance_verified=True).access_token
        me = self.client.get("/api/v1/profiles/me/", **self.headers(token))
        directory = self.client.get("/api/v1/profiles/directory/", **self.headers(token))
        self.assertEqual(me.status_code, 200)  # base role-safe projection only
        self.assertEqual(set(me.json()), {"user_id", "display_name", "role"})
        self.assertEqual(directory.status_code, 403)
        self.assertEqual(directory.json()["code"], "permission")

    def test_invalid_page_size_fails_closed(self):
        response = self.client.get(
            "/api/v1/profiles/directory/?page_size=1000", **self.headers()
        )
        self.assertEqual(response.status_code, 422)

    def test_openapi_schema_declares_stable_bearer_operations(self):
        schema = self.client.get("/api/v1/openapi.json")
        self.assertEqual(schema.status_code, 200)
        document = schema.json()
        me_operation = document["paths"]["/api/v1/profiles/me/"]["get"]
        directory_operation = document["paths"]["/api/v1/profiles/directory/"]["get"]
        self.assertEqual(me_operation["operationId"], "profiles_me")
        self.assertEqual(directory_operation["operationId"], "profiles_support_directory")
        security_schemes = document["components"]["securitySchemes"]
        self.assertIn("CompassBearerAuthentication", security_schemes)
        self.assertEqual(security_schemes["CompassBearerAuthentication"]["scheme"], "bearer")


class BoundaryPurityTests(TestCase):
    def _boundary_sources(self):
        base = Path(__file__).resolve().parent
        for name in (
            "policies.py", "selectors.py", "queries.py",
            "projections.py", "commands.py", "services.py",
        ):
            yield name, (base / name).read_text()

    def test_profiles_boundaries_never_import_http_types(self):
        for name, source in self._boundary_sources():
            with self.subTest(module=name):
                self.assertNotIn("django.http", source)
                for forbidden in ("HttpRequest", "HttpResponse", "Http404", "JsonResponse"):
                    self.assertNotIn(forbidden, source)

    def test_old_broad_directory_selectors_are_gone(self):
        removed_names = (
            "get_counselors_visible_to",
            "get_staff_visible_to",
            "get_student_support_contacts_visible_to",
            "STUDENT_DIRECTORY_GCO_CAPABILITIES",
        )
        legacy_source = Path(access_control_selectors.__file__).read_text()
        for removed in removed_names:
            with self.subTest(selector=removed):
                self.assertFalse(hasattr(access_control_selectors, removed))
                self.assertNotIn(removed, legacy_source)

    def test_shared_cross_domain_student_scope_helper_remains(self):
        # Inventory, Assessments, Reports, support needs, and workflow
        # selectors still depend on this shared helper.
        self.assertTrue(callable(access_control_selectors.get_students_visible_to))
        self.assertTrue(callable(profiles_selectors.select_student_by_id))
