# Project: COMPASS
# File: apps/reports/tests.py
# Module: apps.reports
# Purpose: Focused allow/deny tests for report authorization scope (contract boundary).
# Notes:
#   - CounselorCoverage automatically scopes counselor reports. User-provided
#     filters may narrow that scope but never broaden it.
#   - Head Guidance retains explicit office-wide reports and profiling access.
#   - The special students_profile cohort path and the CSM boundary are
#     deliberately unchanged and asserted explicitly.

from datetime import timedelta
from io import StringIO
import json
from unittest.mock import patch

from django.test import Client, TestCase
from django.core.exceptions import ValidationError as DjangoValidationError
from apps.common.exceptions import ValidationError
from django.core.management import call_command
from django.utils import timezone

from apps.accounts.models import RoleChoices, User
from apps.account_security.api_tokens import issue_token_pair
from apps.access_control.capabilities import Capability
from apps.access_control.choices import GrantReasonCode, ScopeMode
from apps.access_control.models import CounselorCoverage, WorkflowAuthorityGrant
from apps.common.policy import PolicyChangeRequest
from apps.governance.policy_lifecycle import ensure_active_policy_for_target, replace_active_policy_for_target
from apps.profiles.models import (
    CounselorProfile,
    StudentAcademicCohort,
    StudentProfile,
)
from apps.reports.choices import (
    ExportFormatChoices,
    ExportStatusChoices,
    ReportFamilyChoices,
    ReportRunStatus,
    SensitivityLevel,
    SuppressionMode,
)
from apps.reports.models import (
    ALLOWED_SUPPRESSION_MODES_BY_FAMILY,
    ALLOWED_SUPPRESSION_MODES_BY_DEFINITION_KEY,
    CANONICAL_SUPPRESSION_MODE_BY_FAMILY,
    CANONICAL_SUPPRESSION_MODE_BY_DEFINITION_KEY,
    ReportDefinition,
    ReportExportRequest,
    ReportRun,
    SUPPRESSION_MODE_DEFINITION_FAMILY_BY_KEY,
    allowed_suppression_modes_for_definition,
    canonical_suppression_mode_for_definition,
)
from apps.reports.commands import ReportRunCommand
from apps.reports.suppression import (
    MIN_SUPPRESSION_THRESHOLD,
    SUPPRESSION_LABEL,
    resolve_report_suppression_policy,
    suppress_report_data,
    suppress_small_counts,
)
from apps.reports.export_adapters import validate_export_row
from apps.reports.services import apply_suppression
from apps.reports.services import execute_pending_report_run, run_report_command
from apps.reports.export_services import request_report_export
from apps.reports.seed_data import REPORT_DEFINITIONS
from apps.reports.policies import (
    can_approve_report_export,
    can_archive_report_export,
    can_deny_report_export,
    can_download_report_export,
    can_expire_report_export,
    can_generate_report_export,
    can_manage_report_definitions,
    can_manage_report_templates,
    can_request_identifiable_export,
    can_request_report_export,
    can_run_report,
    can_view_export_request,
    can_view_report_definition,
    can_view_sensitive_aggregate,
    get_current_report_export_scope,
    resolve_report_export_policy,
)
from apps.reports.selectors import (
    get_audit_report_access_aggregates,
    get_document_requests_aggregates,
    get_public_contact_aggregates,
    get_student_profile_inventory_aggregates,
)


def _build_user(email, role, *, is_active=True):
    return User.objects.create_user(
        email=email,
        password="correct-horse-battery-staple",
        first_name="Test",
        last_name="User",
        role=role,
        is_active=is_active,
    )


def _grant_report_access(staff, *, office_wide=False, college=None):
    return [WorkflowAuthorityGrant.objects.create(
        grantee=staff, capability=capability.value,
        scope_mode=(ScopeMode.OFFICE_WIDE if office_wide else ScopeMode.EXPLICIT_ORGANIZATION).value,
        college=college, valid_from=timezone.localdate(),
        valid_until=timezone.localdate() + timedelta(days=365) if office_wide else None,
        granted_by=staff, grant_reason_code=GrantReasonCode.LOCAL_WORKFLOW.value,
    ) for capability in (Capability.REPORTS_RUN, Capability.REPORTS_VIEW_DEFINITIONS)]


def _suppression_request(**values):
    envelope = {
        name: values.pop(name, default)
        for name, default in (
            ("key", "reports.suppression"),
            ("effective_from", None),
            ("effective_until", None),
            ("source_reference", "TEST:SUPPRESSION"),
            ("target_type", "reports.ReportDefinition"),
            ("target_reference", ""),
        )
    }
    configuration = {
        "report_key": values.pop("report_key", ""),
        "mode": values.pop("mode", "NONE"),
        "requires_suppression": values.pop("requires_suppression", True),
        "default_threshold": values.pop("default_threshold", MIN_SUPPRESSION_THRESHOLD),
        "threshold": values.pop("threshold", MIN_SUPPRESSION_THRESHOLD),
        "sensitive_categories": list(values.pop("sensitive_categories", ())),
    }
    return PolicyChangeRequest(configuration=configuration, **envelope)


def _build_report_definition(
    *,
    key,
    title,
    family,
    sensitivity_level=SensitivityLevel.SENSITIVE,
    suppression_mode=None,
    requires_suppression=None,
    default_suppression_threshold=MIN_SUPPRESSION_THRESHOLD,
):
    mode = suppression_mode or canonical_suppression_mode_for_definition(
        key=key,
        family=family,
    )
    definition = ReportDefinition.objects.create(
        key=key,
        title=title,
        family=family,
        sensitivity_level=sensitivity_level,
        is_active=True,
    )
    ensure_active_policy_for_target(
        None,
        _suppression_request(
            key="reports.suppression",
            target_type="reports.ReportDefinition",
            target_reference=str(definition.pk),
            source_reference=f"TEST:REPORT:{key}",
            effective_from=timezone.now(),
            report_key=key,
            mode=mode.value if hasattr(mode, "value") else str(mode),
            requires_suppression=(
                mode != SuppressionMode.NONE
                if requires_suppression is None
                else requires_suppression
            ),
            default_threshold=default_suppression_threshold,
            threshold=default_suppression_threshold,
        ),
        system_context=True,
    )
    return definition


def _head_guidance(*, email):
    actor = _build_user(email=email, role=RoleChoices.COUNSELOR)
    CounselorProfile.objects.create(user=actor, is_head_guidance=True)
    return actor


def _set_report_policy(
    definition,
    *,
    threshold=MIN_SUPPRESSION_THRESHOLD,
    default_threshold=None,
    mode=None,
    requires_suppression=None,
    sensitive_categories=(),
    effective_from=None,
    effective_until=None,
):
    resolved_mode = mode or resolve_report_suppression_policy(definition).mode
    resolved_mode = resolved_mode.value if hasattr(resolved_mode, "value") else str(resolved_mode)
    if default_threshold is None:
        default_threshold = resolve_report_suppression_policy(definition).threshold
    if requires_suppression is None:
        requires_suppression = resolved_mode != SuppressionMode.NONE.value
    return replace_active_policy_for_target(
        None,
        _suppression_request(
            key="reports.suppression",
            target_type="reports.ReportDefinition",
            target_reference=str(definition.pk),
            source_reference=f"TEST:REPORT:{definition.key}:UPDATED",
            effective_from=effective_from or timezone.now(),
            effective_until=effective_until,
            report_key=definition.key,
            mode=resolved_mode,
            requires_suppression=requires_suppression,
            default_threshold=default_threshold,
            threshold=threshold,
            sensitive_categories=tuple(sensitive_categories),
        ),
        system_context=True,
    )


class ReportRunPolicyTests(TestCase):
    """Allow/deny matrix for can_run_report across roles and scopes."""

    def setUp(self):
        self.counselor = _build_user(email="counselor@example.test", role=RoleChoices.COUNSELOR)
        self.other_counselor = _build_user(email="other-counselor@example.test", role=RoleChoices.COUNSELOR)
        self.head = _head_guidance(email="head@example.test")
        self.staff = _build_user(email="staff@example.test", role=RoleChoices.GCO_STAFF)
        self.no_scope_staff = _build_user(email="no-scope-staff@example.test", role=RoleChoices.GCO_STAFF)
        self.student = _build_user(email="student@example.test", role=RoleChoices.STUDENT)
        self.it_admin = _build_user(email="it@example.test", role=RoleChoices.IT_ADMIN)

        # Coverage for the primary counselor: campus Main Campus, college CCMS.
        CounselorCoverage.objects.create(
            counselor=self.counselor,
            campus="Main Campus",
            college="CCMS",
            starts_at=timezone.localdate(),
        )

        # A report family shared by counselor and GCO report families.
        self.exit_definition = _build_report_definition(
            key="exit_interview_completion_summary",
            title="Exit Interview Completion",
            family=ReportFamilyChoices.EXIT_INTERVIEW,
        )
        # A family NOT in counselor families (GCO office-wide family).
        self.form_collection_definition = _build_report_definition(
            key="form_collection_progress_summary",
            title="Form Collection Progress",
            family=ReportFamilyChoices.FORM_COLLECTION_PROGRESS,
        )

    def test_counselor_unfiltered_run_allowed_with_live_coverage(self):
        self.assertTrue(can_run_report(self.counselor, self.exit_definition, {}))

    def test_counselor_filter_within_coverage_allowed(self):
        self.assertTrue(
            can_run_report(self.counselor, self.exit_definition, {"college": "CCMS"})
        )
        self.assertTrue(
            can_run_report(
                self.counselor,
                self.exit_definition,
                {"campus": "Main Campus", "college": "CCMS", "department": "Nursing"},
            )
        )
        # Narrowing on a coverage-unbound dimension (program is None on the
        # coverage row) is still allowed: it narrows, it does not broaden.
        self.assertTrue(
            can_run_report(self.counselor, self.exit_definition, {"program": "BSN"})
        )

    def test_counselor_filter_outside_coverage_denied(self):
        self.assertFalse(
            can_run_report(self.counselor, self.exit_definition, {"college": "Biology"})
        )
        self.assertFalse(
            can_run_report(self.counselor, self.exit_definition, {"campus": "Other Campus"})
        )

    def test_counselor_without_coverage_denied(self):
        self.assertFalse(can_run_report(self.other_counselor, self.exit_definition, {}))
        self.assertFalse(
            can_run_report(self.other_counselor, self.exit_definition, {"college": "CCMS"})
        )

    def test_counselor_cannot_run_non_counselor_family(self):
        self.assertFalse(
            can_run_report(self.counselor, self.form_collection_definition, {})
        )

    def test_global_coverage_counselor_allows_any_narrowing_filter(self):
        global_counselor = _build_user(
            email="global-counselor@example.test", role=RoleChoices.COUNSELOR
        )
        CounselorCoverage.objects.create(
            counselor=global_counselor,
            starts_at=timezone.localdate(),
        )
        self.assertTrue(can_run_report(global_counselor, self.exit_definition, {}))
        self.assertTrue(
            can_run_report(
                global_counselor,
                self.exit_definition,
                {"campus": "X", "college": "Y", "department": "Z", "program": "W"},
            )
        )

    def test_head_guidance_unfiltered_office_wide_allowed(self):
        self.assertTrue(can_run_report(self.head, self.exit_definition, {}))
        self.assertTrue(can_run_report(self.head, self.form_collection_definition, {}))

    def test_head_guidance_office_wide_report_scope(self):
        scope = get_current_report_export_scope(self.head, self.exit_definition)
        self.assertEqual(scope["authority"], "HEAD_GUIDANCE")
        self.assertEqual(scope["scopes"], [{"office_wide": True}])

    def test_head_guidance_can_view_sensitive_aggregate(self):
        self.assertTrue(
            can_view_sensitive_aggregate(self.head, self.exit_definition, "gender_code")
        )

    def test_gco_staff_with_unbound_assignment_unfiltered_allowed(self):
        _grant_report_access(self.staff, office_wide=True)
        # Unbound assignment means an office-wide reports-assistance slice;
        # filters only narrow that slice, never broaden it.
        self.assertTrue(can_run_report(self.staff, self.exit_definition, {}))
        self.assertTrue(
            can_run_report(self.staff, self.exit_definition, {"college": "Biology"})
        )

    def test_gco_staff_with_bound_assignment_cannot_exceed_scope(self):
        bound_staff = _build_user(email="bound-staff@example.test", role=RoleChoices.GCO_STAFF)
        _grant_report_access(bound_staff, college="CCMS")
        self.assertTrue(can_run_report(bound_staff, self.exit_definition, {}))
        self.assertTrue(can_run_report(bound_staff, self.exit_definition, {"college": "CCMS"}))
        self.assertFalse(
            can_run_report(bound_staff, self.exit_definition, {"college": "Biology"})
        )

    def test_gco_staff_without_assignment_denied(self):
        self.assertFalse(can_run_report(self.no_scope_staff, self.exit_definition, {}))

    def test_it_admin_and_student_denied(self):
        self.assertFalse(can_run_report(self.it_admin, self.exit_definition, {}))
        self.assertFalse(can_run_report(self.student, self.exit_definition, {}))

    def test_csm_boundary_unchanged(self):
        csm = _build_report_definition(
            key="feedback_csm_summary",
            title="CSM",
            family=ReportFamilyChoices.FEEDBACK_CSM,
        )
        # CSM is filters-less aggregate-only.
        self.assertFalse(can_run_report(self.head, csm, {"anything": "value"}))
        self.assertTrue(can_run_report(self.head, csm, {}))
        self.assertTrue(can_run_report(self.counselor, csm, {}))
        self.assertFalse(can_run_report(self.other_counselor, csm, {}))

class StudentsProfilePathTests(TestCase):
    """The special cohort-gated students_profile path stays unchanged."""

    def setUp(self):
        self.counselor = _build_user(email="counselor@example.test", role=RoleChoices.COUNSELOR)
        self.other_counselor = _build_user(email="other-counselor@example.test", role=RoleChoices.COUNSELOR)
        self.head = _head_guidance(email="head@example.test")

        # Counselor coverage: campus Main Campus, college CCMS.
        CounselorCoverage.objects.create(
            counselor=self.counselor,
            campus="Main Campus",
            college="CCMS",
            starts_at=timezone.localdate(),
        )

        self.definition = _build_report_definition(
            key="students_profile",
            title="Students Profile",
            family=ReportFamilyChoices.STUDENT_PROFILE_INVENTORY,
        )
        self.student = StudentProfile.objects.create(
            user=_build_user(email="stu@example.test", role=RoleChoices.STUDENT),
            campus="Main Campus",
            college="CCMS",
            department="Nursing",
            program="BSN",
            year_level=1,
        )
        self.cohort = StudentAcademicCohort.objects.create(
            student_profile=self.student,
            academic_year="2025-2026",
            campus="Main Campus",
            college="CCMS",
            department="Nursing",
            program="BSN",
            year_level=1,
            enrollment_state="ENROLLED",
        )
        self.valid_filters = {
            "academic_year": "2025-2026",
            "college": "CCMS",
            "year_level": 1,
        }

    def test_counselor_with_coverage_can_run_valid_cohort_release(self):
        self.assertTrue(can_run_report(self.counselor, self.definition, self.valid_filters))

    def test_counselor_students_profile_rejects_program_narrowing(self):
        # The cohort-gated path rejects program/department filters even for a
        # counselor whose coverage would allow them on ordinary families.
        filters = {**self.valid_filters, "program": "BSN"}
        self.assertFalse(can_run_report(self.counselor, self.definition, filters))

    def test_students_profile_requires_full_cohort_context(self):
        self.assertFalse(can_run_report(self.counselor, self.definition, {}))

    def test_counselor_without_coverage_denied(self):
        self.assertFalse(
            can_run_report(self.other_counselor, self.definition, self.valid_filters)
        )

    def test_head_guidance_with_valid_cohort_release_allowed(self):
        self.assertTrue(can_run_report(self.head, self.definition, self.valid_filters))


class ReportExportPolicyTests(TestCase):
    """The shared export path re-checks can_run_report with persisted filters."""

    def setUp(self):
        self.counselor = _build_user(email="counselor@example.test", role=RoleChoices.COUNSELOR)
        CounselorCoverage.objects.create(
            counselor=self.counselor,
            campus="Main Campus",
            college="CCMS",
            starts_at=timezone.localdate(),
        )
        self.definition = _build_report_definition(
            key="exit_interview_completion_summary",
            title="Exit Interview Completion",
            family=ReportFamilyChoices.EXIT_INTERVIEW,
        )

    def test_counselor_unfiltered_aggregate_export_allowed(self):
        decision = resolve_report_export_policy(
            self.counselor,
            self.definition,
            {},
            ExportFormatChoices.CSV,
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.denial_code, "")
        self.assertTrue(
            can_request_report_export(
                self.counselor, self.definition, {}, ExportFormatChoices.CSV
            )
        )

    def test_counselor_out_of_scope_export_denied(self):
        decision = resolve_report_export_policy(
            self.counselor,
            self.definition,
            {"college": "Biology"},
            ExportFormatChoices.CSV,
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.denial_code, "EXPORT_SCOPE_DENIED")
        self.assertFalse(
            can_request_report_export(
                self.counselor,
                self.definition,
                {"college": "Biology"},
                ExportFormatChoices.CSV,
            )
        )

    def test_counselor_can_download_own_unfiltered_export(self):
        request = ReportExportRequest.objects.create(
            requested_by=self.counselor,
            report_definition=self.definition,
            filter_hash="0" * 64,
            filter_summary_json={},
            scope_summary_json=get_current_report_export_scope(self.counselor, self.definition),
            status=ExportStatusChoices.GENERATED,
        )
        self.assertTrue(can_download_report_export(self.counselor, request))
        self.assertTrue(can_view_export_request(self.counselor, request))

    def test_counselor_cannot_download_export_with_out_of_scope_filters(self):
        request = ReportExportRequest.objects.create(
            requested_by=self.counselor,
            report_definition=self.definition,
            filter_hash="0" * 64,
            filter_summary_json={"college": "Biology"},
            scope_summary_json=get_current_report_export_scope(self.counselor, self.definition),
            status=ExportStatusChoices.GENERATED,
        )
        self.assertFalse(can_download_report_export(self.counselor, request))


class ReportSelectorScopeTests(TestCase):
    """Aggregate selectors apply coverage first; filters only narrow."""

    def setUp(self):
        self.counselor = _build_user(email="counselor@example.test", role=RoleChoices.COUNSELOR)
        self.head = _head_guidance(email="head@example.test")
        CounselorCoverage.objects.create(
            counselor=self.counselor,
            college="CCMS",
            starts_at=timezone.localdate(),
        )
        StudentProfile.objects.create(
            user=_build_user(email="ccms-student@example.test", role=RoleChoices.STUDENT),
            campus="Main Campus",
            college="CCMS",
            department="Nursing",
            program="BSN",
            year_level=1,
        )
        StudentProfile.objects.create(
            user=_build_user(email="bio-student@example.test", role=RoleChoices.STUDENT),
            campus="Main Campus",
            college="Biology",
            department="Biology Dept",
            program="BS Biology",
            year_level=1,
        )

    def test_unfiltered_counselor_sees_only_covered_slice(self):
        totals = get_student_profile_inventory_aggregates(self.counselor, {})["profile_totals"]
        self.assertEqual(totals[0]["count"], 1)

    def test_counselor_filter_narrows_covered_slice(self):
        totals = get_student_profile_inventory_aggregates(
            self.counselor, {"college": "CCMS"}
        )["profile_totals"]
        self.assertEqual(totals[0]["count"], 1)

    def test_counselor_filter_for_out_of_scope_slice_is_empty(self):
        totals = get_student_profile_inventory_aggregates(
            self.counselor, {"college": "Biology"}
        )["profile_totals"]
        self.assertEqual(totals[0]["count"], 0)

    def test_head_guidance_unfiltered_is_office_wide(self):
        totals = get_student_profile_inventory_aggregates(self.head, {})["profile_totals"]
        self.assertEqual(totals[0]["count"], 2)


class SuppressionSemanticsTests(TestCase):
    """The generic suppressor preserves true zeros and withholds 1..threshold-1.

    contract boundary regression guarantee: a suppressed count is the canonical
    SUPPRESSION_LABEL and is never rendered as the numeric zero, matching the
    corrected assessment / support-need aggregate builders.
    """

    def test_true_zero_dict_count_stays_zero(self):
        safe, suppressed = suppress_report_data({"program": "BSN", "count": 0})
        self.assertEqual(safe["count"], 0)
        self.assertEqual(suppressed, 0)

    def test_small_dict_count_is_suppressed(self):
        small = MIN_SUPPRESSION_THRESHOLD - 1
        safe, suppressed = suppress_report_data({"program": "BSN", "count": small})
        self.assertEqual(safe["count"], SUPPRESSION_LABEL)
        self.assertGreaterEqual(suppressed, 1)

    def test_threshold_dict_count_is_preserved(self):
        safe, suppressed = suppress_report_data(
            {"program": "BSN", "count": MIN_SUPPRESSION_THRESHOLD}
        )
        self.assertEqual(safe["count"], MIN_SUPPRESSION_THRESHOLD)
        self.assertEqual(suppressed, 0)

    def test_suppress_small_counts_distinguishes_zero_from_suppressed(self):
        rows = suppress_small_counts(
            [
                {"program": "BSN", "count": 0},
                {"program": "BSN", "count": 2},
                {"program": "BSN", "count": 4},
                {"program": "BSN", "count": 8},
            ]
        )
        self.assertEqual(
            [row["count"] for row in rows],
            [0, SUPPRESSION_LABEL, SUPPRESSION_LABEL, 8],
        )

    def test_complementary_suppression_never_targets_true_zero(self):
        rows = suppress_small_counts(
            [
                {"program": "BSN", "count": 0},
                {"program": "BSN", "count": 3},
                {"program": "BSN", "count": 9},
            ]
        )
        # 3 is cell-suppressed; complementary suppression picks the smallest
        # positive remainder (9), never the true zero (0).
        self.assertEqual(
            [row["count"] for row in rows],
            [0, SUPPRESSION_LABEL, SUPPRESSION_LABEL],
        )
class ReportExportScopeSnapshotTests(TestCase):
    """get_current_report_export_scope reflects authority and scope (contract boundary)."""

    def setUp(self):
        self.head = _head_guidance(email="head@example.test")
        self.counselor = _build_user(email="counselor@example.test", role=RoleChoices.COUNSELOR)
        self.it_admin = _build_user(email="it@example.test", role=RoleChoices.IT_ADMIN)
        self.student = _build_user(email="student@example.test", role=RoleChoices.STUDENT)
        self.definition = _build_report_definition(
            key="exit_interview_completion_summary",
            title="Exit Interview Completion",
            family=ReportFamilyChoices.EXIT_INTERVIEW,
        )

    def test_head_scope_is_office_wide(self):
        scope = get_current_report_export_scope(self.head, self.definition)
        self.assertEqual(scope["authority"], "HEAD_GUIDANCE")
        self.assertEqual(scope["scopes"], [{"office_wide": True}])

    def test_counselor_with_coverage_scope_is_coverage(self):
        CounselorCoverage.objects.create(
            counselor=self.counselor,
            campus="Main Campus",
            college="CCMS",
            starts_at=timezone.localdate(),
        )
        scope = get_current_report_export_scope(self.counselor, self.definition)
        self.assertEqual(scope["authority"], "COUNSELOR_COVERAGE")

    def test_counselor_without_coverage_has_no_scope(self):
        self.assertEqual(get_current_report_export_scope(self.counselor, self.definition), {})

    def test_it_admin_and_student_have_no_scope(self):
        self.assertEqual(get_current_report_export_scope(self.it_admin, self.definition), {})
        self.assertEqual(get_current_report_export_scope(self.student, self.definition), {})
class ReportDefinitionVisibilityTests(TestCase):
    """can_view_report_definition is capability + domain-family gated."""

    def setUp(self):
        self.head = _head_guidance(email="head@example.test")
        self.counselor = _build_user(email="counselor@example.test", role=RoleChoices.COUNSELOR)
        CounselorCoverage.objects.create(
            counselor=self.counselor,
            campus="Main Campus",
            college="CCMS",
            starts_at=timezone.localdate(),
        )
        self.staff = _build_user(email="staff@example.test", role=RoleChoices.GCO_STAFF)
        _grant_report_access(self.staff, office_wide=True)
        self.exit_definition = _build_report_definition(
            key="exit_interview_completion_summary",
            title="Exit Interview Completion",
            family=ReportFamilyChoices.EXIT_INTERVIEW,
        )
        self.form_definition = _build_report_definition(
            key="form_collection_progress_summary",
            title="Form Collection Progress",
            family=ReportFamilyChoices.FORM_COLLECTION_PROGRESS,
        )

    def test_head_office_wide_sees_all_active_definitions(self):
        self.assertTrue(can_view_report_definition(self.head, self.exit_definition))
        self.assertTrue(can_view_report_definition(self.head, self.form_definition))

    def test_counselor_sees_only_counselor_family(self):
        self.assertTrue(can_view_report_definition(self.counselor, self.exit_definition))
        self.assertFalse(can_view_report_definition(self.counselor, self.form_definition))

    def test_gco_staff_sees_gco_family_definitions(self):
        # GCO Staff keeps assignment-scoped definition visibility: the
        # REPORTS_VIEW_DEFINITIONS eligibility gate must not block GCO families.
        self.assertTrue(can_view_report_definition(self.staff, self.form_definition))
        self.assertTrue(can_view_report_definition(self.staff, self.exit_definition))


class ReportDefinitionManagementTests(TestCase):
    """Definition/template management: head capability OR IT explicit role."""

    def setUp(self):
        self.head = _head_guidance(email="head@example.test")
        self.counselor = _build_user(email="counselor@example.test", role=RoleChoices.COUNSELOR)
        self.it_admin = _build_user(email="it@example.test", role=RoleChoices.IT_ADMIN)
        self.staff = _build_user(email="staff@example.test", role=RoleChoices.GCO_STAFF)
        self.student = _build_user(email="student@example.test", role=RoleChoices.STUDENT)

    def test_head_and_it_admin_can_manage_definitions_and_templates(self):
        self.assertTrue(can_manage_report_definitions(self.head))
        self.assertTrue(can_manage_report_templates(self.head))
        self.assertFalse(can_manage_report_definitions(self.it_admin))
        self.assertFalse(can_manage_report_templates(self.it_admin))

    def test_other_roles_cannot_manage(self):
        self.assertFalse(can_manage_report_definitions(self.counselor))
        self.assertFalse(can_manage_report_templates(self.counselor))
        self.assertFalse(can_manage_report_definitions(self.staff))
        self.assertFalse(can_manage_report_definitions(self.student))
class SensitiveAggregateAccessTests(TestCase):
    """can_view_sensitive_aggregate preserves the sensitivity taxonomy."""

    def setUp(self):
        self.head = _head_guidance(email="head@example.test")
        self.counselor = _build_user(email="counselor@example.test", role=RoleChoices.COUNSELOR)
        self.it_admin = _build_user(email="it@example.test", role=RoleChoices.IT_ADMIN)
        self.definition = _build_report_definition(
            key="exit_interview_completion_summary",
            title="Exit Interview Completion",
            family=ReportFamilyChoices.EXIT_INTERVIEW,
        )

    def test_head_can_view_restricted_but_never_forbidden(self):
        self.assertTrue(can_view_sensitive_aggregate(self.head, self.definition, "custom_category"))
        self.assertFalse(can_view_sensitive_aggregate(self.head, self.definition, "name"))

    def test_counselor_cannot_view_restricted(self):
        self.assertFalse(can_view_sensitive_aggregate(self.counselor, self.definition, "custom_category"))
        self.assertTrue(can_view_sensitive_aggregate(self.counselor, self.definition, "religion"))

    def test_it_admin_only_internal(self):
        self.assertFalse(can_view_sensitive_aggregate(self.it_admin, self.definition, "campus"))
        self.assertFalse(can_view_sensitive_aggregate(self.it_admin, self.definition, "religion"))
        self.assertFalse(can_view_sensitive_aggregate(self.it_admin, self.definition, "custom_category"))


class ReportExportApprovalTests(TestCase):
    """Approve/deny: head (non-self) via capability; requester ownership preserved."""

    def setUp(self):
        self.head = _head_guidance(email="head@example.test")
        self.other_counselor = _build_user(email="other@example.test", role=RoleChoices.COUNSELOR)
        CounselorCoverage.objects.create(
            counselor=self.other_counselor,
            campus="Main Campus",
            college="CCMS",
            starts_at=timezone.localdate(),
        )
        self.definition = _build_report_definition(
            key="exit_interview_completion_summary",
            title="Exit Interview Completion",
            family=ReportFamilyChoices.EXIT_INTERVIEW,
        )
        self.pending_peer = ReportExportRequest.objects.create(
            requested_by=self.other_counselor,
            report_definition=self.definition,
            filter_hash="0" * 64,
            filter_summary_json={},
            scope_summary_json=get_current_report_export_scope(self.other_counselor, self.definition),
            status=ExportStatusChoices.PENDING_APPROVAL,
        )
        self.pending_head = ReportExportRequest.objects.create(
            requested_by=self.head,
            report_definition=self.definition,
            filter_hash="0" * 64,
            filter_summary_json={},
            scope_summary_json=get_current_report_export_scope(self.head, self.definition),
            status=ExportStatusChoices.PENDING_APPROVAL,
        )

    def test_head_approves_non_self_request(self):
        self.assertTrue(can_approve_report_export(self.head, self.pending_peer))

    def test_head_cannot_approve_own_request(self):
        self.assertFalse(can_approve_report_export(self.head, self.pending_head))

    def test_requester_cannot_approve_or_deny(self):
        self.assertFalse(can_approve_report_export(self.other_counselor, self.pending_peer))
        self.assertFalse(can_deny_report_export(self.other_counselor, self.pending_peer))

    def test_head_can_deny(self):
        self.assertTrue(can_deny_report_export(self.head, self.pending_peer))
class ReportExportLifecycleTests(TestCase):
    """Expire/archive: head + IT expire; requester/head archive released only."""

    def setUp(self):
        self.head = _head_guidance(email="head@example.test")
        self.it_admin = _build_user(email="it@example.test", role=RoleChoices.IT_ADMIN)
        self.counselor = _build_user(email="counselor@example.test", role=RoleChoices.COUNSELOR)
        CounselorCoverage.objects.create(
            counselor=self.counselor,
            campus="Main Campus",
            college="CCMS",
            starts_at=timezone.localdate(),
        )
        self.definition = _build_report_definition(
            key="exit_interview_completion_summary",
            title="Exit Interview Completion",
            family=ReportFamilyChoices.EXIT_INTERVIEW,
        )
        shared = {
            "report_definition": self.definition,
            "filter_hash": "0" * 64,
            "filter_summary_json": {},
        }
        self.generated = ReportExportRequest.objects.create(
            requested_by=self.counselor,
            scope_summary_json=get_current_report_export_scope(self.counselor, self.definition),
            status=ExportStatusChoices.GENERATED,
            **shared,
        )
        self.pending = ReportExportRequest.objects.create(
            requested_by=self.counselor,
            scope_summary_json=get_current_report_export_scope(self.counselor, self.definition),
            status=ExportStatusChoices.PENDING_APPROVAL,
            **shared,
        )
        self.expired = ReportExportRequest.objects.create(
            requested_by=self.counselor,
            scope_summary_json=get_current_report_export_scope(self.counselor, self.definition),
            status=ExportStatusChoices.EXPIRED,
            **shared,
        )

    def test_head_and_it_can_expire(self):
        self.assertTrue(can_expire_report_export(self.head, self.generated))
        self.assertTrue(can_expire_report_export(self.it_admin, self.generated))

    def test_requester_cannot_expire(self):
        self.assertFalse(can_expire_report_export(self.counselor, self.generated))

    def test_requester_can_archive_released_export(self):
        self.assertTrue(can_archive_report_export(self.counselor, self.generated))
        self.assertTrue(can_archive_report_export(self.head, self.generated))

    def test_cannot_archive_pending_or_expired(self):
        self.assertFalse(can_archive_report_export(self.counselor, self.pending))
        self.assertFalse(can_archive_report_export(self.counselor, self.expired))

    def test_it_can_view_safe_export_metadata_but_not_report_content(self):
        self.assertTrue(can_view_export_request(self.it_admin, self.generated))
        self.assertFalse(can_download_report_export(self.it_admin, self.generated))


class ReportExecutionControlTests(TestCase):
    def setUp(self):
        self.head = _head_guidance(email="execution-head@example.test")
        self.definition = _build_report_definition(
            key="workflow_notifications_execution",
            title="Workflow Notifications",
            family=ReportFamilyChoices.WORKFLOW_NOTIFICATIONS,
        )

    @patch(
        "apps.reports.services.report_execution_controls",
        return_value={
            "max_output_bytes": 262144,
            "max_work_units": 1000,
            "async_after_work_units": 100,
            "run_timeout_seconds": 60,
            "export_max_output_bytes": 8 * 1024 * 1024,
            "export_expiry_days": 7,
            "run_retention_days": 30,
        },
    )
    @patch(
        "apps.reports.services.get_report_family_source_selector",
        return_value=lambda actor, filters, definition, context=None: {
            "notifications": [{"status": "sent", "count": 9}],
        },
    )
    def test_expensive_api_run_is_pending_then_processed_without_payload_storage(self, _selector, _controls):
        run, dataset = run_report_command(
            self.head,
            ReportRunCommand(report_key=self.definition.key),
        )
        self.assertEqual(run.status, ReportRunStatus.PENDING)
        self.assertIsNone(dataset)
        self.assertEqual(run.metadata_json["execution_mode"], "ASYNC")
        self.assertNotIn("result", run.metadata_json)

        completed, result = execute_pending_report_run(self.head, str(run.id))
        self.assertEqual(completed.status, ReportRunStatus.COMPLETED)
        self.assertEqual(result["notifications"][0]["count"], 9)
        self.assertNotIn("result", completed.metadata_json)
class SelectorOfficeWideTests(TestCase):
    """Selector row-source width: head office-wide vs counselor coverage slice."""

    def setUp(self):
        self.head = _head_guidance(email="head@example.test")
        self.counselor = _build_user(email="counselor@example.test", role=RoleChoices.COUNSELOR)
        CounselorCoverage.objects.create(
            counselor=self.counselor,
            campus="Main Campus",
            college="CCMS",
            starts_at=timezone.localdate(),
        )
        for email, college, department, program in (
            ("ccms@example.test", "CCMS", "Nursing", "BSN"),
            ("bio@example.test", "Biology", "Biology Dept", "BS Biology"),
        ):
            StudentProfile.objects.create(
                user=_build_user(email=email, role=RoleChoices.STUDENT),
                campus="Main Campus",
                college=college,
                department=department,
                program=program,
                year_level=1,
            )

    def test_head_office_wide_profile_totals(self):
        totals = get_student_profile_inventory_aggregates(self.head, {})["profile_totals"]
        self.assertEqual(totals[0]["count"], 2)

    def test_counselor_covered_slice(self):
        totals = get_student_profile_inventory_aggregates(self.counselor, {})["profile_totals"]
        self.assertEqual(totals[0]["count"], 1)

    def test_delivery_metadata_and_audit_are_head_or_it(self):
        self.it_admin = _build_user(email="it@example.test", role=RoleChoices.IT_ADMIN)
        self.counselor_plain = _build_user(email="counselor2@example.test", role=RoleChoices.COUNSELOR)
        head_data = get_public_contact_aggregates(self.head, {})["delivery_by_state"]
        it_data = get_public_contact_aggregates(self.it_admin, {})["delivery_by_state"]
        self.assertEqual(head_data, it_data)
        self.assertEqual(
            get_public_contact_aggregates(self.counselor_plain, {})["delivery_by_state"], []
        )
        self.assertEqual(get_audit_report_access_aggregates(self.head, {})["audit_actions"], [])
        self.assertEqual(get_audit_report_access_aggregates(self.it_admin, {})["audit_actions"], [])
class CanonicalAuthorityReportTests(TestCase):
    """Reports consume the shared AuthorityContext, not a second resolver."""

    def test_inactive_and_legacy_accounts_fail_closed(self):
        from apps.access_control.authority import has_capability

        inactive = _build_user(
            email="inactive-head@example.test", role=RoleChoices.COUNSELOR, is_active=False
        )
        CounselorProfile.objects.create(user=inactive, is_head_guidance=True)
        legacy = _build_user(email="legacy@example.test", role=RoleChoices.IT_ADMIN)
        legacy.is_superuser = True
        legacy.save(update_fields=["is_superuser"])
        for actor in (inactive, legacy):
            self.assertFalse(has_capability(actor, Capability.REPORTS_VIEW_INSTITUTION))
            self.assertFalse(has_capability(actor, Capability.REPORTS_EXPORT_OPERATE))

    def test_head_fixed_report_capabilities_come_from_shared_context(self):
        from apps.access_control.authority import build_authority_context, resolve_capability

        context = build_authority_context(_head_guidance(email="head@example.test"))
        for capability in (
            Capability.REPORTS_VIEW_INSTITUTION,
            Capability.REPORTS_EXPORT_OPERATE,
            Capability.REPORTS_DEFINITIONS_MANAGE,
            Capability.REPORTS_VIEW_SENSITIVE_AGGREGATES,
            Capability.REPORTS_EXPORT_REQUEST,
            Capability.REPORTS_EXPORT_APPROVE,
        ):
            self.assertTrue(resolve_capability(context, capability))

    def test_context_capability_resolution_adds_no_queries(self):
        from django.db import connection
        from django.test.utils import CaptureQueriesContext
        from apps.access_control.authority import build_authority_context, resolve_capability

        context = build_authority_context(_head_guidance(email="head@example.test"))
        with CaptureQueriesContext(connection) as queries:
            self.assertTrue(resolve_capability(context, Capability.REPORTS_VIEW_INSTITUTION))
            self.assertTrue(resolve_capability(context, Capability.REPORTS_EXPORT_OPERATE))
        self.assertEqual(len(queries), 0)

class SuppressionModeValidationTests(TestCase):
    """Suppression mode is validated by the target-scoped Policy Center."""

    def _command(self, **overrides):
        values = dict(
            key="reports.suppression",
            effective_from=timezone.now(),
            target_type="reports.ReportDefinition",
            target_reference=str(self.definition.pk),
            source_reference="TEST:SUPPRESSION:VALIDATION",
            report_key=self.definition.key,
            mode=SuppressionMode.CELL,
            requires_suppression=True,
            default_threshold=MIN_SUPPRESSION_THRESHOLD,
            threshold=MIN_SUPPRESSION_THRESHOLD,
        )
        values.update(overrides)
        return _suppression_request(**values)

    def setUp(self):
        self.definition = ReportDefinition.objects.create(
            key="exit_interview_completion_summary",
            title="Exit Interview Completion",
            family=ReportFamilyChoices.EXIT_INTERVIEW,
            is_active=True,
        )

    def test_valid_modes_accepted(self):
        valid = [
            ("students_profile", ReportFamilyChoices.STUDENT_PROFILE_INVENTORY, SuppressionMode.SECTION, True),
            ("feedback_csm_aggregate", ReportFamilyChoices.FEEDBACK_CSM, SuppressionMode.DISCLOSURE_SET, True),
            ("workflow_notifications_summary", ReportFamilyChoices.WORKFLOW_NOTIFICATIONS, SuppressionMode.NONE, False),
            ("audit_report_access_summary", ReportFamilyChoices.AUDIT_REPORT_ACCESS, SuppressionMode.NONE, False),
            ("exit_interview_completion_summary", ReportFamilyChoices.EXIT_INTERVIEW, SuppressionMode.CELL, True),
        ]
        for key, family, mode, requires in valid:
            definition = ReportDefinition.objects.create(
                key=key if key == "students_profile" else f"{key}-validation",
                title="Validation",
                family=family,
                is_active=True,
            )
            command = _suppression_request(
                key="reports.suppression",
                effective_from=timezone.now(),
                target_type="reports.ReportDefinition",
                target_reference=str(definition.pk),
                source_reference="TEST:MODE",
                report_key=definition.key,
                mode=mode.value if hasattr(mode, "value") else str(mode),
                requires_suppression=requires,
                default_threshold=5,
                threshold=5,
            )
            ensure_active_policy_for_target(None, command, system_context=True)

    def test_none_rejected_when_suppression_is_required(self):
        with self.assertRaises(ValidationError):
            ensure_active_policy_for_target(
                None,
                self._command(mode=SuppressionMode.NONE.value),
                system_context=True,
            )

    def test_non_none_rejected_when_suppression_is_not_required(self):
        with self.assertRaises(ValidationError):
            ensure_active_policy_for_target(
                None,
                self._command(requires_suppression=False),
                system_context=True,
            )

    def test_mode_outside_family_allowed_set_rejected(self):
        for mode in (SuppressionMode.SECTION, SuppressionMode.DISCLOSURE_SET, SuppressionMode.NONE):
            with self.assertRaises(ValidationError):
                ensure_active_policy_for_target(
                    None,
                    self._command(mode=mode.value),
                    system_context=True,
                )

    def test_key_specific_profile_route_requires_matching_family(self):
        with self.assertRaises(DjangoValidationError):
            ReportDefinition.objects.create(
                key="students_profile",
                title="Students Profile",
                family=ReportFamilyChoices.EXIT_INTERVIEW,
                is_active=True,
            )


class SuppressionModeConsumptionTests(TestCase):
    """The suppression service routes on the authoritative suppression_mode."""

    def test_cell_mode_uses_cell_suppressor(self):
        definition = _build_report_definition(
            key="exit_interview_completion_summary",
            title="Exit Interview Completion",
            family=ReportFamilyChoices.EXIT_INTERVIEW,
        )
        self.assertEqual(resolve_report_suppression_policy(definition).mode, SuppressionMode.CELL)
        dataset = {"rows": [{"program": "BSN", "count": 3}]}
        safe, applied, count = apply_suppression(definition, dataset, {})
        self.assertTrue(applied)
        self.assertGreaterEqual(count, 1)
        self.assertEqual(safe["rows"][0]["count"], SUPPRESSION_LABEL)

    def test_disclosure_set_mode_uses_set_suppressor(self):
        definition = _build_report_definition(
            key="feedback_csm_aggregate",
            title="CSM",
            family=ReportFamilyChoices.FEEDBACK_CSM,
        )
        self.assertEqual(resolve_report_suppression_policy(definition).mode, SuppressionMode.DISCLOSURE_SET)
        dataset = {
            "sqd_item_averages": [
                {"metric": "sqd1", "denominator": 3, "average": 4.5},
                {"metric": "sqd2", "denominator": 9, "average": 4.1},
            ]
        }
        safe, applied, count = apply_suppression(definition, dataset, {})
        self.assertTrue(applied)
        self.assertEqual(count, 0)  # set suppression does not persist a cell counter
        for row in safe["sqd_item_averages"]:
            self.assertEqual(row["denominator"], SUPPRESSION_LABEL)

    def test_unroutable_modes_fail_closed(self):
        for index, (key, mode, family) in enumerate(
            [
                ("students_profile", SuppressionMode.SECTION, ReportFamilyChoices.STUDENT_PROFILE_INVENTORY),
                ("routing-none", SuppressionMode.NONE, ReportFamilyChoices.WORKFLOW_NOTIFICATIONS),
            ]
        ):
            definition = _build_report_definition(
                key=key if index == 0 else f"{key}-{index}",
                title="Routing X",
                family=family,
                suppression_mode=mode,
            )
            with self.assertRaises(ValidationError):
                apply_suppression(definition, {"rows": []}, {})

    def test_run_report_skips_suppression_for_none_mode(self):
        from apps.reports.services import run_report

        head = _head_guidance(email="head-mode@example.test")
        definition = _build_report_definition(
            key="workflow_notifications_summary",
            title="Workflow Notifications",
            family=ReportFamilyChoices.WORKFLOW_NOTIFICATIONS,
        )
        self.assertEqual(resolve_report_suppression_policy(definition).mode, SuppressionMode.NONE)
        run, dataset = run_report(head, definition.key, {})
        self.assertEqual(run.status, ReportRunStatus.COMPLETED)
        self.assertFalse(run.suppression_applied)

    def test_generic_student_profile_inventory_definition_uses_cell_mode(self):
        definition = _build_report_definition(
            key="student_profile_inventory_summary",
            title="Student Profile Inventory",
            family=ReportFamilyChoices.STUDENT_PROFILE_INVENTORY,
        )
        self.assertEqual(resolve_report_suppression_policy(definition).mode, SuppressionMode.CELL)
        safe, applied, count = apply_suppression(
            definition,
            {"rows": [{"program": "BSN", "count": 3}]},
            {},
        )
        self.assertTrue(applied)
        self.assertGreaterEqual(count, 1)
        self.assertEqual(safe["rows"][0]["count"], SUPPRESSION_LABEL)


class SuppressionModeConsistencyTests(TestCase):
    """seed catalog, allowed-mode map, canonical map, and migration map agree."""

    def test_seed_catalog_matches_canonical_and_allowed_modes(self):
        for definition in REPORT_DEFINITIONS:
            family = definition["family"]
            mode = definition["suppression_mode"]
            self.assertEqual(
                mode,
                canonical_suppression_mode_for_definition(
                    key=definition["key"],
                    family=family,
                ),
                f"Seed mode for {definition['key']} diverges from canonical map.",
            )
            self.assertIn(
                mode,
                allowed_suppression_modes_for_definition(
                    key=definition["key"],
                    family=family,
                ),
                f"Seed mode for {definition['key']} not allowed for family.",
            )
            self.assertEqual(
                definition["requires_suppression"],
                mode != SuppressionMode.NONE,
                f"Seed requires_suppression disagrees with mode for {definition['key']}.",
            )

    def test_canonical_map_values_are_allowed_per_family(self):
        for family, mode in CANONICAL_SUPPRESSION_MODE_BY_FAMILY.items():
            self.assertIn(mode, ALLOWED_SUPPRESSION_MODES_BY_FAMILY[family])

    def test_definition_key_exceptions_are_allowed_and_canonical(self):
        self.assertEqual(
            CANONICAL_SUPPRESSION_MODE_BY_DEFINITION_KEY["students_profile"],
            SuppressionMode.SECTION,
        )
        self.assertIn(
            SuppressionMode.SECTION,
            ALLOWED_SUPPRESSION_MODES_BY_DEFINITION_KEY["students_profile"],
        )
        self.assertEqual(
            canonical_suppression_mode_for_definition(
                key="students_profile",
                family=ReportFamilyChoices.STUDENT_PROFILE_INVENTORY,
            ),
            SuppressionMode.SECTION,
        )
        self.assertEqual(
            canonical_suppression_mode_for_definition(
                key="student_profile_inventory_summary",
                family=ReportFamilyChoices.STUDENT_PROFILE_INVENTORY,
            ),
            SuppressionMode.CELL,
        )
        self.assertEqual(
            SUPPRESSION_MODE_DEFINITION_FAMILY_BY_KEY["students_profile"],
            ReportFamilyChoices.STUDENT_PROFILE_INVENTORY,
        )

    def test_every_family_in_canonical_map_has_matching_allowed_set(self):
        for family in CANONICAL_SUPPRESSION_MODE_BY_FAMILY:
            self.assertIn(family, ALLOWED_SUPPRESSION_MODES_BY_FAMILY)


class ResolvedSuppressionPolicyTests(TestCase):
    """Target-scoped Governance policy is the only suppression source."""

    def test_all_seeded_definitions_have_explicit_resolvable_policy(self):
        self.assertEqual(len(REPORT_DEFINITIONS), 11)
        for values in REPORT_DEFINITIONS:
            definition = _build_report_definition(
                key=values["key"],
                title=values["title"],
                family=values["family"],
                sensitivity_level=values["sensitivity_level"],
                suppression_mode=values["suppression_mode"],
                requires_suppression=values["requires_suppression"],
                default_suppression_threshold=values["default_suppression_threshold"],
            )
            policy = resolve_report_suppression_policy(definition)
            self.assertEqual(policy.mode, values["suppression_mode"])
            self.assertEqual(policy.threshold, MIN_SUPPRESSION_THRESHOLD)
            self.assertTrue(set(policy.count_keys).issuperset({"count", "total", "denominator"}))

    def test_definition_threshold_and_active_policy_only_raise_the_floor(self):
        definition = _build_report_definition(
            key="threshold-policy-report",
            title="Threshold Policy Report",
            family=ReportFamilyChoices.EXIT_INTERVIEW,
            default_suppression_threshold=8,
        )
        self.assertEqual(resolve_report_suppression_policy(definition).threshold, 8)

        _set_report_policy(definition, threshold=12, default_threshold=8)
        self.assertEqual(resolve_report_suppression_policy(definition).threshold, 12)

    def test_policy_validity_windows_are_honored(self):
        definition = _build_report_definition(
            key="temporal-policy-report",
            title="Temporal Policy Report",
            family=ReportFamilyChoices.EXIT_INTERVIEW,
        )
        now = timezone.now()
        _set_report_policy(
            definition,
            threshold=12,
            default_threshold=5,
            mode=SuppressionMode.CELL,
            effective_from=now + timedelta(days=1),
        )
        with self.assertRaises(ValidationError):
            resolve_report_suppression_policy(definition, now=now)

        _set_report_policy(
            definition,
            threshold=12,
            default_threshold=5,
            mode=SuppressionMode.CELL,
            effective_from=now - timedelta(days=1),
            effective_until=now + timedelta(days=1),
        )
        self.assertEqual(resolve_report_suppression_policy(definition, now=now).threshold, 12)

        _set_report_policy(
            definition,
            threshold=12,
            mode=SuppressionMode.CELL,
            effective_from=now - timedelta(days=2),
            effective_until=now - timedelta(days=1),
        )
        with self.assertRaises(ValidationError):
            resolve_report_suppression_policy(definition, now=now)

    def test_sensitive_categories_are_additive_to_default_count_keys(self):
        definition = _build_report_definition(
            key="category-policy-report",
            title="Category Policy Report",
            family=ReportFamilyChoices.EXIT_INTERVIEW,
        )
        _set_report_policy(definition, threshold=5, sensitive_categories=("custom_total",))
        policy = resolve_report_suppression_policy(definition)
        self.assertIn("count", policy.count_keys)
        self.assertIn("custom_total", policy.count_keys)

        rows = suppress_small_counts(
            [{"count": 5, "custom_total": 2}],
            threshold=policy.threshold,
            count_keys=list(policy.count_keys),
        )
        self.assertEqual(rows[0]["count"], 5)
        self.assertEqual(rows[0]["custom_total"], SUPPRESSION_LABEL)

    def test_malformed_policy_values_are_rejected(self):
        definition = _build_report_definition(
            key="invalid-policy-report",
            title="Invalid Policy Report",
            family=ReportFamilyChoices.EXIT_INTERVIEW,
        )
        with self.assertRaises(ValidationError):
            _set_report_policy(definition, threshold=4)
        with self.assertRaises(ValidationError):
            _set_report_policy(definition, threshold=True)
        with self.assertRaises(ValidationError):
            _set_report_policy(
                definition,
                effective_from=timezone.now() + timedelta(days=1),
                effective_until=timezone.now(),
            )
        with self.assertRaises(ValidationError):
            _set_report_policy(definition, sensitive_categories=("counseling_notes",))

    def test_definition_mode_cannot_be_changed_by_policy_overlay(self):
        definition = _build_report_definition(
            key="mode-policy-report",
            title="Mode Policy Report",
            family=ReportFamilyChoices.EXIT_INTERVIEW,
            suppression_mode=SuppressionMode.CELL,
        )
        _set_report_policy(definition, threshold=9, sensitive_categories=("custom_total",))
        policy = resolve_report_suppression_policy(definition)
        self.assertEqual(policy.mode, SuppressionMode.CELL)
        self.assertEqual(policy.threshold, 9)

    def test_none_report_remains_unsuppressed_even_with_overlay(self):
        from apps.reports.services import run_report

        head = _head_guidance(email="head-none-overlay@example.test")
        definition = _build_report_definition(
            key="workflow_notifications_summary",
            title="Workflow Notifications",
            family=ReportFamilyChoices.WORKFLOW_NOTIFICATIONS,
        )
        _set_report_policy(definition, threshold=20, sensitive_categories=("count",))
        policy = resolve_report_suppression_policy(definition)
        self.assertEqual(policy.mode, SuppressionMode.NONE)
        run, _dataset = run_report(head, definition.key, {})
        self.assertFalse(run.suppression_applied)

    def test_csv_derived_metric_validation_uses_resolved_threshold(self):
        row = {"count": 8, "average": 4.2}
        validate_export_row(row, threshold=10, count_keys=("count",))
        self.assertEqual(row["average"], SUPPRESSION_LABEL)

        row = {"count": 8, "average": 4.2}
        validate_export_row(row, threshold=5, count_keys=("count",))
        self.assertEqual(row["average"], 4.2)

    def test_seed_reconciliation_does_not_overwrite_existing_policy_fields(self):
        values = REPORT_DEFINITIONS[0]
        existing = _build_report_definition(
            key=values["key"],
            title=values["title"],
            family=values["family"],
            sensitivity_level=values["sensitivity_level"],
            suppression_mode=values["suppression_mode"],
            requires_suppression=values["requires_suppression"],
            default_suppression_threshold=values["default_suppression_threshold"],
        )
        _set_report_policy(existing, threshold=12, default_threshold=5)

        call_command("seed_report_definitions", stdout=StringIO())
        self.assertEqual(resolve_report_suppression_policy(existing).threshold, 12)
        self.assertEqual(resolve_report_suppression_policy(existing).mode, values["suppression_mode"])


class DirectAggregateExportPolicyTests(TestCase):
    def test_authorized_counselor_aggregate_export_has_no_manual_approval_gate(self):
        counselor = _build_user(email="direct-export@example.test", role=RoleChoices.COUNSELOR)
        CounselorCoverage.objects.create(
            counselor=counselor,
            campus="Main Campus",
            college="CCMS",
            starts_at=timezone.localdate(),
        )
        definition = _build_report_definition(
            key="direct-export-summary",
            title="Direct Export Summary",
            family=ReportFamilyChoices.EXIT_INTERVIEW,
        )
        decision = resolve_report_export_policy(counselor, definition, {}, ExportFormatChoices.CSV)
        self.assertTrue(decision.allowed)
        self.assertFalse(decision.requires_independent_approval)
        request = request_report_export(
            counselor,
            definition,
            {},
            ExportFormatChoices.CSV,
            purpose="Scoped aggregate workload review",
        )
        self.assertEqual(request.status, ExportStatusChoices.REQUESTED)

    def test_identifiable_export_is_always_deferred(self):
        head = _head_guidance(email="identifiable-export@example.test")
        definition = _build_report_definition(
            key="identifiable-deferred-summary",
            title="Identifiable Deferred Summary",
            family=ReportFamilyChoices.EXIT_INTERVIEW,
        )
        decision = resolve_report_export_policy(
            head,
            definition,
            {},
            ExportFormatChoices.CSV,
            includes_identifiable_data=True,
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.denial_code, "IDENTIFIABLE_EXPORT_SCOPE_DENIED")


class ReportsApiTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.head = _head_guidance(email="reports-api-head@example.test")
        self.token = issue_token_pair(self.head, assurance_verified=True).access_token
        self.definition = _build_report_definition(
            key="reports-api-summary",
            title="Reports API Summary",
            family=ReportFamilyChoices.EXIT_INTERVIEW,
        )

    def headers(self, token=None):
        return {"HTTP_AUTHORIZATION": f"Bearer {token or self.token}"}

    def test_definition_collection_is_bounded_and_correlated(self):
        response = self.client.get(
            "/api/v1/reports/definitions/?page=1&page_size=1",
            **self.headers(),
        )
        self.assertEqual(response.status_code, 200, response.content)
        payload = response.json()
        self.assertEqual(payload["page_size"], 1)
        self.assertEqual(payload["total"], 1)
        self.assertTrue(response["X-Request-ID"].startswith("REQ-"))
        self.assertEqual(response["Cache-Control"], "no-store")

    def test_definition_detail_exposes_only_the_output_projection(self):
        response = self.client.get(
            f"/api/v1/reports/definitions/{self.definition.key}/",
            **self.headers(),
        )
        self.assertEqual(response.status_code, 200, response.content)
        payload = response.json()
        self.assertEqual(
            set(payload),
            {
                "id",
                "key",
                "title",
                "description",
                "family",
                "sensitivity_level",
                "is_active",
                "activated_at",
                "updated_at",
            },
        )
        self.assertNotIn("allowed_scope_metadata_json", payload)
        self.assertNotIn("metadata_json", payload)

    def test_run_detail_preserves_safe_filter_summary_without_raw_metadata(self):
        report_run = ReportRun.objects.create(
            report_definition=self.definition,
            requested_by=self.head,
            filter_hash="b" * 64,
            filter_summary_json={"college": "CCMS", "year_level": 1},
            status=ReportRunStatus.RUNNING,
            metadata_json={
                "execution_mode": "ASYNC",
                "estimated_work_units": 12,
                "internal_debug": "must-not-leak",
            },
        )
        response = self.client.get(
            f"/api/v1/reports/runs/{report_run.id}/",
            **self.headers(),
        )
        self.assertEqual(response.status_code, 200, response.content)
        payload = response.json()
        self.assertEqual(payload["status"], ReportRunStatus.RUNNING)
        self.assertEqual(payload["filter_summary"], {"college": "CCMS", "year_level": 1})
        self.assertNotIn("internal_debug", payload)
        self.assertNotIn("metadata_json", payload)
        self.assertNotIn("result", payload)

    @patch(
        "apps.reports.api.report_execution_controls",
        return_value={
            "max_output_bytes": 262144,
            "max_work_units": 1000,
            "async_after_work_units": 100,
            "run_timeout_seconds": 60,
            "export_max_output_bytes": 8 * 1024 * 1024,
            "export_expiry_days": 7,
            "run_retention_days": 30,
        },
    )
    @patch("apps.reports.api.run_report_command")
    def test_run_mutation_and_idempotent_replay_use_typed_responses(self, run_command, _controls):
        report_run = ReportRun.objects.create(
            report_definition=self.definition,
            requested_by=self.head,
            filter_hash="c" * 64,
            filter_summary_json={"college": "CCMS"},
            status=ReportRunStatus.COMPLETED,
            aggregate_count=1,
            cell_count=2,
            suppression_applied=True,
            suppressed_cell_count=0,
            started_at=timezone.now(),
            completed_at=timezone.now(),
            expires_at=timezone.now() + timedelta(days=30),
            metadata_json={
                "execution_mode": "SYNC",
                "estimated_work_units": 1,
                "actual_work_units": 1,
                "internal_debug": "must-not-leak",
            },
        )
        run_command.return_value = (
            report_run,
            {"notifications": [{"status": "sent", "count": 9}]},
        )
        request_headers = self.headers()
        request_headers["HTTP_IDEMPOTENCY_KEY"] = "reports-run-response-contract"
        body = json.dumps({"report_key": self.definition.key, "filters": {}})

        response = self.client.post(
            "/api/v1/reports/runs/",
            data=body,
            content_type="application/json",
            **request_headers,
        )
        self.assertEqual(response.status_code, 200, response.content)
        payload = response.json()
        self.assertTrue(payload["result_available"])
        self.assertEqual(payload["result"]["notifications"][0]["count"], 9)
        self.assertNotIn("internal_debug", payload)
        self.assertNotIn("metadata_json", payload)

        replay = self.client.post(
            "/api/v1/reports/runs/",
            data=body,
            content_type="application/json",
            **request_headers,
        )
        self.assertEqual(replay.status_code, 200, replay.content)
        replay_payload = replay.json()
        self.assertFalse(replay_payload["result_available"])
        self.assertIsNone(replay_payload["result"])
        self.assertNotIn("output_size_bytes", replay_payload)

    def test_invalid_pagination_uses_standard_validation_envelope(self):
        response = self.client.get(
            "/api/v1/reports/definitions/?page=1&page_size=101",
            **self.headers(),
        )
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()["code"], "validation")
        self.assertIn("request_id", response.json())

    def test_it_receives_technical_export_metadata_only(self):
        it_admin = _build_user(email="reports-api-it@example.test", role=RoleChoices.IT_ADMIN)
        export = ReportExportRequest.objects.create(
            requested_by=self.head,
            report_definition=self.definition,
            export_format=ExportFormatChoices.CSV,
            status=ExportStatusChoices.GENERATED,
            filter_hash="a" * 64,
            filter_summary_json={"college": "CCMS"},
            includes_sensitive_data=True,
            generation_metadata_json={"status": "generated", "output_classification": "machine"},
        )
        it_token = issue_token_pair(it_admin, assurance_verified=True).access_token
        response = self.client.get(
            f"/api/v1/reports/exports/{export.id}/",
            **self.headers(it_token),
        )
        self.assertEqual(response.status_code, 200, response.content)
        payload = response.json()
        self.assertNotIn("report_key", payload)
        self.assertNotIn("filter_summary", payload)
        self.assertNotIn("suppressed_cell_count", payload)
        self.assertEqual(payload["status"], ExportStatusChoices.GENERATED)

    def test_regular_export_projection_and_lifecycle_replay_are_typed(self):
        export = ReportExportRequest.objects.create(
            requested_by=self.head,
            report_definition=self.definition,
            export_format=ExportFormatChoices.CSV,
            status=ExportStatusChoices.GENERATED,
            filter_hash="d" * 64,
            filter_summary_json={"college": "CCMS", "year_level": 1},
            includes_sensitive_data=True,
            generation_metadata_json={
                "status": "generated",
                "output_classification": "machine",
                "internal_debug": "must-not-leak",
            },
        )
        response = self.client.get(
            f"/api/v1/reports/exports/{export.id}/",
            **self.headers(),
        )
        self.assertEqual(response.status_code, 200, response.content)
        payload = response.json()
        self.assertEqual(payload["report_key"], self.definition.key)
        self.assertEqual(payload["filter_summary"], {"college": "CCMS", "year_level": 1})
        self.assertNotIn("purpose", payload)
        self.assertNotIn("scope_summary_json", payload)
        self.assertNotIn("generation_metadata_json", payload)
        self.assertNotIn("internal_debug", payload)

        pending = ReportExportRequest.objects.create(
            requested_by=self.head,
            report_definition=self.definition,
            export_format=ExportFormatChoices.CSV,
            status=ExportStatusChoices.REQUESTED,
            filter_hash="e" * 64,
            filter_summary_json={},
        )
        request_headers = self.headers()
        request_headers["HTTP_IDEMPOTENCY_KEY"] = "reports-export-cancel-contract"
        body = json.dumps({"expected_status": ExportStatusChoices.REQUESTED, "reason": "duplicate"})
        cancel_url = f"/api/v1/reports/exports/{pending.id}/cancel/"

        cancelled = self.client.post(
            cancel_url,
            data=body,
            content_type="application/json",
            **request_headers,
        )
        self.assertEqual(cancelled.status_code, 200, cancelled.content)
        self.assertEqual(cancelled.json()["status"], ExportStatusChoices.CANCELLED)
        self.assertNotIn("reason", cancelled.json())

        replay = self.client.post(
            cancel_url,
            data=body,
            content_type="application/json",
            **request_headers,
        )
        self.assertEqual(replay.status_code, 200, replay.content)
        self.assertEqual(replay.json()["status"], ExportStatusChoices.CANCELLED)
        self.assertNotIn("expected_status", replay.json())
