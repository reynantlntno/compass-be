# Project: COMPASS
# File: apps/reports/policies.py
# Module: apps.reports
# Purpose: Access control policies for viewing, running, and managing reports

from dataclasses import dataclass

from apps.access_control.authority import AuthorityContext, has_capability, resolve_capability
from apps.access_control.capabilities import Capability
from apps.access_control.rules import (
    is_active_nonlegacy_actor,
    is_counselor,
    is_gco_staff,
    is_it_admin,
    is_student,
)
from apps.access_control.scopes import (
    get_active_workflow_authority_grants,
    get_live_counselor_coverages,
)
from apps.governance.runtime_config import is_policy_active
from apps.reports.choices import ExportStatusChoices, ExportTypeChoices, ReportFamilyChoices
from apps.reports.sensitivity import classify_field_sensitivity, FieldSensitivity


def _has_report_capability(actor, capability, *, context=None) -> bool:
    """Resolve a named report capability from the canonical authority snapshot."""

    return resolve_capability(context if context is not None else actor, capability)


CSM_EXPORT_SCOPE_VERSION = 2
CSM_SCOPE_FIELDS = ("campus", "college", "department", "program")

# These are the approved runtime audiences for the Reports capability. This
# policy is the authoritative boundary for every API and service call.
COUNSELOR_REPORT_FAMILIES = frozenset({
    ReportFamilyChoices.STUDENT_PROFILE_INVENTORY,
    ReportFamilyChoices.FEEDBACK_CSM,
    ReportFamilyChoices.EXIT_INTERVIEW,
    ReportFamilyChoices.GRADUATE_TRACER,
    ReportFamilyChoices.APPOINTMENTS_COUNSELING_WORKLOAD,
    ReportFamilyChoices.REFERRALS_CALL_SLIPS,
})
GCO_REPORT_FAMILIES = frozenset({
    ReportFamilyChoices.DOCUMENT_REQUESTS,
    ReportFamilyChoices.FORM_COLLECTION_PROGRESS,
    ReportFamilyChoices.PUBLIC_CONTACT,
    ReportFamilyChoices.WORKFLOW_NOTIFICATIONS,
    ReportFamilyChoices.FEEDBACK_CSM,
    ReportFamilyChoices.EXIT_INTERVIEW,
    ReportFamilyChoices.GRADUATE_TRACER,
    ReportFamilyChoices.APPOINTMENTS_COUNSELING_WORKLOAD,
    ReportFamilyChoices.REFERRALS_CALL_SLIPS,
})
GCO_OFFICE_WIDE_REPORT_FAMILIES = frozenset({
    ReportFamilyChoices.FORM_COLLECTION_PROGRESS,
    ReportFamilyChoices.PUBLIC_CONTACT,
    ReportFamilyChoices.WORKFLOW_NOTIFICATIONS,
})


def _canonical_geographic_scopes(scopes) -> list[dict]:
    """Return a stable, privacy-safe representation of current report scope."""
    values = {
        tuple(getattr(scope, field, None) or "" for field in CSM_SCOPE_FIELDS)
        for scope in scopes
    }
    return [
        dict(zip(CSM_SCOPE_FIELDS, value))
        for value in sorted(values)
    ]


def get_current_report_export_scope(actor, report_definition=None, context: AuthorityContext | None = None) -> dict:
    """Capture current report authority and geographic scope without report data."""
    if not is_active_nonlegacy_actor(actor):
        return {}
    if is_it_admin(actor) or is_student(actor):
        return {}
    if _has_report_capability(actor, Capability.REPORTS_VIEW_INSTITUTION, context=context):
        return {
            "version": CSM_EXPORT_SCOPE_VERSION,
            "authority": "HEAD_GUIDANCE",
            "scopes": [{"office_wide": True}],
        }
    if is_counselor(actor):
        scopes = _canonical_geographic_scopes(get_live_counselor_coverages(actor))
        if scopes:
            return {
                "version": CSM_EXPORT_SCOPE_VERSION,
                "authority": "COUNSELOR_COVERAGE",
                "scopes": scopes,
            }
        return {}
    if is_gco_staff(actor):
        grants = get_active_workflow_authority_grants(actor, capability=Capability.REPORTS_RUN)
        if not grants.exists():
            return {}
        office_wide = any(grant.scope_mode == "OFFICE_WIDE" for grant in grants)
        scopes = ([{"office_wide": True}] if office_wide else _canonical_geographic_scopes(grants))
        if scopes:
            return {
                "version": CSM_EXPORT_SCOPE_VERSION,
                "authority": "REPORTS_ASSISTANCE",
                "scopes": scopes,
            }
    return {}


def _has_unbound_reports_assignment(actor) -> bool:
    return has_capability(actor, Capability.REPORTS_RUN)


def _has_office_wide_reports_assignment(actor) -> bool:
    return any(grant.scope_mode == "OFFICE_WIDE" for grant in get_active_workflow_authority_grants(
        actor, capability=Capability.REPORTS_RUN,
    ))


def _filters_match_scopes(scopes, filters: dict) -> bool:
    """Require explicit filters to remain inside every populated scope bound."""
    filters = filters or {}
    # Aggregate selectors apply grant scope directly. An empty
    # filter set therefore means the actor's assigned slice, not office-wide
    # access; only caller-supplied geographic narrowing needs comparison.
    if not any(filters.get(field) not in (None, "") for field in CSM_SCOPE_FIELDS):
        return True
    return any(
        all(
            not filters.get(field)
            or not getattr(scope, field, None)
            or getattr(scope, field) == filters.get(field)
            for field in CSM_SCOPE_FIELDS
        )
        for scope in scopes
    )


def can_access_reports_destination(actor, context: AuthorityContext | None = None) -> bool:
    """Single authoritative policy for entering the Reports destination."""
    if not is_active_nonlegacy_actor(actor):
        return False
    if _has_report_capability(actor, Capability.REPORTS_VIEW_INSTITUTION, context=context):
        return True
    if is_counselor(actor):
        return get_live_counselor_coverages(actor).exists()
    if is_gco_staff(actor):
        return _has_unbound_reports_assignment(actor)
    # IT Admin has technical/metadata permissions elsewhere, not Reports.
    return False


def can_view_report_index(actor) -> bool:
    """Checks if the actor can view the main reports listing page."""
    return can_access_reports_destination(actor)


def can_view_report_definition(actor, report_definition, context: AuthorityContext | None = None) -> bool:
    """Checks if the actor is authorized to view a specific report definition catalog entry."""
    if not can_access_reports_destination(actor, context=context) or not report_definition.is_active:
        return False

    if not _has_report_capability(actor, Capability.REPORTS_VIEW_DEFINITIONS, context=context):
        return False

    if report_definition.key == "students_profile":
        # The report definition exposes a sensitive release workflow; only
        # actors who could hold the reporting authority may open its context
        # form. Scope is checked again when a concrete cohort is selected.
        return bool(_has_report_capability(actor, Capability.REPORTS_VIEW_INSTITUTION, context=context) or is_counselor(actor))
    if _has_report_capability(actor, Capability.REPORTS_VIEW_INSTITUTION, context=context):
        return True
    if is_counselor(actor):
        return report_definition.family in COUNSELOR_REPORT_FAMILIES
    if is_gco_staff(actor):
        if report_definition.family not in GCO_REPORT_FAMILIES:
            return False
        if report_definition.family in GCO_OFFICE_WIDE_REPORT_FAMILIES:
            return _has_office_wide_reports_assignment(actor)
        return True
    return False


def can_run_report(actor, report_definition, filters: dict, context: AuthorityContext | None = None) -> bool:
    """Evaluates whether the actor can run a report with specific filter criteria.

    Scope invariants:
    - Head Guidance: explicit office-wide aggregate reports and profiling.
    - Counselors: live CounselorCoverage is the baseline scope. The aggregate
      selectors apply that coverage server-side before aggregation, so an
      unfiltered run resolves to the coverage slice itself. Submitted
      geographic filters may only narrow that slice, never broaden it.
    - GCO Staff: operational/admin aggregates scoped by an unbound reports
      assistance assignment; filters narrow only.
    - IT Admin: safe system/metadata only (no sensitive student/counseling/survey data).
    - Students/Alumni: denied entirely.

    The special ``students_profile`` cohort path is delegated unchanged to
    ``_can_run_students_profile`` and the CSM path keeps its own filters-less
    aggregate-only boundary; neither is affected by the counselor branch.
    """
    if not is_active_nonlegacy_actor(actor):
        return False

    if not report_definition.is_active:
        return False

    # 1. Deny Students/Alumni
    if is_student(actor):
        return False

    if report_definition.key == "students_profile":
        return _can_run_students_profile(actor, filters, context=context)


    # CSM has one aggregate-only authorization boundary and no user-controlled
    # filters. Technical flags, service rendering, and workflow assignment do
    # not add authority.
    if report_definition.family == ReportFamilyChoices.FEEDBACK_CSM:
        if filters:
            return False
        if is_it_admin(actor):
            return False
        if _has_report_capability(actor, Capability.REPORTS_VIEW_INSTITUTION, context=context):
            return True
        if is_counselor(actor):
            return get_live_counselor_coverages(actor).exists()
        if is_gco_staff(actor):
            return get_active_workflow_authority_grants(actor, capability=Capability.REPORTS_RUN).exists()
        return False

    # IT Admin has metadata-only export inspection, never report execution.
    if is_it_admin(actor):
        return False

    # 3. Office-wide reporting authority (Head Guidance).
    if _has_report_capability(actor, Capability.REPORTS_VIEW_INSTITUTION, context=context):
        # Can view all approved active definitions
        return True

    # 4. Counselor checks (Scope-based validation)
    if is_counselor(actor):
        if report_definition.family not in COUNSELOR_REPORT_FAMILIES:
            return False

        coverages = get_live_counselor_coverages(actor)
        if not coverages.exists():
            return False  # No coverage, no report execution allowed.

        # CounselorCoverage automatically scopes the report server-side: the
        # aggregate selectors apply the live coverage slice before aggregation.
        # User-provided geographic filters may only narrow that slice; an empty
        # filter set resolves to the coverage slice itself and is therefore
        # allowed. The same _filters_match_scopes helper used for GCO Staff
        # assignment scope is reused here so the semantics stay identical.
        return _filters_match_scopes(coverages, filters)

    # 5. GCO Staff checks
    if is_gco_staff(actor):
        assignments = get_active_workflow_authority_grants(actor, capability=Capability.REPORTS_RUN)
        if not assignments.exists():
            return False
        if report_definition.family not in GCO_REPORT_FAMILIES:
            return False
        if report_definition.family in GCO_OFFICE_WIDE_REPORT_FAMILIES:
            return _has_office_wide_reports_assignment(actor)
        return _filters_match_scopes(assignments, filters)

    return False


def can_view_sensitive_aggregate(actor, report_definition, field_key: str, context: AuthorityContext | None = None) -> bool:
    """Checks if the actor has authority to view a specific sensitive aggregate category/column."""
    if not is_active_nonlegacy_actor(actor):
        return False

    sensitivity = classify_field_sensitivity(field_key)

    # Forbidden fields can NEVER be viewed in report aggregate output
    if sensitivity == FieldSensitivity.FORBIDDEN:
        return False

    if is_it_admin(actor):
        # IT Admin is technical-only and never receives report data.
        return False

    if _has_report_capability(actor, Capability.REPORTS_VIEW_SENSITIVE_AGGREGATES, context=context):
        return True

    if is_counselor(actor):
        # Counselors can view sensitive aggregates (e.g. religion, disability counts) if within their scope
        return sensitivity != FieldSensitivity.RESTRICTED

    if is_gco_staff(actor):
        # GCO staff can only view public or internal fields unless designated reports assistant
        if sensitivity in (FieldSensitivity.PUBLIC, FieldSensitivity.INTERNAL):
            return True
        # If reports assistant, they can view sensitive survey metrics but not highly restricted clinical ones
        has_reports_scope = _has_unbound_reports_assignment(actor)
        return has_reports_scope and sensitivity != FieldSensitivity.RESTRICTED

    return False


def can_view_unsuppressed_aggregate(actor, report_definition) -> bool:
    """Checks if the actor can override/view unsuppressed sensitive aggregate cells.

    By default in #20, this is deferred and returns False (no override allowed).
    """
    return False


def can_manage_report_definitions(actor, context: AuthorityContext | None = None) -> bool:
    """Checks if the actor can create, edit, or deactivate ReportDefinitions."""
    if not is_active_nonlegacy_actor(actor):
        return False
    return bool(
        is_policy_active("reports.definitions")
        and _has_report_capability(actor, Capability.REPORTS_DEFINITIONS_MANAGE, context=context)
    )


def can_request_identifiable_export(actor, report_definition=None, filters=None, context: AuthorityContext | None = None) -> bool:
    """Identifiable row exports remain outside the aggregate Reports API."""
    return False


@dataclass(frozen=True)
class ReportExportPolicyDecision:
    """Bounded, auditable policy result shared by request and generation."""

    allowed: bool
    initial_status: str
    export_type: str
    requires_purpose: bool
    requires_independent_approval: bool
    includes_sensitive_data: bool
    includes_identifiable_data: bool
    scope_summary: dict
    denial_code: str = ""


def resolve_report_export_policy(
    actor,
    definition,
    filters,
    format,
    includes_identifiable_data=False,
    context: AuthorityContext | None = None,
) -> ReportExportPolicyDecision:
    """Resolve export authorization without creating or changing any state."""
    from apps.reports.choices import ExportFormatChoices, SensitivityLevel

    filters = filters or {}
    includes_identifiable = bool(includes_identifiable_data)
    includes_sensitive = bool(
        definition
        and definition.sensitivity_level in (SensitivityLevel.SENSITIVE, SensitivityLevel.RESTRICTED)
    )
    metadata = (definition.metadata_json or {}) if definition else {}
    official_template = bool(
        metadata.get("structural_reference") or metadata.get("document_template_key")
    )
    scope_summary = get_current_report_export_scope(actor, definition, context=context)

    def denied(code: str) -> ReportExportPolicyDecision:
        return ReportExportPolicyDecision(
            allowed=False,
            initial_status=ExportStatusChoices.DENIED,
            export_type=ExportTypeChoices.DENIED_DEFERRED,
            requires_purpose=False,
            requires_independent_approval=False,
            includes_sensitive_data=includes_sensitive,
            includes_identifiable_data=includes_identifiable,
            scope_summary=scope_summary,
            denial_code=code,
        )

    if not is_active_nonlegacy_actor(actor):
        return denied("INACTIVE_OR_ANONYMOUS")
    if not definition or not definition.is_active:
        return denied("INACTIVE_DEFINITION")
    if format == ExportFormatChoices.PDF:
        if (
            definition.key != "students_profile"
            or metadata.get("document_template_key") != "students_profile"
        ):
            return denied("UNSUPPORTED_EXPORT_FORMAT")
    elif format != ExportFormatChoices.CSV:
        return denied("UNSUPPORTED_EXPORT_FORMAT")
    if not can_run_report(actor, definition, filters, context=context):
        return denied("EXPORT_SCOPE_DENIED")
    if includes_identifiable and not can_request_identifiable_export(actor, definition, filters, context=context):
        return denied("IDENTIFIABLE_EXPORT_SCOPE_DENIED")

    # Aggregate exports are governed by capability, live scope, suppression,
    # and audit. They do not require a per-export DPO or Head approval.
    # Identifiable exports are rejected above and therefore never reach this
    # branch.
    requires_independent_approval = False
    requires_purpose = bool(
        includes_sensitive or includes_identifiable or official_template or requires_independent_approval
    )
    if includes_identifiable:
        export_type = ExportTypeChoices.IDENTIFIABLE
    elif official_template:
        export_type = ExportTypeChoices.OFFICIAL_TEMPLATE
    elif is_gco_staff(actor):
        export_type = (
            ExportTypeChoices.SENSITIVE_AGGREGATE
            if includes_sensitive
            else ExportTypeChoices.ADMINISTRATIVE_OPERATIONAL
        )
    elif includes_sensitive:
        export_type = ExportTypeChoices.SENSITIVE_AGGREGATE
    else:
        export_type = ExportTypeChoices.AGGREGATE
    return ReportExportPolicyDecision(
        allowed=True,
        initial_status=(
            ExportStatusChoices.PENDING_APPROVAL
            if requires_independent_approval
            else ExportStatusChoices.REQUESTED
        ),
        export_type=export_type,
        requires_purpose=requires_purpose,
        requires_independent_approval=requires_independent_approval,
        includes_sensitive_data=includes_sensitive,
        includes_identifiable_data=includes_identifiable,
        scope_summary=scope_summary,
    )


def can_request_report_export(actor, report_definition, filters: dict, export_format: str) -> bool:
    """Checks if the actor is authorized to request an export."""
    return resolve_report_export_policy(actor, report_definition, filters, export_format).allowed


def can_approve_report_export(actor, export_request, context: AuthorityContext | None = None) -> bool:
    """Checks if the actor is authorized to approve the report export request.

    Rules:
    - Only Head Guidance (REPORTS_EXPORT_APPROVE) can approve.
    - Requester cannot approve their own sensitive/identifiable export.
    """
    if not is_active_nonlegacy_actor(actor):
        return False
    if not _has_report_capability(actor, Capability.REPORTS_EXPORT_APPROVE, context=context):
        return False
    if export_request.requested_by == actor:
        return False
    return True


def can_deny_report_export(actor, export_request, context: AuthorityContext | None = None) -> bool:
    """Checks if the actor is authorized to deny the report export request."""
    if not is_active_nonlegacy_actor(actor):
        return False
    return _has_report_capability(actor, Capability.REPORTS_EXPORT_APPROVE, context=context)


def can_generate_report_export(actor, export_request, context: AuthorityContext | None = None) -> bool:
    """Checks if the actor is authorized to generate/regenerate the report export."""
    if not is_active_nonlegacy_actor(actor):
        return False


    # Must be either the office-wide export operator (Head Guidance) or the requester
    if not (_has_report_capability(actor, Capability.REPORTS_EXPORT_OPERATE, context=context) or actor == export_request.requested_by):
        return False

    # Raw identifiable exports remain explicitly deferred even after approval.
    if export_request.includes_identifiable_data:
        return False

    requester = export_request.requested_by
    if not is_active_nonlegacy_actor(requester):
        return False
    decision = resolve_report_export_policy(
        requester,
        export_request.report_definition,
        export_request.filter_summary_json or {},
        export_request.export_format,
        includes_identifiable_data=export_request.includes_identifiable_data,
    )
    if not decision.allowed or not _export_scope_is_current(export_request):
        return False
    if decision.requires_independent_approval:
        return export_request.status == ExportStatusChoices.APPROVED
    return export_request.status in (ExportStatusChoices.REQUESTED, ExportStatusChoices.APPROVED)


def _export_scope_is_current(export_request) -> bool:
    """Revalidate the requester's role, account, family and scope snapshot."""
    requester = export_request.requested_by
    if not is_active_nonlegacy_actor(requester):
        return False
    current = get_current_report_export_scope(requester, export_request.report_definition)
    stored = export_request.scope_summary_json or {}
    if not stored or stored.get("version") != CSM_EXPORT_SCOPE_VERSION:
        return False
    return bool(current) and current == stored


def can_download_report_export(actor, export_request, context: AuthorityContext | None = None) -> bool:
    """Checks if the actor is authorized to download the generated export file.

    Rules:
    - Must be authenticated, active, and non-student.
    - Request status must be GENERATED or DOWNLOADED.
    - Must not be expired (either past expires_at or expired_at is set).
    - Head Guidance can download any generated export.
    - Counselors/Staff can download only their own requested exports.
    - IT Admin cannot download content (metadata-only).
    """
    if not is_active_nonlegacy_actor(actor):
        return False
    if is_student(actor) or is_it_admin(actor):
        return False

    if export_request.includes_identifiable_data:
        return False

    from apps.reports.choices import ExportStatusChoices
    from django.utils import timezone

    if export_request.status not in (ExportStatusChoices.GENERATED, ExportStatusChoices.DOWNLOADED):
        return False

    if export_request.expired_at:
        return False
    if export_request.expires_at and export_request.expires_at <= timezone.now():
        return False

    filters = export_request.filter_summary_json or {}
    if not can_run_report(actor, export_request.report_definition, filters, context=context):
        return False
    if not _export_scope_is_current(export_request):
        return False
    if _has_report_capability(actor, Capability.REPORTS_EXPORT_OPERATE, context=context):
        return True
    return actor == export_request.requested_by


def can_view_export_request(actor, export_request, context: AuthorityContext | None = None) -> bool:
    """Checks if the actor is authorized to view the export request metadata."""
    if not is_active_nonlegacy_actor(actor):
        return False
    if is_student(actor):
        return False
    if is_it_admin(actor):
        # IT receives only bounded lifecycle/technical metadata. The API
        # projection never includes report definitions, filters, payloads, or
        # protected-file access, and this capability cannot run/download data.
        return _has_report_capability(actor, Capability.REPORTS_EXPORT_MAINTAIN, context=context)
    if _has_report_capability(actor, Capability.REPORTS_EXPORT_OPERATE, context=context):
        return True
    if actor != export_request.requested_by:
        return False
    filters = export_request.filter_summary_json or {}
    return can_run_report(actor, export_request.report_definition, filters, context=context) and _export_scope_is_current(export_request)


def _can_run_students_profile(actor, filters: dict, context: AuthorityContext | None = None) -> bool:
    """Require one complete, live-authorized historical cohort release context."""
    from apps.common.exceptions import ValidationError

    from apps.profiles.models import CohortEnrollmentState, StudentAcademicCohort
    from apps.reports.profiling import ProfilingContext

    if not is_active_nonlegacy_actor(actor):
        return False
    if is_student(actor) or is_it_admin(actor) or is_gco_staff(actor):
        return False
    try:
        profiling_context = ProfilingContext.from_filters(filters or {})
    except ValidationError:
        return False
    if profiling_context.department or profiling_context.program:
        return False

    cohort = StudentAcademicCohort.objects.filter(
        enrollment_state=CohortEnrollmentState.ENROLLED,
        academic_year=profiling_context.academic_year,
        college=profiling_context.college,
        year_level=profiling_context.year_level,
    )
    if not cohort.exists():
        return False
    if profiling_context.campus:
        campus_cohort = cohort.filter(campus=profiling_context.campus)
        # Campus is permitted only as descriptive context, never as a narrower
        # differencing dimension for the same college/year release cohort.
        if not campus_cohort.exists() or campus_cohort.count() != cohort.count():
            return False
        cohort = campus_cohort

    if _has_report_capability(actor, Capability.REPORTS_VIEW_INSTITUTION, context=context):
        return True
    if not is_counselor(actor):
        return False

    coverages = list(get_live_counselor_coverages(actor))
    if not coverages:
        return False
    historical_scopes = cohort.values_list(
        "campus", "college", "department", "program"
    ).distinct()
    for campus, college, department, program in historical_scopes:
        values = {
            "campus": campus,
            "college": college,
            "department": department,
            "program": program,
        }
        if not any(
            all(not getattr(coverage, field) or getattr(coverage, field) == values[field]
                for field in CSM_SCOPE_FIELDS)
            for coverage in coverages
        ):
            return False
    return True


def can_manage_report_templates(actor, context: AuthorityContext | None = None) -> bool:
    """Checks if the actor can manage report templates."""
    if not is_active_nonlegacy_actor(actor):
        return False
    return bool(
        is_policy_active("reports.definitions")
        and _has_report_capability(actor, Capability.REPORTS_DEFINITIONS_MANAGE, context=context)
    )


def can_expire_report_export(actor, export_request, context: AuthorityContext | None = None) -> bool:
    """Checks if the actor is authorized to expire a report export."""
    if not is_active_nonlegacy_actor(actor):
        return False
    return bool(
        _has_report_capability(actor, Capability.REPORTS_EXPORT_OPERATE, context=context)
        or _has_report_capability(actor, Capability.REPORTS_EXPORT_MAINTAIN, context=context)
    )


def can_archive_report_export(actor, export_request, context: AuthorityContext | None = None) -> bool:
    """Allow the requester or Head Guidance to close a released export."""
    if not is_active_nonlegacy_actor(actor):
        return False
    if is_student(actor) or is_it_admin(actor):
        return False
    if export_request.status not in (ExportStatusChoices.GENERATED, ExportStatusChoices.DOWNLOADED):
        return False
    return bool(
        _has_report_capability(actor, Capability.REPORTS_EXPORT_OPERATE, context=context)
        or _has_report_capability(actor, Capability.REPORTS_EXPORT_MAINTAIN, context=context)
        or actor == export_request.requested_by
    )


def report_export_file_policy(user, protected_file, action) -> bool:
    """Protected file access policy callback for report export files."""
    from apps.reports.models import ReportExportRequest

    # Try to find the export request that references this file
    export_request = ReportExportRequest.objects.filter(protected_file=protected_file).first()
    if not export_request:
        return False

    if action == "read_content":
        return can_download_report_export(user, export_request)
    elif action in ("read_metadata", "inspect"):
        return can_view_export_request(user, export_request)
    elif action == "delete":
        return can_expire_report_export(user, export_request) or can_archive_report_export(user, export_request)

    return False


def report_export_generated_document_policy(user, action: str, *, generated_document=None, context=None) -> bool:
    """Authorize document rendering only for an in-flight governed report export."""
    from apps.reports.models import ReportExportRequest

    if not is_active_nonlegacy_actor(user):
        return False

    if action == "generate":
        context = context or {}
        if (
            context.get("owning_app_label") != "reports"
            or context.get("owning_model_name") != "ReportExportRequest"
            or not context.get("owning_object_id")
        ):
            return False
        try:
            export_request = ReportExportRequest.objects.select_related("report_definition").get(
                pk=context["owning_object_id"],
            )
        except (ReportExportRequest.DoesNotExist, ValueError, TypeError):
            return False
        return bool(
            export_request.export_format == "pdf"
            and export_request.status == ExportStatusChoices.GENERATING
            and export_request.report_definition.key == "students_profile"
            and (_has_report_capability(user, Capability.REPORTS_EXPORT_OPERATE) or user == export_request.requested_by)
            and can_run_report(
                user,
                export_request.report_definition,
                export_request.filter_summary_json or {},
            )
        )

    if action == "read_content" and generated_document:
        export_request = ReportExportRequest.objects.filter(
            generated_document=generated_document,
        ).first()
        return bool(export_request and can_download_report_export(user, export_request))

    return False
