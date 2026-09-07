# Project: COMPASS
# File: apps/reports/services.py
# Module: apps.reports
# Purpose: Service functions for executing reports and recording run metadata

import time

from django.db import transaction
from django.utils import timezone

from apps.common.exceptions import (
    DependencyFailureError,
    NotFoundError,
    PermissionDeniedError as PermissionDenied,
    StaleStateError,
    ValidationError,
)
from apps.access_control.authority import build_authority_context, resolve_capability
from apps.access_control.capabilities import Capability
from apps.access_control.rules import is_active_nonlegacy_actor, is_counselor, is_gco_staff
from apps.access_control.scopes import get_active_workflow_authority_grants, get_live_counselor_coverages
from apps.reports.models import ReportDefinition, ReportRun
from apps.reports.choices import FieldSensitivity, ReportRunStatus, ReportFamilyChoices, SuppressionMode
from apps.reports.policies import (
    GCO_OFFICE_WIDE_REPORT_FAMILIES,
    GCO_REPORT_FAMILIES,
    COUNSELOR_REPORT_FAMILIES,
    can_access_reports_destination,
    can_run_report,
)
from apps.reports.sensitivity import classify_field_sensitivity
from apps.reports.suppression import (
    build_safe_filter_hash,
    redact_report_filters,
    resolve_report_suppression_policy,
    suppress_csm_disclosure_set,
    suppress_report_data,
    suppression_policy_audit_metadata,
)
from apps.reports.selectors import (
    get_student_profile_inventory_aggregates,
    get_students_profile_aggregates,
    get_feedback_csm_aggregates,
    get_exit_interview_aggregates,
    get_graduate_tracer_aggregates,
    get_form_collection_progress_aggregates,
    get_document_requests_aggregates,
    get_appointments_counseling_workload_aggregates,
    get_referrals_call_slips_aggregates,
    get_public_contact_aggregates,
    get_workflow_notifications_aggregates,
    get_audit_report_access_aggregates,
)
from apps.reports.profiling import ProfilingContext, build_students_profile_report
from apps.audit.services import audit_log
from apps.governance.runtime_config import resolve_runtime_setting
from apps.reports.commands import ReportRunCommand, ReportExportCommand


def list_report_definitions_for_actor(actor):
    """Return a database-bounded queryset of definitions visible to the actor."""
    if not is_active_nonlegacy_actor(actor):
        return ReportDefinition.objects.none()

    context = build_authority_context(actor)
    if not can_access_reports_destination(actor, context=context):
        return ReportDefinition.objects.none()
    if not resolve_capability(context, Capability.REPORTS_VIEW_DEFINITIONS):
        return ReportDefinition.objects.none()

    definitions = ReportDefinition.objects.filter(is_active=True)
    if resolve_capability(context, Capability.REPORTS_VIEW_INSTITUTION):
        return definitions
    if is_counselor(actor):
        if not get_live_counselor_coverages(actor).exists():
            return ReportDefinition.objects.none()
        return definitions.filter(family__in=COUNSELOR_REPORT_FAMILIES)
    if is_gco_staff(actor):
        grants = get_active_workflow_authority_grants(actor, capability=Capability.REPORTS_RUN)
        if not grants.exists():
            return ReportDefinition.objects.none()
        if any(grant.scope_mode == "OFFICE_WIDE" for grant in grants):
            return definitions.filter(family__in=GCO_REPORT_FAMILIES)
        return definitions.filter(
            family__in=GCO_REPORT_FAMILIES,
        ).exclude(family__in=GCO_OFFICE_WIDE_REPORT_FAMILIES)
    return ReportDefinition.objects.none()


def validate_report_filters(report_definition, filters: dict) -> dict:
    """Sanitizes and whitelists incoming filters to prevent arbitrary or unsafe queries."""
    if report_definition.family == ReportFamilyChoices.FEEDBACK_CSM:
        if filters:
            raise ValidationError("CSM report filters are not available for privacy protection.")
        return {}

    if report_definition.key == "students_profile":
        provided_filters = {
            key: value for key, value in (filters or {}).items()
            if value not in (None, "")
        }
        allowed = {"academic_year", "college", "year_level", "campus"}
        if set(provided_filters) - allowed:
            raise ValidationError("Only academic year, college, year level, and non-narrowing campus are allowed.")
        context = ProfilingContext.from_filters(provided_filters)
        # Return the normalized primitive values, never arbitrary query data.
        return context.as_filters()

    if not filters:
        return {}

    provided_filters = {key: value for key, value in filters.items() if value not in (None, "")}

    allowed_keys = {
        "campus",
        "college",
        "department",
        "program",
        "year_level",
        "academic_year",
        "service_category",
        "client_type",
        "form_collection",
        "form_revision",
        "employment_status",
        "graduation_year",
        "assigned_counselor",
        "status"
    }

    forbidden_keys = [
        key for key in provided_filters.keys()
        if classify_field_sensitivity(key) == FieldSensitivity.FORBIDDEN
    ]
    if forbidden_keys:
        raise ValidationError("Forbidden report filter keys are not allowed.")

    sanitized = {k: v for k, v in provided_filters.items() if k in allowed_keys}

    # Basic data type normalization (coerce string values or enforce lists/integers)
    return sanitized


def get_report_family_source_selector(family: str):
    """Maps a report family to its aggregate data selector function."""
    mapping = {
        ReportFamilyChoices.STUDENT_PROFILE_INVENTORY: get_student_profile_inventory_aggregates,
        ReportFamilyChoices.FEEDBACK_CSM: get_feedback_csm_aggregates,
        ReportFamilyChoices.EXIT_INTERVIEW: get_exit_interview_aggregates,
        ReportFamilyChoices.GRADUATE_TRACER: get_graduate_tracer_aggregates,
        ReportFamilyChoices.FORM_COLLECTION_PROGRESS: get_form_collection_progress_aggregates,
        ReportFamilyChoices.DOCUMENT_REQUESTS: get_document_requests_aggregates,
        ReportFamilyChoices.APPOINTMENTS_COUNSELING_WORKLOAD: get_appointments_counseling_workload_aggregates,
        ReportFamilyChoices.REFERRALS_CALL_SLIPS: get_referrals_call_slips_aggregates,
        ReportFamilyChoices.PUBLIC_CONTACT: get_public_contact_aggregates,
        ReportFamilyChoices.WORKFLOW_NOTIFICATIONS: get_workflow_notifications_aggregates,
        ReportFamilyChoices.AUDIT_REPORT_ACCESS: get_audit_report_access_aggregates,
    }

    selector = mapping.get(family)
    if not selector:
        raise ValidationError("The requested report family is not available.")
    return selector


def apply_suppression(
    report_definition,
    aggregate_dataset: dict,
    filters: dict,
    *,
    policy=None,
) -> tuple[dict, bool, int]:
    """Applies suppression according to the definition's authoritative mode.

    Returns the suppressed dataset, a boolean indicating if suppression was applied,
    and the count of suppressed cells. Only CELL and DISCLOSURE_SET modes reach this
    path; any other mode fails closed because the caller must route it elsewhere
    (profiling SECTION and NONE families never enter here).
    """
    policy = policy or resolve_report_suppression_policy(report_definition)
    threshold = policy.threshold
    mode = policy.mode

    if mode == SuppressionMode.DISCLOSURE_SET:
        suppressed_dataset, suppression_applied = suppress_csm_disclosure_set(
            aggregate_dataset,
            threshold,
        )
        # CSM does not persist a suppressed-cell counter because the counter is
        # itself a disclosure side channel. The boolean records only that the
        # fixed disclosure set was protected.
        return suppressed_dataset, suppression_applied, 0

    if mode != SuppressionMode.CELL:
        raise ValidationError(
            f"Suppression mode {mode} is not routable through apply_suppression."
        )

    suppressed_dataset, suppressed_cell_count = suppress_report_data(
        aggregate_dataset,
        threshold=threshold,
        count_keys=list(policy.count_keys),
    )

    return suppressed_dataset, suppressed_cell_count > 0, suppressed_cell_count


def _resolve_audit_suppression_policy(report_definition, policy=None):
    if policy is not None:
        return policy
    try:
        return resolve_report_suppression_policy(report_definition)
    except Exception:
        # Audit provenance must never turn a safe denial/failure into a second
        # exception, and a malformed policy is intentionally not represented
        # as a fabricated policy version.
        return None


def record_report_view_audit(
    actor,
    report_definition,
    filters: dict,
    outcome: str,
    run_id=None,
    error_code=None,
    *,
    suppression_policy=None,
):
    """Wraps the system audit_log to record report access events safely."""
    redacted_filters = redact_report_filters(filters, actor)
    filter_hash = build_safe_filter_hash(redacted_filters)

    metadata = {
        "report_key": report_definition.key,
        "report_family": report_definition.family,
        "filter_hash": filter_hash,
        "filter_keys": sorted(redacted_filters.keys()),
        "outcome": outcome,
        "run_id": str(run_id) if run_id else None,
    }
    metadata.update(suppression_policy_audit_metadata(
        _resolve_audit_suppression_policy(report_definition, suppression_policy)
    ))
    if error_code:
        metadata["error_code"] = error_code

    action_type = f"REPORT_RUN_{outcome.upper()}"

    audit_log(
        action_type=action_type,
        event_category="DATA_ACCESS",
        target_model="reports.ReportDefinition",
        target_object_id=str(report_definition.id),
        actor_user=actor,
        metadata=metadata
    )


REPORT_WORK_BASELINES = {
    ReportFamilyChoices.STUDENT_PROFILE_INVENTORY: 5000,
    ReportFamilyChoices.FEEDBACK_CSM: 1200,
    ReportFamilyChoices.EXIT_INTERVIEW: 1600,
    ReportFamilyChoices.GRADUATE_TRACER: 1600,
    ReportFamilyChoices.FORM_COLLECTION_PROGRESS: 1200,
    ReportFamilyChoices.DOCUMENT_REQUESTS: 1000,
    ReportFamilyChoices.APPOINTMENTS_COUNSELING_WORKLOAD: 1400,
    ReportFamilyChoices.REFERRALS_CALL_SLIPS: 1400,
    ReportFamilyChoices.PUBLIC_CONTACT: 1000,
    ReportFamilyChoices.WORKFLOW_NOTIFICATIONS: 1000,
    ReportFamilyChoices.AUDIT_REPORT_ACCESS: 1800,
}


def estimate_report_work_units(actor, report_definition, filters: dict, *, context=None) -> int:
    """Return a conservative, bounded estimate used only for sync/async choice."""
    baseline = REPORT_WORK_BASELINES.get(report_definition.family, 1000)
    narrowing_bonus = min(500, len(filters or {}) * 25)
    return min(100_000, baseline + narrowing_bonus)


def report_execution_controls() -> dict[str, int]:
    """Resolve all bounded execution controls from Governance."""
    keys = {
        "max_output_bytes": "REPORT_SYNC_MAX_OUTPUT_BYTES",
        "max_work_units": "REPORT_SYNC_MAX_WORK_UNITS",
        "async_after_work_units": "REPORT_ASYNC_AFTER_WORK_UNITS",
        "run_timeout_seconds": "REPORT_RUN_TIMEOUT_SECONDS",
        "export_max_output_bytes": "REPORT_EXPORT_MAX_OUTPUT_BYTES",
        "export_expiry_days": "REPORT_EXPORT_EXPIRY_DAYS",
        "run_retention_days": "REPORT_RUN_RETENTION_DAYS",
    }
    return {
        name: resolve_runtime_setting("reports.execution_controls", setting_key)
        for name, setting_key in keys.items()
    }


def _safe_run_metadata(run, *, execution_mode: str, suppression_policy=None, **values) -> dict:
    metadata = dict(run if isinstance(run, dict) else (run.metadata_json or {}))
    metadata.update({"execution_mode": execution_mode})
    metadata.update({key: value for key, value in values.items() if value is not None})
    metadata.update(suppression_policy_audit_metadata(suppression_policy))
    return metadata


def _new_report_run(actor, definition, sanitized_filters, suppression_policy, *, status, execution_mode, estimated_work_units=None):
    redacted_filters = (
        dict(sanitized_filters)
        if definition.key == "students_profile"
        else redact_report_filters(sanitized_filters, actor)
    )
    now = timezone.now()
    controls = report_execution_controls()
    run = ReportRun.objects.create(
        report_definition=definition,
        requested_by=actor,
        filter_hash=build_safe_filter_hash(redacted_filters),
        filter_summary_json=redacted_filters,
        status=status,
        started_at=now if status == ReportRunStatus.RUNNING else None,
        expires_at=now + timezone.timedelta(days=controls["run_retention_days"]),
        metadata_json=_safe_run_metadata(
            {},
            execution_mode=execution_mode,
            suppression_policy=suppression_policy,
            estimated_work_units=estimated_work_units,
        ),
    )
    return run, redacted_filters


def _prepare_report(actor, report_key: str, filters: dict):
    try:
        report_definition = ReportDefinition.objects.get(key=report_key)
    except ReportDefinition.DoesNotExist:
        raise NotFoundError()
    sanitized_filters = validate_report_filters(report_definition, filters)
    actor_context = build_authority_context(actor)
    if not can_run_report(actor, report_definition, sanitized_filters, context=actor_context):
        record_report_view_audit(actor, report_definition, sanitized_filters, outcome="DENIED")
        raise PermissionDenied("You do not have permission to run this report with the provided filters.")
    suppression_policy = resolve_report_suppression_policy(report_definition)
    return report_definition, sanitized_filters, actor_context, suppression_policy


def _ensure_report_timeout(started_at: float, controls: dict[str, int]) -> None:
    if time.monotonic() - started_at > controls["run_timeout_seconds"]:
        raise DependencyFailureError()


def _execute_report_run(actor, report_run, report_definition, sanitized_filters, actor_context, suppression_policy):
    started_at = time.monotonic()
    controls = report_execution_controls()
    profiling_payload = report_definition.key == "students_profile"
    try:
        if profiling_payload:
            raw_dataset = build_students_profile_report(
                ProfilingContext.from_filters(sanitized_filters),
                suppression_threshold=suppression_policy.threshold,
            )
        else:
            selector_func = get_report_family_source_selector(report_definition.family)
            raw_dataset = selector_func(actor, sanitized_filters, report_definition, context=actor_context)
        _ensure_report_timeout(started_at, controls)

        if profiling_payload:
            suppressed_dataset = raw_dataset
            suppression_applied = True
            suppressed_cell_count = 0
        elif suppression_policy.mode != SuppressionMode.NONE:
            suppressed_dataset, suppression_applied, suppressed_cell_count = apply_suppression(
                report_definition,
                raw_dataset,
                sanitized_filters,
                policy=suppression_policy,
            )
        else:
            suppressed_dataset = raw_dataset
            suppression_applied = False
            suppressed_cell_count = 0
        _ensure_report_timeout(started_at, controls)

        aggregate_count = None
        cell_count = None
        if report_definition.family != ReportFamilyChoices.FEEDBACK_CSM and not profiling_payload:
            aggregate_count = 0
            cell_count = 0
            for value in suppressed_dataset.values():
                if isinstance(value, list):
                    aggregate_count += len(value)
                    for row in value:
                        if isinstance(row, dict):
                            cell_count += len(row)
                elif isinstance(value, dict):
                    cell_count += len(value)

        now = timezone.now()
        report_run.status = ReportRunStatus.COMPLETED
        report_run.aggregate_count = aggregate_count
        report_run.cell_count = cell_count
        report_run.suppression_applied = suppression_applied
        report_run.suppressed_cell_count = suppressed_cell_count
        report_run.completed_at = now
        report_run.expires_at = now + timezone.timedelta(days=controls["run_retention_days"])
        report_run.metadata_json = _safe_run_metadata(
            report_run,
            execution_mode=(report_run.metadata_json or {}).get("execution_mode", "SYNC"),
            suppression_policy=suppression_policy,
            actual_work_units=max(1, aggregate_count or cell_count or 1),
        )
        report_run.save()
        record_report_view_audit(
            actor,
            report_definition,
            sanitized_filters,
            outcome="COMPLETED",
            run_id=report_run.id,
            suppression_policy=suppression_policy,
        )
        return report_run, suppressed_dataset
    except Exception as exc:
        report_run.status = ReportRunStatus.FAILED
        report_run.failed_at = timezone.now()
        report_run.metadata_json = _safe_run_metadata(
            report_run,
            execution_mode=(report_run.metadata_json or {}).get("execution_mode", "SYNC"),
            suppression_policy=suppression_policy,
            error_code=getattr(getattr(exc, "code", None), "value", None) or "REPORT_EXECUTION_FAILED",
            error_category="report_execution",
        )
        report_run.save()
        record_report_view_audit(
            actor,
            report_definition,
            sanitized_filters,
            outcome="FAILED",
            run_id=report_run.id,
            error_code="REPORT_EXECUTION_FAILED",
            suppression_policy=suppression_policy,
        )
        raise


def run_report(actor, report_key: str, filters: dict) -> tuple[ReportRun, dict]:
    """Execute one report synchronously for internal export workflows."""
    report_definition, sanitized_filters, actor_context, suppression_policy = _prepare_report(
        actor, report_key, filters
    )
    report_run, _ = _new_report_run(
        actor,
        report_definition,
        sanitized_filters,
        suppression_policy,
        status=ReportRunStatus.RUNNING,
        execution_mode="SYNC",
    )
    record_report_view_audit(
        actor,
        report_definition,
        sanitized_filters,
        outcome="STARTED",
        run_id=report_run.id,
        suppression_policy=suppression_policy,
    )
    return _execute_report_run(
        actor, report_run, report_definition, sanitized_filters, actor_context, suppression_policy
    )


def run_report_command(actor, command: ReportRunCommand) -> tuple[ReportRun, dict]:
    """Execute one validated typed report command."""
    definition, sanitized_filters, actor_context, suppression_policy = _prepare_report(
        actor, command.report_key, dict(command.filters)
    )
    if command.expected_definition_updated_at and definition.updated_at != command.expected_definition_updated_at:
        raise StaleStateError()
    estimate = estimate_report_work_units(actor, definition, sanitized_filters, context=actor_context)
    controls = report_execution_controls()
    if estimate >= controls["async_after_work_units"]:
        report_run, _ = _new_report_run(
            actor,
            definition,
            sanitized_filters,
            suppression_policy,
            status=ReportRunStatus.PENDING,
            execution_mode="ASYNC",
            estimated_work_units=estimate,
        )
        record_report_view_audit(
            actor,
            definition,
            sanitized_filters,
            outcome="PENDING",
            run_id=report_run.id,
            suppression_policy=suppression_policy,
        )
        return report_run, None
    report_run, _ = _new_report_run(
        actor,
        definition,
        sanitized_filters,
        suppression_policy,
        status=ReportRunStatus.RUNNING,
        execution_mode="SYNC",
    )
    record_report_view_audit(
        actor,
        definition,
        sanitized_filters,
        outcome="STARTED",
        run_id=report_run.id,
        suppression_policy=suppression_policy,
    )
    return _execute_report_run(
        actor, report_run, definition, sanitized_filters, actor_context, suppression_policy
    )


def execute_pending_report_run(actor, run_id: str) -> tuple[ReportRun, dict | None]:
    """Claim and execute one pending run using its stable ID."""
    if not is_active_nonlegacy_actor(actor):
        raise PermissionDenied()
    with transaction.atomic():
        report_run = (
            ReportRun.objects.select_for_update()
            .select_related("report_definition")
            .filter(id=run_id)
            .first()
        )
        if report_run is None:
            raise NotFoundError()
        if report_run.requested_by_id != getattr(actor, "pk", None):
            raise PermissionDenied()
        if report_run.status == ReportRunStatus.COMPLETED:
            return report_run, None
        if report_run.status != ReportRunStatus.PENDING:
            raise StaleStateError()
        filters = dict(report_run.filter_summary_json or {})
        report_definition = report_run.report_definition
        sanitized_filters = validate_report_filters(report_definition, filters)
        actor_context = build_authority_context(actor)
        if not can_run_report(actor, report_definition, sanitized_filters, context=actor_context):
            raise PermissionDenied()
        suppression_policy = resolve_report_suppression_policy(report_definition)
        report_run.status = ReportRunStatus.RUNNING
        report_run.started_at = timezone.now()
        report_run.metadata_json = _safe_run_metadata(
            report_run,
            execution_mode="ASYNC",
            suppression_policy=suppression_policy,
        )
        report_run.save(update_fields=["status", "started_at", "metadata_json", "updated_at"])
    record_report_view_audit(
        actor,
        report_definition,
        sanitized_filters,
        outcome="STARTED",
        run_id=report_run.id,
        suppression_policy=suppression_policy,
    )
    return _execute_report_run(
        actor, report_run, report_definition, sanitized_filters, actor_context, suppression_policy
    )


def request_export_command(actor, command: ReportExportCommand) -> object:
    """Create one governed aggregate export request from a typed command."""
    definition = ReportDefinition.objects.filter(key=command.report_key, is_active=True).first()
    if definition is None:
        raise NotFoundError()
    if command.expected_definition_updated_at and definition.updated_at != command.expected_definition_updated_at:
        raise StaleStateError()
    from apps.reports.export_services import request_report_export
    return request_report_export(
        actor,
        definition,
        dict(command.filters),
        command.export_format,
        purpose=command.purpose,
        includes_identifiable_data=False,
    )
