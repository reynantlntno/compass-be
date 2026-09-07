# Project: COMPASS
# File: apps/reports/export_services.py
# Module: apps.reports
# Purpose: Service functions for executing and auditing report export transitions

import re
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Dict, Tuple

from django.db import transaction
from django.utils import timezone

from apps.audit.services import audit_log
from apps.common.exceptions import (
    CompassError,
    DependencyFailureError,
    NotFoundError,
    PayloadTooLargeError,
    PermissionDeniedError as PermissionDenied,
    StaleStateError,
    ValidationError,
)
from apps.access_control.authority import AuthorityContext, resolve_capability
from apps.access_control.capabilities import Capability
from apps.access_control.rules import is_active_nonlegacy_actor
from apps.reports.choices import (
    ExportFormatChoices,
    ExportStatusChoices,
    ExportTypeChoices,
    ReportFamilyChoices,
    SensitivityLevel,
)
from apps.reports.export_adapters import export_dataset_to_csv, export_students_profile_to_csv
from apps.reports.profiling_pdf import render_students_profile_export
from apps.reports.models import ReportDefinition, ReportExportRequest
from apps.reports.policies import (
    can_approve_report_export,
    can_archive_report_export,
    can_deny_report_export,
    can_download_report_export,
    can_expire_report_export,
    can_generate_report_export,
    can_request_identifiable_export,
    can_request_report_export,
    can_view_export_request,
    get_current_report_export_scope,
    resolve_report_export_policy,
)
from apps.reports.commands import ReportExportLifecycleCommand
from apps.reports.services import report_execution_controls, run_report, validate_report_filters
from apps.reports.suppression import (
    build_safe_filter_hash,
    redact_report_filters,
    resolve_report_suppression_policy,
    suppression_policy_audit_metadata,
)
from apps.security.exceptions import SecurityError
from apps.security.file_services import delete_marker_protected_file, open_protected_file, store_protected_file


SAFE_REASON_MAX_LENGTH = 500
EXPORT_DUPLICATE_WINDOW = timedelta(hours=24)


@dataclass(frozen=True, slots=True)
class ReportDownloadResult:
    content: bytes
    export_format: str

REUSABLE_EXPORT_STATUSES = (
    ExportStatusChoices.REQUESTED,
    ExportStatusChoices.PENDING_APPROVAL,
    ExportStatusChoices.APPROVED,
    ExportStatusChoices.GENERATING,
    ExportStatusChoices.GENERATED,
    ExportStatusChoices.DOWNLOADED,
)

SENSITIVE_REASON_PATTERNS = (
    re.compile(r"\b[A-Z]{2,}[- ]?\d{2,}[- ]?\d{2,}\b"),
    re.compile(r"\b\d{2,4}[- ]?\d{3,}[- ]?\d{2,}\b"),
    re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"\b(?:09|\+639)\d{9}\b"),
    re.compile(r"\b(?:name|student|control|contact|email)\s*[:=]", re.IGNORECASE),
)

SENSITIVE_REASON_KEYWORDS = {
    "counseling",
    "referral",
    "case detail",
    "case details",
    "narrative",
    "free text",
    "raw request",
    "request body",
    "diagnosis",
    "health",
    "disability",
    "religion",
    "income",
}


def classify_export_sensitivity(
    report_definition: ReportDefinition,
    filters: Dict[str, Any],
    *,
    includes_identifiable_data: bool = False,
) -> Tuple[bool, bool]:
    """Determines whether the requested export contains sensitive or identifiable categories."""
    includes_sensitive = report_definition.sensitivity_level in (
        SensitivityLevel.SENSITIVE,
        SensitivityLevel.RESTRICTED,
    )
    includes_identifiable = bool(includes_identifiable_data)
    return includes_sensitive, includes_identifiable


def clean_export_reason(value: str, *, required: bool = False, field_label: str = "reason") -> str:
    """Validate and normalize bounded business-purpose text."""
    normalized = " ".join(str(value or "").split())
    if required and not normalized:
        raise ValidationError(f"A safe {field_label} is required.")
    if len(normalized) > SAFE_REASON_MAX_LENGTH:
        raise ValidationError(f"The {field_label} must be {SAFE_REASON_MAX_LENGTH} characters or fewer.")
    lowered = normalized.lower()
    if any(keyword in lowered for keyword in SENSITIVE_REASON_KEYWORDS):
        raise ValidationError(
            "Use a brief business purpose only. Do not include student identifiers or sensitive personal details."
        )
    if any(pattern.search(normalized) for pattern in SENSITIVE_REASON_PATTERNS):
        raise ValidationError(
            "Use a brief business purpose only. Do not include student identifiers or sensitive personal details."
        )
    return normalized


def _safe_export_metadata(export_request: ReportExportRequest, outcome: str, metadata: Dict[str, Any] | None = None) -> Dict[str, Any]:
    safe_meta = {
        "export_request_id": str(export_request.id),
        "report_key": export_request.report_definition.key,
        "report_run_id": str(export_request.report_run.id) if export_request.report_run else None,
        "export_format": export_request.export_format,
        "export_type": export_request.export_type,
        "status": export_request.status,
        "outcome": outcome,
        "suppression_applied": export_request.suppression_applied,
        "expires_at": export_request.expires_at.isoformat() if export_request.expires_at else None,
    }
    stored_generation_metadata = export_request.generation_metadata_json or {}
    stored_policy_metadata = {
        key: stored_generation_metadata.get(key)
        for key in (
            "suppression_policy_id",
            "suppression_policy_effective_from",
            "suppression_policy_effective_until",
            "suppression_policy_source_reference",
        )
        if isinstance(stored_generation_metadata, dict) and stored_generation_metadata.get(key) is not None
    }
    if stored_policy_metadata.get("suppression_policy_id"):
        safe_meta.update(stored_policy_metadata)
    else:
        try:
            suppression_policy = resolve_report_suppression_policy(export_request.report_definition)
        except Exception:
            suppression_policy = None
        safe_meta.update(suppression_policy_audit_metadata(suppression_policy))
    if (
        export_request.report_definition.family != ReportFamilyChoices.FEEDBACK_CSM
        and export_request.report_definition.key != "students_profile"
    ):
        safe_meta["suppressed_cell_count"] = export_request.suppressed_cell_count
    for key, value in (metadata or {}).items():
        if key in {"error_code", "error_category", "denial_code", "event_code", "reused_request_id"}:
            safe_meta[key] = value
    return safe_meta


def record_export_audit(
    actor,
    export_request: ReportExportRequest,
    action_type: str,
    outcome: str,
    metadata: Dict[str, Any] | None = None,
) -> None:
    """Logs export transitions to the audit trail using only non-sensitive metadata."""
    audit_log(
        action_type=action_type,
        event_category="DATA_ACCESS",
        target_model="reports.ReportExportRequest",
        target_object_id=str(export_request.id),
        actor_user=actor,
        metadata=_safe_export_metadata(export_request, outcome, metadata),
    )


def record_export_definition_audit(
    actor,
    report_definition: ReportDefinition,
    action_type: str,
    outcome: str,
    metadata: Dict[str, Any] | None = None,
) -> None:
    safe_meta = {
        "report_key": report_definition.key,
        "outcome": outcome,
    }
    try:
        safe_meta.update(suppression_policy_audit_metadata(resolve_report_suppression_policy(report_definition)))
    except Exception:
        pass
    for key, value in (metadata or {}).items():
        if key in {"export_format", "error_code", "error_category", "event_code"}:
            safe_meta[key] = value
    audit_log(
        action_type=action_type,
        event_category="DATA_ACCESS",
        target_model="reports.ReportDefinition",
        target_object_id=str(report_definition.id),
        actor_user=actor,
        metadata=safe_meta,
    )


def request_report_export(
    actor,
    report_definition: ReportDefinition,
    filters: Dict[str, Any],
    export_format: str,
    purpose: str = "",
    *,
    includes_identifiable_data: bool = False,
    context: AuthorityContext | None = None,
) -> ReportExportRequest:
    """Initiates or reuses an export request after policy, purpose, and format checks."""
    try:
        sanitized_filters = validate_report_filters(report_definition, filters)
    except ValidationError as exc:
        record_export_definition_audit(
            actor,
            report_definition,
            "forbidden_field_export_attempted",
            "DENIED",
            {"export_format": export_format, "error_code": "FORBIDDEN_FILTER"},
        )
        raise PermissionDenied("Export request filters are not allowed.") from exc

    decision = resolve_report_export_policy(
        actor,
        report_definition,
        sanitized_filters,
        export_format,
        includes_identifiable_data=includes_identifiable_data,
        context=context,
    )
    if not decision.allowed:
        denial_code = decision.denial_code or "EXPORT_SCOPE_DENIED"
        record_export_definition_audit(
            actor,
            report_definition,
            "unsupported_format_attempted" if denial_code == "UNSUPPORTED_EXPORT_FORMAT" else "export_scope_rejected",
            "DENIED",
            {"export_format": export_format, "error_code": denial_code},
        )
        if denial_code == "UNSUPPORTED_EXPORT_FORMAT":
            raise PermissionDenied("Unsupported export format.")
        if denial_code == "IDENTIFIABLE_EXPORT_SCOPE_DENIED":
            raise PermissionDenied("Identifiable exports require Head Guidance authorization.")
        raise PermissionDenied("You do not have permission to request this export.")

    includes_sensitive = decision.includes_sensitive_data
    includes_identifiable = decision.includes_identifiable_data
    cleaned_purpose = clean_export_reason(
        purpose,
        required=decision.requires_purpose,
        field_label="purpose",
    )

    persisted_filters = (
        dict(sanitized_filters)
        if report_definition.key == "students_profile"
        else redact_report_filters(sanitized_filters, actor)
    )
    filter_hash = build_safe_filter_hash(persisted_filters)
    scope_summary = decision.scope_summary
    initial_status = decision.initial_status
    export_type = decision.export_type

    reuse_cutoff = timezone.now() - EXPORT_DUPLICATE_WINDOW
    with transaction.atomic():
        reusable_requests = (
            ReportExportRequest.objects.select_for_update()
            .filter(
                requested_by=actor,
                report_definition=report_definition,
                filter_hash=filter_hash,
                export_type=export_type,
                export_format=export_format,
                status__in=(
                    (ExportStatusChoices.REQUESTED, ExportStatusChoices.APPROVED,
                     ExportStatusChoices.GENERATING, ExportStatusChoices.GENERATED,
                     ExportStatusChoices.DOWNLOADED)
                    if not decision.requires_independent_approval
                    else (ExportStatusChoices.PENDING_APPROVAL, ExportStatusChoices.APPROVED,
                          ExportStatusChoices.GENERATING, ExportStatusChoices.GENERATED,
                          ExportStatusChoices.DOWNLOADED)
                ),
                requested_at__gte=reuse_cutoff,
            )
            .order_by("-requested_at")
        )
        reusable_requests = reusable_requests.filter(scope_summary_json=scope_summary)
        existing_request = reusable_requests.first()
        if existing_request:
            record_export_audit(
                actor,
                existing_request,
                "report_export_request_reused",
                "SUCCESS",
                {"reused_request_id": str(existing_request.id)},
            )
            return existing_request

        export_request = ReportExportRequest.objects.create(
            requested_by=actor,
            report_definition=report_definition,
            export_type=export_type,
            export_format=export_format,
            status=initial_status,
            scope_summary_json=scope_summary,
            filter_hash=filter_hash,
            filter_summary_json=persisted_filters,
            includes_sensitive_data=includes_sensitive,
            includes_identifiable_data=includes_identifiable,
            purpose=cleaned_purpose,
        )

    record_export_audit(actor, export_request, "report_export_requested", "SUCCESS")
    return export_request


def approve_report_export(actor, export_request: ReportExportRequest, approval_reason: str = "", *, context: AuthorityContext | None = None) -> ReportExportRequest:
    """Approves a pending export request."""
    if not can_approve_report_export(actor, export_request, context=context):
        record_export_audit(actor, export_request, "report_export_approved", "DENIED", {"denial_code": "POLICY_DENIED"})
        raise PermissionDenied("You are not authorized to approve this export request.")

    if export_request.status != ExportStatusChoices.PENDING_APPROVAL:
        raise ValidationError("Only pending approval requests can be approved.")

    cleaned_reason = clean_export_reason(approval_reason, required=False, field_label="approval reason")
    with transaction.atomic():
        export_request.status = ExportStatusChoices.APPROVED
        export_request.approved_by = actor
        export_request.approved_at = timezone.now()
        export_request.approval_reason = cleaned_reason
        export_request.save()

    record_export_audit(actor, export_request, "report_export_approved", "SUCCESS")
    return export_request


def deny_report_export(actor, export_request: ReportExportRequest, denial_reason: str = "", *, context: AuthorityContext | None = None) -> ReportExportRequest:
    """Denies a pending export request."""
    if not can_deny_report_export(actor, export_request, context=context):
        record_export_audit(actor, export_request, "report_export_denied", "DENIED", {"denial_code": "POLICY_DENIED"})
        raise PermissionDenied("You are not authorized to deny this export request.")

    if export_request.status != ExportStatusChoices.PENDING_APPROVAL:
        raise ValidationError("Only pending approval requests can be denied.")

    cleaned_reason = clean_export_reason(denial_reason, required=True, field_label="denial reason")
    with transaction.atomic():
        export_request.status = ExportStatusChoices.DENIED
        export_request.denied_by = actor
        export_request.denied_at = timezone.now()
        export_request.denial_reason = cleaned_reason
        export_request.save()

    record_export_audit(actor, export_request, "report_export_denied", "SUCCESS")
    return export_request


def _locked_export_request(export_id: str) -> ReportExportRequest:
    try:
        return (
            ReportExportRequest.objects.select_for_update(of=("self",))
            .select_related("report_definition", "requested_by", "protected_file", "report_run")
            .get(id=export_id)
        )
    except ReportExportRequest.DoesNotExist as exc:
        raise NotFoundError() from exc


def _validate_lifecycle_command(export_id: str, command: ReportExportLifecycleCommand) -> None:
    if str(command.export_id) != str(export_id):
        raise ValidationError("The lifecycle command target does not match the requested export.")


def _mark_generation_failed(actor, export_id: str, *, error_code: str = "EXPORT_GENERATION_FAILED"):
    with transaction.atomic():
        failed_request = _locked_export_request(export_id)
        failed_request.status = ExportStatusChoices.GENERATION_FAILED
        failed_request.generation_metadata_json = {
            "status": "generation_failed",
            "error_code": error_code,
            "error_category": "generation",
        }
        failed_request.save(update_fields=["status", "generation_metadata_json", "updated_at"])
    record_export_audit(
        actor,
        failed_request,
        "report_export_generation_failed",
        "FAILED",
        {"error_code": error_code, "error_category": "generation"},
    )
    return failed_request


def generate_report_export(
    actor,
    export_id: str,
    command: ReportExportLifecycleCommand,
    *,
    context: AuthorityContext | None = None,
) -> ReportExportRequest:
    """Generate a policy-checked aggregate export through protected storage."""
    from apps.access_control.policies import DestinationKey, can_access_destination

    _validate_lifecycle_command(export_id, command)
    if not can_access_destination(actor, DestinationKey.REPORTS):
        raise PermissionDenied("You are not authorized to generate this export.")
    denied_event = None
    with transaction.atomic():
        locked_request = _locked_export_request(export_id)
        if command.expected_status and locked_request.status != command.expected_status:
            raise StaleStateError()
        if locked_request.status in (ExportStatusChoices.GENERATED, ExportStatusChoices.DOWNLOADED) and locked_request.protected_file:
            return locked_request

        if locked_request.status in (
            ExportStatusChoices.DENIED,
            ExportStatusChoices.CANCELLED,
            ExportStatusChoices.EXPIRED,
            ExportStatusChoices.ARCHIVED,
        ):
            denied_event = (
                "report_export_generation_denied",
                {"denial_code": "TERMINAL_STATUS"},
            )
        elif locked_request.includes_identifiable_data:
            locked_request.status = ExportStatusChoices.DENIED
            locked_request.denied_by = actor
            locked_request.denied_at = timezone.now()
            locked_request.denial_reason = "Identifiable raw-row export is deferred."
            locked_request.save(
                update_fields=[
                    "status",
                    "denied_by",
                    "denied_at",
                    "denial_reason",
                    "updated_at",
                ]
            )
            denied_event = (
                "identifiable_export_deferred",
                {"error_code": "IDENTIFIABLE_EXPORT_DEFERRED"},
            )
        elif locked_request.export_format not in (ExportFormatChoices.CSV, ExportFormatChoices.PDF):
            denied_event = ("unsupported_format_attempted", {"error_code": "UNSUPPORTED_EXPORT_FORMAT"})
        elif (
            locked_request.export_format == ExportFormatChoices.PDF
            and locked_request.report_definition.key != "students_profile"
        ):
            denied_event = ("unsupported_format_attempted", {"error_code": "UNSUPPORTED_EXPORT_FORMAT"})

        elif not can_generate_report_export(actor, locked_request, context=context):
            denied_event = ("report_export_generation_denied", {"denial_code": "POLICY_DENIED"})

        else:
            locked_request.status = ExportStatusChoices.GENERATING
            locked_request.generation_started_at = timezone.now()
            locked_request.generated_by = actor
            locked_request.generation_metadata_json = {
                "status": "generation_started",
                "error_code": "",
                "error_category": "",
            }
            locked_request.save()

    if denied_event:
        action_type, metadata = denied_event
        record_export_audit(actor, locked_request, action_type, "DENIED", metadata)
        if action_type == "unsupported_format_attempted":
            raise PermissionDenied("Unsupported export format.")
        raise PermissionDenied("You are not authorized to generate this export.")

    record_export_audit(actor, locked_request, "report_export_generation_started", "SUCCESS")

    try:
        report_run, suppressed_dataset = run_report(
            locked_request.requested_by,
            locked_request.report_definition.key,
            locked_request.filter_summary_json,
        )
        generated_scope_summary = get_current_report_export_scope(
            locked_request.requested_by,
            locked_request.report_definition,
        )

        generation_metadata = {
            "status": "generated",
            "error_code": "",
            "error_category": "",
            "safe_context": {
                "source_context": "Internal approved aggregate report",
                "reporting_context": "Configured report metadata unavailable",
            },
        }
        if isinstance(report_run.metadata_json, dict):
            generation_metadata.update({
                key: report_run.metadata_json.get(key)
                for key in (
                    "suppression_policy_id",
                    "suppression_policy_effective_from",
                    "suppression_policy_effective_until",
                    "suppression_policy_source_reference",
                )
                if report_run.metadata_json.get(key) is not None
            })
        if (locked_request.report_definition.metadata_json or {}).get("structural_reference"):
            generation_metadata["safe_context"]["source_context"] = (
                "Institutional multi-college student profiling structural reference"
            )
            record_export_audit(
                actor,
                locked_request,
                "official_template_source_used",
                "SUCCESS",
                {"event_code": "OFFICIAL_TEMPLATE_STRUCTURAL_REFERENCE"},
            )

        locked_request.generation_metadata_json = generation_metadata
        if locked_request.export_format == ExportFormatChoices.PDF:
            generated_document = render_students_profile_export(
                actor=actor,
                export_request=locked_request,
                dataset=suppressed_dataset,
            )
            protected_file = generated_document.protected_file
            if not protected_file:
                raise ValidationError("Generated Students' Profile PDF is unavailable.")
            if (protected_file.file_size_bytes or 0) > report_execution_controls()["export_max_output_bytes"]:
                raise PayloadTooLargeError()
            generation_metadata["document_template"] = {
                "stable_key": generated_document.template_version.template.stable_key,
                "version_label": generated_document.template_version.version_label,
                "form_code": generated_document.form_revision.official_form_code if generated_document.form_revision else "",
                "form_revision": generated_document.form_revision.official_revision if generated_document.form_revision else "",
            }
            document_control = (generated_document.generation_context_snapshot_json or {}).get("document_control", {})
            generation_metadata["document_readiness"] = {
                "intent": document_control.get("intent", "PREVIEW"),
                "readiness": document_control.get("readiness", "PENDING_APPROVAL"),
                "label": document_control.get("label", "PREVIEW — PENDING APPROVAL"),
                "reasons": document_control.get("reasons", []),
            }
        else:
            generated_document = None
            generation_metadata["output_classification"] = "COMPASS_NATIVE_MACHINE_EXPORT"
            generation_metadata["official_printable"] = False
            csv_bytes = (
                export_students_profile_to_csv(locked_request, suppressed_dataset, actor)
                if locked_request.report_definition.key == "students_profile"
                else export_dataset_to_csv(locked_request, suppressed_dataset, actor)
            )
            if len(csv_bytes) > report_execution_controls()["export_max_output_bytes"]:
                raise PayloadTooLargeError()
            protected_file = store_protected_file(
                user=actor,
                content=csv_bytes,
                original_filename=f"report_export_{locked_request.id}.csv",
                content_type="text/csv",
                purpose="GENERATED_DOCUMENT",
                classification="PROTECTED",
                app_label="reports",
                model_name="ReportExportRequest",
                object_id=str(locked_request.id),
                access_policy_key="REPORT_EXPORT",
            )

        with transaction.atomic():
            locked_request = ReportExportRequest.objects.select_for_update().get(id=locked_request.id)
            if locked_request.status in (ExportStatusChoices.GENERATED, ExportStatusChoices.DOWNLOADED) and locked_request.protected_file:
                return locked_request
            locked_request.status = ExportStatusChoices.GENERATED
            locked_request.generated_at = timezone.now()
            locked_request.protected_file = protected_file
            locked_request.generated_document = generated_document
            locked_request.document_template_version = (
                generated_document.template_version if generated_document else None
            )
            locked_request.report_run = report_run
            locked_request.scope_summary_json = generated_scope_summary
            locked_request.suppression_applied = report_run.suppression_applied
            locked_request.suppressed_cell_count = report_run.suppressed_cell_count
            locked_request.expires_at = timezone.now() + timezone.timedelta(
                days=report_execution_controls()["export_expiry_days"]
            )
            locked_request.generation_metadata_json = generation_metadata
            locked_request.save()

        record_export_audit(actor, locked_request, "report_export_generation_completed", "SUCCESS")
        return locked_request

    except CompassError as exc:
        _mark_generation_failed(actor, export_id, error_code=getattr(getattr(exc, "code", None), "value", None) or "EXPORT_GENERATION_FAILED")
        raise
    except SecurityError as exc:
        _mark_generation_failed(actor, export_id, error_code="DEPENDENCY_FAILURE")
        raise DependencyFailureError() from exc
    except Exception:
        _mark_generation_failed(actor, export_id)
        raise


def download_report_export(
    actor,
    export_id: str,
    *,
    context: AuthorityContext | None = None,
) -> ReportDownloadResult:
    """Verifies access policies, reads protected content, and marks status as downloaded."""
    with transaction.atomic():
        export_request = _locked_export_request(export_id)
        if not can_download_report_export(actor, export_request, context=context):
            record_export_audit(
                actor,
                export_request,
                "report_export_download_denied",
                "DENIED",
                {"denial_code": "POLICY_DENIED"},
            )
            raise PermissionDenied("You are not authorized to download this file.")
        if not export_request.protected_file:
            record_export_audit(
                actor,
                export_request,
                "report_export_download_denied",
                "DENIED",
                {"error_code": "MISSING_PROTECTED_FILE"},
            )
            raise ValidationError("Export file is unavailable.")
        protected_file_id = export_request.protected_file.id
        export_format = export_request.export_format
    try:
        content, _ = open_protected_file(actor, protected_file_id)
    except SecurityError as exc:
        record_export_audit(
            actor,
            export_request,
            "report_export_download_denied",
            "DENIED",
            {"error_code": "PROTECTED_FILE_UNAVAILABLE"},
        )
        raise DependencyFailureError() from exc
    except Exception:
        record_export_audit(
            actor,
            export_request,
            "report_export_download_denied",
            "DENIED",
            {"error_code": "PROTECTED_FILE_UNAVAILABLE"},
        )
        raise

    with transaction.atomic():
        updated_request = _locked_export_request(export_id)
        if not can_download_report_export(actor, updated_request, context=context):
            raise PermissionDenied("You are not authorized to download this file.")
        updated_request.status = ExportStatusChoices.DOWNLOADED
        updated_request.downloaded_at = timezone.now()
        updated_request.save(update_fields=["status", "downloaded_at", "updated_at"])

    record_export_audit(actor, updated_request, "report_export_downloaded", "SUCCESS")
    return ReportDownloadResult(content=content, export_format=export_format)


def expire_report_export(
    actor,
    export_id: str,
    command: ReportExportLifecycleCommand,
    *,
    context: AuthorityContext | None = None,
) -> ReportExportRequest:
    """Expire a generated export and revoke its download without physical deletion."""
    _validate_lifecycle_command(export_id, command)
    with transaction.atomic():
        export_request = _locked_export_request(export_id)
        if not can_expire_report_export(actor, export_request, context=context):
            record_export_audit(
                actor,
                export_request,
                "report_export_expire_denied",
                "DENIED",
                {"denial_code": "POLICY_DENIED"},
            )
            raise PermissionDenied("You are not authorized to expire this export.")
        if command.expected_status and export_request.status != command.expected_status:
            raise StaleStateError()
        if export_request.status == ExportStatusChoices.EXPIRED:
            return export_request
        if export_request.status not in (ExportStatusChoices.GENERATED, ExportStatusChoices.DOWNLOADED):
            raise ValidationError("Only generated or downloaded exports can expire.")
        export_request.status = ExportStatusChoices.EXPIRED
        export_request.expired_at = timezone.now()
        export_request.save(update_fields=["status", "expired_at", "updated_at"])
        if export_request.protected_file:
            try:
                delete_marker_protected_file(actor, export_request.protected_file.id)
            except SecurityError:
                # A legal hold preserves the artifact but never preserves download access.
                pass

    record_export_audit(actor, export_request, "report_export_expired", "SUCCESS")
    return export_request


def expire_due_report_exports(actor, *, now=None, limit=None, context: AuthorityContext | None = None) -> int:
    """Expire every due generated export exactly once."""
    if not is_active_nonlegacy_actor(actor) or not can_expire_report_export(actor, None, context=context):
        raise PermissionDenied("You are not authorized to expire report exports.")

    now = now or timezone.now()
    candidates = ReportExportRequest.objects.filter(
        status__in=(ExportStatusChoices.GENERATED, ExportStatusChoices.DOWNLOADED),
        expires_at__isnull=False,
        expires_at__lte=now,
    ).order_by("expires_at")
    if limit:
        candidates = candidates[:limit]

    expired = 0
    for export_request in candidates:
        expire_report_export(
            actor,
            str(export_request.id),
            ReportExportLifecycleCommand(export_id=str(export_request.id), expected_status=export_request.status),
            context=context,
        )
        expired += 1
    return expired


def archive_report_export(
    actor,
    export_id: str,
    command: ReportExportLifecycleCommand,
    *,
    context: AuthorityContext | None = None,
) -> ReportExportRequest:
    """Archive a generated/downloaded export and revoke further download."""
    _validate_lifecycle_command(export_id, command)
    with transaction.atomic():
        locked_request = _locked_export_request(export_id)
        if not can_archive_report_export(actor, locked_request, context=context):
            record_export_audit(
                actor,
                locked_request,
                "report_export_archive_denied",
                "DENIED",
                {"denial_code": "POLICY_DENIED"},
            )
            raise PermissionDenied("You are not authorized to archive this export.")
        if command.expected_status and locked_request.status != command.expected_status:
            raise StaleStateError()
        if locked_request.protected_file:
            try:
                delete_marker_protected_file(actor, locked_request.protected_file.id)
            except SecurityError:
                pass
        locked_request.status = ExportStatusChoices.ARCHIVED
        locked_request.archived_at = timezone.now()
        locked_request.save(update_fields=["status", "archived_at", "updated_at"])

    record_export_audit(actor, locked_request, "report_export_archived", "SUCCESS")
    return locked_request


def revoke_csm_export_download_for_retention_hold(
    actor,
    export_request: ReportExportRequest,
    *,
    context: AuthorityContext | None = None,
) -> ReportExportRequest:
    """Deny download when a CSM file cannot be delete-marked under retention hold."""
    if (
        export_request.report_definition.family != ReportFamilyChoices.FEEDBACK_CSM
        or not can_expire_report_export(actor, export_request, context=context)
        or not export_request.protected_file
        or not export_request.protected_file.retention_hold
    ):
        raise PermissionDenied("CSM retention-hold revocation is not authorized.")

    with transaction.atomic():
        locked_request = ReportExportRequest.objects.select_for_update().get(id=export_request.id)
        locked_request.status = ExportStatusChoices.EXPIRED
        locked_request.expired_at = timezone.now()
        locked_request.save(update_fields=["status", "expired_at", "updated_at"])

    record_export_audit(
        actor,
        locked_request,
        "report_export_expired",
        "SUCCESS",
        {"event_code": "RETENTION_HOLD_DOWNLOAD_REVOKED"},
    )
    return locked_request


def cancel_report_export(
    actor,
    export_id: str,
    command: ReportExportLifecycleCommand,
    *,
    context: AuthorityContext | None = None,
) -> ReportExportRequest:
    """Cancels a requested or pending export."""
    _validate_lifecycle_command(export_id, command)
    with transaction.atomic():
        export_request = _locked_export_request(export_id)
        if command.expected_status and export_request.status != command.expected_status:
            raise StaleStateError()
        return _cancel_locked_export(actor, export_request, context=context)


def _cancel_locked_export(actor, export_request, *, context=None):
    if not is_active_nonlegacy_actor(actor):
        record_export_audit(
            actor,
            export_request,
            "report_export_cancel_denied",
            "DENIED",
            {"denial_code": "POLICY_DENIED"},
        )
        raise PermissionDenied("You are not authorized to cancel this export.")

    if not (actor == export_request.requested_by or can_expire_report_export(actor, export_request, context=context)):
        record_export_audit(
            actor,
            export_request,
            "report_export_cancel_denied",
            "DENIED",
            {"denial_code": "POLICY_DENIED"},
        )
        raise PermissionDenied("You are not authorized to cancel this export.")

    if export_request.status in (
        ExportStatusChoices.GENERATED,
        ExportStatusChoices.DOWNLOADED,
        ExportStatusChoices.EXPIRED,
        ExportStatusChoices.ARCHIVED,
    ):
        record_export_audit(
            actor,
            export_request,
            "report_export_cancel_denied",
            "DENIED",
            {"denial_code": "INVALID_STATUS"},
        )
        raise ValidationError("Cannot cancel a completed or expired export.")

    export_request.status = ExportStatusChoices.CANCELLED
    export_request.cancelled_at = timezone.now()
    export_request.save(update_fields=["status", "cancelled_at", "updated_at"])

    record_export_audit(actor, export_request, "report_export_cancelled", "SUCCESS")
    return export_request


def list_export_requests_for_actor(actor, *, context: AuthorityContext | None = None):
    """Lists export requests authorized for the given actor."""
    if not is_active_nonlegacy_actor(actor):
        return ReportExportRequest.objects.none()

    authority = context if context is not None else actor
    if resolve_capability(authority, Capability.REPORTS_EXPORT_OPERATE) or resolve_capability(
        authority, Capability.REPORTS_EXPORT_MAINTAIN
    ):
        return ReportExportRequest.objects.all().order_by("-requested_at")
    return ReportExportRequest.objects.filter(requested_by=actor).order_by("-requested_at")


def get_export_request_for_actor(actor, export_request_id: str, *, context: AuthorityContext | None = None) -> ReportExportRequest:
    """Retrieves a specific export request, ensuring visibility policy validation."""
    try:
        req = ReportExportRequest.objects.select_related("report_definition", "requested_by").get(id=export_request_id)
    except ReportExportRequest.DoesNotExist:
        raise NotFoundError()

    if not can_view_export_request(actor, req, context=context):
        raise PermissionDenied("Export request not found or access denied.")

    return req
