# Project: COMPASS
# File: apps/reports/export_adapters.py
# Module: apps.reports
# Purpose: CSV adapter for aggregate report exports using standard-library csv

import csv
import io
from typing import Dict, Any
from apps.common.exceptions import ValidationError
from apps.audit.services import audit_log
from apps.reports.choices import ExportFormatChoices, SuppressionMode
from apps.reports.suppression import (
    SUPPRESSION_LABEL,
    DERIVED_METRIC_KEYS,
    DEFAULT_COUNT_KEYS,
    resolve_report_suppression_policy,
    suppression_policy_audit_metadata,
)
from apps.reports.projections import validate_aggregate_dataset


FORBIDDEN_FIELDS = {
    "student_number", "control_number", "first_name", "last_name", "middle_name",
    "email", "phone", "contact_number", "counseling_notes",
    "referral_reason", "case_details", "narrative", "free_text", "response_json",
    "password", "token", "hash", "salt", "ip_address", "user_agent", "counseling_notes_text",
    "id", "primary_key", "feedback_id", "reference_code", "respondent", "respondent_user",
    "submitted_at", "exact_timestamp", "related_reference_code", "workflow_reference",
    "form_invitation", "form_collection", "comment_text", "experience_feedback", "visit_detail",
    "raw_rating", "rating_response",
}

def _is_forbidden_export_field(field_name: object) -> bool:
    """Classify a canonical lower-cased export field name without reading its value."""
    normalized = str(field_name).lower()
    return (
        normalized in FORBIDDEN_FIELDS
        or normalized.startswith("sqd")
        or normalized.startswith("sq_personnel_")
        or normalized.startswith("op_")
    )


def _audit_adapter_rejection(export_request, actor, action_type: str, error_code: str) -> None:
    try:
        policy_metadata = suppression_policy_audit_metadata(
            resolve_report_suppression_policy(export_request.report_definition)
        )
    except Exception:
        policy_metadata = {}
    audit_log(
        action_type=action_type,
        event_category="DATA_ACCESS",
        target_model="reports.ReportExportRequest",
        target_object_id=str(export_request.id),
        actor_user=actor,
        metadata={
            "export_request_id": str(export_request.id),
            "report_key": export_request.report_definition.key,
            "export_format": export_request.export_format,
            "export_type": export_request.export_type,
            "error_code": error_code,
            **policy_metadata,
        },
    )


def validate_export_row(
    row: Dict[str, Any],
    *,
    threshold: int,
    count_keys=None,
    apply_derived_suppression: bool = True,
) -> None:
    """Ensures row is flat, contains no forbidden fields, and suppresses derived metrics if count is suppressed."""
    for key, value in row.items():
        if _is_forbidden_export_field(key):
            raise ValidationError("Export dataset contains a forbidden field.")

        # Raw/nested lists or dicts are not allowed in output rows
        if isinstance(value, (dict, list, set, tuple)):
            raise ValidationError("Raw rows or nested unsafe dictionaries are not allowed in export output.")

    if not apply_derived_suppression:
        return

    count_keys = count_keys or DEFAULT_COUNT_KEYS
    # Redundant safety check: suppress derived metrics if supporting counts are suppressed or below threshold.
    supporting_count = None
    for count_key in count_keys:
        if count_key in row:
            supporting_count = row[count_key]
            break

    should_suppress = supporting_count == SUPPRESSION_LABEL or (
        isinstance(supporting_count, (int, float)) and 0 < supporting_count < threshold
    )

    if should_suppress:
        for key in list(row.keys()):
            key_lower = str(key).lower()
            if (
                key_lower in DERIVED_METRIC_KEYS
                or key_lower.startswith("avg_")
                or key_lower.endswith("_avg")
                or key_lower.endswith("_average")
                or key_lower.endswith("_percentage")
                or key_lower.endswith("_rate")
                or key_lower.endswith("_ratio")
            ):
                row[key] = SUPPRESSION_LABEL


def _export_category_rows(value):
    """Normalize one approved aggregate category to flat CSV rows."""
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return value
    raise ValidationError("Export dataset contains an invalid category.")


def export_dataset_to_csv(export_request, dataset: Dict[str, Any], actor) -> bytes:
    """Converts a suppressed aggregate dataset dictionary to policy-compliant CSV bytes.

    Appends metadata headers at the top of the CSV file.
    """
    try:
        dataset = validate_aggregate_dataset(dataset)
    except ValidationError:
        _audit_adapter_rejection(export_request, actor, "export_scope_rejected", "INVALID_EXPORT_DATASET")
        raise

    if export_request.export_format != ExportFormatChoices.CSV:
        _audit_adapter_rejection(export_request, actor, "unsupported_format_attempted", "UNSUPPORTED_EXPORT_FORMAT")
        raise ValidationError("Unsupported export format.")

    policy = resolve_report_suppression_policy(export_request.report_definition)
    use_derived_suppression = policy.mode != SuppressionMode.NONE

    # 1. Pre-validation of all rows in all categories
    normalized_categories = {}
    for category_name, value in dataset.items():
        try:
            rows = _export_category_rows(value)
        except ValidationError:
            _audit_adapter_rejection(export_request, actor, "export_scope_rejected", "INVALID_EXPORT_CATEGORY")
            raise
        normalized_categories[category_name] = rows
        for row in rows:
            if not isinstance(row, dict):
                _audit_adapter_rejection(export_request, actor, "export_scope_rejected", "INVALID_EXPORT_ROW")
                raise ValidationError("Export dataset contains an invalid row.")
            try:
                validate_export_row(
                    row,
                    threshold=policy.threshold,
                    count_keys=policy.count_keys,
                    apply_derived_suppression=use_derived_suppression,
                )
            except ValidationError as exc:
                _audit_adapter_rejection(
                    export_request,
                    actor,
                    "forbidden_field_export_attempted",
                    "FORBIDDEN_OR_RAW_EXPORT_FIELD",
                )
                raise exc

    # 2. Build CSV using io.StringIO and standard csv writer
    output = io.StringIO()
    writer = csv.writer(output)

    # Write metadata block at the top
    writer.writerow(["# COMPASS OFFICIAL REPORT EXPORT"])
    writer.writerow(["Report Title", export_request.report_definition.title])
    writer.writerow(["Report Key", export_request.report_definition.key])
    writer.writerow(["Export Request ID", str(export_request.id)])
    writer.writerow(["Generated By", getattr(actor, "role", "system") if actor else "system"])

    gen_time = export_request.generated_at or export_request.created_at
    writer.writerow(["Generated At", gen_time.isoformat() if gen_time else ""])

    expires = export_request.expires_at
    writer.writerow(["Expires At", expires.isoformat() if expires else ""])

    filter_keys = sorted((export_request.filter_summary_json or {}).keys())
    filter_summary = f"{len(filter_keys)} approved filter(s) applied" if filter_keys else "No filters"
    writer.writerow(["Filter Summary", filter_summary])

    if policy.mode == SuppressionMode.NONE:
        suppression_note = "No small-count suppression applies to this bounded operational report."
    else:
        suppression_note = (
            f"Minimum displayed cohort threshold: {policy.threshold}. Protected cells are suppressed."
        )
    writer.writerow(["Suppression Note", suppression_note])
    writer.writerow(["Confidentiality Notice", "CONFIDENTIAL - For authorized internal use only."])

    safe_context = (export_request.generation_metadata_json or {}).get("safe_context") or {}
    writer.writerow(["Source Context", safe_context.get("source_context", "Internal approved aggregate report")])
    writer.writerow(["Reporting Context", safe_context.get("reporting_context", "Configured report metadata unavailable")])

    # Separation rows
    writer.writerow([])
    writer.writerow([])

    # 3. Write data sections
    for category_name, rows in normalized_categories.items():
        writer.writerow([f"=== Category: {category_name} ==="])
        if not rows:
            writer.writerow(["(No records matching filter criteria)"])
            writer.writerow([])
            continue

        # Extract headers from first row keys
        headers = list(rows[0].keys())
        writer.writerow(headers)

        for row in rows:
            writer.writerow([row.get(h) for h in headers])

        writer.writerow([])  # Blank row separating categories

    return output.getvalue().encode("utf-8")


def export_students_profile_to_csv(export_request, dataset: Dict[str, Any], actor) -> bytes:
    """Serialize only the finalized, suppressed students_profile_aggregate presentation model."""
    policy = resolve_report_suppression_policy(export_request.report_definition)
    if policy.mode != SuppressionMode.SECTION:
        raise ValidationError("Students' Profile export requires SECTION suppression mode.")
    payload = dataset.get("profiling_report", dataset) if isinstance(dataset, dict) else None
    if not isinstance(payload, dict):
        raise ValidationError("Students' Profile export data is unavailable.")
    context = payload.get("report_context")
    sections = payload.get("sections")
    if not isinstance(context, dict) or not isinstance(sections, list):
        raise ValidationError("Students' Profile export data is invalid.")

    allowed_context = ("academic_year", "campus", "college", "year_level", "mapping_version")
    if not context.get("academic_year") or not context.get("college") or not context.get("year_level"):
        raise ValidationError("Students' Profile export context is incomplete.")

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["# COMPASS STUDENTS' PROFILE REPORT"])
    writer.writerow(["Report Code", "COMPASS-RPT-STUDENTS-PROFILE"])
    writer.writerow(["Report Title", export_request.report_definition.title])
    for key in allowed_context:
        value = context.get(key)
        if value not in (None, ""):
            if isinstance(value, (dict, list, set, tuple)):
                raise ValidationError("Students' Profile export context is invalid.")
            writer.writerow([key.replace("_", " ").title(), value])
    writer.writerow([
        "Suppression Note",
        f"Protected cells, dependent totals, and percentages are suppressed at a minimum threshold of {policy.threshold}.",
    ])
    writer.writerow(["Confidentiality Notice", "CONFIDENTIAL - For authorized internal use only."])
    writer.writerow([])

    for section in sections:
        if not isinstance(section, dict) or not isinstance(section.get("rows"), list):
            raise ValidationError("Students' Profile export section is invalid.")
        title = section.get("title")
        if not isinstance(title, str):
            raise ValidationError("Students' Profile export section title is invalid.")
        raw_columns = section.get("columns")
        if not isinstance(raw_columns, list):
            raise ValidationError("Students' Profile export columns are invalid.")
        columns = []
        for column in raw_columns:
            if not isinstance(column, dict):
                raise ValidationError("Students' Profile export column is invalid.")
            key = column.get("key")
            label = column.get("label")
            if not isinstance(key, str) or not isinstance(label, str):
                raise ValidationError("Students' Profile export column is invalid.")
            columns.append((key, label))
        writer.writerow([f"=== {title} ==="])
        writer.writerow([section.get("row_heading") or "Category", *[label for _key, label in columns]])
        for row in section["rows"]:
            values = row.get("values") if isinstance(row, dict) else None
            if not isinstance(row, dict) or not isinstance(row.get("label"), str) or not isinstance(values, dict):
                raise ValidationError("Students' Profile export row is invalid.")
            rendered = []
            for key, _label in columns:
                value = values.get(key, "-")
                if isinstance(value, (dict, list, set, tuple)):
                    raise ValidationError("Students' Profile export row contains nested data.")
                rendered.append(value)
            writer.writerow([row["label"], *rendered])
        writer.writerow([])

    return output.getvalue().encode("utf-8")
