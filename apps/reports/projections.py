"""Fixed JSON projection boundary for the reports domain.

Only named projection functions with explicit allowlists may be added here.
Raw model instances, QuerySets, encrypted fields, secrets, and arbitrary
metadata must not be returned to a client.
"""

import re

from apps.common.contracts import to_json_object
from apps.common.exceptions import ValidationError
from apps.reports.sensitivity import FieldSensitivity, classify_field_sensitivity


_SAFE_FILTER_KEYS = frozenset({
    "campus", "college", "department", "program", "year_level", "academic_year",
    "service_category", "client_type", "form_collection", "form_revision",
    "employment_status", "graduation_year", "assigned_counselor", "status",
})
_SAFE_CATEGORY_KEY = re.compile(r"^[a-z][a-z0-9_]{0,79}$")
_FORBIDDEN_FIELDS = frozenset({
    "student_number", "control_number", "first_name", "last_name", "middle_name",
    "email", "phone", "contact_number", "counseling_notes", "referral_reason",
    "case_details", "narrative", "free_text", "response_json", "password", "token",
    "hash", "salt", "ip_address", "user_agent", "id", "primary_key", "feedback_id",
    "reference_code", "respondent", "respondent_user", "submitted_at", "exact_timestamp",
    "related_reference_code", "workflow_reference", "form_invitation", "form_collection",
    "comment_text", "experience_feedback", "visit_detail", "raw_rating", "rating_response",
})

_SAFE_PROFILE_KEY = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,79}$")
_SAFE_PROFILE_TEXT_MAX = 160
_SAFE_PROFILE_LIST_MAX = 500


def _forbidden_field(value) -> bool:
    key = str(value).lower()
    return (
        key in _FORBIDDEN_FIELDS
        or key.startswith("sqd")
        or key.startswith("sq_personnel_")
        or key.startswith("op_")
        or classify_field_sensitivity(key) == FieldSensitivity.FORBIDDEN
    )


def _safe_profile_text(value, *, label: str) -> None:
    if not isinstance(value, str) or not value or len(value) > _SAFE_PROFILE_TEXT_MAX:
        raise ValidationError(f"Report preview contains an invalid {label}.")
    if any(ord(char) < 32 and char not in "\t\n\r" for char in value):
        raise ValidationError(f"Report preview contains an invalid {label}.")


def _safe_profile_key(value, *, label: str) -> None:
    _safe_profile_text(value, label=label)
    if not _SAFE_PROFILE_KEY.fullmatch(value) or _forbidden_field(value.lower()):
        raise ValidationError(f"Report preview contains an invalid {label}.")


def _safe_profile_scalar(value, *, label: str) -> None:
    if isinstance(value, (dict, list, tuple, set, frozenset)):
        raise ValidationError(f"Report preview contains an invalid {label}.")
    if isinstance(value, str):
        if len(value) > _SAFE_PROFILE_TEXT_MAX:
            raise ValidationError(f"Report preview contains an invalid {label}.")
        if any(ord(char) < 32 and char not in "\t\n\r" for char in value):
            raise ValidationError(f"Report preview contains an invalid {label}.")
        return
    if value is not None and not isinstance(value, (int, float, bool)):
        raise ValidationError(f"Report preview contains an invalid {label}.")


def _safe_filter_summary(value) -> dict:
    if not isinstance(value, dict):
        return {}
    result = {}
    for key, item in value.items():
        if key not in _SAFE_FILTER_KEYS or isinstance(item, (dict, list, tuple, set)):
            continue
        if isinstance(item, (str, int, float, bool)) and not isinstance(item, str) or item is None:
            result[key] = item
        elif isinstance(item, str):
            result[key] = item[:120]
    return result


def _validate_profile_payload(payload: dict) -> None:
    allowed_root = {"report_context", "sections", "privacy_controls_enforced"}
    if set(payload) - allowed_root or not isinstance(payload.get("report_context"), dict):
        raise ValidationError("Report preview contains an invalid Students' Profile projection.")
    context = payload["report_context"]
    allowed_context = {
        "academic_year", "campus", "college", "year_level", "department", "program",
        "mapping_version", "program_labels", "cohort_total",
    }
    if set(context) - allowed_context:
        raise ValidationError("Report preview contains an unsafe profiling context.")
    for key, value in context.items():
        if key == "program_labels":
            if not isinstance(value, list) or len(value) > _SAFE_PROFILE_LIST_MAX:
                raise ValidationError("Report preview contains invalid profiling labels.")
            for item in value:
                if not isinstance(item, dict) or set(item) - {"key", "label"}:
                    raise ValidationError("Report preview contains invalid profiling labels.")
                _safe_profile_key(item.get("key"), label="profiling label key")
                _safe_profile_text(item.get("label"), label="profiling label")
        elif not isinstance(value, (str, int, float, bool)) and value is not None:
            raise ValidationError("Report preview contains an unsafe profiling value.")
    sections = payload.get("sections")
    if not isinstance(sections, list) or len(sections) > _SAFE_PROFILE_LIST_MAX:
        raise ValidationError("Report preview requires profiling sections.")
    if not isinstance(payload.get("privacy_controls_enforced"), bool):
        raise ValidationError("Report preview contains invalid privacy-control metadata.")
    section_keys = {
        "metric_key", "title", "row_heading", "columns", "program_columns", "rows",
        "cohort_total", "suppression_notice",
    }
    for section in sections:
        if not isinstance(section, dict) or set(section) - section_keys:
            raise ValidationError("Report preview contains an invalid profiling section.")
        _safe_profile_key(section.get("metric_key"), label="profiling metric key")
        _safe_profile_text(section.get("title"), label="profiling section title")
        if "row_heading" in section:
            _safe_profile_text(section.get("row_heading"), label="profiling row heading")
        if "suppression_notice" in section:
            _safe_profile_text(section.get("suppression_notice"), label="suppression notice")
        if not isinstance(section.get("cohort_total"), int) or section.get("cohort_total") < 0:
            raise ValidationError("Report preview contains an invalid profiling cohort total.")
        if not isinstance(section.get("columns"), list) or not isinstance(section.get("rows"), list):
            raise ValidationError("Report preview contains an invalid profiling matrix.")
        if not isinstance(section.get("program_columns"), list):
            raise ValidationError("Report preview contains an invalid profiling program columns list.")
        if len(section["columns"]) > _SAFE_PROFILE_LIST_MAX or len(section["program_columns"]) > _SAFE_PROFILE_LIST_MAX:
            raise ValidationError("Report preview contains too many profiling columns.")
        for column in section["columns"]:
            if not isinstance(column, dict) or set(column) - {"key", "label"}:
                raise ValidationError("Report preview contains an invalid profiling column.")
            _safe_profile_key(column.get("key"), label="profiling column key")
            _safe_profile_text(column.get("label"), label="profiling column label")
        for column in section["program_columns"]:
            if not isinstance(column, dict) or set(column) - {"key", "label"}:
                raise ValidationError("Report preview contains an invalid profiling program column.")
            _safe_profile_key(column.get("key"), label="profiling program column key")
            _safe_profile_text(column.get("label"), label="profiling program column label")
        if len(section["rows"]) > _SAFE_PROFILE_LIST_MAX:
            raise ValidationError("Report preview contains too many profiling rows.")
        for row in section["rows"]:
            if not isinstance(row, dict):
                raise ValidationError("Report preview contains an invalid profiling row.")
            row_keys = {"code", "label", "program_counts", "total", "percentage", "is_total", "values"}
            if set(row) - row_keys or not isinstance(row.get("program_counts"), dict) or not isinstance(row.get("values"), dict):
                raise ValidationError("Report preview contains an unsafe profiling row.")
            _safe_profile_key(row.get("code"), label="profiling row code")
            _safe_profile_text(row.get("label"), label="profiling row label")
            if not isinstance(row.get("is_total"), bool):
                raise ValidationError("Report preview contains an invalid profiling row flag.")
            for mapping in (row["program_counts"], row["values"]):
                if len(mapping) > _SAFE_PROFILE_LIST_MAX:
                    raise ValidationError("Report preview contains too many profiling values.")
                for key, value in mapping.items():
                    _safe_profile_key(key, label="profiling value key")
                    _safe_profile_scalar(value, label="profiling value")
            _safe_profile_scalar(row.get("total"), label="profiling row total")
            _safe_profile_scalar(row.get("percentage"), label="profiling row percentage")


def validate_aggregate_dataset(dataset) -> dict:
    """Validate the exact aggregate shapes before any preview or export output."""
    if not isinstance(dataset, dict):
        raise ValidationError("Report output must be a bounded aggregate object.")
    if "profiling_report" in dataset or {"report_context", "sections"}.issubset(dataset):
        if "profiling_report" in dataset and set(dataset) != {"profiling_report"}:
            raise ValidationError("Report preview contains unexpected profiling data.")
        payload = dataset.get("profiling_report", dataset)
        if not isinstance(payload, dict):
            raise ValidationError("Report preview contains an invalid profiling payload.")
        _validate_profile_payload(payload)
        return to_json_object(dataset)
    if len(dataset) > 100:
        raise ValidationError("Report output contains too many aggregate categories.")
    for category, rows in dataset.items():
        if not isinstance(category, str) or not _SAFE_CATEGORY_KEY.fullmatch(category):
            raise ValidationError("Report output contains an invalid category.")
        if isinstance(rows, dict):
            rows_to_validate = [rows]
        elif isinstance(rows, list):
            rows_to_validate = rows
        else:
            raise ValidationError("Report output contains an invalid category.")
        if len(rows_to_validate) > _SAFE_PROFILE_LIST_MAX:
            raise ValidationError("Report output contains too many aggregate rows.")
        for row in rows_to_validate:
            if not isinstance(row, dict):
                raise ValidationError("Report output contains an invalid aggregate row.")
            if len(row) > 100:
                raise ValidationError("Report output contains too many aggregate fields.")
            for key, value in row.items():
                if not isinstance(key, str) or not _SAFE_CATEGORY_KEY.fullmatch(key) or _forbidden_field(key):
                    raise ValidationError("Report output contains a forbidden field.")
                _safe_profile_scalar(value, label="aggregate value")
    return to_json_object(dataset)


def _iso(value):
    return value.isoformat() if value is not None else None


def report_definition_projection(definition) -> dict:
    return {
        "id": str(definition.id),
        "key": definition.key,
        "title": definition.title,
        "description": definition.description,
        "family": definition.family,
        "sensitivity_level": definition.sensitivity_level,
        "is_active": bool(definition.is_active),
        "activated_at": _iso(definition.activated_at),
        "updated_at": _iso(definition.updated_at),
    }


def report_run_projection(run) -> dict:
    metadata = run.metadata_json or {}
    return {
        "id": str(run.id),
        "report_key": run.report_definition.key,
        "status": run.status,
        "filter_hash": run.filter_hash,
        "filter_summary": _safe_filter_summary(run.filter_summary_json),
        "aggregate_count": run.aggregate_count,
        "cell_count": run.cell_count,
        "suppression_applied": bool(run.suppression_applied),
        "suppressed_cell_count": run.suppressed_cell_count,
        "started_at": _iso(run.started_at),
        "completed_at": _iso(run.completed_at),
        "failed_at": _iso(run.failed_at),
        "expires_at": _iso(run.expires_at),
        "execution_mode": metadata.get("execution_mode", "SYNC") if isinstance(metadata, dict) else "SYNC",
        "estimated_work_units": metadata.get("estimated_work_units") if isinstance(metadata, dict) else None,
        "actual_work_units": metadata.get("actual_work_units") if isinstance(metadata, dict) else None,
        "error_code": metadata.get("error_code") if isinstance(metadata, dict) else None,
        "suppression_policy_id": metadata.get("suppression_policy_id") if isinstance(metadata, dict) else None,
    }


def report_export_projection(export_request) -> dict:
    metadata = export_request.generation_metadata_json or {}
    return {
        "id": str(export_request.id),
        "report_key": export_request.report_definition.key,
        "status": export_request.status,
        "export_type": export_request.export_type,
        "export_format": export_request.export_format,
        "filter_hash": export_request.filter_hash,
        "filter_summary": _safe_filter_summary(export_request.filter_summary_json),
        "includes_sensitive_data": bool(export_request.includes_sensitive_data),
        "includes_identifiable_data": False,
        "suppression_applied": bool(export_request.suppression_applied),
        "suppressed_cell_count": export_request.suppressed_cell_count,
        "suppression_policy_id": metadata.get("suppression_policy_id") if isinstance(metadata, dict) else None,
        "suppression_policy_effective_from": metadata.get("suppression_policy_effective_from") if isinstance(metadata, dict) else None,
        "suppression_policy_effective_until": metadata.get("suppression_policy_effective_until") if isinstance(metadata, dict) else None,
        "requested_at": _iso(export_request.requested_at),
        "generated_at": _iso(export_request.generated_at),
        "expires_at": _iso(export_request.expires_at),
        "download_available": bool(export_request.protected_file_id),
        "generation_state": metadata.get("status") if isinstance(metadata, dict) else None,
        "output_classification": metadata.get("output_classification") if isinstance(metadata, dict) else None,
    }


def report_export_technical_projection(export_request) -> dict:
    """Return only lifecycle/technical metadata for IT maintenance access."""
    metadata = export_request.generation_metadata_json or {}
    return {
        "id": str(export_request.id),
        "status": export_request.status,
        "export_format": export_request.export_format,
        "export_type": export_request.export_type,
        "requested_at": _iso(export_request.requested_at),
        "generated_at": _iso(export_request.generated_at),
        "expires_at": _iso(export_request.expires_at),
        "generation_state": metadata.get("status") if isinstance(metadata, dict) else None,
        "output_classification": metadata.get("output_classification") if isinstance(metadata, dict) else None,
        "protected_file_available": bool(export_request.protected_file_id),
    }


def aggregate_result_projection(dataset) -> dict:
    """Return only JSON-safe aggregate output from an approved report run."""
    return validate_aggregate_dataset(dataset)
