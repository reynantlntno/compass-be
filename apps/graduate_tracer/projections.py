"""Explicit JSON-safe Graduate Tracer projections."""

from apps.common.contracts import to_json_value


def response_metadata(value):
    return {
        "id": str(value.pk),
        "reference_code": value.reference_code,
        "student_id": str(value.student_id) if value.student_id else None,
        "lifecycle_snapshot": value.lifecycle_snapshot,
        "graduation_year": value.graduation_year,
        "program_snapshot": value.program_snapshot,
        "college_snapshot": value.college_snapshot,
        "status": value.status,
        "form_revision_id": str(value.form_revision_id),
        "form_collection_id": str(value.form_collection_id) if value.form_collection_id else None,
        "employment_status": value.employment_status,
        "submitted_at": to_json_value(value.submitted_at),
        "created_at": to_json_value(value.created_at),
    }


def response_sensitive(value):
    result = response_metadata(value)
    result["answers"] = to_json_value(value.response_json or {})
    return result


def status(value):
    return {
        "has_response": bool(value.get("has_response")),
        "status": value.get("status"),
        "reference_code": value.get("reference_code"),
        "submitted_at": to_json_value(value.get("submitted_at")),
    }
