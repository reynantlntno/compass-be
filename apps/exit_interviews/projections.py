"""Explicit JSON-safe Exit Interview projections."""

from apps.common.contracts import to_json_value


def response_metadata(value):
    return {
        "id": str(value.pk),
        "reference_code": value.reference_code,
        "student_id": str(value.student_id),
        "lifecycle_snapshot": value.lifecycle_snapshot,
        "program_snapshot": value.program_snapshot,
        "college_snapshot": value.college_snapshot,
        "academic_year": value.academic_year,
        "graduation_year_snapshot": value.graduation_year_snapshot,
        "eligibility_source": value.eligibility_source,
        "status": value.status,
        "form_revision_id": str(value.form_revision_id),
        "form_collection_id": str(value.form_collection_id) if value.form_collection_id else None,
        "submitted_at": to_json_value(value.submitted_at),
        "counselor_acknowledged_at": to_json_value(value.counselor_acknowledged_at),
        "created_at": to_json_value(value.created_at),
    }


def response_sensitive(value):
    result = response_metadata(value)
    result["answers"] = to_json_value(value.response_json or {})
    result["counselor_acknowledged_by"] = str(value.counselor_acknowledged_by_id) if value.counselor_acknowledged_by_id else None
    return result


def assignment(value):
    return {
        "id": str(value.pk),
        "student_id": str(value.student_id),
        "collection_id": str(value.collection_id) if value.collection_id else None,
        "due_at": to_json_value(value.due_at),
        "status": value.status,
        "assigned_at": to_json_value(value.assigned_at),
    }


def status(value):
    return {
        "has_response": bool(value.get("has_response")),
        "status": value.get("status"),
        "reference_code": value.get("reference_code"),
        "submitted_at": to_json_value(value.get("submitted_at")),
    }
