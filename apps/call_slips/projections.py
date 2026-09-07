"""Fixed JSON projection boundary for the call_slips domain.

Only named projection functions with explicit allowlists may be added here.
Raw model instances, QuerySets, encrypted fields, secrets, and arbitrary
metadata must not be returned to a client.
"""

from apps.common.contracts import to_json_object


def project_call_slip_queue_item(actor, slip) -> dict | None:
    """Return safe queue metadata; no encrypted or student-detail fields."""
    if slip is None:
        return None
    from apps.call_slips.policies import (
        can_student_view_call_slip,
        can_view_call_slip_sensitive_detail,
    )
    if not (can_student_view_call_slip(actor, slip) or can_view_call_slip_sensitive_detail(actor, slip)):
        return None
    return to_json_object({
        "reference_code": slip.reference_code,
        "status_code": slip.status,
        "status_label": slip.get_status_display(),
        "schedule_bucket": "Unscheduled" if not slip.scheduled_start_at else slip.scheduled_start_at.date().isoformat(),
        "assignment_state": "Assigned" if slip.assigned_counselor_id else "Unassigned",
        "updated_at": slip.updated_at,
    })


def project_call_slip_detail(actor, reference_code: str) -> dict | None:
    from apps.access_control.rules import is_student
    from apps.call_slips.selectors import (
        get_operational_call_slip_sensitive_detail,
        get_student_call_slip_detail,
    )

    if is_student(actor):
        value = get_student_call_slip_detail(actor, reference_code)
    else:
        value = get_operational_call_slip_sensitive_detail(actor, reference_code)
    return to_json_object(value) if value is not None else None


def project_student_call_slip_detail(actor, reference_code: str) -> dict | None:
    from apps.call_slips.selectors import get_student_call_slip_detail

    value = get_student_call_slip_detail(actor, reference_code)
    return to_json_object(value) if value is not None else None


def project_printable_call_slip(actor, reference_code: str) -> dict | None:
    from apps.call_slips.selectors import get_printable_call_slip_dto

    value = get_printable_call_slip_dto(actor, reference_code)
    return to_json_object(value) if value is not None else None


def project_reschedule_request(actor, request) -> dict | None:
    from apps.call_slips.selectors import get_call_slip_reschedule_request_dto

    return to_json_object(get_call_slip_reschedule_request_dto(actor, request)) if request else None
