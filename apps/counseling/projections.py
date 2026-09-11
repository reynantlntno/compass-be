"""Explicit output boundaries for counseling read data.

The counseling selectors in :mod:`apps.counseling.selectors` are internal ORM
query sources. Consumers must use the projections in this module rather than
serializing counseling model instances directly. ``defer()`` remains a query
performance optimization; these fixed allowlists are the security and privacy
output boundary.
"""

from datetime import date, datetime, time

from apps.access_control.rules import is_student, owns_user
from apps.counseling.encryption import (
    NOTE_CONFIDENTIAL_FIELDS,
    ROUTINE_CONFIDENTIAL_FIELDS,
    read_routine_evaluation,
    read_routine_intake,
    SESSION_CONFIDENTIAL_FIELDS,
    read_counselor_note,
    read_student_visible_summary,
)
from apps.counseling.policies import (
    can_view_counseling_case,
    can_view_counseling_notes,
    can_view_routine_interview_evaluation,
    can_view_routine_interview_intake,
    can_view_routine_interview_metadata,
    can_view_session,
)


STAFF_SESSION_METADATA_FIELDS = (
    "reference_code",
    "student_id",
    "appointment_id",
    "assigned_counselor_id",
    "session_type",
    "session_mode",
    "session_source",
    "status",
    "scheduled_start_at",
    "scheduled_end_at",
    "actual_started_at",
    "actual_ended_at",
    "actual_duration_minutes",
    "ended_early_flag",
    "completed_at",
    "finalized_at",
    "locked_at",
)

QUEUE_STAFF_SESSION_METADATA_FIELDS = (
    "reference_code",
    "session_type",
    "session_mode",
    "session_source",
    "status",
    "scheduled_start_at",
    "scheduled_end_at",
    "actual_started_at",
    "actual_ended_at",
    "actual_duration_minutes",
    "ended_early_flag",
    "completed_at",
    "finalized_at",
    "locked_at",
)

STUDENT_SESSION_METADATA_FIELDS = (
    "reference_code",
    "session_type",
    "session_mode",
    "status",
    "scheduled_start_at",
    "scheduled_end_at",
    "actual_started_at",
    "actual_ended_at",
    "actual_duration_minutes",
    "completed_at",
)

STUDENT_SESSION_SUMMARY_FIELDS = ("student_visible_summary",)

COUNSELOR_NOTE_FIELDS = (
    "student_visible_summary",
    "counselor_narrative",
    "recommendations",
    "special_concerns",
    "follow_up_needed",
    "follow_up_notes",
)

CASE_METADATA_FIELDS = (
    "reference_code",
    "student_id",
    "assigned_counselor_id",
    "concern_category",
    "priority",
    "status",
    "created_at",
    "updated_at",
    "resolved_at",
    "closed_at",
    "reopened_at",
)

STUDENT_CASE_METADATA_FIELDS = (
    "reference_code",
    "status",
    "created_at",
    "updated_at",
    "resolved_at",
    "closed_at",
)

ROUTINE_STAFF_METADATA_FIELDS = (
    "session_reference_code",
    "student_id",
    "assigned_counselor_id",
    "status",
    "visit_date",
    "visit_time",
    "duration_minutes",
    "nature_of_visit",
    "concern_academic",
    "concern_friends",
    "concern_classmates",
    "concern_vices",
    "concern_love_life",
    "concern_sleeping_problems",
    "concern_family",
    "concern_financial",
    "concern_suicidal_thought",
    "concern_dorm_boarding_house",
    "concern_past_painful_experience",
    "concern_others",
    "rating_emotionally",
    "rating_academically",
    "rating_physically",
    "rating_socially",
    "rating_spiritually",
    "rating_financially",
    "rating_others",
    "evaluation_date",
    "submitted_at",
    "evaluated_at",
    "completed_at",
    "finalized_at",
    "locked_at",
    "reopened_at",
)

ROUTINE_STUDENT_INTAKE_FIELDS = (
    "session_reference_code",
    "status",
    "visit_date",
    "visit_time",
    "duration_minutes",
    "nature_of_visit",
    "coping_challenges",
    "coping_remarks",
    "ucn_experience",
    "reason_for_coming",
    "difficulties_encountered",
    "stress_anxiety_causes",
    "stress_anxiety_management",
    "family_background_notes",
    "concerns_explanation",
    "college_adjustment",
    "academic_goals",
    "career_goals",
    "concern_academic",
    "concern_friends",
    "concern_classmates",
    "concern_vices",
    "concern_love_life",
    "concern_sleeping_problems",
    "concern_family",
    "concern_financial",
    "concern_suicidal_thought",
    "concern_dorm_boarding_house",
    "concern_past_painful_experience",
    "concern_others",
    "concern_others_text",
    "submitted_at",
)

ROUTINE_SENSITIVE_DETAIL_FIELDS = (
    *ROUTINE_STAFF_METADATA_FIELDS,
    "coping_challenges",
    "coping_remarks",
    "ucn_experience",
    "reason_for_coming",
    "difficulties_encountered",
    "stress_anxiety_causes",
    "stress_anxiety_management",
    "family_background_notes",
    "concerns_explanation",
    "college_adjustment",
    "academic_goals",
    "career_goals",
    "concern_others_text",
    "rating_others_label",
    "special_concern",
    "recommendations",
)

ROUTINE_QUEUE_METADATA_FIELDS = tuple(
    field
    for field in ROUTINE_STAFF_METADATA_FIELDS
    if field not in {"student_id", "assigned_counselor_id"}
)

ROUTINE_API_SENSITIVE_DETAIL_FIELDS = tuple(
    field
    for field in ROUTINE_SENSITIVE_DETAIL_FIELDS
    if field not in {"student_id", "assigned_counselor_id"}
)


def _student_owner_can_view(actor, session) -> bool:
    """Return whether ``actor`` is the active student who owns ``session``."""
    return bool(
        session
        and is_student(actor)
        and owns_user(actor, session.student_id)
        and can_view_session(actor, session)
    )


def _project_fields(session, fields) -> dict:
    """Build a plain dictionary from an explicit field allowlist."""
    return {field: _json_safe(getattr(session, field)) for field in fields}


def _json_safe(value):
    """Normalize approved scalar values without serializing model objects."""
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"Unsupported projection value: {type(value).__name__}")


def _routine_value(record, field):
    if field == "session_reference_code":
        return record.session.reference_code
    if field == "student_id":
        return record.session.student_id
    if field == "assigned_counselor_id":
        return record.session.assigned_counselor_id
    return getattr(record, field)


def _project_routine_model_fields(record, fields) -> dict:
    return {field: _json_safe(_routine_value(record, field)) for field in fields}


def _student_routine_owner_can_view(actor, record) -> bool:
    return bool(
        record
        and is_student(actor)
        and owns_user(actor, record.session.student_id)
        and can_view_routine_interview_metadata(actor, record)
    )


def project_staff_session_metadata(actor, session) -> dict | None:
    """Return safe staff metadata when the actor may view the session row.

    This projection intentionally excludes concern/reason text, all session
    note fields, encrypted fields, email addresses, and model instances.  A
    student must use the narrower student projection even though the existing
    row-visibility policy allows the student to see their own session.
    """
    if not session or is_student(actor) or not can_view_session(actor, session):
        return None
    return _project_fields(session, STAFF_SESSION_METADATA_FIELDS)


def project_staff_session_queue_metadata(actor, session) -> dict | None:
    """Return queue-safe staff metadata with bounded student display fields.

    The existing staff metadata projection remains unchanged for callers that
    depend on its established allowlist.  Queue consumers may opt into this
    additive presentation projection without widening detail or note output.
    """
    from apps.access_control.display import safe_student_display_label

    existing_payload = project_staff_session_metadata(actor, session)
    if existing_payload is None:
        return None
    payload = {
        field: existing_payload[field]
        for field in QUEUE_STAFF_SESSION_METADATA_FIELDS
    }
    student = getattr(session, "student", None)
    profile = getattr(student, "student_profile", None)
    payload.update(
        {
            "student_display_name": safe_student_display_label(profile),
            "student_number": getattr(profile, "student_number", None),
            "assignment_state": (
                "Unassigned"
                if session.assigned_counselor_id is None
                else "Assigned to you"
                if session.assigned_counselor_id == getattr(actor, "pk", None)
                else "Assigned"
            ),
        }
    )
    return payload


def project_student_session_metadata(actor, session) -> dict | None:
    """Return the owner-only student session metadata projection."""
    if not _student_owner_can_view(actor, session):
        return None
    return _project_fields(session, STUDENT_SESSION_METADATA_FIELDS)


def project_student_session_summary(actor, session) -> dict | None:
    """Return only the student-safe summary for the owning student.

    The existing encrypted reader remains the authority for decrypting and
    validating the student-visible note field.  Counselor narrative,
    recommendations, special concerns, follow-up notes, and all other
    confidential fields are deliberately not part of this output.
    """
    if not _student_owner_can_view(actor, session):
        return None
    return {
        "student_visible_summary": read_student_visible_summary(actor, session),
    }


def project_counselor_note(actor, session) -> dict | None:
    """Return the raw counselor-note projection for an authorized reader.

    ``read_counselor_note`` remains the decryption and group-policy boundary.
    This function converts its mapping into the only approved plain-dictionary
    output and intentionally excludes encrypted storage fields, authorship,
    actor identifiers, and workflow metadata.
    """
    if not session or not can_view_counseling_notes(actor, session):
        return None
    note = read_counselor_note(actor, session)
    if note is None:
        return None
    return {field: note[field] for field in COUNSELOR_NOTE_FIELDS}


def project_case_metadata(actor, counseling_case) -> dict | None:
    """Return safe counseling-case metadata for an authorized staff actor.

    The current case model is intentionally metadata-only. This projection
    excludes workflow actor IDs, close/reopen reason codes, collaborator
    relations, names, emails, model instances, and any future narrative
    fields until those fields receive their own sensitivity decision.
    """
    if not counseling_case or not can_view_counseling_case(actor, counseling_case):
        return None
    return _project_fields(counseling_case, CASE_METADATA_FIELDS)


def project_student_case_metadata(actor, counseling_case) -> dict | None:
    """Return the minimal owner-safe counseling-case status projection."""
    if not counseling_case or not is_student(actor):
        return None
    if not can_view_counseling_case(actor, counseling_case):
        return None
    return _project_fields(counseling_case, STUDENT_CASE_METADATA_FIELDS)


def project_routine_interview_metadata(actor, record) -> dict | None:
    """Return safe structured routine data for an authorized staff actor.

    Coverage-only counselors and Head Guidance outside their own
    assignment/coverage receive this projection, never raw intake or
    evaluation text. Students use ``project_student_routine_interview``.
    """
    if not record or is_student(actor) or not can_view_routine_interview_metadata(actor, record):
        return None
    return _project_routine_model_fields(record, ROUTINE_STAFF_METADATA_FIELDS)


def project_routine_interview_queue_metadata(actor, record) -> dict | None:
    """Return the bounded staff queue projection for routine interviews.

    The established routine metadata projection is intentionally retained for
    internal consumers.  Queue responses use this narrower presentation
    projection so database and counselor identifiers never cross the API
    boundary, while still exposing the same safe structured interview facts.
    """
    from apps.access_control.display import safe_student_display_label

    existing_payload = project_routine_interview_metadata(actor, record)
    if existing_payload is None:
        return None
    session = record.session
    student = getattr(session, "student", None)
    profile = getattr(student, "student_profile", None)
    student_number = getattr(profile, "student_number", None)
    payload = {
        field: existing_payload[field]
        for field in ROUTINE_QUEUE_METADATA_FIELDS
    }
    payload.update(
        {
            "student_display_name": safe_student_display_label(profile)[:160],
            "student_number": str(student_number)[:50] if student_number is not None else None,
            "assignment_state": (
                "Unassigned"
                if session.assigned_counselor_id is None
                else "Assigned to you"
                if session.assigned_counselor_id == getattr(actor, "pk", None)
                else "Assigned"
            ),
            "updated_at": _json_safe(record.updated_at),
        }
    )
    return payload


def project_student_routine_interview(actor, record) -> dict | None:
    """Return the owner-only routine intake projection."""
    if not _student_routine_owner_can_view(actor, record):
        return None
    intake = read_routine_intake(actor, record)
    payload = _project_routine_model_fields(record, ("session_reference_code", "status"))
    payload.update(
        {
            field: _json_safe(intake[field])
            for field in ROUTINE_STUDENT_INTAKE_FIELDS
            if field not in {"session_reference_code", "status"}
        }
    )
    return payload


def project_routine_interview_sensitive_detail(actor, record) -> dict | None:
    """Return raw routine fields only to an assigned/in-scope counselor."""
    if not record:
        return None
    if not can_view_routine_interview_intake(actor, record):
        return None
    if not can_view_routine_interview_evaluation(actor, record):
        return None
    intake = read_routine_intake(actor, record)
    evaluation = read_routine_evaluation(actor, record)
    payload = _project_routine_model_fields(record, ROUTINE_STAFF_METADATA_FIELDS)
    for field in ROUTINE_SENSITIVE_DETAIL_FIELDS:
        if field in payload:
            continue
        source = intake if field in intake else evaluation
        payload[field] = _json_safe(source[field])
    return payload


def project_routine_interview_api_sensitive_detail(actor, record) -> dict | None:
    """Return only the approved API-safe sensitive routine fields.

    ``project_routine_interview_sensitive_detail`` remains the internal
    decryption and authorization boundary.  This wrapper removes database and
    actor identifiers before the dedicated API operation serializes it.
    """
    payload = project_routine_interview_sensitive_detail(actor, record)
    if payload is None:
        return None
    return {
        field: payload[field]
        for field in ROUTINE_API_SENSITIVE_DETAIL_FIELDS
    }


if set(STAFF_SESSION_METADATA_FIELDS) & set(SESSION_CONFIDENTIAL_FIELDS):
    raise RuntimeError("Staff session metadata overlaps confidential session fields")
if set(STUDENT_SESSION_METADATA_FIELDS) & set(SESSION_CONFIDENTIAL_FIELDS):
    raise RuntimeError("Student session metadata overlaps confidential session fields")
if not (
    set(COUNSELOR_NOTE_FIELDS) - {"follow_up_needed"}
).issubset(NOTE_CONFIDENTIAL_FIELDS):
    raise RuntimeError("Counselor note projection contains an unknown note field")
if set(ROUTINE_STAFF_METADATA_FIELDS) & set(ROUTINE_CONFIDENTIAL_FIELDS):
    raise RuntimeError("Routine staff metadata overlaps routine confidential fields")
for _routine_fields in (
    ROUTINE_STUDENT_INTAKE_FIELDS,
    ROUTINE_SENSITIVE_DETAIL_FIELDS,
    ROUTINE_QUEUE_METADATA_FIELDS,
    ROUTINE_API_SENSITIVE_DETAIL_FIELDS,
):
    if any(field.endswith("_encrypted") for field in _routine_fields):
        raise RuntimeError("Routine projection contains encrypted storage fields")
if any(
    field in {"assigned_counselor_confirmation", "submitted_by", "evaluated_by", "completed_by", "finalized_by", "locked_by", "reopened_by"}
    for field in ROUTINE_SENSITIVE_DETAIL_FIELDS
):
    raise RuntimeError("Routine sensitive projection contains actor relation fields")
