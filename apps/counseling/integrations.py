"""Safe cross-workflow projections for the counseling workspace.

This module is deliberately an integration boundary.  It composes existing
domain selectors and policies, then returns small dictionaries containing only
public workflow references and operational timestamps.  It must not become a
shortcut around a domain's detail or mutation policy.
"""

from __future__ import annotations

from django.db.models import Q

from apps.common.contracts import PageRequest, PageResult, to_json_value


def _timestamp(value):
    return to_json_value(value) if value is not None else None


def _record(record_type: str, reference_code: str, status: str | None, *, created_at=None, updated_at=None):
    return {
        "record_type": record_type,
        "reference_code": str(reference_code),
        "status": str(status) if status is not None else None,
        "created_at": _timestamp(created_at),
        "updated_at": _timestamp(updated_at),
    }


def project_related_records(actor, session) -> list[dict]:
    """Project the records related to one already-authorized session.

    Each optional relationship is checked through its owning domain's read
    policy.  Missing or unauthorized records are omitted rather than exposed
    as placeholders, so this endpoint cannot be used as a relationship oracle.
    """

    from apps.appointments.policies import can_view_appointment
    from apps.call_slips.models import CallSlip
    from apps.call_slips.policies import can_view_call_slip_sensitive_detail
    from apps.counseling.policies import (
        can_view_counseling_case,
        can_view_ecounseling_session,
        can_view_session,
        can_view_urgent_support_request,
    )
    from apps.counseling.selectors import (
        get_cases_for_session,
        get_ecounseling_session_for_counseling_session,
        get_routine_interview_for_session,
        get_urgent_support_requests_for_session,
    )
    from apps.referrals.policies import can_view_referral_safe_metadata

    if session is None or not can_view_session(actor, session):
        return []

    rows: list[dict] = []
    appointment = getattr(session, "appointment", None)
    if appointment is not None and can_view_appointment(actor, appointment):
        rows.append(
            _record(
                "appointment",
                appointment.reference_code,
                appointment.status,
                created_at=appointment.created_at,
                updated_at=appointment.updated_at,
            )
        )

        # Referrals are related to a session through appointment call slips;
        # the referral and Call Slip policies still decide independently.
        slips = (
            CallSlip.objects.filter(appointment=appointment)
            .select_related("referral")
            .order_by("created_at", "pk")
        )
        for slip in slips:
            if can_view_call_slip_sensitive_detail(actor, slip):
                rows.append(
                    _record(
                        "call_slip",
                        slip.reference_code,
                        slip.status,
                        created_at=slip.created_at,
                        updated_at=slip.updated_at,
                    )
                )
            referral = getattr(slip, "referral", None)
            if referral is not None and can_view_referral_safe_metadata(actor, referral):
                rows.append(
                    _record(
                        "referral",
                        referral.reference_code,
                        referral.status,
                        created_at=referral.created_at,
                        updated_at=referral.updated_at,
                    )
                )

    routine = get_routine_interview_for_session(actor, session)
    if routine is not None:
        rows.append(
            _record(
                "routine_interview",
                routine.session.reference_code,
                routine.status,
                created_at=routine.created_at,
                updated_at=routine.updated_at,
            )
        )

    for counseling_case in get_cases_for_session(actor, session):
        if can_view_counseling_case(actor, counseling_case):
            rows.append(
                _record(
                    "case",
                    counseling_case.reference_code,
                    counseling_case.status,
                    created_at=counseling_case.created_at,
                    updated_at=counseling_case.updated_at,
                )
            )

    for urgent_support in get_urgent_support_requests_for_session(actor, session):
        if can_view_urgent_support_request(actor, urgent_support):
            rows.append(
                _record(
                    "urgent_support",
                    urgent_support.reference_code,
                    urgent_support.status,
                    created_at=urgent_support.created_at,
                    updated_at=urgent_support.updated_at,
                )
            )

    ecounseling = get_ecounseling_session_for_counseling_session(actor, session)
    if ecounseling is not None and can_view_ecounseling_session(actor, ecounseling):
        rows.append(
            _record(
                "ecounseling",
                ecounseling.reference_code,
                ecounseling.status,
                created_at=ecounseling.created_at,
                updated_at=ecounseling.updated_at,
            )
        )

    # A relationship can only be present once.  Keep the projection stable if
    # old data contains duplicate call-slip/referral paths.
    seen: set[tuple[str, str]] = set()
    unique_rows = []
    for row in rows:
        key = (row["record_type"], row["reference_code"])
        if key not in seen:
            seen.add(key)
            unique_rows.append(row)
    return unique_rows


def _link_option(reference_code: str, status: str | None) -> dict:
    return {"reference_code": str(reference_code), "status": str(status) if status is not None else None}


def get_session_urgent_support_options(actor, session, page: PageRequest) -> PageResult[dict]:
    """Return same-student urgent requests the actor may link to a session."""

    from apps.counseling.policies import can_link_urgent_support_to_session, can_view_session
    from apps.counseling.selectors import get_urgent_support_requests_visible_to

    if session is None or not can_view_session(actor, session):
        return PageResult((), page.page, page.page_size, 0)

    queryset = (
        get_urgent_support_requests_visible_to(actor)
        .filter(student_id=session.student_id)
        .exclude(Q(originating_session=session) | Q(documentation_session=session))
        .order_by("-updated_at", "-pk")
    )
    candidates = [
        _link_option(item.reference_code, item.status)
        for item in queryset
        if can_link_urgent_support_to_session(actor, item, session)
    ]
    return PageResult(
        items=tuple(candidates[page.offset : page.offset + page.page_size]),
        page=page.page,
        page_size=page.page_size,
        total=len(candidates),
    )


def get_urgent_link_options(actor, urgent_support) -> dict[str, list[dict]]:
    """Return policy-scoped same-student session and case link options."""

    from apps.counseling.policies import (
        can_link_urgent_support_to_case,
        can_link_urgent_support_to_session,
        can_view_urgent_support_request,
    )
    from apps.counseling.selectors import (
        get_counseling_cases_visible_to,
        get_sessions_visible_to,
    )

    if urgent_support is None or not can_view_urgent_support_request(actor, urgent_support):
        return {"sessions": [], "cases": []}

    sessions = [
        _link_option(session.reference_code, session.status)
        for session in get_sessions_visible_to(actor)
        .filter(student_id=urgent_support.student_id)
        .exclude(
            Q(originating_urgent_supports=urgent_support)
            | Q(documented_urgent_supports=urgent_support)
        )
        .order_by("-updated_at", "-pk")[:50]
        if can_link_urgent_support_to_session(actor, urgent_support, session)
    ]
    cases = [
        _link_option(counseling_case.reference_code, counseling_case.status)
        for counseling_case in get_counseling_cases_visible_to(actor)
        .filter(student_id=urgent_support.student_id)
        .exclude(urgent_support_requests=urgent_support)
        .order_by("-updated_at", "-pk")[:50]
        if can_link_urgent_support_to_case(actor, urgent_support, counseling_case)
    ]
    return {"sessions": sessions, "cases": cases}
