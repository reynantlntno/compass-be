# Project: COMPASS
# File: apps/call_slips/selectors.py
# Module: apps.call_slips
# Purpose: Side-effect-free query selectors for call slip workflows.
# Domain boundary and service policy.

import datetime
from django.db import models
from django.db.models import F, OuterRef, Q, Subquery
from django.utils import timezone

from apps.access_control.authority import has_capability, has_fixed_capability
from apps.access_control.capabilities import Capability
from apps.access_control.rules import (
    is_active_nonlegacy_actor,
    is_counselor,
    is_gco_staff,
    is_student,
    owns_user,
)
from apps.access_control.display import office_student_display_label
from apps.access_control.scopes import (
    get_active_workflow_authority_grants,
    get_live_counselor_coverages,
    scope_matches_student_profile,
    workflow_authority_authorizes_record,
    build_geographic_scope_q,
    build_workflow_authority_scope_q,
)
from apps.accounts.models import RoleChoices
from apps.call_slips.models import (
    CallSlip,
    CallSlipStatusChoices,
    CallSlipRescheduleRequest,
    COUNSELOR_TIME_PURPOSES,
    EVER_ISSUED_STATUSES,
    TERMINAL_STATUSES,
)
from apps.call_slips.encryption import (
    CALL_SLIP_CONFIDENTIAL_FIELDS,
    RESCHEDULE_CONFIDENTIAL_FIELDS,
    CS_INSTRUCTIONS,
    CS_OFFICE_REMARKS,
    CS_RESCHEDULE_REQUEST,
    CallSlipEncryptionError,
    read_group,
)


def _safe_call_slips():
    return CallSlip.objects.defer(*CALL_SLIP_CONFIDENTIAL_FIELDS)


def _active(user):
    return is_active_nonlegacy_actor(user)


def _valid_student(student):
    return bool(_active(student) and is_student(student) and hasattr(student, "student_profile"))


def _active_counselor(user):
    return bool(_active(user) and is_counselor(user))


def _workflow_grant_matches(user, student, assigned_counselor=None):
    if not _active(user) or not is_gco_staff(user) or not _valid_student(student):
        return False
    return workflow_authority_authorizes_record(
        user, capability=Capability.CALL_SLIPS_PREPARE,
        student_profile=student.student_profile,
        assigned_counselor=assigned_counselor,
    )


def get_head_call_slip_queue(user) -> models.QuerySet:
    if not _active(user) or not has_fixed_capability(user, Capability.CALL_SLIPS_PREPARE):
        return CallSlip.objects.none()
    return _safe_call_slips().filter(
        student__is_active=True, student__is_superuser=False, student__role=RoleChoices.STUDENT,
    )


def get_assigned_call_slip_queue(user) -> models.QuerySet:
    if not _active_counselor(user):
        return CallSlip.objects.none()
    return _safe_call_slips().filter(
        assigned_counselor=user,
        student__is_active=True, student__is_superuser=False, student__role=RoleChoices.STUDENT,
    )


def get_coverage_call_slip_queue(user) -> models.QuerySet:
    if not _active_counselor(user):
        return CallSlip.objects.none()

    coverage_q = build_geographic_scope_q(
        get_live_counselor_coverages(user),
        {
            "campus": "student__student_profile__campus",
            "college": "student__student_profile__college",
            "department": "student__student_profile__department",
            "program": "student__student_profile__program",
        },
    )
    return _safe_call_slips().filter(
        assigned_counselor__isnull=True,
        student__is_active=True, student__is_superuser=False, student__role=RoleChoices.STUDENT,
    ).filter(coverage_q)


def get_staff_call_slip_queue(user) -> models.QuerySet:
    if not _active(user) or not is_gco_staff(user):
        return CallSlip.objects.none()

    scope_q = build_workflow_authority_scope_q(
        user,
        capability=Capability.CALL_SLIPS_PREPARE,
        field_map={
            "campus": "student__student_profile__campus",
            "college": "student__student_profile__college",
            "department": "student__student_profile__department",
            "program": "student__student_profile__program",
        },
        counselor_field="assigned_counselor_id",
    )
    return _safe_call_slips().filter(
        student__is_active=True, student__is_superuser=False, student__role=RoleChoices.STUDENT,
    ).filter(scope_q)


def get_student_call_slips(user) -> models.QuerySet:
    if not _active(user) or not is_student(user):
        return CallSlip.objects.none()
    return _safe_call_slips().filter(student=user).filter(
        Q(status__in=EVER_ISSUED_STATUSES)
        | Q(status=CallSlipStatusChoices.CANCELLED, issued_at__isnull=False)
    ).filter(student__is_active=True, student__is_superuser=False).order_by("-updated_at", "-pk")


def _schedule_bucket(value):
    if not value:
        return "Unscheduled"
    scheduled_date = timezone.localtime(value).date()
    today = timezone.localdate()
    if scheduled_date == today:
        return "Today"
    if scheduled_date < today:
        return "Past"
    return "Future"


def get_operational_call_slip_queue_items(user) -> list[dict]:
    if not _active(user):
        return []
    if has_capability(user, Capability.CALL_SLIPS_PREPARE):
        slips = get_head_call_slip_queue(user)
    elif is_counselor(user):
        assigned = get_assigned_call_slip_queue(user)
        coverage = get_coverage_call_slip_queue(user)
        slips = (assigned | coverage).distinct()
    elif is_gco_staff(user):
        slips = get_staff_call_slip_queue(user)
    else:
        return []
    return [
        {
            "reference_code": slip.reference_code,
            "status_label": slip.get_status_display(),
            "status_code": slip.status,
            "schedule_bucket": _schedule_bucket(slip.scheduled_start_at),
            "assignment_state": "Assigned" if slip.assigned_counselor_id else "Unassigned",
        }
        for slip in slips
    ]


def get_referral_linked_call_slips(user, referral) -> list[dict]:
    """Return a privacy-safe linked Call Slip projection for one Referral."""
    from apps.call_slips.policies import (
        can_cancel_call_slip,
        can_expire_call_slip,
        can_issue_call_slip,
        can_mark_no_show,
        can_reissue_referral_call_slip,
        can_record_attendance,
        can_update_call_slip_draft,
        can_view_call_slip_sensitive_detail,
    )

    successor_reference = (
        CallSlip.objects
        .filter(reissued_from_id=OuterRef("pk"))
        .order_by("created_at", "pk")
        .values("reference_code")[:1]
    )
    slips = (
        _safe_call_slips()
        .filter(referral=referral)
        .select_related("student", "student__student_profile", "assigned_counselor")
        .annotate(
            lineage_predecessor_reference=F("reissued_from__reference_code"),
            lineage_successor_reference=Subquery(successor_reference),
        )
        .order_by("created_at", "pk")
    )
    rows = []
    for slip in slips:
        if not can_view_call_slip_sensitive_detail(user, slip):
            continue
        rows.append({
            "reference_code": slip.reference_code,
            "status_code": slip.status,
            "status_label": slip.get_status_display(),
            "scheduled_start_at": slip.scheduled_start_at,
            "scheduled_end_at": slip.scheduled_end_at,
            "issued_at": slip.issued_at,
            "acknowledged_at": slip.acknowledged_at,
            "is_issued": bool(slip.issued_at),
            "is_acknowledged": bool(slip.acknowledged_at),
            "is_terminal": slip.status in TERMINAL_STATUSES,
            "reissued_from_reference": slip.lineage_predecessor_reference or "",
            "successor_reference": slip.lineage_successor_reference or "",
            "permissions": {
                "update": can_update_call_slip_draft(user, slip),
                "issue": can_issue_call_slip(user, slip),
                "attendance": can_record_attendance(user, slip),
                "no_show": can_mark_no_show(user, slip),
                "expire": can_expire_call_slip(user, slip),
                "cancel": can_cancel_call_slip(user, slip),
                "reissue": can_reissue_referral_call_slip(user, slip),
                "print": bool(slip.issued_at),
            },
        })

    # A lineage reference is useful only when its related Call Slip is also
    # visible to this actor.  Resolve that boundary from the already-filtered
    # projection rather than fetching predecessor/successor model instances.
    visible_references = {row["reference_code"] for row in rows}
    for row in rows:
        predecessor_reference = row["reissued_from_reference"]
        successor_reference = row["successor_reference"]
        if predecessor_reference not in visible_references:
            row["reissued_from_reference"] = ""
        if successor_reference not in visible_references:
            row["successor_reference"] = ""
        row["has_successor"] = bool(row["successor_reference"])
    return rows


def get_call_slip_by_reference_for_action(user, reference_code, action):
    from apps.referrals.encryption import REFERRAL_CONFIDENTIAL_FIELDS
    from apps.call_slips.policies import (
        can_view_call_slip_sensitive_detail,
        can_student_view_call_slip,
        can_update_call_slip_draft,
        can_assign_call_slip,
        can_reassign_call_slip,
        can_issue_call_slip,
        can_acknowledge_call_slip,
        can_request_reschedule,
        can_record_attendance,
        can_mark_no_show,
        can_expire_call_slip,
        can_cancel_call_slip,
    )
    try:
        cs = _safe_call_slips().select_related(
            "student", "student__student_profile", "assigned_counselor", "referral"
        ).defer(
            *(f"referral__{field}" for field in REFERRAL_CONFIDENTIAL_FIELDS)
        ).get(reference_code=reference_code)
    except CallSlip.DoesNotExist:
        return None

    policy_map = {
        "view_detail": lambda u, c: can_view_call_slip_sensitive_detail(u, c) or can_student_view_call_slip(u, c),
        "update": can_update_call_slip_draft,
        "assign": can_assign_call_slip,
        "reassign": can_reassign_call_slip,
        "issue": can_issue_call_slip,
        "acknowledge": lambda u, c: can_acknowledge_call_slip(u, c) or (
            _active(u) and is_student(u) and owns_user(u, c.student_id) and c.status == CallSlipStatusChoices.ACKNOWLEDGED
        ),
        "reschedule_request": can_request_reschedule,
        "attendance": can_record_attendance,
        "no_show": can_mark_no_show,
        "expire": can_expire_call_slip,
        "cancel": can_cancel_call_slip,
    }

    check = policy_map.get(action)
    if not check or not check(user, cs):
        return None
    return cs


def get_operational_call_slip_sensitive_detail(user, reference_code, purpose="detail"):
    from apps.referrals.encryption import REFERRAL_CONFIDENTIAL_FIELDS
    try:
        cs = _safe_call_slips().select_related(
            "student", "student__student_profile", "assigned_counselor",
            "referral", "referral__student", "referral__student__student_profile",
            "referral__assigned_counselor",
        ).defer(
            *(f"referral__{field}" for field in REFERRAL_CONFIDENTIAL_FIELDS)
        ).get(reference_code=reference_code)
    except CallSlip.DoesNotExist:
        return None

    from apps.call_slips.policies import can_view_call_slip_sensitive_detail
    if not can_view_call_slip_sensitive_detail(user, cs):
        return None
    try:
        instructions = read_group(user, cs, CS_INSTRUCTIONS)
        office_remarks = read_group(user, cs, CS_OFFICE_REMARKS)
    except CallSlipEncryptionError:
        return None
    referral_reference = ""
    if cs.referral_id:
        from apps.referrals.policies import can_view_referral_safe_metadata
        if can_view_referral_safe_metadata(user, cs.referral):
            referral_reference = cs.referral.reference_code
    return {
        "reference_code": cs.reference_code,
        "status_label": cs.get_status_display(),
        "status_code": cs.status,
        "student_label": office_student_display_label(cs.student.student_profile),
        "source_type_label": cs.get_source_type_display(),
        "purpose_label": cs.get_purpose_code_display(),
        "assignment_state": "Assigned" if cs.assigned_counselor_id else "Unassigned",
        "destination_label": cs.get_destination_code_display(),
        "report_to_destination": cs.report_to_destination,
        "scheduled_start_at": cs.scheduled_start_at,
        "scheduled_end_at": cs.scheduled_end_at,
        "expected_duration_minutes": cs.expected_duration_minutes,
        "mode_label": cs.get_mode_display(),
        "student_safe_location": cs.student_safe_location,
        "student_safe_instructions": instructions,
        "office_only_remarks": office_remarks,
        # Do not render a dead or guessable backlink when the Call Slip is
        # visible but the actor cannot access the source Referral metadata.
        "has_referral_link": bool(referral_reference),
        "referral_reference": referral_reference,
        "has_appointment_link": bool(cs.appointment_id),
        "created_at": cs.created_at,
        "updated_at": cs.updated_at,
        "source_form_code": cs.source_form_code,
        "source_form_revision": cs.source_form_revision,
        "is_printable": bool(cs.issued_at),
    }


def get_student_call_slip_detail(user, reference_code) -> dict:
    try:
        cs = _safe_call_slips().select_related("student", "student__student_profile").get(reference_code=reference_code)
    except CallSlip.DoesNotExist:
        return None

    from apps.call_slips.policies import can_student_view_call_slip
    if not can_student_view_call_slip(user, cs):
        return None
    try:
        instructions = read_group(user, cs, CS_INSTRUCTIONS)
    except CallSlipEncryptionError:
        return None

    from apps.call_slips.policies import can_acknowledge_call_slip, can_request_reschedule
    return {
        "reference_code": cs.reference_code,
        "issued_date": cs.issued_at.date() if cs.issued_at else None,
        "scheduled_start_at": cs.scheduled_start_at,
        "scheduled_end_at": cs.scheduled_end_at,
        "expected_duration_minutes": cs.expected_duration_minutes,
        "mode_label": cs.get_mode_display(),
        "safe_destination": cs.student_safe_location,
        "purpose_label": cs.get_purpose_code_display(),
        "student_safe_instructions": instructions,
        "status_label": cs.get_status_display(),
        "can_acknowledge": can_acknowledge_call_slip(user, cs),
        "can_reschedule": can_request_reschedule(user, cs),
    }


def get_printable_call_slip_dto(user, reference_code) -> dict:
    try:
        cs = _safe_call_slips().select_related(
            "student", "student__student_profile", "assigned_counselor"
        ).get(reference_code=reference_code)
    except CallSlip.DoesNotExist:
        return None

    from apps.call_slips.policies import can_student_view_call_slip, can_view_call_slip_sensitive_detail
    is_stud = can_student_view_call_slip(user, cs)
    is_oper = can_view_call_slip_sensitive_detail(user, cs)

    if (not is_stud and not is_oper) or not cs.issued_at:
        return None
    try:
        instructions = read_group(user, cs, CS_INSTRUCTIONS)
    except CallSlipEncryptionError:
        return None

    return {
        "reference_code": cs.reference_code,
        "issued_date": cs.issued_at.date() if cs.issued_at else None,
        "scheduled_start_at": cs.scheduled_start_at,
        "scheduled_end_at": cs.scheduled_end_at,
        "expected_duration_minutes": cs.expected_duration_minutes,
        "mode_label": cs.get_mode_display(),
        "safe_destination": cs.student_safe_location,
        "purpose_label": cs.get_purpose_code_display(),
        "student_safe_instructions": instructions,
        "status_label": cs.get_status_display(),
        "source_form_code": cs.source_form_code,
        "source_form_revision": cs.source_form_revision,
        "source_form_family": cs.source_form_family,
    }


def get_call_slip_reschedule_request_dto(user, request: CallSlipRescheduleRequest) -> dict:
    # Only an authorized pending decider receives the request narrative.
    from apps.call_slips.policies import can_decide_reschedule
    include_reason = can_decide_reschedule(user, request)
    reason = "[REDACTED]"
    if include_reason:
        try:
            reason = read_group(user, request, CS_RESCHEDULE_REQUEST)
        except CallSlipEncryptionError:
            reason = "[REDACTED]"

    return {
        "id": request.pk,
        "reference_code": request.call_slip.reference_code,
        "status": request.status,
        "previous_start_at": request.previous_start_at,
        "previous_end_at": request.previous_end_at,
        "proposed_start_at": request.proposed_start_at,
        "proposed_end_at": request.proposed_end_at,
        "student_reason": reason,
        "decision_code": request.decision_code,
        "decision_detail": "[REDACTED]",
    }


def get_reschedule_request_for_decision(user, request_id) -> CallSlipRescheduleRequest:
    try:
        req = CallSlipRescheduleRequest.objects.defer(*RESCHEDULE_CONFIDENTIAL_FIELDS).select_related(
            "call_slip", "call_slip__student", "call_slip__student__student_profile",
            "call_slip__assigned_counselor",
        ).defer(*(f"call_slip__{name}" for name in CALL_SLIP_CONFIDENTIAL_FIELDS)).get(pk=request_id)
    except CallSlipRescheduleRequest.DoesNotExist:
        return None

    from apps.call_slips.policies import can_decide_reschedule
    if not can_decide_reschedule(user, req):
        return None
    return req


def get_call_slip_blocking_intervals(counselor, date: datetime.date, exclude_slip=None) -> list[dict]:
    # Return only schedule intervals that should hard-block appointment slots.
    tz = timezone.get_current_timezone()
    start_dt = timezone.make_aware(datetime.datetime.combine(date, datetime.time.min), tz)
    end_dt = timezone.make_aware(datetime.datetime.combine(date, datetime.time.max), tz)

    qs = _safe_call_slips().filter(
        assigned_counselor=counselor,
        assigned_counselor__is_active=True,
        status__in=[
            CallSlipStatusChoices.ISSUED,
            CallSlipStatusChoices.ACKNOWLEDGED,
            CallSlipStatusChoices.RESCHEDULE_REQUESTED,
        ],
        scheduled_start_at__isnull=False,
        scheduled_end_at__isnull=False,
        purpose_code__in=COUNSELOR_TIME_PURPOSES,
    )
    if exclude_slip:
        qs = qs.exclude(pk=exclude_slip.pk)

    # Overlaps with the date
    qs = qs.filter(
        scheduled_start_at__lt=end_dt,
        scheduled_end_at__gt=start_dt,
    ).select_related("appointment")

    intervals = []
    for cs in qs:
        if _is_same_scheduled_appointment_reservation(cs, counselor, tz):
            continue
        intervals.append({
            "start": timezone.localtime(cs.scheduled_start_at, tz),
            "end": timezone.localtime(cs.scheduled_end_at, tz),
        })
    return intervals


def _is_same_scheduled_appointment_reservation(call_slip: CallSlip, counselor, tz) -> bool:
    if not call_slip.appointment_id:
        return False
    appointment = call_slip.appointment
    if not (
        appointment.status == "SCHEDULED"
        and appointment.confirmed_date
        and appointment.confirmed_start_time
        and appointment.confirmed_end_time
        and appointment.student_id == call_slip.student_id
        and appointment.assigned_counselor_id == counselor.pk
    ):
        return False
    appointment_start = timezone.make_aware(
        datetime.datetime.combine(appointment.confirmed_date, appointment.confirmed_start_time),
        tz,
    )
    appointment_end = timezone.make_aware(
        datetime.datetime.combine(appointment.confirmed_date, appointment.confirmed_end_time),
        tz,
    )
    return appointment_start == call_slip.scheduled_start_at and appointment_end == call_slip.scheduled_end_at
def get_call_slip_counselor_options(actor, slip, *, q=None, page=None):
    """Return scoped active counselor options for a Call Slip assign action.

    Only counselors who are current, policy-eligible assign targets for this
    Call Slip are disclosed. The returned selector is opaque and bound to the
    requesting actor and this Call Slip.
    """
    from apps.access_control.display import safe_user_display_label
    from apps.access_control.selection_tokens import issue_counselor_selection_token
    from apps.accounts.models import RoleChoices, User
    from apps.common.contracts import PageRequest, PageResult, page_queryset
    from apps.call_slips.policies import (
        can_assign_call_slip,
        can_reassign_call_slip,
        can_view_call_slip_sensitive_detail,
    )

    empty = PageResult((), page.page if page else 1, page.page_size if page else 25, 0)
    if not can_view_call_slip_sensitive_detail(actor, slip):
        return empty
    if not (can_assign_call_slip(actor, slip) or can_reassign_call_slip(actor, slip)):
        return empty

    queryset = User.objects.filter(
        is_active=True,
        is_superuser=False,
        role=RoleChoices.COUNSELOR,
    ).order_by("last_name", "first_name", "pk")
    search = " ".join(str(q or "").split())[:80]
    if search:
        queryset = queryset.filter(
            Q(first_name__icontains=search) | Q(last_name__icontains=search)
        )
    allowed_ids = [
        counselor.pk
        for counselor in queryset
        if can_assign_call_slip(actor, slip, counselor)
        or can_reassign_call_slip(actor, slip, counselor)
    ]
    request = page or PageRequest()
    paged = page_queryset(
        queryset.filter(pk__in=allowed_ids),
        request,
        lambda counselor: {
            "selection_token": issue_counselor_selection_token(
                actor, "call_slip", slip.reference_code, counselor,
            ),
            "display_name": safe_user_display_label(counselor),
        },
    )
    return PageResult(
        items=tuple(item for item in paged["items"] if item is not None),
        page=paged["page"],
        page_size=paged["page_size"],
        total=paged["total"],
    )
