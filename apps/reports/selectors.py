# Project: COMPASS
# File: apps/reports/selectors.py
# Module: apps.reports
# Purpose: Actor-scoped aggregate data selectors for report families

from datetime import timedelta

from django.db.models import Avg, Case, CharField, Count, Q, Value, When
from django.utils import timezone

from apps.common.exceptions import ValidationError
from apps.access_control.authority import AuthorityContext, build_authority_context, has_capability, resolve_capability
from apps.access_control.capabilities import Capability
from apps.access_control.rules import is_counselor, is_gco_staff
from apps.access_control.scopes import (
    build_geographic_scope_q,
    build_workflow_authority_scope_q,
    get_active_workflow_authority_grants,
    get_live_counselor_coverages,
)
from apps.appointments.models import Appointment, AppointmentStatusChoices
from apps.audit.models import AuditLogEntry
from apps.call_slips.models import CallSlip, CallSlipStatusChoices
from apps.content.models import ContactReply, ContactReplyStatus, PublicContactSubmission
from apps.counseling.models import CounselingSession, SessionStatusChoices
from apps.documents.models import GeneratedDocument
from apps.exit_interviews.models import (
    COUNSELOR_FIELDS,
    CURRICULUM_FIELDS,
    DEAN_FIELDS,
    FACILITIES_FIELDS,
    FACULTY_FIELDS,
    OFFICE_STAFF_FIELDS,
    SELF_ASSESSMENT_FIELDS,
    ExitInterviewResponse,
)
from apps.feedback.models import FeedbackStatus, FeedbackSubmission
from apps.form_collection.models import FormCollection, FormInvitation
from apps.good_moral.models import GoodMoralRequest
from apps.graduate_tracer.models import GraduateTracerResponse
from apps.inventory.models import StudentInventorySnapshot
from apps.notifications.models import Notification, EmailDelivery
from apps.profiles.models import StudentProfile
from apps.referrals.models import Referral, ReferralAction
from apps.workflow.models import IdempotencyKey, OutboxEvent


def _none(qs):
    return qs.none()


def _coverage_q(actor, field_map: dict[str, str]) -> Q:
    return build_geographic_scope_q(
        get_live_counselor_coverages(actor),
        field_map,
    )


def _grant_scope_q(
    actor,
    field_map: dict[str, str],
    capability: Capability = Capability.REPORTS_RUN,
    *,
    counselor_field: str | None = None,
) -> Q:
    return build_workflow_authority_scope_q(
        actor,
        capability=capability,
        field_map=field_map,
        counselor_field=counselor_field,
    )


def _apply_filters(qs, filters: dict, field_map: dict[str, str]):
    for filter_key, model_field in field_map.items():
        value = filters.get(filter_key)
        if value not in (None, ""):
            qs = qs.filter(**{model_field: value})
    return qs


def _student_profile_scope(actor, *, office_wide: bool = False) -> Q:
    if office_wide:
        return Q()
    if is_counselor(actor):
        return _coverage_q(
            actor,
            {
                "campus": "campus",
                "college": "college",
                "department": "department",
                "program": "program",
            },
        )
    if is_gco_staff(actor):
        return _grant_scope_q(
            actor,
            {
                "campus": "campus",
                "college": "college",
                "department": "department",
                "program": "program",
            },
        )
    return Q(pk__in=[])


def _student_user_scope(actor, *, office_wide: bool = False) -> Q:
    if office_wide:
        return Q()
    if is_counselor(actor):
        return _coverage_q(
            actor,
            {
                "campus": "student__student_profile__campus",
                "college": "student__student_profile__college",
                "department": "student__student_profile__department",
                "program": "student__student_profile__program",
            },
        )
    return Q(pk__in=[])


def _respondent_scope(actor, *, office_wide: bool = False) -> Q:
    if office_wide:
        return Q()
    if is_counselor(actor):
        return _coverage_q(
            actor,
            {
                "campus": "respondent_user__student_profile__campus",
                "college": "respondent_user__student_profile__college",
                "department": "respondent_user__student_profile__department",
                "program": "respondent_user__student_profile__program",
            },
        )
    if is_gco_staff(actor):
        return _grant_scope_q(
            actor,
            {
                "campus": "respondent_user__student_profile__campus",
                "college": "respondent_user__student_profile__college",
                "department": "respondent_user__student_profile__department",
                "program": "respondent_user__student_profile__program",
            },
        )
    return Q(pk__in=[])


def _snapshot_scope(actor, *, program_field: str, college_field: str, office_wide: bool = False) -> Q:
    if office_wide:
        return Q()
    if is_counselor(actor):
        return _coverage_q(actor, {"college": college_field, "program": program_field})
    if is_gco_staff(actor):
        return _grant_scope_q(actor, {"college": college_field, "program": program_field})
    return Q(pk__in=[])


def _student_profile_relation_scope(actor, prefix: str, *, office_wide: bool = False) -> Q:
    if office_wide:
        return Q()
    if is_counselor(actor):
        return _coverage_q(
            actor,
            {
                "campus": f"{prefix}campus",
                "college": f"{prefix}college",
                "department": f"{prefix}department",
                "program": f"{prefix}program",
            },
        )
    if is_gco_staff(actor):
        return _grant_scope_q(
            actor,
            {
                "campus": f"{prefix}campus",
                "college": f"{prefix}college",
                "department": f"{prefix}department",
                "program": f"{prefix}program",
            },
        )
    return Q(pk__in=[])


def _assigned_or_student_scope(actor, student_prefix: str = "student__student_profile__", *, office_wide: bool = False) -> Q:
    if office_wide:
        return Q()
    if is_counselor(actor):
        coverage_q = _coverage_q(
            actor,
            {
                "campus": f"{student_prefix}campus",
                "college": f"{student_prefix}college",
                "department": f"{student_prefix}department",
                "program": f"{student_prefix}program",
            },
        )
        return Q(assigned_counselor=actor) | coverage_q
    if is_gco_staff(actor):
        return _grant_scope_q(
            actor,
            {
                "campus": f"{student_prefix}campus",
                "college": f"{student_prefix}college",
                "department": f"{student_prefix}department",
                "program": f"{student_prefix}program",
            },
            counselor_field="assigned_counselor",
        )
    return Q(pk__in=[])


def get_student_profile_inventory_aggregates(actor, filters: dict, report_definition=None, context: AuthorityContext | None = None) -> dict:
    """Aggregates student profile and inventory counts after actor scoping."""
    auth = context if context is not None else build_authority_context(actor)
    profiles = StudentProfile.objects.filter(_student_profile_scope(actor, office_wide=resolve_capability(auth, Capability.REPORTS_VIEW_INSTITUTION)))
    snapshots = StudentInventorySnapshot.objects.filter(student_profile__in=profiles)

    profiles = _apply_filters(
        profiles,
        filters,
        {
            "campus": "campus",
            "college": "college",
            "department": "department",
            "program": "program",
            "year_level": "year_level",
        },
    )
    snapshots = _apply_filters(
        snapshots,
        filters,
        {
            "campus": "student_profile__campus",
            "college": "student_profile__college",
            "department": "student_profile__department",
            "program": "student_profile__program",
            "year_level": "student_profile__year_level",
            "academic_year": "academic_year",
        },
    )

    return {
        "profile_totals": [{"metric": "profiles", "count": profiles.count()}],
        "by_lifecycle": list(profiles.values("lifecycle_status").annotate(count=Count("id")).order_by("lifecycle_status")),
        "by_campus": list(profiles.values("campus").annotate(count=Count("id")).order_by("campus")),
        "by_program": list(profiles.values("program").annotate(count=Count("id")).order_by("program")),
        "inventory_submissions": list(snapshots.values("academic_year", "status").annotate(count=Count("id")).order_by("academic_year", "status")),
    }


CSM_AGGREGATE_STATUSES = (
    FeedbackStatus.SUBMITTED,
    FeedbackStatus.REVIEWED,
    FeedbackStatus.RESPONDED,
    FeedbackStatus.CLOSED,
    FeedbackStatus.ARCHIVED,
)


def get_feedback_csm_aggregates(actor, filters: dict, report_definition=None, context: AuthorityContext | None = None) -> dict:
    """Return one fixed-shape, scope-first CSM aggregate disclosure set.

    User-controlled CSM filters and high-cardinality breakdowns are deliberately
    unavailable because overlapping results could reconstruct a protected
    cohort. Actor coverage/assignment scope is applied directly to authoritative
    linked student profiles before aggregation. Public, anonymous-channel, and
    unlinked-token rows without that relation are excluded rather than inferred.
    """
    if filters:
        raise ValidationError("CSM report filters are not available for privacy protection.")

    auth = context if context is not None else build_authority_context(actor)

    submissions = (
        FeedbackSubmission.objects.filter(
            _respondent_scope(actor, office_wide=resolve_capability(auth, Capability.REPORTS_VIEW_INSTITUTION)),
            status__in=CSM_AGGREGATE_STATUSES,
            respondent_user__student_profile__isnull=False,
        )
        .distinct()
    )

    # Per-item averages for the three official rating matrices. Each average
    # only considers rows where the item was rated (null = N/A / unanswered),
    # so the normalized columns drive reliable aggregation.
    sqd_item_fields = [f"sqd{i}" for i in range(9)]
    service_personnel_fields = [
        "sq_personnel_helpfulness",
        "sq_personnel_competence",
        "sq_personnel_flexibility",
        "sq_personnel_accuracy",
        "sq_personnel_appearance",
        "sq_personnel_delivered",
    ]
    office_premises_fields = [
        "op_located",
        "op_cleanliness",
        "op_environment",
        "op_office_hours",
        "op_availability",
    ]

    def _item_averages(fields):
        rows = []
        for field in fields:
            aggregate = submissions.aggregate(
                denominator=Count(field),
                average=Avg(field),
            )
            rows.append({
                "metric": field,
                "denominator": aggregate["denominator"],
                "average": round(aggregate["average"], 2) if aggregate["average"] is not None else None,
            })
        return rows

    return {
        "ratings_summary": _item_averages(["overall_satisfaction", "sqd_average"]),
        "sqd_item_averages": _item_averages(sqd_item_fields),
        "service_personnel_averages": _item_averages(service_personnel_fields),
        "office_premises_averages": _item_averages(office_premises_fields),
    }


REPORTABLE_EXIT_RESPONSE_STATUSES = ("SUBMITTED", "ARCHIVED")


def get_exit_interview_aggregates(actor, filters: dict, report_definition=None, context: AuthorityContext | None = None) -> dict:
    """Aggregates Exit Interview ratings without comments, raw JSON, or free text.

    Per-item averages only consider rows where the item was rated
    (null = N/A / unanswered), so normalized columns drive reliable aggregation.
    """
    auth = context if context is not None else build_authority_context(actor)
    responses = ExitInterviewResponse.objects.filter(
        _student_profile_relation_scope(actor, "student__", office_wide=resolve_capability(auth, Capability.REPORTS_VIEW_INSTITUTION)),
        status__in=REPORTABLE_EXIT_RESPONSE_STATUSES,
    )
    responses = _apply_filters(
        responses,
        filters,
        {
            "program": "program_snapshot",
            "college": "college_snapshot",
            "academic_year": "academic_year",
            "graduation_year": "graduation_year_snapshot",
            "form_collection": "form_collection",
            "form_revision": "form_revision",
            "status": "status",
        },
    )

    def _item_averages(fields):
        rows = []
        for field in fields:
            avg = responses.filter(**{f"{field}__isnull": False}).aggregate(avg=Avg(field))["avg"]
            rows.append({"item": field, "average": round(avg, 2) if avg is not None else None})
        return rows

    cohort_readiness = list(
        responses.annotate(
            cohort_state=Case(
                When(
                    graduation_year_snapshot__in=(None, ""),
                    then=Value("MISSING_COHORT_METADATA"),
                ),
                default=Value("COHORT_METADATA_PRESENT"),
                output_field=CharField(),
            )
        )
        .values("cohort_state")
        .annotate(count=Count("id"))
        .order_by("cohort_state")
    )

    return {
        "completion_totals": [{"metric": "completed_responses", "count": responses.count()}],
        "by_program": list(responses.values("program_snapshot").annotate(count=Count("id")).order_by("program_snapshot")),
        "by_college": list(responses.values("college_snapshot").annotate(count=Count("id")).order_by("college_snapshot")),
        "by_graduation_year": list(responses.values("graduation_year_snapshot").annotate(count=Count("id")).order_by("graduation_year_snapshot")),
        "by_eligibility_source": list(responses.values("eligibility_source").annotate(count=Count("id")).order_by("eligibility_source")),
        "cohort_readiness": cohort_readiness,
        "by_submission_channel": list(
            responses.annotate(
                submission_channel=Case(
                    When(form_invitation__isnull=True, then=Value("AUTHENTICATED")),
                    default=Value("TOKEN"),
                    output_field=CharField(),
                )
            ).values("submission_channel").annotate(count=Count("id")).order_by("submission_channel")
        ),
        "by_academic_year": list(responses.values("academic_year", "status").annotate(count=Count("id")).order_by("academic_year", "status")),
        "by_program_schedule": list(
            responses.exclude(program_schedule="").values("program_snapshot", "program_schedule")
            .annotate(count=Count("id")).order_by("program_snapshot", "program_schedule")
        ),
        "ratings_summary": responses.aggregate(total_count=Count("id")),
        "self_assessment_averages": _item_averages(SELF_ASSESSMENT_FIELDS),
        "dean_averages": _item_averages(DEAN_FIELDS),
        "faculty_averages": _item_averages(FACULTY_FIELDS),
        "curriculum_averages": _item_averages(CURRICULUM_FIELDS),
        "counselor_averages": _item_averages(COUNSELOR_FIELDS),
        "office_staff_averages": _item_averages(OFFICE_STAFF_FIELDS),
        "facilities_averages": _item_averages(FACILITIES_FIELDS),
    }


REPORTABLE_GTS_RESPONSE_STATUSES = ("SUBMITTED", "ARCHIVED")


def get_graduate_tracer_aggregates(actor, filters: dict, report_definition=None, context: AuthorityContext | None = None) -> dict:
    """Aggregates GTS outcomes without contact, employer, salary, or response JSON fields."""
    auth = context if context is not None else build_authority_context(actor)
    responses = GraduateTracerResponse.objects.filter(
        _student_profile_relation_scope(actor, "student__", office_wide=resolve_capability(auth, Capability.REPORTS_VIEW_INSTITUTION)),
        status__in=REPORTABLE_GTS_RESPONSE_STATUSES,
    )
    responses = _apply_filters(
        responses,
        filters,
        {
            "program": "program_snapshot",
            "college": "college_snapshot",
            "graduation_year": "graduation_year",
            "employment_status": "employment_status",
            "presently_employed": "presently_employed",
            "business_line": "business_line",
            "first_job_search_duration": "first_job_search_duration",
            "form_collection": "form_collection",
            "form_revision": "form_revision",
            "status": "status",
        },
    )

    def _counts(*fields):
        qs = responses
        for field in fields:
            qs = qs.exclude(**{f"{field}": ""})
        return list(qs.values(*fields).annotate(count=Count("id")).order_by(*fields))

    def _json_row_counts(list_key: str, label_key: str) -> list:
        """Aggregate counts of rows inside a structured response_json list.

        Iterates over the persisted structured lists (professional examinations,
        trainings/advance studies) and counts occurrences by their label so
        reports can summarise exam/training frequency without exposing free
        text or alumni contact details.
        """
        tally: dict = {}
        for payload in responses.values_list("response_json", flat=True):
            if not isinstance(payload, dict):
                continue
            for row in payload.get(list_key) or []:
                if not isinstance(row, dict):
                    continue
                label = (row.get(label_key) or "").strip()
                if not label:
                    continue
                key = label[:120]
                tally[key] = tally.get(key, 0) + 1
        return [{"label": label, "count": count} for label, count in sorted(tally.items())]

    return {
        "completion_totals": [{"metric": "completed_responses", "count": responses.count()}],
        "by_employment": list(responses.values("employment_status").annotate(count=Count("id")).order_by("employment_status")),
        "by_relevance": list(responses.values("first_job_related").annotate(count=Count("id")).order_by("first_job_related")),
        "by_program": list(responses.values("program_snapshot", "employment_status").annotate(count=Count("id")).order_by("program_snapshot", "employment_status")),
        "by_college": _counts("college_snapshot"),
        "by_year": _counts("graduation_year"),
        "by_presently_employed": _counts("presently_employed"),
        "by_employment_category": _counts("present_employment_category"),
        "by_business_line": _counts("business_line"),
        "by_first_job_level": _counts("first_job_level"),
        "by_current_job_level": _counts("current_job_level"),
        "by_curriculum_relevant": list(
            responses.exclude(curriculum_relevant__isnull=True)
            .values("curriculum_relevant").annotate(count=Count("id")).order_by("curriculum_relevant")
        ),
        "by_first_job_search_duration": _counts("first_job_search_duration"),
        "by_sex": _counts("sex"),
        "by_region_of_origin": _counts("region_of_origin"),
        "received_honors_summary": {
            "with_honors": responses.filter(received_honors=True).count(),
            "without_honors": responses.filter(received_honors=False).count(),
        },
        "professional_examination_counts": _json_row_counts("professional_examinations", "name"),
        "training_advanced_studies_counts": _json_row_counts("trainings_advanced_studies", "title"),
        "education_outcomes": _json_row_counts("trainings_advanced_studies", "title"),
    }


def get_form_collection_progress_aggregates(actor, filters: dict, report_definition=None, context: AuthorityContext | None = None) -> dict:
    """Aggregates collection token lifecycle counts without token identifiers."""
    auth = context if context is not None else build_authority_context(actor)
    if not (
        resolve_capability(auth, Capability.REPORTS_VIEW_INSTITUTION)
        or (
            is_gco_staff(actor)
            and any(grant.scope_mode == "OFFICE_WIDE" for grant in get_active_workflow_authority_grants(
                actor, capability=Capability.REPORTS_RUN
            ))
        )
    ):
        collections = FormCollection.objects.none()
    else:
        collections = FormCollection.objects.exclude(status="ARCHIVED")

    collection_id = filters.get("form_collection")
    if collection_id:
        collections = collections.filter(pk=collection_id)

    rows = []
    for collection in collections.order_by("name"):
        progress = (
            FormInvitation.objects.filter(collection=collection)
            .values("status")
            .annotate(count=Count("id"))
            .order_by("status")
        )
        for item in progress:
            rows.append({
                "collection_name": collection.name,
                "status": item["status"],
                "count": item["count"],
            })
    return {"collection_progress": rows}


def get_document_requests_aggregates(actor, filters: dict, report_definition=None, context: AuthorityContext | None = None) -> dict:
    """Aggregates Good Moral/document metadata counts without generated content or file details."""
    auth = context if context is not None else build_authority_context(actor)
    if not (resolve_capability(auth, Capability.REPORTS_VIEW_INSTITUTION) or is_gco_staff(actor)):
        requests = GoodMoralRequest.objects.none()
        documents = GeneratedDocument.objects.none()
    elif resolve_capability(auth, Capability.REPORTS_VIEW_INSTITUTION):
        requests = GoodMoralRequest.objects.all()
        documents = GeneratedDocument.objects.all()
    else:
        requests = GoodMoralRequest.objects.filter(_student_profile_scope(actor, office_wide=resolve_capability(auth, Capability.REPORTS_VIEW_INSTITUTION)))
        # Generated document content remains a separate protected surface;
        # GCO Reports Assistance receives request lifecycle counts only.
        documents = GeneratedDocument.objects.none()

    requests = _apply_filters(requests, filters, {"status": "status"})

    return {
        "requests_by_status": list(requests.values("status").annotate(count=Count("id")).order_by("status")),
        "documents_by_kind": list(documents.values("template_version__template__document_kind").annotate(count=Count("id")).order_by("template_version__template__document_kind")),
    }


def get_appointments_counseling_workload_aggregates(actor, filters: dict, report_definition=None, context: AuthorityContext | None = None) -> dict:
    """Aggregates appointment/session workload counts without reasons or notes."""
    auth = context if context is not None else build_authority_context(actor)
    appointments = Appointment.objects.filter(_assigned_or_student_scope(actor, office_wide=resolve_capability(auth, Capability.REPORTS_VIEW_INSTITUTION)))
    sessions = CounselingSession.objects.filter(_assigned_or_student_scope(actor, office_wide=resolve_capability(auth, Capability.REPORTS_VIEW_INSTITUTION)))
    student_profile_filters = {
        "campus": "student__student_profile__campus",
        "college": "student__student_profile__college",
        "department": "student__student_profile__department",
        "program": "student__student_profile__program",
        "year_level": "student__student_profile__year_level",
    }
    appointments = _apply_filters(appointments, filters, student_profile_filters)
    sessions = _apply_filters(sessions, filters, student_profile_filters)

    counselor = filters.get("assigned_counselor")
    if counselor:
        appointments = appointments.filter(assigned_counselor=counselor)
        sessions = sessions.filter(assigned_counselor=counselor)

    linked_sessions = sessions.filter(appointment__isnull=False)
    linked_appointments = appointments.filter(counseling_sessions__isnull=False).distinct()
    completion_statuses = (
        SessionStatusChoices.COMPLETED,
        SessionStatusChoices.FINALIZED,
        SessionStatusChoices.LOCKED,
    )

    workload_rows = [
        {"record_type": "APPOINTMENT", "assignment_state": "ASSIGNED", "count": appointments.filter(assigned_counselor__isnull=False).count()},
        {"record_type": "COUNSELING_SESSION", "assignment_state": "ASSIGNED", "count": sessions.filter(assigned_counselor__isnull=False).count()},
    ]
    journey_rows = [
        {"outcome": "APPOINTMENTS", "count": appointments.count()},
        {"outcome": "COUNSELING_SESSIONS", "count": sessions.count()},
        {"outcome": "APPOINTMENTS_WITH_LINKED_SESSION", "count": linked_appointments.count()},
        {
            "outcome": "APPOINTMENTS_WITHOUT_LINKED_SESSION",
            "count": appointments.filter(counseling_sessions__isnull=True).distinct().count(),
        },
        {"outcome": "LINKED_SESSIONS", "count": linked_sessions.count()},
        {"outcome": "UNLINKED_SESSIONS", "count": sessions.filter(appointment__isnull=True).count()},
        {"outcome": "COMPLETED_OR_FINALIZED_SESSIONS", "count": linked_sessions.filter(status__in=completion_statuses).count()},
        {"outcome": "NO_SHOW_APPOINTMENTS", "count": appointments.filter(status=AppointmentStatusChoices.NO_SHOW).count()},
        {"outcome": "CANCELLED_APPOINTMENTS", "count": appointments.filter(status__icontains="CANCEL").count()},
        {"outcome": "NO_SHOW_SESSIONS", "count": sessions.filter(status=SessionStatusChoices.NO_SHOW).count()},
        {"outcome": "CANCELLED_SESSIONS", "count": sessions.filter(status=SessionStatusChoices.CANCELLED).count()},
    ]

    return {
        "appointment_status_counts": list(appointments.values("status").annotate(count=Count("id")).order_by("status")),
        "session_status_counts": list(sessions.values("status").annotate(count=Count("id")).order_by("status")),
        "linked_session_status_counts": list(
            linked_sessions.values("status").annotate(count=Count("id")).order_by("status")
        ),
        "session_type_counts": list(sessions.values("session_type").annotate(count=Count("id")).order_by("session_type")),
        "journey_outcomes": journey_rows,
        "assignment_workload": workload_rows,
    }


def get_referrals_call_slips_aggregates(actor, filters: dict, report_definition=None, context: AuthorityContext | None = None) -> dict:
    """Aggregates referral/call-slip operational counts without reason text or remarks."""
    auth = context if context is not None else build_authority_context(actor)
    referrals = Referral.objects.filter(_assigned_or_student_scope(actor, office_wide=resolve_capability(auth, Capability.REPORTS_VIEW_INSTITUTION)))
    call_slips = CallSlip.objects.filter(_assigned_or_student_scope(actor, office_wide=resolve_capability(auth, Capability.REPORTS_VIEW_INSTITUTION)))
    student_profile_filters = {
        "campus": "student__student_profile__campus",
        "college": "student__student_profile__college",
        "department": "student__student_profile__department",
        "program": "student__student_profile__program",
        "year_level": "student__student_profile__year_level",
    }
    referrals = _apply_filters(referrals, filters, student_profile_filters)
    call_slips = _apply_filters(call_slips, filters, student_profile_filters)

    status = filters.get("status")
    if status:
        referrals = referrals.filter(status=status)
        call_slips = call_slips.filter(status=status)

    referral_actions = ReferralAction.objects.filter(referral__in=referrals)
    linked_referral_ids = call_slips.filter(
        referral__isnull=False,
    ).values("referral_id")
    verified_session_referral_ids = call_slips.filter(
        referral__isnull=False,
        appointment__counseling_sessions__isnull=False,
    ).values("referral_id")
    verified_session_referrals = referrals.filter(pk__in=verified_session_referral_ids)
    verified_session_call_slips = call_slips.filter(
        referral__isnull=False,
        appointment__counseling_sessions__isnull=False,
    )

    return {
        "referral_status_counts": list(referrals.values("status").annotate(count=Count("id")).order_by("status")),
        "referral_reason_counts": list(referrals.values("reason_category_code").annotate(count=Count("id")).order_by("reason_category_code")),
        "referral_action_outcome_counts": list(
            referral_actions.values("action_code", "outcome_code")
            .annotate(count=Count("id"))
            .order_by("action_code", "outcome_code")
        ),
        "call_slip_status_counts": list(call_slips.values("status").annotate(count=Count("id")).order_by("status")),
        "call_slip_outcomes": [
            {
                "outcome": "ISSUED",
                "count": call_slips.filter(
                    status__in=(
                        CallSlipStatusChoices.ISSUED,
                        CallSlipStatusChoices.ACKNOWLEDGED,
                        CallSlipStatusChoices.RESCHEDULE_REQUESTED,
                        CallSlipStatusChoices.ATTENDED,
                        CallSlipStatusChoices.NO_SHOW,
                        CallSlipStatusChoices.EXPIRED,
                    )
                ).count(),
            },
            {
                "outcome": "COMPLETED",
                "count": call_slips.filter(status=CallSlipStatusChoices.ATTENDED).count(),
            },
        ],
        "verified_cross_scope_outcomes": [
            {"outcome": "REFERRALS_WITH_CALL_SLIP", "count": referrals.filter(pk__in=linked_referral_ids).count()},
            {"outcome": "CALL_SLIPS_WITH_APPOINTMENT", "count": call_slips.filter(appointment__isnull=False).count()},
            {"outcome": "REFERRALS_WITH_SESSION_VIA_CALL_SLIP_APPOINTMENT", "count": verified_session_referrals.count()},
            {"outcome": "CALL_SLIPS_WITH_SESSION_VIA_APPOINTMENT", "count": verified_session_call_slips.count()},
        ],
    }


def get_public_contact_aggregates(actor, filters: dict, report_definition=None, context: AuthorityContext | None = None) -> dict:
    """Aggregates public contact queue metadata without subject/body/contact fields."""
    auth = context if context is not None else build_authority_context(actor)
    if resolve_capability(auth, Capability.REPORTS_VIEW_INSTITUTION) or (
        is_gco_staff(actor)
        and any(grant.scope_mode == "OFFICE_WIDE" for grant in get_active_workflow_authority_grants(
            actor, capability=Capability.REPORTS_RUN
        ))
    ):
        submissions = PublicContactSubmission.objects.all()
    else:
        submissions = PublicContactSubmission.objects.none()

    now = timezone.now()
    aging_cutoff = now - timedelta(days=7)
    unresolved_statuses = {
        "new", "triaged", "assigned", "response_evidence_missing",
    }
    failed_submission_ids = ContactReply.objects.filter(
        status=ContactReplyStatus.DELIVERY_FAILED,
    ).values("submission_id")
    unresolved_q = Q(status__in=unresolved_statuses) | Q(pk__in=failed_submission_ids)
    summary = {
        "new": submissions.filter(status="new").count(),
        "aging": submissions.filter(created_at__lt=aging_cutoff).filter(unresolved_q).count(),
        "assigned": submissions.filter(status="assigned").count(),
        "responded": submissions.filter(status="responded").count(),
        "duplicate": submissions.filter(status="duplicate").count(),
        "spam": submissions.filter(status="spam").count(),
        "delivery_failed": submissions.filter(pk__in=failed_submission_ids).count(),
        "evidence_missing": submissions.filter(status="response_evidence_missing").count(),
        "unresolved": submissions.filter(unresolved_q).count(),
    }
    return {
        "submissions_by_type": list(submissions.values("submission_type").annotate(count=Count("id")).order_by("submission_type")),
        "submissions_by_affiliation": list(submissions.values("affiliation").annotate(count=Count("id")).order_by("affiliation")),
        "submissions_by_status": list(submissions.values("status").annotate(count=Count("id")).order_by("status")),
        "contact_workflow_summary": summary,
        "delivery_by_state": list(
            EmailDelivery.objects.filter(template_key="contact_reply")
            .values("delivery_state").annotate(count=Count("id")).order_by("delivery_state")
        ) if resolve_capability(auth, Capability.REPORTS_VIEW_INSTITUTION) else [],
    }


def get_workflow_notifications_aggregates(actor, filters: dict, report_definition=None, context: AuthorityContext | None = None) -> dict:
    """Aggregates safe workflow/notification metadata only."""
    auth = context if context is not None else build_authority_context(actor)
    if not (
        resolve_capability(auth, Capability.REPORTS_VIEW_INSTITUTION)
        or (
            is_gco_staff(actor)
            and any(grant.scope_mode == "OFFICE_WIDE" for grant in get_active_workflow_authority_grants(
                actor, capability=Capability.REPORTS_RUN
            ))
        )
    ):
        notifications = Notification.objects.none()
        outbox = OutboxEvent.objects.none()
        idempotency = IdempotencyKey.objects.none()
    else:
        notifications = Notification.objects.all()
        outbox = OutboxEvent.objects.all()
        idempotency = IdempotencyKey.objects.all()

    return {
        "notifications_by_type": list(notifications.values("notification_type").annotate(count=Count("id")).order_by("notification_type")),
        "outbox_by_status": list(outbox.values("status").annotate(count=Count("id")).order_by("status")),
        "idempotency_by_status": list(idempotency.values("status").annotate(count=Count("id")).order_by("status")),
    }


def get_audit_report_access_aggregates(actor, filters: dict, report_definition=None, context: AuthorityContext | None = None) -> dict:
    """Aggregates report-access audit summaries without raw audit metadata."""
    auth = context if context is not None else build_authority_context(actor)
    if not resolve_capability(auth, Capability.REPORTS_VIEW_INSTITUTION):
        logs = AuditLogEntry.objects.none()
    else:
        logs = AuditLogEntry.objects.filter(event_category="DATA_ACCESS")

    return {
        "audit_actions": list(logs.values("action_type").annotate(count=Count("id")).order_by("action_type")),
        "audit_roles": list(logs.values("actor_role").annotate(count=Count("id")).order_by("actor_role")),
    }


INSTITUTIONAL_PROFILE_SAFE_AGGREGATE_KEYS = {
    "student_profile_program_totals",
    "student_profile_inventory_submission_totals",
}


def _aggregate_total(rows: list[dict]) -> int:
    total = 0
    for row in rows:
        count = row.get("count")
        if isinstance(count, int):
            total += count
    return total


def _safe_percentage(count: int, total: int) -> float:
    if not total:
        return 0.0
    return round((count / total) * 100, 2)


def get_students_profile_aggregates(actor, filters: dict, report_definition=None, context: AuthorityContext | None = None) -> dict:
    """Maps the institutional profiling report to reviewed safe aggregates.

    The historical CCMS source DOCX is used only as a structural reference. This selector does
    not read inventory JSON, raw rows, names, student numbers, control numbers,
    contact details, or narrative fields.
    """
    base_dataset = get_student_profile_inventory_aggregates(actor, filters, report_definition, context=context)
    by_program = base_dataset.get("by_program", [])
    inventory_submissions = base_dataset.get("inventory_submissions", [])

    program_total = _aggregate_total(by_program)
    submission_total = _aggregate_total(inventory_submissions)

    program_rows = []
    for row in by_program:
        count = row.get("count") or 0
        program_rows.append(
            {
                "section": "student_profile_program_totals",
                "category": "Student profile count",
                "program": row.get("program") or "Not specified",
                "count": count,
                "total_count": program_total,
                "percentage": _safe_percentage(count, program_total),
            }
        )

    submission_rows = []
    for row in inventory_submissions:
        count = row.get("count") or 0
        submission_rows.append(
            {
                "section": "inventory_submission_totals",
                "category": row.get("status") or "Not specified",
                "academic_year": row.get("academic_year") or "Not specified",
                "count": count,
                "total_count": submission_total,
                "percentage": _safe_percentage(count, submission_total),
            }
        )

    return {
        "student_profile_program_totals": program_rows,
        "student_profile_inventory_submission_totals": submission_rows,
    }
