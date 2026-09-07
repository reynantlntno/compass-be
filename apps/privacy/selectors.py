"""Fail-closed ORM selectors for privacy reads."""

from apps.access_control.rules import is_active_nonlegacy_actor, is_it_admin, is_student
from apps.governance.selectors import effective_policy_snapshots

from .models import DataSubjectRequest, PrivacyAcceptanceEvent, PrivacyIncident, PrivacyLegalHold
from .policies import can_manage_legal_hold, can_view_incident, can_view_request, can_view_retention, is_current_dpo
from .services import hash_safe_reference, reviewer_allowed_categories, resolve_current_notice


def current_notice(notice_identifier: str, purpose_workflow: str, *, locale: str = "en"):
    return resolve_current_notice(notice_identifier, purpose_workflow, locale=locale)


def visible_requests(actor):
    if not is_active_nonlegacy_actor(actor):
        return DataSubjectRequest.objects.none()
    if is_student(actor):
        return DataSubjectRequest.objects.filter(
            subject_reference_hash=hash_safe_reference(
                f"user:{actor.pk}", namespace="subject:privacy_request"
            )
        ).order_by("-submitted_at", "-created_at")
    if is_current_dpo(actor):
        return DataSubjectRequest.objects.all().order_by("-submitted_at", "-created_at")
    categories = reviewer_allowed_categories(actor, "request_review")
    if categories is None:
        return DataSubjectRequest.objects.all().order_by("-submitted_at", "-created_at")
    if not categories:
        return DataSubjectRequest.objects.none()
    return DataSubjectRequest.objects.filter(target_category__in=categories).order_by(
        "-submitted_at", "-created_at"
    )


def request_for_actor(actor, reference_code: str):
    row = (
        DataSubjectRequest.objects.select_related("assigned_reviewer", "protected_fulfillment_file")
        .filter(reference_code=str(reference_code or "").strip())
        .first()
    )
    return row if row is not None and can_view_request(actor, row) else None


def request_for_update(reference_code: str):
    return (
        DataSubjectRequest.objects.select_for_update()
        .filter(reference_code=str(reference_code or "").strip())
        .first()
    )


def acceptance_events_for_actor(actor, *, purpose_workflow: str = ""):
    if not is_active_nonlegacy_actor(actor):
        return PrivacyAcceptanceEvent.objects.none()
    query = PrivacyAcceptanceEvent.objects.select_related("notice_revision")
    if is_student(actor):
        query = query.filter(
            subject_reference_hash=hash_safe_reference(
                f"user:{actor.pk}", namespace=f"subject:{purpose_workflow}"
            )
        )
    elif not is_current_dpo(actor):
        return PrivacyAcceptanceEvent.objects.none()
    if purpose_workflow:
        query = query.filter(purpose_workflow=purpose_workflow)
    return query.order_by("-decided_at", "-created_at")


def visible_incidents(actor):
    if not is_active_nonlegacy_actor(actor):
        return PrivacyIncident.objects.none()
    if is_current_dpo(actor):
        return PrivacyIncident.objects.all().order_by("-discovered_at", "-created_at")
    if is_it_admin(actor):
        return (
            PrivacyIncident.objects.all().order_by("-discovered_at", "-created_at")
            if can_view_incident(actor)
            else PrivacyIncident.objects.none()
        )
    categories = reviewer_allowed_categories(actor, "incident_record")
    if categories is None:
        return PrivacyIncident.objects.all().order_by("-discovered_at", "-created_at")
    if not categories:
        return PrivacyIncident.objects.none()
    return PrivacyIncident.objects.filter(affected_record_category__in=categories).order_by(
        "-discovered_at", "-created_at"
    )


def incident_for_actor(actor, incident_code: str):
    row = PrivacyIncident.objects.filter(incident_code=str(incident_code or "").strip()).first()
    return row if row is not None and can_view_incident(
        actor, target_category=row.affected_record_category
    ) else None


def legal_holds_for_actor(actor):
    if not is_active_nonlegacy_actor(actor):
        return PrivacyLegalHold.objects.none()
    if is_current_dpo(actor):
        return PrivacyLegalHold.objects.all().order_by("-placed_at", "-created_at")
    categories = reviewer_allowed_categories(actor, "legal_hold")
    if categories is None:
        return PrivacyLegalHold.objects.all().order_by("-placed_at", "-created_at")
    if not categories:
        return PrivacyLegalHold.objects.none()
    return PrivacyLegalHold.objects.filter(record_category__in=categories).order_by(
        "-placed_at", "-created_at"
    )


def legal_hold_for_actor(actor, hold_id):
    row = PrivacyLegalHold.objects.filter(pk=hold_id).first()
    return row if row is not None and can_manage_legal_hold(
        actor, target_category=row.record_category
    ) else None


def effective_retention_policies(actor, *, at=None):
    if not can_view_retention(actor):
        return ()
    return effective_policy_snapshots(
        "privacy.retention",
        target_type="privacy.RetentionRule",
        at=at,
    )


def retention_evaluations_for_actor(actor):
    from .models import RetentionEvaluation

    if not can_view_retention(actor):
        return RetentionEvaluation.objects.none()
    return RetentionEvaluation.objects.all().order_by("-evaluated_at", "-created_at")
