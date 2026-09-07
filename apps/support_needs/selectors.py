# Project: COMPASS
# File: apps/support_needs/selectors.py
# Module: apps.support_needs
# Purpose: Side-effect free query selectors to fetch and scope student support needs.

from django.db import models
from apps.access_control.selectors import get_students_visible_to
from apps.access_control.rules import is_active_nonlegacy_actor, is_counselor
from apps.support_needs.models import StudentSupportNeed, SupportNeedType
from apps.support_needs.choices import SupportNeedStatus
from apps.support_needs.policies import has_support_need_scope


def get_support_needs_visible_to(actor) -> models.QuerySet:
    """
    Get all StudentSupportNeeds visible to the actor.
    Only returns support_needs for visible student profiles.
    Students and IT Admins get none.
    """
    if not is_active_nonlegacy_actor(actor):
        return StudentSupportNeed.objects.none()

    # support_needs.scope does not grant GCO Staff a Student Support Needs workflow
    # scope; only active counselors (including Head Guidance) may enumerate
    # these records.
    if not is_counselor(actor):
        return StudentSupportNeed.objects.none()

    visible_students = get_students_visible_to(actor)
    return StudentSupportNeed.objects.filter(student_profile__in=visible_students)


def get_support_need_for_actor(actor, support_need_id) -> StudentSupportNeed | None:
    """Return one scoped record or ``None`` for missing/out-of-scope targets."""
    qs = (
        get_support_needs_visible_to(actor)
        .select_related("student_profile", "support_need_type")
    )
    return qs.filter(id=support_need_id).first()


def get_support_needs_for_student(actor, student_profile) -> models.QuerySet:
    """Get all support_needs for a specific student visible to the actor."""
    qs = get_support_needs_visible_to(actor)
    return qs.filter(student_profile=student_profile)


def get_support_need_review_queue(actor) -> models.QuerySet:
    """Get support_needs that require review (needs_review status) visible to the actor."""
    qs = get_support_needs_visible_to(actor)
    return qs.filter(status=SupportNeedStatus.NEEDS_REVIEW)


def get_support_need_type_catalog(actor) -> models.QuerySet:
    """Get all active support-need types visible to eligible counselors."""
    if not is_active_nonlegacy_actor(actor):
        return SupportNeedType.objects.none()
    if not has_support_need_scope(actor):
        return SupportNeedType.objects.none()
    return SupportNeedType.objects.filter(is_active=True)
