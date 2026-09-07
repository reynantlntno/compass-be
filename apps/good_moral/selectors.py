# Project: COMPASS
# File: apps/good_moral/selectors.py
# Module: apps.good_moral
# Purpose: Selector layer query definitions for Good Moral requests
# Domain boundary and service policy.

import logging
from django.db.models import QuerySet

from apps.good_moral.models import GoodMoralRequest, GoodMoralStatusChoices
from apps.good_moral.policies import (
    can_view_request,
    can_view_review_queue,
    visible_request_filter_for,
)
from apps.access_control.rules import is_active_nonlegacy_actor, is_counselor

logger = logging.getLogger(__name__)


def _request_queryset():
    return GoodMoralRequest.objects.select_related(
        "requester_user",
        "student_profile",
        "student_profile__user",
        "assigned_reviewer",
        "generated_document",
        "generated_document__template_version",
        "generated_document__template_version__template",
        "generated_document__protected_file",
    )


def get_visible_request(user, pk) -> GoodMoralRequest | None:
    """Return a request only when the actor may see its current scope."""
    try:
        request = _request_queryset().get(pk=pk)
    except (GoodMoralRequest.DoesNotExist, ValueError):
        return None

    if not can_view_request(user, request):
        return None

    return request


def list_student_own_requests(user) -> QuerySet[GoodMoralRequest]:
    """List all requests owned by the authenticated student."""
    if not is_active_nonlegacy_actor(user):
        return GoodMoralRequest.objects.none()
    return GoodMoralRequest.objects.filter(requester_user=user).order_by("-created_at")


def list_staff_review_queue(user) -> QuerySet[GoodMoralRequest]:
    """List requests scoped to the actor's operational role/status/assignment."""
    if not is_active_nonlegacy_actor(user):
        return GoodMoralRequest.objects.none()
    if not can_view_review_queue(user):
        return GoodMoralRequest.objects.none()
    return (
        GoodMoralRequest.objects
        .filter(visible_request_filter_for(user))
        .exclude(status=GoodMoralStatusChoices.DRAFT)
        .order_by("-created_at")
    )


def list_assigned_reviewer_queue(user) -> QuerySet[GoodMoralRequest]:
    """List requests currently assigned to the calling reviewer/counselor."""
    if not is_active_nonlegacy_actor(user) or not is_counselor(user):
        return GoodMoralRequest.objects.none()
    from apps.good_moral.policies import _counselor_scope_q

    return GoodMoralRequest.objects.filter(_counselor_scope_q(user)).order_by("-created_at")


def get_visible_request_by_reference(user, reference_code) -> GoodMoralRequest | None:
    """Reference-code lookup with fail-closed object-level authorization."""
    try:
        request = _request_queryset().get(reference_code=reference_code)
    except GoodMoralRequest.DoesNotExist:
        return None

    if not can_view_request(user, request):
        return None
    return request
