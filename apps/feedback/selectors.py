# Project: COMPASS
# File: apps/feedback/selectors.py
# Module: apps.feedback
# Purpose: Fail-closed raw selectors and privacy-safe CSM projections

from django.core.exceptions import PermissionDenied
from django.db.models import QuerySet

from apps.feedback.models import FeedbackSubmission


def list_feedback_for_actor(user) -> QuerySet[FeedbackSubmission]:
    """Return no raw CSM rows for any normal user-facing caller."""
    return FeedbackSubmission.objects.none()


def get_feedback_detail_for_actor(user, feedback_id: str) -> FeedbackSubmission:
    """Fail closed before looking up an individual CSM record."""
    raise PermissionDenied("Feedback submission is unavailable.")


def get_feedback_detail_for_actor_by_reference(user, reference_code: str) -> FeedbackSubmission:
    """Fail closed before resolving a reference to an individual CSM record."""
    raise PermissionDenied("Feedback submission is unavailable.")


def get_feedback_completion_stats(user) -> dict:
    """Raw-workflow statistics are not an approved CSM disclosure surface."""
    raise PermissionDenied("Feedback statistics are available only through approved aggregate reports.")


def can_view_review_queue(user) -> bool:
    """The individual CSM review queue is disabled for every user."""
    return False
