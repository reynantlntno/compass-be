# Project: COMPASS
# File: apps/feedback/policies.py
# Module: apps.feedback
# Purpose: Fail-closed individual CSM policy boundary

from apps.access_control.rules import is_student
from apps.feedback.models import FeedbackSubmission


def can_submit_public_feedback(user) -> bool:
    """Generic public CSM is closed; service invitations are required."""
    return False


def can_submit_authenticated_feedback(user) -> bool:
    """A role alone never grants CSM intake without an owned invitation."""
    return False


def can_view_feedback(user, submission: FeedbackSubmission) -> bool:
    """Individual CSM records have no normal user-facing authorization.

    Respondent receipt access is enforced separately in the success view from
    the bound completion session or authenticated ownership. It is not a raw
    record-view entitlement and must never be reused by office workflows.
    """
    return False


def can_review_feedback(user, submission: FeedbackSubmission) -> bool:
    """No approved individual CSM review workflow exists."""
    return False


def can_assign_feedback(user) -> bool:
    """No approved individual CSM assignment workflow exists."""
    return False


def can_mark_feedback_spam(user) -> bool:
    """No approved user-facing individual CSM moderation workflow exists."""
    return False


def can_close_feedback(user, submission: FeedbackSubmission) -> bool:
    """No approved individual CSM lifecycle workflow exists."""
    return False


def can_view_feedback_free_text(user) -> bool:
    """Raw CSM free text is never available through a normal user policy."""
    return False
