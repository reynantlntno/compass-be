from django.utils import timezone
from apps.access_control.rules import is_active_nonlegacy_actor, is_counselor, is_gco_staff, is_it_admin, is_student
from apps.access_control.authority import has_capability, has_fixed_capability
from apps.access_control.capabilities import Capability
from apps.content.models import (
    ContentStatus,
    AudienceChoices,
    ContactReplyStatus,
    TargetScopeChoices,
    ContentPage,
    ServiceGuide,
)
from apps.access_control.scopes import get_live_counselor_coverages
from apps.governance.runtime_config import is_policy_active


def _active(user):
    return is_active_nonlegacy_actor(user)


def _content_active(user):
    return bool(_active(user) and not getattr(user, "is_superuser", False))


def _institution_content_active() -> bool:
    return is_policy_active("content.institution")


def _has_content_assignment(user, capability=Capability.CONTENT_LOCAL_VIEW, target=None) -> bool:
    return has_capability(user, capability, target=target)


def _has_front_desk_assignment(user, capability=Capability.CONTACT_QUEUE_TRIAGE, target=None) -> bool:
    return has_capability(user, capability, target=target)


def can_view_contact_queue(user) -> bool:
    """Destination gate for the safe front-desk queue projection."""
    if not _active(user):
        return False
    if has_capability(user, Capability.CONTACT_QUEUE_TRIAGE):
        return True
    if is_gco_staff(user):
        return _has_front_desk_assignment(user)
    # IT uses separate System Operations/technical metadata surfaces; the
    # front-desk queue is not an IT destination.
    return False


def can_view_content_workspace(user) -> bool:
    """Allow only active guidance actors to discover the content workspace."""
    if not _content_active(user):
        return False
    return bool(
        any(
            _has_content_assignment(user, capability)
            for capability in (
                Capability.CONTENT_LOCAL_VIEW,
                Capability.CONTENT_LOCAL_PREPARE,
                Capability.CONTENT_LOCAL_PUBLISH,
                Capability.CONTENT_LOCAL_SCHEDULE,
                Capability.CONTENT_LOCAL_ARCHIVE,
            )
        )
    )


def can_prepare_content(user, content=None) -> bool:
    """Allow draft preparation without granting publication authority.

    Counselors may prepare office content under the approved interim policy.
    GCO Staff require an explicit, date-scoped Content Management assignment.
    """
    if not _content_active(user):
        return False
    if isinstance(content, (ContentPage, ServiceGuide)):
        return bool(_institution_content_active() and has_fixed_capability(user, Capability.CONTENT_INSTITUTION_MANAGE))
    if has_capability(user, Capability.CONTENT_LOCAL_PREPARE, target=content):
        return True
    if content is None:
        return _has_content_assignment(user, Capability.CONTENT_LOCAL_PREPARE)
    return _has_content_assignment(user, Capability.CONTENT_LOCAL_PREPARE, target=content)


def can_publish_content(user, content=None) -> bool:
    """Governed global publication is fixed; local publication is account-granted."""
    if not _content_active(user):
        return False
    if isinstance(content, (ContentPage, ServiceGuide)) or content is None:
        return bool(_institution_content_active() and has_fixed_capability(user, Capability.CONTENT_INSTITUTION_MANAGE))
    if has_capability(user, Capability.CONTENT_LOCAL_PUBLISH, target=content):
        return True
    return _has_content_assignment(user, Capability.CONTENT_LOCAL_PUBLISH, target=content)


def can_schedule_content(user, content=None) -> bool:
    if not _content_active(user):
        return False
    if isinstance(content, (ContentPage, ServiceGuide)) or content is None:
        return bool(_institution_content_active() and has_fixed_capability(user, Capability.CONTENT_INSTITUTION_MANAGE))
    if has_capability(user, Capability.CONTENT_LOCAL_SCHEDULE, target=content):
        return True
    return content is not None and _has_content_assignment(
        user, Capability.CONTENT_LOCAL_SCHEDULE, target=content
    )


def can_archive_content(user, content=None) -> bool:
    if not _content_active(user):
        return False
    if isinstance(content, (ContentPage, ServiceGuide)) or content is None:
        return bool(_institution_content_active() and has_fixed_capability(user, Capability.CONTENT_INSTITUTION_MANAGE))
    if has_capability(user, Capability.CONTENT_LOCAL_ARCHIVE, target=content):
        return True
    return content is not None and _has_content_assignment(
        user, Capability.CONTENT_LOCAL_ARCHIVE, target=content
    )


def can_manage_content(user) -> bool:
    return bool(
        _content_active(user)
        and _institution_content_active()
        and has_fixed_capability(user, Capability.CONTENT_INSTITUTION_MANAGE)
    )


def can_manage_contact_submissions(user, submission=None) -> bool:
    """Return True if the user can view/work a scoped contact submission.

    Head Guidance can work every submission.  A counselor's scope is limited
    to the submission explicitly assigned to that counselor; this predicate
    is intentionally reused for full-detail and correspondence access, not
    for triage/assignment administration.
    """
    if not _active(user):
        return False
    if has_capability(user, Capability.CONTACT_QUEUE_TRIAGE, target=submission):
        return True
    if is_gco_staff(user):
        return bool(
            submission is not None
            and _has_front_desk_assignment(user, target=submission)
            and submission.assigned_to_id == getattr(user, "id", None)
        )
    if submission is not None and submission.assigned_to_id == getattr(user, "id", None):
        return is_counselor(user)
    return False


def can_manage_contact_admin(user, submission=None) -> bool:
    """Return True for Head Guidance-only triage and assignment actions."""
    return bool(
        _active(user)
        and has_capability(user, Capability.CONTACT_QUEUE_ASSIGN, target=submission)
    )


def can_view_contact_submission_metadata(user) -> bool:
    """Allow only technical metadata visibility for IT Admins."""
    if not _active(user):
        return False
    return has_fixed_capability(user, Capability.CONTENT_DELIVERY_METADATA_VIEW)


def can_view_contact_submission_full(user, submission=None) -> bool:
    """Return True for users allowed to see contact body and contact details."""
    return can_manage_contact_submissions(user, submission)


def can_manage_contact_reply(user, reply=None) -> bool:
    """Reply preparation/approval are separate named account authorities."""
    if not _active(user) or is_student(user) or is_it_admin(user):
        return False
    if reply is None:
        return bool(
            has_capability(user, Capability.CONTACT_REPLY_PREPARE)
            or has_capability(user, Capability.CONTACT_REPLY_APPROVE)
        )
    submission = getattr(reply, "submission", None)
    return bool(
        has_capability(user, Capability.CONTACT_REPLY_PREPARE, target=submission)
        or has_capability(user, Capability.CONTACT_REPLY_APPROVE, target=submission)
    )


def can_view_contact_delivery_metadata(user) -> bool:
    """IT may see delivery state/health, never contact body or recipient data."""
    return can_view_contact_submission_metadata(user)


def can_transition_contact_reply(user, reply, target_status: str) -> bool:
    if target_status in {
        ContactReplyStatus.APPROVED,
        ContactReplyStatus.REJECTED,
        ContactReplyStatus.CANCELLED,
    }:
        return bool(
            _active(user)
            and not is_student(user)
            and not is_it_admin(user)
            and has_capability(
                user,
                Capability.CONTACT_REPLY_APPROVE,
                target=getattr(reply, "submission", None),
            )
        )
    return bool(
        can_manage_contact_reply(user, reply)
        and has_capability(
            user,
            Capability.CONTACT_REPLY_PREPARE,
            target=getattr(reply, "submission", None),
        )
    )


def can_view_announcement(user, announcement) -> bool:
    """Determine if a user (guest or authenticated) can view an announcement."""
    if can_manage_content(user) and announcement.target_scope_mode == TargetScopeChoices.INSTITUTION_WIDE:
        return True

    # Guests/students/staff cannot view draft/archived
    if announcement.status in (ContentStatus.DRAFT, ContentStatus.ARCHIVED):
        return False

    # Check scheduling window if scheduled or published
    now = timezone.now()
    if announcement.publish_start and now < announcement.publish_start:
        return False
    if announcement.publish_end and now >= announcement.publish_end:
        return False

    return _check_audience(user, announcement.audience) and _target_visible(user, announcement)


def can_view_resource(user, resource) -> bool:
    """Determine if a user (guest or authenticated) can view a resource."""
    if can_manage_content(user) and resource.target_scope_mode == TargetScopeChoices.INSTITUTION_WIDE:
        return True

    # Guests/students/staff cannot view draft/archived
    if resource.status in (ContentStatus.DRAFT, ContentStatus.ARCHIVED):
        return False

    now = timezone.now()
    if resource.publish_start and now < resource.publish_start:
        return False
    if resource.publish_end and now >= resource.publish_end:
        return False

    return _check_audience(user, resource.audience) and _target_visible(user, resource)


def _target_visible(user, content) -> bool:
    """Contain local target scope inside the actor's profile/coverage/grant."""
    if content.target_scope_mode == TargetScopeChoices.INSTITUTION_WIDE:
        return True
    profile = getattr(user, "student_profile", None)
    if is_student(user):
        return bool(profile and all(
            not getattr(content, f"target_{field}", None)
            or getattr(content, f"target_{field}", None) == getattr(profile, field, None)
            for field in ("campus", "college", "department", "program")
        ))
    if is_counselor(user):
        profile_scopes = get_live_counselor_coverages(user)
        return any(all(
            not getattr(content, f"target_{field}", None)
            or not getattr(scope, field, None)
            or getattr(content, f"target_{field}", None) == getattr(scope, field, None)
            for field in ("campus", "college", "department", "program")
        ) for scope in profile_scopes.filter(is_active=True))
    if is_gco_staff(user):
        return has_capability(user, Capability.CONTENT_LOCAL_VIEW, target=content)
    return False


def _check_audience(user, audience: str) -> bool:
    """Help filter content based on the target audience and user's role."""
    if audience == AudienceChoices.PUBLIC:
        return True

    if not _active(user):
        return False

    if audience == AudienceChoices.ALL_AUTHENTICATED:
        return True

    if audience == AudienceChoices.STUDENTS:
        return is_student(user)

    if audience == AudienceChoices.STAFF:
        return is_gco_staff(user) or is_counselor(user)

    if audience == AudienceChoices.COUNSELORS:
        return is_counselor(user)

    return False
