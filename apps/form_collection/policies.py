# Project: COMPASS
# File: apps/form_collection/policies.py
# Module: apps.form_collection
# Purpose: Access control and permission policy definitions for collections and form_invitations
# Domain boundary and service policy.

from apps.access_control.authority import has_capability
from apps.access_control.capabilities import Capability
from apps.access_control.rules import is_active_nonlegacy_actor
from apps.governance.runtime_config import is_policy_active


def _collection_governance_active() -> bool:
    return is_policy_active("form_collection.governance")


def can_create_collection(user) -> bool:
    """Only Head Guidance can create a collection."""
    return bool(is_active_nonlegacy_actor(user) and _collection_governance_active() and has_capability(user, Capability.FORM_COLLECTION_MANAGE))


def can_configure_collection(user, collection) -> bool:
    """Only Head Guidance can configure a collection."""
    return bool(is_active_nonlegacy_actor(user) and _collection_governance_active() and has_capability(user, Capability.FORM_COLLECTION_MANAGE))


def can_launch_collection(user, collection) -> bool:
    """Only Head Guidance can launch a collection."""
    return bool(is_active_nonlegacy_actor(user) and _collection_governance_active() and has_capability(user, Capability.FORM_COLLECTION_MANAGE))


def can_issue_invitation_batch(user, collection) -> bool:
    """Only Head Guidance can issue a token invitation_batch for a collection."""
    return bool(is_active_nonlegacy_actor(user) and _collection_governance_active() and has_capability(user, Capability.FORM_COLLECTION_MANAGE))


def can_revoke_form_invitation(user, token) -> bool:
    """Only Head Guidance can revoke a token."""
    return bool(is_active_nonlegacy_actor(user) and _collection_governance_active() and has_capability(user, Capability.FORM_COLLECTION_MANAGE))


def can_view_collection(user, collection) -> bool:
    """Collection administration metadata is a Head-owned business surface."""
    return bool(is_active_nonlegacy_actor(user) and _collection_governance_active() and has_capability(user, Capability.FORM_COLLECTION_MANAGE))


def can_view_invitation_metadata(user, token) -> bool:
    """Invitation metadata is restricted to the Head-owned collection surface."""
    return bool(is_active_nonlegacy_actor(user) and _collection_governance_active() and has_capability(user, Capability.FORM_COLLECTION_MANAGE))


def can_verify_form_invitation_public(user) -> bool:
    """Any public/anonymous user can attempt token verification."""
    return True


def can_link_unlinked_submission(user) -> bool:
    """Only Head Guidance can link unlinked records to official student accounts."""
    return bool(is_active_nonlegacy_actor(user) and _collection_governance_active() and has_capability(user, Capability.FORM_COLLECTION_MANAGE))


def can_review_manual_match(user) -> bool:
    """Only Head Guidance can review and resolve ambiguous manual matches."""
    return bool(_collection_governance_active() and has_capability(user, Capability.FORM_COLLECTION_MANAGE))


def can_change_student_lifecycle(user) -> bool:
    """Only Head Guidance can transition student lifecycles."""
    return bool(_collection_governance_active() and has_capability(user, Capability.FORM_COLLECTION_MANAGE))


def can_access_alumni_token_form(user, token) -> bool:
    """Check if the user/token allows accessing alumni-specific token form."""
    if not token:
        return False
    # Verify the token is active/valid
    return token.collection.status == "ACTIVE" and token.status in ("ISSUED", "OPENED", "VERIFIED", "DRAFT_STARTED")
