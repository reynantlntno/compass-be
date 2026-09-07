# Project: COMPASS
# File: apps/organizations/policies.py
# Module: organizations
# Purpose: Permission policies for institutional document governance
# Domain boundary and service policy.
# Notes:
#   Head Guidance is a counselor designation, NOT a standalone role.
#   IT Admin is a technical role — NOT office/form authority alone.
#   Django framework permission flags are NOT COMPASS business authority.

from apps.access_control.authority import has_capability
from apps.access_control.capabilities import Capability
from apps.governance.runtime_config import is_policy_active


def _governance_surface_active() -> bool:
    return is_policy_active("organizations.governance")


def can_view_document_governance(user) -> bool:
    """View internal governance metadata (profiles, assets, form registry).

    Governance source content is Head Guidance-owned; technical metadata
    inspection is handled separately by the IT technical plane.
    """
    if not user or not user.is_authenticated:
        return False
    return bool(_governance_surface_active() and has_capability(user, Capability.ORGANIZATION_GOVERNANCE_MANAGE))


def can_create_governance_draft(user) -> bool:
    """Create draft institution profiles, office profiles, brand assets, or form revisions.

    Head Guidance may create drafts. IT Admin is not business-governance
    authority.
    """
    if not user or not user.is_authenticated:
        return False
    return bool(_governance_surface_active() and has_capability(user, Capability.ORGANIZATION_GOVERNANCE_MANAGE))


def can_activate_governance_record(user) -> bool:
    """Activate an official profile, asset, or form revision.

    Only Head Guidance may activate official records.
    IT Admin alone cannot activate official form/identity meaning.
    """
    if not user or not user.is_authenticated:
        return False
    return bool(_governance_surface_active() and has_capability(user, Capability.ORGANIZATION_GOVERNANCE_MANAGE))


def can_retire_governance_record(user) -> bool:
    """Retire a governance record (profile, asset, or form revision).

    Only Head Guidance may retire official records.
    """
    if not user or not user.is_authenticated:
        return False
    return bool(_governance_surface_active() and has_capability(user, Capability.ORGANIZATION_GOVERNANCE_MANAGE))


def can_archive_governance_record(user) -> bool:
    """Archive a governance record.

    Head Guidance may archive.
    """
    if not user or not user.is_authenticated:
        return False
    return bool(_governance_surface_active() and has_capability(user, Capability.ORGANIZATION_GOVERNANCE_MANAGE))


def can_upload_brand_asset(user) -> bool:
    """Upload brand asset files.

    Head Guidance owns the business asset meaning. IT technical metadata and
    delivery operations are separate capabilities.
    """
    if not user or not user.is_authenticated:
        return False
    return bool(_governance_surface_active() and has_capability(user, Capability.ORGANIZATION_GOVERNANCE_MANAGE))


def can_mark_form_revision_used(user=None, *, system_context: bool = False) -> bool:
    """Mark a form revision as used by a workflow submission.

    System-level context (automated workflow) or Head Guidance may mark used.
    """
    if system_context:
        return _governance_surface_active()
    if not user or not user.is_authenticated:
        return False
    return bool(_governance_surface_active() and has_capability(user, Capability.ORGANIZATION_GOVERNANCE_MANAGE))


def can_view_good_moral_exit_prerequisite_policy(user) -> bool:
    """Allow governed policy metadata to the existing governance audience."""
    return can_view_document_governance(user)


def can_create_good_moral_exit_prerequisite_draft(user) -> bool:
    """Use the central Policy Center owner-plane decision."""
    from apps.governance.policy_lifecycle import can_manage_policy

    return can_manage_policy(user, "good_moral.exit_prerequisite")


def can_view_office_governance(user) -> bool:
    """View safe office-configuration status and readiness metadata."""
    if not user or not user.is_authenticated:
        return False
    return bool(_governance_surface_active() and has_capability(user, Capability.ORGANIZATION_GOVERNANCE_MANAGE))


def can_prepare_office_governance(user) -> bool:
    """Prepare technical/draft governance records, never official meaning."""
    if not user or not user.is_authenticated:
        return False
    return bool(_governance_surface_active() and has_capability(user, Capability.ORGANIZATION_GOVERNANCE_MANAGE))


def can_configure_office_governance(user) -> bool:
    """Configure a previously approved record for an effective date."""
    return can_prepare_office_governance(user)


def can_approve_office_governance(user) -> bool:
    """Only Head Guidance may approve or activate official meaning."""
    if not user or not user.is_authenticated:
        return False
    return bool(_governance_surface_active() and has_capability(user, Capability.ORGANIZATION_GOVERNANCE_MANAGE))


def can_view_form_source_content(user) -> bool:
    """Retrieve a protected controlling form source, never for read-only roles."""
    if not user or not user.is_authenticated:
        return False
    return bool(_governance_surface_active() and has_capability(user, Capability.ORGANIZATION_GOVERNANCE_MANAGE))
