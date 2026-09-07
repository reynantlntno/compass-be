"""Institution-owned governance policy catalog definitions."""

from apps.common.policy import (
    PolicyDefinition,
    normalize_empty_configuration,
    validate_empty_configuration,
)


ORGANIZATIONS_GOVERNANCE_POLICY_DEFINITION = PolicyDefinition(
    key="organizations.governance",
    configuration_fields=(),
    normalize=normalize_empty_configuration,
    validate=validate_empty_configuration,
    owner_plane="HEAD_BUSINESS",
    sensitivity="governance",
    lifecycle_actions=("DRAFT", "PENDING_APPROVAL", "ACTIVE", "RETIRED"),
    approval_required=True,
    projection_fields=("target_type", "source_reference"),
    runtime_reader="apps.organizations.policies._governance_surface_active",
    runtime_consumer="apps.organizations.policies._governance_surface_active",
)
