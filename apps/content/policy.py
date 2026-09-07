"""Domain-owned institutional content policy definition."""

from apps.common.policy import PolicyDefinition, normalize_empty_configuration, validate_empty_configuration


CONTENT_INSTITUTION_POLICY_DEFINITION = PolicyDefinition(
    key="content.institution",
    configuration_fields=(),
    normalize=normalize_empty_configuration,
    validate=validate_empty_configuration,
    owner_plane="HEAD_BUSINESS",
    sensitivity="governance",
    lifecycle_actions=("DRAFT", "PENDING_APPROVAL", "ACTIVE", "RETIRED"),
    approval_required=True,
    projection_fields=("target_type", "source_reference"),
    runtime_reader="apps.content.policies._institution_content_active",
    runtime_consumer="apps.content.policies._institution_content_active",
)
