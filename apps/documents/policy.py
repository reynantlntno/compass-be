"""Domain-owned template governance definition."""

from apps.common.policy import PolicyDefinition, normalize_empty_configuration, validate_empty_configuration


DOCUMENTS_TEMPLATES_POLICY_DEFINITION = PolicyDefinition(
    key="documents.templates",
    configuration_fields=(),
    normalize=normalize_empty_configuration,
    validate=validate_empty_configuration,
    owner_plane="HEAD_BUSINESS",
    sensitivity="governance",
    lifecycle_actions=("DRAFT", "PENDING_APPROVAL", "ACTIVE", "RETIRED"),
    approval_required=True,
    projection_fields=("target_type", "source_reference"),
    runtime_reader="apps.documents.policies._template_governance_active",
    runtime_consumer="apps.documents.policies._template_governance_active",
)
