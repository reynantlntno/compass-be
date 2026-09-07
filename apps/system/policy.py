"""System-owned feature flag policy definition."""

from collections.abc import Mapping

from apps.common.exceptions import ValidationError
from apps.common.policy import PolicyDefinition


KEY = "system.feature_flags"
FIELDS = ("is_enabled",)


def normalize_feature_flag_configuration(configuration: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(configuration, Mapping) or set(configuration) != set(FIELDS):
        raise ValidationError("Feature flag configuration fields are incomplete or unsupported.")
    return dict(configuration)


def validate_feature_flag_configuration(configuration):
    values = normalize_feature_flag_configuration(configuration)
    if not isinstance(values["is_enabled"], bool):
        raise ValidationError("Feature flag is_enabled must be boolean.")


FEATURE_FLAGS_POLICY_DEFINITION = PolicyDefinition(
    key=KEY,
    configuration_fields=FIELDS,
    normalize=normalize_feature_flag_configuration,
    validate=validate_feature_flag_configuration,
    configuration_defaults={"is_enabled": False},
    owner_plane="IT_TECHNICAL",
    sensitivity="technical",
    lifecycle_actions=("DRAFT", "PENDING_APPROVAL", "ACTIVE", "RETIRED"),
    approval_required=False,
    projection_fields=("is_enabled",),
    target_type="system.FeatureFlag",
    target_required=True,
    runtime_reader="apps.governance.selectors.resolve_feature_flag",
    runtime_consumer="apps.governance.selectors.resolve_feature_flag",
)
