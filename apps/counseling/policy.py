"""Counseling-owned e-counseling controls definition."""

from apps.common.policy import PolicyDefinition
from config.runtime_settings import (
    normalize_policy_runtime_configuration,
    validate_policy_runtime_configuration,
)


KEY = "counseling.ecounseling_controls"
FIELDS = ("setting_key", "value", "deployment_owned")


def validate_request(request, configuration):
    validate_policy_runtime_configuration(KEY, configuration)
    if request.target_reference != configuration["setting_key"]:
        raise ValueError("A runtime setting policy requires a matching setting target.")


def validate_configuration(configuration):
    validate_policy_runtime_configuration(KEY, configuration)


ECOUNSELING_CONTROLS_POLICY_DEFINITION = PolicyDefinition(
    key=KEY,
    configuration_fields=FIELDS,
    normalize=normalize_policy_runtime_configuration,
    validate=validate_configuration,
    request_validator=validate_request,
    owner_plane="IT_TECHNICAL",
    sensitivity="technical",
    lifecycle_actions=("DRAFT", "PENDING_APPROVAL", "ACTIVE", "RETIRED"),
    approval_required=True,
    projection_fields=FIELDS,
    target_type="governance.RuntimeSetting",
    target_required=True,
    runtime_reader="apps.governance.runtime_config.resolve_runtime_setting",
    runtime_consumer="apps.governance.runtime_config.resolve_runtime_setting",
)
