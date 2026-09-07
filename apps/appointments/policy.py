"""Appointment-owned policy definitions."""

from apps.common.policy import PolicyDefinition, normalize_empty_configuration, validate_empty_configuration
from config.runtime_settings import (
    normalize_policy_runtime_configuration,
    validate_policy_runtime_configuration,
)


RUNTIME_FIELDS = ("setting_key", "value", "deployment_owned")
SCHEDULING_KEY = "appointments.scheduling_controls"


OFFICE_CLOSURES_POLICY_DEFINITION = PolicyDefinition(
    key="office.closures",
    configuration_fields=(),
    normalize=normalize_empty_configuration,
    validate=validate_empty_configuration,
    owner_plane="HEAD_BUSINESS",
    sensitivity="operational",
    lifecycle_actions=("DRAFT", "PENDING_APPROVAL", "ACTIVE", "RETIRED"),
    approval_required=True,
    requires_effective_dates=True,
    projection_fields=("target_type", "source_reference"),
    runtime_reader="apps.governance.runtime_config.is_policy_active",
    runtime_consumer="apps.governance.runtime_config.is_policy_active",
)


def validate_scheduling_request(request, configuration):
    validate_policy_runtime_configuration(SCHEDULING_KEY, configuration)
    if request.target_reference != configuration["setting_key"]:
        raise ValueError("A runtime setting policy requires a matching setting target.")


def validate_scheduling_configuration(configuration):
    validate_policy_runtime_configuration(SCHEDULING_KEY, configuration)


APPOINTMENTS_SCHEDULING_POLICY_DEFINITION = PolicyDefinition(
    key=SCHEDULING_KEY,
    configuration_fields=RUNTIME_FIELDS,
    normalize=normalize_policy_runtime_configuration,
    validate=validate_scheduling_configuration,
    request_validator=validate_scheduling_request,
    owner_plane="HEAD_BUSINESS",
    sensitivity="workflow",
    lifecycle_actions=("DRAFT", "PENDING_APPROVAL", "ACTIVE", "RETIRED"),
    approval_required=True,
    projection_fields=RUNTIME_FIELDS,
    target_type="governance.RuntimeSetting",
    target_required=True,
    runtime_reader="apps.governance.runtime_config.resolve_runtime_setting",
    runtime_consumer="apps.governance.runtime_config.resolve_runtime_setting",
)
