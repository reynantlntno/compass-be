"""Domain-owned validation for abuse-control policy configuration."""

from collections.abc import Mapping

from apps.common.exceptions import ValidationError
from apps.common.policy import PolicyDefinition
from config.runtime_settings import (
    normalize_policy_runtime_configuration,
    validate_policy_runtime_configuration,
)


ABUSE_CONTROLS_KEY = "security.abuse_controls"
ABUSE_CONTROLS_FIELDS = (
    "window_seconds",
    "challenge_threshold",
    "hard_limit",
    "ip_challenge_threshold",
    "ip_hard_limit",
)
SECURITY_ACCOUNT_SECURITY_KEY = "security.account_security_controls"
RUNTIME_FIELDS = ("setting_key", "value", "deployment_owned")


def normalize_abuse_configuration(configuration: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(configuration, Mapping) or set(configuration) != set(ABUSE_CONTROLS_FIELDS):
        raise ValidationError("Abuse-control configuration fields are incomplete or unsupported.")
    return dict(configuration)


def validate_abuse_configuration(configuration: Mapping[str, object]) -> None:
    values = normalize_abuse_configuration(configuration)
    numbers = tuple(values[field] for field in ABUSE_CONTROLS_FIELDS)
    if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in numbers):
        raise ValidationError("Abuse-control thresholds must be positive integers.")
    if values["challenge_threshold"] > values["hard_limit"]:
        raise ValidationError("The challenge threshold cannot exceed the hard limit.")
    if values["ip_challenge_threshold"] > values["ip_hard_limit"]:
        raise ValidationError("The IP challenge threshold cannot exceed the IP hard limit.")


ABUSE_CONTROLS_POLICY_DEFINITION = PolicyDefinition(
    key=ABUSE_CONTROLS_KEY,
    configuration_fields=ABUSE_CONTROLS_FIELDS,
    normalize=normalize_abuse_configuration,
    validate=validate_abuse_configuration,
    configuration_defaults={
        "window_seconds": 900,
        "challenge_threshold": 3,
        "hard_limit": 5,
        "ip_challenge_threshold": 18,
        "ip_hard_limit": 60,
    },
    owner_plane="IT_TECHNICAL",
    sensitivity="technical",
    lifecycle_actions=("DRAFT", "PENDING_APPROVAL", "ACTIVE", "RETIRED"),
    approval_required=False,
    projection_fields=ABUSE_CONTROLS_FIELDS,
    target_type="account_security.AbuseAction",
    target_required=True,
    stricter_update=lambda previous, new: None,
    runtime_reader="apps.account_security.abuse_controls.get_policy",
    runtime_consumer="apps.account_security.abuse_controls.get_policy",
)


def validate_account_security_runtime_request(request, configuration):
    validate_policy_runtime_configuration(SECURITY_ACCOUNT_SECURITY_KEY, configuration)
    if request.target_reference != configuration["setting_key"]:
        raise ValueError("A runtime setting policy requires a matching setting target.")


def validate_account_security_runtime_configuration(configuration):
    validate_policy_runtime_configuration(SECURITY_ACCOUNT_SECURITY_KEY, configuration)


SECURITY_ACCOUNT_SECURITY_POLICY_DEFINITION = PolicyDefinition(
    key=SECURITY_ACCOUNT_SECURITY_KEY,
    configuration_fields=RUNTIME_FIELDS,
    normalize=normalize_policy_runtime_configuration,
    validate=validate_account_security_runtime_configuration,
    request_validator=validate_account_security_runtime_request,
    owner_plane="IT_TECHNICAL",
    sensitivity="technical",
    lifecycle_actions=("DRAFT", "PENDING_APPROVAL", "ACTIVE", "RETIRED"),
    approval_required=False,
    projection_fields=RUNTIME_FIELDS,
    target_type="governance.RuntimeSetting",
    target_required=True,
    runtime_reader="apps.governance.runtime_config.resolve_runtime_setting",
    runtime_consumer="apps.governance.runtime_config.resolve_runtime_setting",
)
