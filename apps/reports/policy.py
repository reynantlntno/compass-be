"""Domain-owned validation for target-scoped report suppression policies."""

from __future__ import annotations

from collections.abc import Mapping

from apps.common.exceptions import ValidationError
from apps.common.policy import (
    PolicyDefinition,
    normalize_empty_configuration,
    validate_empty_configuration,
)
from config.runtime_settings import (
    normalize_policy_runtime_configuration,
    validate_policy_runtime_configuration,
)


REPORT_SUPPRESSION_KEY = "reports.suppression"
REPORTS_DEFINITIONS_KEY = "reports.definitions"
REPORTS_EXECUTION_CONTROLS_KEY = "reports.execution_controls"
RUNTIME_FIELDS = ("setting_key", "value", "deployment_owned")
REPORT_SUPPRESSION_FIELDS = (
    "report_key",
    "mode",
    "requires_suppression",
    "default_threshold",
    "threshold",
    "sensitive_categories",
)


def normalize_report_suppression_configuration(configuration: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(configuration, Mapping) or set(configuration) != set(REPORT_SUPPRESSION_FIELDS):
        raise ValidationError("Report suppression configuration fields are incomplete or unsupported.")
    values = dict(configuration)
    categories = values["sensitive_categories"]
    if isinstance(categories, tuple):
        categories = list(categories)
    if not isinstance(categories, list):
        raise ValidationError("Sensitive categories must be a JSON list.")
    values["sensitive_categories"] = categories
    return values


def validate_report_suppression_configuration(configuration: Mapping[str, object]) -> None:
    values = normalize_report_suppression_configuration(configuration)
    if not isinstance(values["report_key"], str) or not values["report_key"] or len(values["report_key"]) > 100:
        raise ValidationError("A bounded report definition key is required.")
    if not isinstance(values["mode"], str) or not values["mode"]:
        raise ValidationError("Report suppression mode is required.")
    if not isinstance(values["requires_suppression"], bool):
        raise ValidationError("Report suppression requirement must be boolean.")
    for field_name in ("default_threshold", "threshold"):
        value = values[field_name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 5:
            raise ValidationError("Report suppression thresholds cannot be lower than five.")


def validate_report_suppression_request(request, configuration) -> None:
    from apps.reports.models import ReportDefinition, allowed_suppression_modes_for_definition
    from apps.reports.suppression import normalize_suppression_categories

    definition = ReportDefinition.objects.filter(pk=request.target_reference).first()
    if definition is None or definition.key != configuration["report_key"]:
        raise ValidationError("Report suppression must target the matching report definition.")
    normalize_suppression_categories(list(configuration["sensitive_categories"]))
    allowed_modes = {
        mode.value if hasattr(mode, "value") else str(mode)
        for mode in allowed_suppression_modes_for_definition(key=definition.key, family=definition.family)
    }
    if configuration["mode"] not in allowed_modes:
        raise ValidationError("Report suppression mode is not registered.")
    if configuration["mode"] == "NONE" and configuration["requires_suppression"]:
        raise ValidationError("A suppression-required report cannot use NONE mode.")
    if configuration["mode"] != "NONE" and not configuration["requires_suppression"]:
        raise ValidationError("A suppressing report must require suppression.")


def assert_stricter_report_suppression_update(previous, new_configuration) -> None:
    for field in ("threshold", "default_threshold"):
        old_value = previous.get(field)
        new_value = new_configuration.get(field)
        if isinstance(old_value, int) and isinstance(new_value, int) and new_value < old_value:
            raise ValidationError("Report suppression policy cannot lower an existing threshold.")
    old_categories = set(previous.get("sensitive_categories") or ())
    new_categories = set(new_configuration.get("sensitive_categories") or ())
    if not old_categories.issubset(new_categories):
        raise ValidationError("Report suppression policy categories may only be added.")


REPORT_SUPPRESSION_POLICY_DEFINITION = PolicyDefinition(
    key=REPORT_SUPPRESSION_KEY,
    configuration_fields=REPORT_SUPPRESSION_FIELDS,
    normalize=normalize_report_suppression_configuration,
    validate=validate_report_suppression_configuration,
    request_validator=validate_report_suppression_request,
    stricter_update=assert_stricter_report_suppression_update,
    owner_plane="DPO_PRIVACY",
    sensitivity="privacy",
    lifecycle_actions=("DRAFT", "PENDING_APPROVAL", "ACTIVE", "RETIRED"),
    approval_required=True,
    requires_effective_dates=True,
    projection_fields=("threshold", "sensitive_categories"),
    target_type="reports.ReportDefinition",
    target_required=True,
    runtime_reader="apps.reports.suppression.resolve_report_suppression_policy",
    runtime_consumer="apps.reports.suppression.resolve_report_suppression_policy",
)


REPORTS_DEFINITIONS_POLICY_DEFINITION = PolicyDefinition(
    key=REPORTS_DEFINITIONS_KEY,
    configuration_fields=(),
    normalize=normalize_empty_configuration,
    validate=validate_empty_configuration,
    owner_plane="HEAD_BUSINESS",
    sensitivity="governance",
    lifecycle_actions=("DRAFT", "PENDING_APPROVAL", "ACTIVE", "RETIRED"),
    approval_required=True,
    projection_fields=("definition_key", "availability"),
    runtime_reader="apps.governance.runtime_config.is_policy_active",
    runtime_consumer="apps.governance.runtime_config.is_policy_active",
)


def validate_reports_execution_request(request, configuration):
    validate_policy_runtime_configuration(REPORTS_EXECUTION_CONTROLS_KEY, configuration)
    if request.target_reference != configuration["setting_key"]:
        raise ValueError("A runtime setting policy requires a matching setting target.")


def validate_reports_execution_configuration(configuration):
    validate_policy_runtime_configuration(REPORTS_EXECUTION_CONTROLS_KEY, configuration)


REPORTS_EXECUTION_CONTROLS_POLICY_DEFINITION = PolicyDefinition(
    key=REPORTS_EXECUTION_CONTROLS_KEY,
    configuration_fields=RUNTIME_FIELDS,
    normalize=normalize_policy_runtime_configuration,
    validate=validate_reports_execution_configuration,
    request_validator=validate_reports_execution_request,
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
