"""Domain-owned validation for privacy retention policy configuration."""

from collections.abc import Mapping

from django.utils.dateparse import parse_datetime

from apps.common.exceptions import ValidationError
from apps.common.policy import (
    PolicyDefinition,
    normalize_empty_configuration,
    validate_empty_configuration,
)


PRIVACY_RETENTION_KEY = "privacy.retention"
PRIVACY_RETENTION_FIELDS = (
    "record_category",
    "retention_trigger",
    "retention_period_days",
    "review_due_at",
    "legal_basis",
    "owner_role",
    "legal_hold_behavior",
    "disposal_method",
    "evidence_requirement",
    "exception_status",
)


def _marker(key, *, owner_plane, sensitivity, approval_required, projection_fields, runtime_reader):
    return PolicyDefinition(
        key=key,
        configuration_fields=(),
        normalize=normalize_empty_configuration,
        validate=validate_empty_configuration,
        owner_plane=owner_plane,
        sensitivity=sensitivity,
        lifecycle_actions=("DRAFT", "PENDING_APPROVAL", "ACTIVE", "RETIRED"),
        approval_required=approval_required,
        projection_fields=projection_fields,
        runtime_reader=runtime_reader,
        runtime_consumer=runtime_reader,
    )


PRIVACY_NOTICES_POLICY_DEFINITION = _marker(
    "privacy.notices",
    owner_plane="DPO_PRIVACY",
    sensitivity="privacy",
    approval_required=True,
    projection_fields=("purpose_workflow", "notice_revision_id"),
    runtime_reader="apps.governance.runtime_config.is_policy_active",
)
PRIVACY_REVIEWER_AUTHORIZATIONS_POLICY_DEFINITION = _marker(
    "privacy.reviewer_authorizations",
    owner_plane="DPO_PRIVACY",
    sensitivity="privacy",
    approval_required=True,
    projection_fields=("authorized_user_id", "valid_from", "valid_until", "status"),
    runtime_reader="apps.governance.runtime_config.is_policy_active",
)
PRIVACY_INCIDENTS_POLICY_DEFINITION = _marker(
    "privacy.incidents",
    owner_plane="DPO_PRIVACY",
    sensitivity="privacy",
    approval_required=True,
    projection_fields=("decision_scope", "technical_containment_separate"),
    runtime_reader="apps.governance.runtime_config.is_policy_active",
)
PRIVACY_INCIDENT_CONTAINMENT_POLICY_DEFINITION = _marker(
    "privacy.incident_containment",
    owner_plane="IT_TECHNICAL",
    sensitivity="technical",
    approval_required=False,
    projection_fields=("target_type", "source_reference"),
    runtime_reader="apps.governance.runtime_config.is_policy_active",
)


def normalize_privacy_retention_configuration(configuration: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(configuration, Mapping) or set(configuration) != set(PRIVACY_RETENTION_FIELDS):
        raise ValidationError("Retention policy configuration fields are incomplete or unsupported.")
    return dict(configuration)


def validate_privacy_retention_configuration(configuration: Mapping[str, object]) -> None:
    values = normalize_privacy_retention_configuration(configuration)
    if not isinstance(values["record_category"], str) or not values["record_category"] or len(values["record_category"]) > 120:
        raise ValidationError("A bounded retention record category is required.")
    if values["retention_period_days"] is None and not values["review_due_at"]:
        raise ValidationError("Retention requires a period or review date.")
    if values["retention_period_days"] is not None and (
        isinstance(values["retention_period_days"], bool)
        or not isinstance(values["retention_period_days"], int)
        or not 1 <= values["retention_period_days"] <= 36500
    ):
        raise ValidationError("Retention period is outside the safety bounds.")
    if values["review_due_at"] and not parse_datetime(str(values["review_due_at"])):
        raise ValidationError("The retention review date is invalid.")
    if not all(
        isinstance(values[field], str) and 0 < len(values[field].strip()) <= 255
        for field in ("legal_basis", "owner_role", "legal_hold_behavior", "disposal_method", "evidence_requirement")
    ):
        raise ValidationError("Retention governance fields must be bounded and non-empty.")


def validate_privacy_retention_request(request, configuration) -> None:
    from apps.privacy.choices import RetentionTriggerChoices

    if request.target_reference != configuration["record_category"]:
        raise ValidationError("Retention policy target must match its record category.")
    if configuration["retention_trigger"] not in RetentionTriggerChoices.values:
        raise ValidationError("The retention trigger is not registered.")


PRIVACY_RETENTION_POLICY_DEFINITION = PolicyDefinition(
    key=PRIVACY_RETENTION_KEY,
    configuration_fields=PRIVACY_RETENTION_FIELDS,
    normalize=normalize_privacy_retention_configuration,
    validate=validate_privacy_retention_configuration,
    request_validator=validate_privacy_retention_request,
    owner_plane="DPO_PRIVACY",
    sensitivity="privacy",
    lifecycle_actions=("DRAFT", "PENDING_APPROVAL", "ACTIVE", "RETIRED"),
    approval_required=True,
    requires_effective_dates=True,
    projection_fields=(
        "record_category", "retention_trigger", "retention_period_days", "review_due_at",
        "legal_basis", "owner_role", "legal_hold_behavior", "disposal_method",
        "evidence_requirement", "exception_status",
    ),
    target_type="privacy.RetentionRule",
    target_required=True,
    runtime_reader="apps.governance.runtime_config.is_policy_active",
    runtime_consumer="apps.governance.runtime_config.is_policy_active",
)
