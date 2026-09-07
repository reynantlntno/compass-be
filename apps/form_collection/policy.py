"""Domain-owned validation for Form Collection invitation controls."""

from __future__ import annotations

from collections.abc import Mapping

from apps.common.exceptions import ValidationError
from apps.common.policy import (
    PolicyDefinition,
    normalize_empty_configuration,
    validate_empty_configuration,
)


FORM_COLLECTION_INVITATION_KEY = "form_collection.invitation_controls"
FORM_COLLECTION_INVITATION_FIELDS = (
    "default_token_expiry_days",
    "identity_verification_policy",
    "max_uses_per_token",
    "allow_draft",
)


FORM_COLLECTION_GOVERNANCE_POLICY_DEFINITION = PolicyDefinition(
    key="form_collection.governance",
    configuration_fields=(),
    normalize=normalize_empty_configuration,
    validate=validate_empty_configuration,
    owner_plane="HEAD_BUSINESS",
    sensitivity="governance",
    lifecycle_actions=("DRAFT", "PENDING_APPROVAL", "ACTIVE", "RETIRED"),
    approval_required=True,
    projection_fields=("target_type", "source_reference"),
    runtime_reader="apps.form_collection.policies._collection_governance_active",
    runtime_consumer="apps.form_collection.policies._collection_governance_active",
)


def normalize_form_collection_configuration(configuration: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(configuration, Mapping) or set(configuration) != set(FORM_COLLECTION_INVITATION_FIELDS):
        raise ValidationError("Form Collection policy configuration fields are incomplete or unsupported.")
    return dict(configuration)


def validate_form_collection_configuration(configuration: Mapping[str, object]) -> None:
    values = normalize_form_collection_configuration(configuration)
    if (
        isinstance(values["default_token_expiry_days"], bool)
        or not isinstance(values["default_token_expiry_days"], int)
        or not 1 <= values["default_token_expiry_days"] <= 366
    ):
        raise ValidationError("Token expiry must be between 1 and 366 days.")
    if (
        isinstance(values["max_uses_per_token"], bool)
        or not isinstance(values["max_uses_per_token"], int)
        or not 1 <= values["max_uses_per_token"] <= 100
    ):
        raise ValidationError("Token use limit must be between 1 and 100.")
    if not isinstance(values["identity_verification_policy"], str):
        raise ValidationError("The identity-verification policy is invalid.")
    if not isinstance(values["allow_draft"], bool):
        raise ValidationError("allow_draft must be boolean.")


def validate_form_collection_request(request, configuration) -> None:
    from apps.form_collection.models import FormCollection, IdentityVerificationPolicy

    if not FormCollection.objects.filter(pk=request.target_reference).exists():
        raise ValidationError("Form Collection controls must target an existing collection.")
    if configuration["identity_verification_policy"] not in IdentityVerificationPolicy.values:
        raise ValidationError("The identity-verification policy is not registered.")


def assert_stricter_form_collection_update(previous, new_configuration) -> None:
    if int(new_configuration.get("default_token_expiry_days", 0)) > int(previous.get("default_token_expiry_days", 0)):
        raise ValidationError("Form invitation expiry cannot be extended by a stricter-only policy.")
    if int(new_configuration.get("max_uses_per_token", 0)) > int(previous.get("max_uses_per_token", 0)):
        raise ValidationError("Form invitation use limits cannot be relaxed by a stricter-only policy.")
    if previous.get("allow_draft") is False and new_configuration.get("allow_draft") is True:
        raise ValidationError("A stricter-only invitation policy cannot re-enable drafts.")


FORM_COLLECTION_INVITATION_POLICY_DEFINITION = PolicyDefinition(
    key=FORM_COLLECTION_INVITATION_KEY,
    configuration_fields=FORM_COLLECTION_INVITATION_FIELDS,
    normalize=normalize_form_collection_configuration,
    validate=validate_form_collection_configuration,
    request_validator=validate_form_collection_request,
    stricter_update=assert_stricter_form_collection_update,
    configuration_defaults={
        "default_token_expiry_days": 30,
        "identity_verification_policy": "NONE",
        "max_uses_per_token": 1,
        "allow_draft": True,
    },
    owner_plane="HEAD_BUSINESS",
    sensitivity="workflow",
    lifecycle_actions=("DRAFT", "PENDING_APPROVAL", "ACTIVE", "RETIRED"),
    approval_required=True,
    requires_effective_dates=False,
    projection_fields=("default_token_expiry_days", "identity_verification_policy", "max_uses_per_token", "allow_draft"),
    target_type="form_collection.FormCollection",
    target_required=True,
    runtime_reader="apps.form_collection.services._collection_controls",
    runtime_consumer="apps.form_collection.services._collection_controls",
)
