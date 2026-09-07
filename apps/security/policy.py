"""Domain-owned validation for security upload policies."""

from collections.abc import Mapping

from apps.common.exceptions import ValidationError
from apps.common.policy import PolicyDefinition
from config.runtime_settings import (
    normalize_policy_runtime_configuration,
    validate_policy_runtime_configuration,
)


ASSESSMENT_UPLOAD_KEY = "security.assessment_upload_controls"
ASSESSMENT_UPLOAD_FIELDS = ("max_file_size_bytes", "allowed_content_types", "allowed_extensions")
_ALLOWED_TYPES = {"application/pdf", "image/jpeg", "image/png"}
_ALLOWED_EXTENSIONS = {".pdf", ".jpg", ".jpeg", ".png"}
PROTECTED_STORAGE_KEY = "security.protected_storage"
PROTECTED_STORAGE_FIELDS = ("setting_key", "value", "deployment_owned")


def _mapping(configuration, fields):
    if not isinstance(configuration, Mapping) or set(configuration) != set(fields):
        raise ValidationError("Security policy configuration fields are incomplete or unsupported.")
    return dict(configuration)


def normalize_assessment_configuration(configuration):
    values = _mapping(configuration, ASSESSMENT_UPLOAD_FIELDS)
    for field in ("allowed_content_types", "allowed_extensions"):
        if isinstance(values[field], tuple):
            values[field] = list(values[field])
    return values


def validate_assessment_configuration(configuration):
    values = normalize_assessment_configuration(configuration)
    if isinstance(values["max_file_size_bytes"], bool) or not isinstance(values["max_file_size_bytes"], int) or not 1024 <= values["max_file_size_bytes"] <= 100 * 1024 * 1024:
        raise ValidationError("Assessment upload size is outside the safety bounds.")
    if not values["allowed_content_types"] or not set(values["allowed_content_types"]).issubset(_ALLOWED_TYPES):
        raise ValidationError("Assessment upload content types are not allowlisted.")
    if not values["allowed_extensions"] or not set(values["allowed_extensions"]).issubset(_ALLOWED_EXTENSIONS):
        raise ValidationError("Assessment upload extensions are not allowlisted.")


def assert_stricter_assessment_update(previous, new_configuration):
    if int(new_configuration.get("max_file_size_bytes", 0)) > int(previous.get("max_file_size_bytes", 0)):
        raise ValidationError("Assessment upload size cannot be relaxed by a stricter-only policy.")
    if not set(new_configuration.get("allowed_content_types") or ()).issubset(set(previous.get("allowed_content_types") or ())):
        raise ValidationError("Assessment upload content types may only be narrowed.")
    if not set(new_configuration.get("allowed_extensions") or ()).issubset(set(previous.get("allowed_extensions") or ())):
        raise ValidationError("Assessment upload extensions may only be narrowed.")


ASSESSMENT_UPLOAD_POLICY_DEFINITION = PolicyDefinition(
    key=ASSESSMENT_UPLOAD_KEY,
    configuration_fields=ASSESSMENT_UPLOAD_FIELDS,
    normalize=normalize_assessment_configuration,
    validate=validate_assessment_configuration,
    configuration_defaults={
        "max_file_size_bytes": 10 * 1024 * 1024,
        "allowed_content_types": ["application/pdf", "image/jpeg", "image/png"],
        "allowed_extensions": [".pdf", ".jpg", ".jpeg", ".png"],
    },
    stricter_update=assert_stricter_assessment_update,
    owner_plane="IT_TECHNICAL",
    sensitivity="technical",
    lifecycle_actions=("DRAFT", "PENDING_APPROVAL", "ACTIVE", "RETIRED"),
    approval_required=False,
    projection_fields=("max_file_size_bytes", "allowed_content_types", "allowed_extensions"),
    target_type="",
    runtime_reader="apps.security.file_services._assessment_upload_policy",
    runtime_consumer="apps.security.file_services._assessment_upload_policy",
)


def validate_protected_storage_request(request, configuration):
    validate_policy_runtime_configuration(PROTECTED_STORAGE_KEY, configuration)
    if request.target_reference != configuration["setting_key"]:
        raise ValueError("A runtime setting policy requires a matching setting target.")


def validate_protected_storage_configuration(configuration):
    validate_policy_runtime_configuration(PROTECTED_STORAGE_KEY, configuration)


PROTECTED_STORAGE_POLICY_DEFINITION = PolicyDefinition(
    key=PROTECTED_STORAGE_KEY,
    configuration_fields=PROTECTED_STORAGE_FIELDS,
    normalize=normalize_policy_runtime_configuration,
    validate=validate_protected_storage_configuration,
    request_validator=validate_protected_storage_request,
    owner_plane="IT_TECHNICAL",
    sensitivity="technical",
    lifecycle_actions=("DRAFT", "PENDING_APPROVAL", "ACTIVE", "RETIRED"),
    approval_required=False,
    projection_fields=PROTECTED_STORAGE_FIELDS,
    target_type="governance.RuntimeSetting",
    target_required=True,
    runtime_reader="apps.governance.runtime_config.resolve_runtime_setting",
    runtime_consumer="apps.governance.runtime_config.resolve_runtime_setting",
)
