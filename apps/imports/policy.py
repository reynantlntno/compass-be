"""Student-import domain policy definition."""

from collections.abc import Mapping

from apps.common.exceptions import ValidationError
from apps.common.policy import PolicyDefinition


KEY = "student_import.controls"
FIELDS = ("max_upload_bytes", "max_upload_rows")


def normalize_student_import_configuration(configuration: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(configuration, Mapping) or set(configuration) != set(FIELDS):
        raise ValidationError("Student-import policy configuration fields are incomplete or unsupported.")
    return dict(configuration)


def validate_student_import_configuration(configuration):
    values = normalize_student_import_configuration(configuration)
    if isinstance(values["max_upload_bytes"], bool) or not isinstance(values["max_upload_bytes"], int) or not 1024 <= values["max_upload_bytes"] <= 100 * 1024 * 1024:
        raise ValidationError("Student-import upload size is outside the safety bounds.")
    if isinstance(values["max_upload_rows"], bool) or not isinstance(values["max_upload_rows"], int) or not 1 <= values["max_upload_rows"] <= 100_000:
        raise ValidationError("Student-import row limit is outside the safety bounds.")


def assert_stricter_student_import_update(previous, new_configuration):
    if int(new_configuration.get("max_upload_bytes", 0)) > int(previous.get("max_upload_bytes", 0)):
        raise ValidationError("Student-import upload size cannot be relaxed by a stricter-only policy.")
    if int(new_configuration.get("max_upload_rows", 0)) > int(previous.get("max_upload_rows", 0)):
        raise ValidationError("Student-import row limit cannot be relaxed by a stricter-only policy.")


STUDENT_IMPORT_POLICY_DEFINITION = PolicyDefinition(
    key=KEY,
    configuration_fields=FIELDS,
    normalize=normalize_student_import_configuration,
    validate=validate_student_import_configuration,
    stricter_update=assert_stricter_student_import_update,
    configuration_defaults={
        "max_upload_bytes": 2 * 1024 * 1024,
        "max_upload_rows": 2000,
    },
    owner_plane="IT_TECHNICAL",
    sensitivity="technical",
    lifecycle_actions=("DRAFT", "PENDING_APPROVAL", "ACTIVE", "RETIRED"),
    approval_required=False,
    projection_fields=("max_upload_bytes", "max_upload_rows"),
    runtime_reader="apps.imports.onboarding._max_upload_bytes",
    runtime_consumer="apps.imports.onboarding._max_upload_bytes",
)
