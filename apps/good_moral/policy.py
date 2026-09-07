"""Domain-owned policy definition for the Good Moral exit prerequisite."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, fields

from apps.common.exceptions import ValidationError
from apps.common.policy import PolicyDefinition


GOOD_MORAL_EXIT_PREREQUISITE_KEY = "good_moral.exit_prerequisite"
GOOD_MORAL_EXIT_PREREQUISITE_FIELDS = (
    "enforcement_enabled",
    "effective_graduation_year",
    "effective_academic_year",
    "qualifying_exit_statuses",
    "counselor_acknowledgment_required",
    "enforce_on_submission",
    "enforce_on_approval",
    "enforce_on_generation",
    "enforce_on_release",
    "grandfather_existing_requests",
    "reopen_void_behavior",
    "decision_record_reference",
)
_BOOLEAN_FIELDS = {
    "enforcement_enabled",
    "counselor_acknowledgment_required",
    "enforce_on_submission",
    "enforce_on_approval",
    "enforce_on_generation",
    "enforce_on_release",
    "grandfather_existing_requests",
}
_REOPEN_BEHAVIORS = {"BLOCK_FINAL_BOUNDARY", "ALLOW_EXISTING_ISSUED"}


@dataclass(frozen=True, slots=True)
class GoodMoralExitPrerequisiteConfiguration:
    enforcement_enabled: bool = False
    effective_graduation_year: int | None = None
    effective_academic_year: str = ""
    qualifying_exit_statuses: tuple[str, ...] = ()
    counselor_acknowledgment_required: bool = False
    enforce_on_submission: bool = False
    enforce_on_approval: bool = False
    enforce_on_generation: bool = False
    enforce_on_release: bool = False
    grandfather_existing_requests: bool = False
    reopen_void_behavior: str = "BLOCK_FINAL_BOUNDARY"
    decision_record_reference: str = ""

    def as_json(self) -> dict[str, object]:
        return {
            "enforcement_enabled": self.enforcement_enabled,
            "effective_graduation_year": self.effective_graduation_year,
            "effective_academic_year": self.effective_academic_year,
            "qualifying_exit_statuses": list(self.qualifying_exit_statuses),
            "counselor_acknowledgment_required": self.counselor_acknowledgment_required,
            "enforce_on_submission": self.enforce_on_submission,
            "enforce_on_approval": self.enforce_on_approval,
            "enforce_on_generation": self.enforce_on_generation,
            "enforce_on_release": self.enforce_on_release,
            "grandfather_existing_requests": self.grandfather_existing_requests,
            "reopen_void_behavior": self.reopen_void_behavior,
            "decision_record_reference": self.decision_record_reference,
        }


def normalize_good_moral_configuration(configuration: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(configuration, Mapping):
        raise ValidationError("Good Moral policy configuration must be an object.")
    values = dict(configuration)
    if set(values) != set(GOOD_MORAL_EXIT_PREREQUISITE_FIELDS):
        raise ValidationError("Good Moral policy configuration fields are incomplete or unsupported.")
    statuses = values["qualifying_exit_statuses"]
    if not isinstance(statuses, (list, tuple)) or any(
        not isinstance(status, str) or not status.strip() for status in statuses
    ):
        raise ValidationError("Qualifying Exit Interview statuses must be non-empty strings.")
    normalized = dict(values)
    normalized["qualifying_exit_statuses"] = [status.strip() for status in statuses]
    return normalized


def validate_good_moral_configuration(configuration: Mapping[str, object]) -> None:
    values = normalize_good_moral_configuration(configuration)
    for field_name in _BOOLEAN_FIELDS:
        if not isinstance(values[field_name], bool):
            raise ValidationError(f"{field_name} must be boolean.")
    cohort = values["effective_graduation_year"]
    if cohort is not None and (
        isinstance(cohort, bool) or not isinstance(cohort, int) or not 1900 <= cohort <= 2200
    ):
        raise ValidationError("The graduation cohort is outside the allowed range.")
    if values["enforcement_enabled"] and cohort is None:
        raise ValidationError("An enforced prerequisite requires a graduation cohort.")
    if values["enforcement_enabled"] and not values["qualifying_exit_statuses"]:
        raise ValidationError("An enforced prerequisite requires qualifying Exit Interview statuses.")
    from apps.exit_interviews.models import ExitResponseStatus

    if any(status not in ExitResponseStatus.values for status in values["qualifying_exit_statuses"]):
        raise ValidationError("The prerequisite contains an unsupported Exit Interview status.")
    academic_year = values["effective_academic_year"]
    if not isinstance(academic_year, str) or len(academic_year) > 32:
        raise ValidationError("The effective academic year is invalid.")
    if values["reopen_void_behavior"] not in _REOPEN_BEHAVIORS:
        raise ValidationError("The reopen/void behavior is not registered.")
    decision_reference = values["decision_record_reference"]
    if not isinstance(decision_reference, str) or len(decision_reference) > 255:
        raise ValidationError("The decision record reference is invalid.")
    if values["enforcement_enabled"] and not decision_reference.strip():
        raise ValidationError("An enforced prerequisite requires a decision record reference.")


GOOD_MORAL_POLICY_DEFINITION = PolicyDefinition(
    key=GOOD_MORAL_EXIT_PREREQUISITE_KEY,
    configuration_fields=GOOD_MORAL_EXIT_PREREQUISITE_FIELDS,
    normalize=normalize_good_moral_configuration,
    validate=validate_good_moral_configuration,
    configuration_defaults=GoodMoralExitPrerequisiteConfiguration().as_json(),
    owner_plane="HEAD_BUSINESS",
    sensitivity="workflow",
    lifecycle_actions=("DRAFT", "PENDING_APPROVAL", "ACTIVE", "RETIRED"),
    approval_required=True,
    requires_effective_dates=True,
    projection_fields=("enforcement_enabled", "effective_graduation_year", "effective_academic_year"),
    runtime_reader="apps.good_moral.exit_prerequisite._effective_policy",
    runtime_consumer="apps.good_moral.exit_prerequisite._effective_policy",
)
