"""Neutral contracts shared by policy owners and Governance.

The request object deliberately contains no domain-specific command type.  A
domain owns the meaning of ``configuration`` while Governance owns the
persisted lifecycle envelope and its audit trail.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Mapping


def normalize_empty_configuration(configuration: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(configuration, Mapping) or configuration:
        raise ValueError("This policy does not accept configuration fields.")
    return {}


def validate_empty_configuration(configuration: Mapping[str, object]) -> None:
    normalize_empty_configuration(configuration)


@dataclass(frozen=True, slots=True)
class PolicyChangeRequest:
    """Generic input accepted by the Governance policy lifecycle.

    ``configuration`` remains a mapping at this boundary.  The registered
    policy definition is responsible for normalizing it into a typed,
    JSON-safe shape and validating domain invariants.
    """

    key: str
    configuration: Mapping[str, object]
    effective_from: datetime | None = None
    effective_until: datetime | None = None
    source_reference: str = ""
    target_type: str = ""
    target_reference: str = ""


@dataclass(frozen=True, slots=True)
class PolicyDefinition:
    """A domain's schema/normalization/validation boundary.

    Governance stores the resulting JSON envelope and runs its lifecycle. It
    does not need to know the domain's Python model or business invariants.
    """

    key: str
    configuration_fields: tuple[str, ...]
    normalize: Callable[[Mapping[str, object]], dict[str, object]]
    validate: Callable[[Mapping[str, object]], None]
    request_validator: Callable[[PolicyChangeRequest, Mapping[str, object]], None] | None = None
    stricter_update: Callable[[Mapping[str, object], Mapping[str, object]], None] | None = None
    configuration_defaults: Mapping[str, object] = field(default_factory=dict)
    owner_plane: str = ""
    sensitivity: str = ""
    lifecycle_actions: tuple[str, ...] = ()
    approval_required: bool = True
    requires_effective_dates: bool = False
    projection_fields: tuple[str, ...] = ()
    target_type: str = ""
    target_required: bool = False
    runtime_reader: str = ""
    runtime_consumer: str = ""

    def normalize_configuration(self, configuration: Mapping[str, object]) -> dict[str, object]:
        normalized = self.normalize(configuration)
        if set(normalized) != set(self.configuration_fields):
            raise ValueError(
                f"Policy {self.key!r} returned an incomplete configuration contract."
            )
        self.validate(normalized)
        return normalized

    def default_configuration(self) -> dict[str, object]:
        """Return the owner's validated, JSON-safe configuration defaults."""

        return self.normalize_configuration(dict(self.configuration_defaults))

    def validate_request(
        self,
        request: PolicyChangeRequest,
        configuration: Mapping[str, object] | None = None,
    ) -> None:
        normalized = self.normalize_configuration(configuration or request.configuration)
        if self.request_validator is not None:
            self.request_validator(request, normalized)

    @property
    def stricter_only(self) -> bool:
        return self.stricter_update is not None

    def assert_stricter_update(
        self,
        previous: Mapping[str, object],
        new_configuration: Mapping[str, object],
    ) -> None:
        if self.stricter_update is not None:
            self.stricter_update(previous, new_configuration)
