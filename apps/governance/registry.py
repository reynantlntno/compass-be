"""Generic registration store for domain-owned policy definitions.

Governance deliberately does not import any domain policy module here. Each
owner registers a :class:`~apps.common.policy.PolicyDefinition` from its
``AppConfig.ready`` hook. This module stores lifecycle/catalog metadata and
provides lookup only.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence

from apps.common.policy import PolicyDefinition


_DOMAIN_POLICY_DEFINITIONS: dict[str, PolicyDefinition] = {}


def register_policy_definition(definition: PolicyDefinition) -> None:
    """Register one domain definition and fail immediately on duplicates."""

    if not isinstance(definition, PolicyDefinition):
        raise TypeError("A PolicyDefinition is required.")
    key = str(definition.key or "").strip()
    if key != definition.key:
        raise ValueError("A policy definition key must be a non-empty canonical string.")
    existing = _DOMAIN_POLICY_DEFINITIONS.get(key)
    if existing is not None:
        raise RuntimeError(f"Policy definition {key!r} was registered more than once.")
    _DOMAIN_POLICY_DEFINITIONS[key] = definition


def get_policy_definition(key: str) -> PolicyDefinition | None:
    return _DOMAIN_POLICY_DEFINITIONS.get(str(key or "").strip())


def get_policy_spec(key: str) -> PolicyDefinition | None:
    """Return catalog metadata under the historical selector name."""

    return get_policy_definition(key)


def policy_definitions() -> tuple[PolicyDefinition, ...]:
    return tuple(_DOMAIN_POLICY_DEFINITIONS[key] for key in sorted(_DOMAIN_POLICY_DEFINITIONS))


class _DefinitionSequence(Sequence[PolicyDefinition]):
    """A live read-only view so imports made before ``AppConfig.ready`` work."""

    def __iter__(self) -> Iterator[PolicyDefinition]:
        return iter(policy_definitions())

    def __len__(self) -> int:
        return len(_DOMAIN_POLICY_DEFINITIONS)

    def __getitem__(self, index):
        return policy_definitions()[index]


class _DefinitionMap(Mapping[str, PolicyDefinition]):
    def __iter__(self) -> Iterator[str]:
        return iter(sorted(_DOMAIN_POLICY_DEFINITIONS))

    def __len__(self) -> int:
        return len(_DOMAIN_POLICY_DEFINITIONS)

    def __getitem__(self, key: str) -> PolicyDefinition:
        return _DOMAIN_POLICY_DEFINITIONS[key]

    def get(self, key: str, default=None):
        return _DOMAIN_POLICY_DEFINITIONS.get(str(key or "").strip(), default)


# Catalog view names remain stable for selectors and projections. They contain
# no central specification list and are populated only by domain registration.
POLICY_SPECS = _DefinitionSequence()
POLICY_SPEC_BY_KEY = _DefinitionMap()


def validate_policy_registry() -> None:
    """Validate the complete registration surface after Django startup."""

    expected_keys = {
        "good_moral.exit_prerequisite",
        "organizations.governance",
        "documents.templates",
        "content.institution",
        "office.closures",
        "form_collection.governance",
        "reports.definitions",
        "reports.execution_controls",
        "reports.suppression",
        "privacy.notices",
        "privacy.retention",
        "privacy.reviewer_authorizations",
        "privacy.incidents",
        "privacy.incident_containment",
        "technical.configuration",
        "technical.renderer",
        "technical.backup_metadata",
        "technical.delivery_operations",
        "form_collection.invitation_controls",
        "system.feature_flags",
        "security.abuse_controls",
        "security.account_security_controls",
        "appointments.scheduling_controls",
        "counseling.ecounseling_controls",
        "security.protected_storage",
        "security.assessment_upload_controls",
        "student_import.controls",
    }
    registered_keys = set(_DOMAIN_POLICY_DEFINITIONS)
    if registered_keys != expected_keys:
        raise RuntimeError(
            "Policy registration is incomplete: "
            f"missing={sorted(expected_keys - registered_keys)}, "
            f"unexpected={sorted(registered_keys - expected_keys)}."
        )
    for definition in policy_definitions():
        if not definition.key or not definition.lifecycle_actions:
            raise RuntimeError(f"Incomplete policy catalog metadata: {definition.key!r}.")
        if "DRAFT" not in definition.lifecycle_actions or "ACTIVE" not in definition.lifecycle_actions:
            raise RuntimeError(f"Policy lifecycle metadata is incomplete: {definition.key!r}.")
        if definition.target_required and not definition.target_type:
            raise RuntimeError(f"Target-scoped policy has no target type: {definition.key!r}.")
        if not callable(definition.normalize) or not callable(definition.validate):
            raise RuntimeError(f"Policy definition has no callable schema boundary: {definition.key!r}.")
        if definition.configuration_defaults:
            try:
                definition.default_configuration()
            except (TypeError, ValueError) as exc:
                raise RuntimeError(
                    f"Policy definition has invalid owner defaults: {definition.key!r}."
                ) from exc
