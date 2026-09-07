"""Framework-neutral lifecycle mechanics shared by bounded contexts.

The contract deliberately knows nothing about Django models or a particular
domain's states.  A domain supplies its state graph, invariants, persistence,
and side effects; this module supplies the repeatable transition checks and
evidence boundary.
"""

from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from apps.common.contracts import to_json_object
from apps.common.exceptions import LifecycleConflictError, StaleStateError, ValidationError


@dataclass(frozen=True, slots=True)
class LifecycleRequest:
    """Caller-supplied concurrency, reason, and evidence facts."""

    reason_code: str
    expected_state: str | None = None
    expected_version: object | None = None
    evidence: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        reason = str(self.reason_code or "").strip()
        if not reason or len(reason) > 80:
            raise ValidationError("A bounded lifecycle reason code is required.")
        object.__setattr__(self, "reason_code", reason)
        object.__setattr__(self, "evidence", to_json_object(dict(self.evidence or {})))


@dataclass(frozen=True, slots=True)
class LifecycleTransition:
    """Validated transition evidence returned by the shared engine."""

    contract: str
    from_state: str
    to_state: str
    actor: object | None
    reason_code: str
    evidence: dict[str, object]


class LifecycleContract:
    """Validate and execute a domain-owned state transition.

    ``persist`` is responsible for the domain's model mutation and side
    effects.  ``audit`` is called after persistence and must return a truthy
    append-only evidence object.  Callers that use a database transaction
    should pass its context manager through ``atomic``; expected state/version
    checks then happen inside the same transaction as the optional ``lock``.
    """

    def __init__(self, name: str, transitions: Mapping[str, set[str] | tuple[str, ...] | list[str]]):
        self.name = str(name or "").strip()
        if not self.name:
            raise ValueError("A lifecycle contract name is required.")
        self.transitions = {
            str(source): frozenset(str(target) for target in targets)
            for source, targets in transitions.items()
        }

    def validate_transition(self, from_state: str, to_state: str) -> None:
        allowed = self.transitions.get(str(from_state), frozenset())
        if str(to_state) not in allowed:
            raise LifecycleConflictError(
                f"{self.name} does not allow {from_state!r} -> {to_state!r}."
            )

    @staticmethod
    def validate_expected(
        *,
        current_state: str,
        current_version: object | None,
        request: LifecycleRequest,
    ) -> None:
        if request.expected_state is not None and str(request.expected_state) != str(current_state):
            raise StaleStateError()
        if request.expected_version is not None and request.expected_version != current_version:
            raise StaleStateError()

    def execute(
        self,
        target: object,
        *,
        to_state: str,
        request: LifecycleRequest,
        actor: object | None = None,
        state_getter: Callable[[object], str] = lambda value: str(getattr(value, "status")),
        version_getter: Callable[[object], object | None] = lambda value: getattr(value, "updated_at", None),
        lock: Callable[[object], object] | None = None,
        authorize: Callable[[object | None, object, LifecycleRequest], None] | None = None,
        invariant: Callable[[object, str, LifecycleRequest], None] | None = None,
        persist: Callable[[object, str, LifecycleRequest, object | None], None] | None = None,
        audit: Callable[[LifecycleTransition], object] | None = None,
        atomic: Callable[[], Any] | None = None,
    ) -> LifecycleTransition:
        context = atomic() if atomic else nullcontext()
        with context:
            current = lock(target) if lock else target
            from_state = state_getter(current)
            self.validate_expected(
                current_state=from_state,
                current_version=version_getter(current),
                request=request,
            )
            self.validate_transition(from_state, to_state)
            if authorize:
                authorize(actor, current, request)
            if invariant:
                invariant(current, to_state, request)
            if persist:
                persist(current, to_state, request, actor)
            transition = LifecycleTransition(
                contract=self.name,
                from_state=str(from_state),
                to_state=str(to_state),
                actor=actor,
                reason_code=request.reason_code,
                evidence=dict(request.evidence),
            )
            if audit and not audit(transition):
                raise LifecycleConflictError("Lifecycle audit evidence could not be recorded.")
            return transition
