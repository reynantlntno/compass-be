"""Frozen, framework-neutral commands for appointment mutations.

Commands carry only bounded primitives, stable references, enums, dates,
timestamps, and explicitly allowlisted text fields. Django models, arbitrary
mappings, and unbounded text never cross the mutation-service boundary.
"""

from dataclasses import dataclass
from datetime import date, datetime, time

from apps.common.exceptions import ValidationError


_MAX_REFERENCE_LENGTH = 64
_MAX_REASON_LENGTH = 1000
_MAX_NOTES_LENGTH = 2000


def _bounded_text(value, field_name: str, *, maximum: int = _MAX_REASON_LENGTH, required: bool = False) -> str:
    normalized = "" if value is None else str(value).strip()
    if required and not normalized:
        raise ValidationError(f"{field_name} is required.")
    if len(normalized) > maximum:
        raise ValidationError(f"{field_name} is too long.")
    return normalized


def _stable_id(value, field_name: str) -> str | None:
    if value in (None, ""):
        return None
    normalized = str(value).strip()
    if not normalized or len(normalized) > _MAX_REFERENCE_LENGTH:
        raise ValidationError(f"{field_name} is invalid.")
    return normalized


def _action(value, field_name: str, allowed: frozenset[str]) -> str:
    normalized = _bounded_text(value, field_name, maximum=32, required=True)
    if normalized not in allowed:
        raise ValidationError(f"{field_name} is invalid.")
    return normalized


@dataclass(frozen=True)
class AppointmentRequestCommand:
    appointment_type: str = ""
    appointment_mode: str = ""
    preferred_counselor_id: str | None = None
    requested_date: date | None = None
    requested_start_time: time | None = None
    reason: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "appointment_type",
            _bounded_text(self.appointment_type, "appointment_type", maximum=32, required=True),
        )
        object.__setattr__(
            self,
            "appointment_mode",
            _bounded_text(self.appointment_mode, "appointment_mode", maximum=32, required=True),
        )
        object.__setattr__(self, "preferred_counselor_id", _stable_id(self.preferred_counselor_id, "preferred_counselor_id"))
        object.__setattr__(self, "reason", _bounded_text(self.reason, "reason", maximum=_MAX_REASON_LENGTH, required=True))
        if self.requested_date is not None and not isinstance(self.requested_date, date):
            raise ValidationError("requested_date is invalid.")
        if self.requested_start_time is not None and not isinstance(self.requested_start_time, time):
            raise ValidationError("requested_start_time is invalid.")


@dataclass(frozen=True)
class AppointmentReviewCommand:
    action: str
    assigned_counselor_id: str | None = None
    confirmed_date: date | None = None
    confirmed_start_time: time | None = None
    confirmed_end_time: time | None = None
    decline_reason: str = ""
    internal_notes: str = ""
    reason: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "action", _action(self.action, "action", frozenset({"approve", "decline"})))
        object.__setattr__(self, "assigned_counselor_id", _stable_id(self.assigned_counselor_id, "assigned_counselor_id"))
        for field_name in ("confirmed_date",):
            value = getattr(self, field_name)
            if value is not None and (
                not isinstance(value, date) or isinstance(value, datetime)
            ):
                raise ValidationError(f"{field_name} is invalid.")
        for field_name in ("confirmed_start_time", "confirmed_end_time"):
            value = getattr(self, field_name)
            if value is not None and not isinstance(value, time):
                raise ValidationError(f"{field_name} is invalid.")
        object.__setattr__(self, "decline_reason", _bounded_text(self.decline_reason, "decline_reason"))
        object.__setattr__(self, "internal_notes", _bounded_text(self.internal_notes, "internal_notes", maximum=_MAX_NOTES_LENGTH))
        object.__setattr__(self, "reason", _bounded_text(self.reason, "reason"))


@dataclass(frozen=True)
class AppointmentScheduleCommand:
    confirmed_date: date | None = None
    confirmed_start_time: time | None = None
    confirmed_end_time: time | None = None
    internal_notes: str = ""

    def __post_init__(self) -> None:
        for field_name in ("confirmed_date",):
            value = getattr(self, field_name)
            if value is not None and (
                not isinstance(value, date) or isinstance(value, datetime)
            ):
                raise ValidationError(f"{field_name} is invalid.")
        for field_name in ("confirmed_start_time", "confirmed_end_time"):
            value = getattr(self, field_name)
            if value is not None and not isinstance(value, time):
                raise ValidationError(f"{field_name} is invalid.")
        object.__setattr__(self, "internal_notes", _bounded_text(self.internal_notes, "internal_notes", maximum=_MAX_NOTES_LENGTH))


@dataclass(frozen=True)
class AppointmentCancellationCommand:
    reason: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason", _bounded_text(self.reason, "reason", required=True))


@dataclass(frozen=True)
class LateCancellationRequestCommand:
    reason: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason", _bounded_text(self.reason, "reason", required=True))


@dataclass(frozen=True)
class LateCancellationDecisionCommand:
    decision: str
    notes: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "decision", _action(self.decision, "decision", frozenset({"approve", "decline"})))
        object.__setattr__(self, "notes", _bounded_text(self.notes, "notes", maximum=_MAX_NOTES_LENGTH))


@dataclass(frozen=True)
class AppointmentCompletionCommand:
    actual_start_time: datetime | None = None
    actual_end_time: datetime | None = None

    def __post_init__(self) -> None:
        for field_name in ("actual_start_time", "actual_end_time"):
            value = getattr(self, field_name)
            if value is not None and not isinstance(value, datetime):
                raise ValidationError(f"{field_name} must be a timestamp.")


@dataclass(frozen=True)
class AppointmentNoShowCommand:
    notes: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "notes", _bounded_text(self.notes, "notes", maximum=_MAX_NOTES_LENGTH))


@dataclass(frozen=True)
class AppointmentAssignmentCommand:
    counselor_id: str
    reason: str = ""

    def __post_init__(self) -> None:
        counselor_id = _stable_id(self.counselor_id, "counselor_id")
        if counselor_id is None:
            raise ValidationError("counselor_id is required.")
        object.__setattr__(self, "counselor_id", counselor_id)
        object.__setattr__(self, "reason", _bounded_text(self.reason, "reason"))


_SCHEDULE_KINDS = frozenset({"availability_rule", "unavailable_block", "office_closure"})
_SCHEDULE_OPERATIONS = frozenset({"create", "update", "void"})
_SCHEDULE_HANDOFF_ACTIONS = frozenset({"", "save_and_handoff"})


@dataclass(frozen=True)
class ScheduleChangeCommand:
    """Typed input for availability rules, blocks, and office closures.

    ``payload()`` is an internal adapter for the record builder only; callers
    cross this boundary exclusively through the frozen command fields.
    """

    kind: str = ""
    operation: str = "create"
    target_reference: str | None = None
    counselor_id: str | None = None
    day_of_week: int | None = None
    start_time: time | None = None
    end_time: time | None = None
    mode: str = ""
    location: str = ""
    slot_duration_minutes: int | None = None
    max_appointments_per_slot: int | None = None
    block_date: date | None = None
    is_all_day: bool = False
    scope_reason: str = ""
    effective_from: date | None = None
    effective_until: date | None = None
    reason: str = ""
    request_key: str = ""
    expected_fingerprint: str = ""
    confirm: bool = False
    handoff_action: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or self.kind not in _SCHEDULE_KINDS:
            raise ValidationError("kind must identify a schedule record type.")
        if not isinstance(self.operation, str) or self.operation not in _SCHEDULE_OPERATIONS:
            raise ValidationError("operation must be create, update, or void.")
        object.__setattr__(self, "target_reference", _stable_id(self.target_reference, "target_reference"))
        object.__setattr__(self, "counselor_id", _stable_id(self.counselor_id, "counselor_id"))
        if self.day_of_week is not None and (
            isinstance(self.day_of_week, bool)
            or not isinstance(self.day_of_week, int)
            or not 0 <= self.day_of_week <= 6
        ):
            raise ValidationError("day_of_week is invalid.")
        for field_name in ("start_time", "end_time"):
            value = getattr(self, field_name)
            if value is not None and not isinstance(value, time):
                raise ValidationError(f"{field_name} is invalid.")
        for field_name in ("block_date", "effective_from", "effective_until"):
            value = getattr(self, field_name)
            if value is not None and (
                not isinstance(value, date) or isinstance(value, datetime)
            ):
                raise ValidationError(f"{field_name} is invalid.")
        for field_name in ("slot_duration_minutes", "max_appointments_per_slot"):
            value = getattr(self, field_name)
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or value <= 0
            ):
                raise ValidationError(f"{field_name} is invalid.")
        if (
            self.effective_from is not None
            and self.effective_until is not None
            and self.effective_until < self.effective_from
        ):
            raise ValidationError("effective_until cannot precede effective_from.")
        object.__setattr__(self, "mode", _bounded_text(self.mode, "mode", maximum=16))
        object.__setattr__(self, "location", _bounded_text(self.location, "location", maximum=200))
        object.__setattr__(self, "scope_reason", _bounded_text(self.scope_reason, "scope_reason", maximum=200))
        object.__setattr__(self, "reason", _bounded_text(self.reason, "reason", required=True))
        object.__setattr__(self, "request_key", _bounded_text(self.request_key, "request_key", maximum=64, required=True))
        object.__setattr__(self, "expected_fingerprint", _bounded_text(self.expected_fingerprint, "expected_fingerprint", maximum=128))
        if not isinstance(self.confirm, bool):
            raise ValidationError("confirm must be a boolean.")
        handoff_action = _bounded_text(self.handoff_action, "handoff_action", maximum=32)
        if handoff_action not in _SCHEDULE_HANDOFF_ACTIONS:
            raise ValidationError("handoff_action is invalid.")
        object.__setattr__(self, "handoff_action", handoff_action)

    def payload(self) -> dict:
        """Internal JSON-safe view consumed by the schedule record builder."""
        payload: dict = {}
        if self.day_of_week is not None:
            payload["day_of_week"] = self.day_of_week
        if self.start_time is not None:
            payload["start_time"] = self.start_time.isoformat()
        if self.end_time is not None:
            payload["end_time"] = self.end_time.isoformat()
        if self.mode:
            payload["mode"] = self.mode
        payload["location"] = self.location
        if self.slot_duration_minutes is not None:
            payload["slot_duration_minutes"] = self.slot_duration_minutes
        if self.max_appointments_per_slot is not None:
            payload["max_appointments_per_slot"] = self.max_appointments_per_slot
        if self.block_date is not None:
            payload["date"] = self.block_date.isoformat()
        payload["is_all_day"] = self.is_all_day
        if self.scope_reason:
            payload["reason"] = self.scope_reason
        if self.effective_from is not None:
            payload["effective_from"] = self.effective_from.isoformat()
        if self.effective_until is not None:
            payload["effective_until"] = self.effective_until.isoformat()
        if self.handoff_action:
            payload["handoff_action"] = self.handoff_action
        return payload
