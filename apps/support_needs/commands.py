"""Frozen, framework-neutral commands for Student Support Needs.

Every command is bounded: stable student/type references, controlled reason
codes, allowlisted evidence fields.  Commands never accept target
reassignment, arbitrary metadata mappings, model instances, or unknown
lifecycle fields.
"""

import datetime
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from django.core.exceptions import ValidationError as DjangoValidationError

from apps.common.exceptions import ValidationError


UNSET = object()

MAX_REFERENCE_LENGTH = 64
MAX_LABEL_LENGTH = 160


def _stable_reference(value, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} is required.")
    normalized = value.strip()
    if not normalized or len(normalized) > MAX_REFERENCE_LENGTH:
        raise ValidationError(f"{field_name} is invalid.")
    return normalized


def _bounded_label(value) -> str:
    if value in (None, ""):
        return ""
    if not isinstance(value, str) or len(value.strip()) > MAX_LABEL_LENGTH:
        raise ValidationError("The source label is too long.")
    return " ".join(value.split())


def _optional_date(value, field_name: str):
    if value is None or value is UNSET:
        return value
    if isinstance(value, datetime.datetime):
        return value.date()
    if isinstance(value, datetime.date):
        return value
    raise ValidationError(f"{field_name} must be a date.")


def _optional_datetime(value, field_name: str):
    if value is None or value is UNSET:
        return value
    if isinstance(value, datetime.datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValidationError(f"{field_name} must include a timezone.")
        return value
    raise ValidationError(f"{field_name} must be a timestamp.")


def _validated_evidence(value):
    """Allowlist evidence summaries so they cannot become raw data dumps."""

    if value is None or value is UNSET:
        return value
    if not isinstance(value, dict):
        raise ValidationError("Support-need evidence must be a JSON object.")
    # Model validators own the canonical safe-key/scalar rules; convert their
    # framework error into the shared Compass hierarchy here.
    from apps.support_needs.models import validate_support_evidence_summary

    try:
        validate_support_evidence_summary(value)
    except DjangoValidationError as exc:
        raise ValidationError(
            "Support-need evidence contains an unsupported field."
        ) from exc
    return MappingProxyType(dict(value))


@dataclass(frozen=True)
class SupportNeedCreateCommand:
    """Counselor/Head manual candidate creation with bounded fields only."""

    student_profile_id: str
    support_need_type_key: str
    source_type: str
    source_snapshot_label: str = ""
    evidence_summary: Mapping[str, Any] | None = None
    effective_from: datetime.date | None = None
    effective_until: datetime.date | None = None
    review_due_at: datetime.datetime | None = None

    def __post_init__(self):
        object.__setattr__(
            self,
            "student_profile_id",
            _stable_reference(self.student_profile_id, "student_profile_id"),
        )
        object.__setattr__(
            self,
            "support_need_type_key",
            _stable_reference(self.support_need_type_key, "support_need_type_key"),
        )
        source = self.source_type
        if not isinstance(source, str) or not source.strip():
            raise ValidationError("A support-need source type is required.")
        object.__setattr__(self, "source_type", source.strip())
        object.__setattr__(self, "source_snapshot_label", _bounded_label(self.source_snapshot_label))
        object.__setattr__(self, "evidence_summary", _validated_evidence(self.evidence_summary))
        for field_name in ("effective_from", "effective_until"):
            object.__setattr__(
                self, field_name, _optional_date(getattr(self, field_name), field_name)
            )
        object.__setattr__(
            self,
            "review_due_at",
            _optional_datetime(self.review_due_at, "review_due_at"),
        )


@dataclass(frozen=True)
class SupportNeedUpdateCommand:
    """Bounded mutable operational fields only.

    The student profile, support-need type, source provenance, inventory
    snapshot, and submission-history bindings are immutable after creation
    and are deliberately absent from this command.
    """

    effective_from: object = UNSET
    effective_until: object = UNSET
    review_due_at: object = UNSET
    source_snapshot_label: object = UNSET
    evidence_summary: object = UNSET

    def __post_init__(self):
        for field_name in ("effective_from", "effective_until"):
            object.__setattr__(
                self, field_name, _optional_date(getattr(self, field_name), field_name)
            )
        object.__setattr__(
            self,
            "review_due_at",
            _optional_datetime(self.review_due_at, "review_due_at"),
        )
        label = self.source_snapshot_label
        if label is not UNSET:
            object.__setattr__(self, "source_snapshot_label", _bounded_label(label))
        if self.evidence_summary is not UNSET:
            object.__setattr__(self, "evidence_summary", _validated_evidence(self.evidence_summary))


@dataclass(frozen=True)
class SupportNeedMaterializationCommand:
    """Typed provenance command used only by Inventory orchestration."""

    student_profile_id: str
    support_need_type_id: str
    evidence_summary: Mapping[str, Any]
    source_snapshot_label: str
    source_inventory_snapshot_id: str
    source_submission_history_id: str
    source_object_id: str
    source_mapping_version: str

    def __post_init__(self):
        for field_name in (
            "student_profile_id",
            "support_need_type_id",
            "source_inventory_snapshot_id",
            "source_submission_history_id",
            "source_object_id",
            "source_mapping_version",
        ):
            object.__setattr__(
                self,
                field_name,
                _stable_reference(getattr(self, field_name), field_name),
            )
        object.__setattr__(
            self,
            "source_snapshot_label",
            _bounded_label(self.source_snapshot_label),
        )
        object.__setattr__(
            self,
            "evidence_summary",
            _validated_evidence(self.evidence_summary),
        )


@dataclass(frozen=True)
class SupportNeedInventoryReviewCommand:
    """Typed command for pausing Inventory-derived support decisions."""

    source_inventory_snapshot_id: str
    reason_code: str = "inventory_reopened"
    support_need_type_ids: tuple[str, ...] = ()

    def __post_init__(self):
        object.__setattr__(
            self,
            "source_inventory_snapshot_id",
            _stable_reference(self.source_inventory_snapshot_id, "source_inventory_snapshot_id"),
        )
        if not isinstance(self.reason_code, str) or len(self.reason_code) > 64:
            raise ValidationError("The support-need review reason is invalid.")
        normalized_ids = tuple(
            _stable_reference(value, "support_need_type_id")
            for value in self.support_need_type_ids
        )
        object.__setattr__(self, "support_need_type_ids", normalized_ids)


@dataclass(frozen=True)
class SupportNeedReasonCommand:
    """Controlled lifecycle reason code; free text is never accepted."""

    reason_code: str = ""

    def __post_init__(self):
        if self.reason_code is None:
            object.__setattr__(self, "reason_code", "")
        elif not isinstance(self.reason_code, str) or len(self.reason_code) > 64:
            raise ValidationError("The lifecycle reason code is invalid.")
