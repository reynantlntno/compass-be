"""Frozen, framework-neutral commands for the Form Collection boundary.

The collection domain deliberately has no generic ``data`` command. Form
answers are validated by the selected immutable form revision before they are
wrapped in :class:`ValidatedAnswerSet` and passed to a response domain.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from apps.common.exceptions import ValidationError
from apps.common.form_values import (
    MAX_COMMAND_NOTE,
    normalize_command_id,
    normalize_command_text,
    normalize_expected_updated_at,
)


UNSET = object()


_MAX_NOTE = MAX_COMMAND_NOTE
_id = normalize_command_id
_text = normalize_command_text
_expected_updated_at = normalize_expected_updated_at


@dataclass(frozen=True, slots=True)
class InvitationRecipient:
    email: str | None = None
    control_number: str | None = None
    student_number: str | None = None
    name: str | None = None
    surname: str | None = None
    birthdate: date | None = None

    def __post_init__(self) -> None:
        for field_name in ("email", "control_number", "student_number", "name", "surname"):
            value = getattr(self, field_name)
            if value is not None:
                object.__setattr__(self, field_name, _text(value, field_name, maximum=255))
        if self.birthdate is not None and not isinstance(self.birthdate, date):
            raise ValidationError("birthdate is invalid.")
        if not any((self.email, self.control_number, self.student_number)):
            raise ValidationError("At least one recipient identifier is required.")


@dataclass(frozen=True, slots=True)
class FormCollectionCreateCommand:
    name: str
    start_at: datetime
    end_at: datetime
    form_type: str
    form_family_id: str | None = None
    form_revision_id: str | None = None
    description: str = ""
    audience: str = "CUSTOM"

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _text(self.name, "name", maximum=255, required=True))
        object.__setattr__(self, "description", _text(self.description, "description", maximum=2000))
        object.__setattr__(self, "audience", _text(self.audience, "audience", maximum=50, required=True))
        object.__setattr__(self, "form_type", _text(self.form_type, "form_type", maximum=50, required=True))
        object.__setattr__(self, "form_family_id", _id(self.form_family_id, "form_family_id"))
        object.__setattr__(self, "form_revision_id", _id(self.form_revision_id, "form_revision_id"))
        if not isinstance(self.start_at, datetime) or not isinstance(self.end_at, datetime):
            raise ValidationError("Collection dates are invalid.")
        if self.start_at >= self.end_at:
            raise ValidationError("start_at must be before end_at.")


@dataclass(frozen=True, slots=True)
class FormCollectionConfigureCommand:
    name: str | object = UNSET
    description: str | object = UNSET
    audience: str | object = UNSET
    start_at: datetime | object = UNSET
    end_at: datetime | object = UNSET
    form_family_id: str | None | object = UNSET
    form_revision_id: str | None | object = UNSET
    default_token_expiry_days: int | object = UNSET
    identity_verification_policy: str | object = UNSET
    max_uses_per_token: int | object = UNSET
    allow_draft: bool | object = UNSET
    expected_updated_at: str | None = None

    def __post_init__(self) -> None:
        for field_name in ("name", "description", "audience", "form_family_id", "form_revision_id"):
            value = getattr(self, field_name)
            if value is not UNSET:
                if field_name.endswith("_id"):
                    value = _id(value, field_name)
                else:
                    value = _text(value, field_name, maximum=2000 if field_name == "description" else 255)
                object.__setattr__(self, field_name, value)
        if self.default_token_expiry_days is not UNSET:
            if isinstance(self.default_token_expiry_days, bool) or not isinstance(self.default_token_expiry_days, int) or not 1 <= self.default_token_expiry_days <= 366:
                raise ValidationError("default_token_expiry_days is invalid.")
        if self.identity_verification_policy is not UNSET:
            object.__setattr__(self, "identity_verification_policy", _text(self.identity_verification_policy, "identity_verification_policy", maximum=64, required=True))
        if self.max_uses_per_token is not UNSET:
            if isinstance(self.max_uses_per_token, bool) or not isinstance(self.max_uses_per_token, int) or not 1 <= self.max_uses_per_token <= 100:
                raise ValidationError("max_uses_per_token is invalid.")
        if self.allow_draft is not UNSET and not isinstance(self.allow_draft, bool):
            raise ValidationError("allow_draft is invalid.")
        for field_name in ("start_at", "end_at"):
            value = getattr(self, field_name)
            if value is not UNSET and not isinstance(value, datetime):
                raise ValidationError(f"{field_name} is invalid.")
        object.__setattr__(self, "expected_updated_at", _expected_updated_at(self.expected_updated_at))

    def has(self, field: str) -> bool:
        return getattr(self, field) is not UNSET


@dataclass(frozen=True, slots=True)
class FormCollectionLifecycleCommand:
    expected_updated_at: str | None = None
    reason: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "expected_updated_at", _expected_updated_at(self.expected_updated_at))
        object.__setattr__(self, "reason", _text(self.reason, "reason", maximum=_MAX_NOTE))


@dataclass(frozen=True, slots=True)
class InvitationBatchCommand:
    name: str
    source_type: str = "MANUAL"
    total_requested: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _text(self.name, "name", maximum=255, required=True))
        object.__setattr__(self, "source_type", _text(self.source_type, "source_type", maximum=50, required=True))
        if isinstance(self.total_requested, bool) or not isinstance(self.total_requested, int) or self.total_requested < 0 or self.total_requested > 10000:
            raise ValidationError("total_requested is invalid.")


@dataclass(frozen=True, slots=True)
class InvitationIssueCommand:
    recipients: tuple[InvitationRecipient, ...]

    def __post_init__(self) -> None:
        recipients = tuple(self.recipients)
        if not recipients or len(recipients) > 10000 or not all(isinstance(item, InvitationRecipient) for item in recipients):
            raise ValidationError("recipients must be a bounded tuple of InvitationRecipient values.")
        object.__setattr__(self, "recipients", recipients)


@dataclass(frozen=True, slots=True)
class InvitationRevokeCommand:
    reason: str = ""
    expected_updated_at: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason", _text(self.reason, "reason", maximum=_MAX_NOTE))
        object.__setattr__(self, "expected_updated_at", _expected_updated_at(self.expected_updated_at))


@dataclass(frozen=True, slots=True)
class InvitationVerificationCommand:
    selector: str
    verifier: str
    control_number: str | None = None
    surname: str | None = None
    birthdate: date | None = None
    student_number: str | None = None
    email: str | None = None
    otp: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "selector", _text(self.selector, "selector", maximum=64, required=True))
        object.__setattr__(self, "verifier", _text(self.verifier, "verifier", maximum=128, required=True))
        for field_name in ("control_number", "surname", "student_number", "email", "otp"):
            value = getattr(self, field_name)
            if value is not None:
                object.__setattr__(self, field_name, _text(value, field_name, maximum=255))
        if self.birthdate is not None and not isinstance(self.birthdate, date):
            raise ValidationError("birthdate is invalid.")

    def as_verification_data(self) -> dict[str, object]:
        return {
            key: value
            for key, value in {
                "control_number": self.control_number,
                "surname": self.surname,
                "birthdate": self.birthdate,
                "student_number": self.student_number,
                "email": self.email,
                "otp": self.otp,
            }.items()
            if value is not None
        }


@dataclass(frozen=True, slots=True)
class FormInvitationLifecycleCommand:
    invitation_id: str
    expected_updated_at: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "invitation_id", _id(self.invitation_id, "invitation_id", required=True))
        object.__setattr__(self, "expected_updated_at", _expected_updated_at(self.expected_updated_at))


@dataclass(frozen=True, slots=True)
class ManualMatchDecisionCommand:
    student_profile_id: str | None = None
    reason: str = ""
    expected_updated_at: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "student_profile_id", _id(self.student_profile_id, "student_profile_id"))
        object.__setattr__(self, "reason", _text(self.reason, "reason", maximum=_MAX_NOTE))
        object.__setattr__(self, "expected_updated_at", _expected_updated_at(self.expected_updated_at))


@dataclass(frozen=True, slots=True)
class UnlinkedSubmissionCommand:
    collection_id: str
    invitation_id: str
    recipient: InvitationRecipient

    def __post_init__(self) -> None:
        object.__setattr__(self, "collection_id", _id(self.collection_id, "collection_id", required=True))
        object.__setattr__(self, "invitation_id", _id(self.invitation_id, "invitation_id", required=True))
        if not isinstance(self.recipient, InvitationRecipient):
            raise ValidationError("recipient must be an InvitationRecipient.")
