"""Typed, framework-neutral inputs for cross-domain application workflows."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Mapping, TYPE_CHECKING
from uuid import UUID

from apps.common.contracts import to_json_object
from apps.common.exceptions import ValidationError

if TYPE_CHECKING:  # pragma: no cover - imported only by type checkers
    from apps.counseling.commands import CounselingNoteCommand


_FEEDBACK_WORKFLOW_TYPES = frozenset({
    "counseling_session",
    "call_slip",
    "referral",
    "good_moral",
})


def _stable_id(value, field_name: str) -> str:
    if value in (None, ""):
        raise ValidationError(f"{field_name} is required.")
    if isinstance(value, bool) or not isinstance(value, (str, int, UUID)):
        raise ValidationError(f"{field_name} is invalid.")
    normalized = str(value).strip()
    if not normalized or len(normalized) > 128 or any(character.isspace() for character in normalized):
        raise ValidationError(f"{field_name} is invalid.")
    return normalized


def _bounded_text(value, field_name: str, *, maximum: int = 500, required: bool = False) -> str:
    if value is not None and not isinstance(value, str):
        raise ValidationError(f"{field_name} must be a string.")
    normalized = "" if value is None else value.strip()
    if required and not normalized:
        raise ValidationError(f"{field_name} is required.")
    if len(normalized) > maximum:
        raise ValidationError(f"{field_name} is too long.")
    return normalized


def _optional_timestamp(value, field_name: str) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str) or len(value) > 40:
        raise ValidationError(f"{field_name} is invalid.")
    return value


@dataclass(frozen=True, slots=True)
class LinkedAppointmentCommand:
    appointment_id: str
    reason: str = ""
    actual_start_time: datetime | None = None
    actual_end_time: datetime | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "appointment_id", _stable_id(self.appointment_id, "appointment_id"))
        object.__setattr__(self, "reason", _bounded_text(self.reason, "reason"))


@dataclass(frozen=True, slots=True)
class LinkedCounselingSessionCommand:
    session_id: str
    reason: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "session_id", _stable_id(self.session_id, "session_id"))
        object.__setattr__(self, "reason", _bounded_text(self.reason, "reason"))


@dataclass(frozen=True, slots=True)
class CompleteCounselingSessionCommand:
    session_id: str
    note: "CounselingNoteCommand"

    def __post_init__(self) -> None:
        object.__setattr__(self, "session_id", _stable_id(self.session_id, "session_id"))
        from apps.counseling.commands import CounselingNoteCommand

        if not isinstance(self.note, CounselingNoteCommand):
            raise ValidationError("Counseling completion requires a CounselingNoteCommand.")


@dataclass(frozen=True, slots=True)
class FeedbackInvitationCommand:
    workflow_type: str
    source_id: str

    def __post_init__(self) -> None:
        workflow_type = _bounded_text(self.workflow_type, "workflow_type", maximum=64, required=True)
        if workflow_type not in _FEEDBACK_WORKFLOW_TYPES:
            raise ValidationError("The feedback workflow type is not supported.")
        object.__setattr__(self, "workflow_type", workflow_type)
        object.__setattr__(self, "source_id", _stable_id(self.source_id, "source_id"))


@dataclass(frozen=True, slots=True)
class FormRevisionUsageCommand:
    revision_id: str
    system_context: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "revision_id", _stable_id(self.revision_id, "revision_id"))
        if not isinstance(self.system_context, bool):
            raise ValidationError("system_context must be a boolean.")


@dataclass(frozen=True, slots=True)
class FormInvitationLifecycleCommand:
    invitation_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "invitation_id", _stable_id(self.invitation_id, "invitation_id"))


@dataclass(frozen=True, slots=True)
class FormSubmissionMatchCommand:
    record_id: str
    student_profile_id: str | None = None
    reason: str = ""
    expected_updated_at: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "record_id", _stable_id(self.record_id, "record_id"))
        if self.student_profile_id is not None:
            object.__setattr__(self, "student_profile_id", _stable_id(self.student_profile_id, "student_profile_id"))
        object.__setattr__(self, "reason", _bounded_text(self.reason, "reason", maximum=1000))
        object.__setattr__(self, "expected_updated_at", _optional_timestamp(self.expected_updated_at, "expected_updated_at"))


@dataclass(frozen=True, slots=True)
class InventorySupportNeedsCommand:
    snapshot_id: str
    submission_history_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "snapshot_id", _stable_id(self.snapshot_id, "snapshot_id"))
        if self.submission_history_id is not None:
            object.__setattr__(
                self,
                "submission_history_id",
                _stable_id(self.submission_history_id, "submission_history_id"),
            )


@dataclass(frozen=True, slots=True)
class InventoryReviewCommand:
    snapshot_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "snapshot_id", _stable_id(self.snapshot_id, "snapshot_id"))


@dataclass(frozen=True, slots=True)
class InventorySubmitWorkflowCommand:
    """Submit one owned inventory snapshot through the composed workflow."""

    snapshot_id: str
    privacy_acknowledged: bool = False
    expected_updated_at: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "snapshot_id", _stable_id(self.snapshot_id, "snapshot_id"))
        if not isinstance(self.privacy_acknowledged, bool):
            raise ValidationError("privacy_acknowledged must be a boolean.")
        object.__setattr__(
            self,
            "expected_updated_at",
            _optional_timestamp(self.expected_updated_at, "expected_updated_at"),
        )


@dataclass(frozen=True, slots=True)
class InventoryReopenWorkflowCommand:
    """Reopen a submitted snapshot and pause derived support needs."""

    snapshot_id: str
    reason: str
    expected_state_token: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "snapshot_id", _stable_id(self.snapshot_id, "snapshot_id"))
        from apps.inventory.validation import normalize_correction_reason

        try:
            normalized_reason = normalize_correction_reason(self.reason)
        except ValueError:
            raise ValidationError("A bounded correction reason is required.") from None
        object.__setattr__(self, "reason", normalized_reason)
        token = self.expected_state_token or ""
        if not isinstance(token, str) or len(token) > 512:
            raise ValidationError("The correction state token is invalid.")
        object.__setattr__(self, "expected_state_token", token)


@dataclass(frozen=True, slots=True)
class PrivacyAcceptanceCommand:
    notice_identifier: str
    purpose_workflow: str
    subject_reference: str
    source_route: str

    def __post_init__(self) -> None:
        for field_name in ("notice_identifier", "purpose_workflow", "subject_reference", "source_route"):
            object.__setattr__(
                self,
                field_name,
                _bounded_text(getattr(self, field_name), field_name, maximum=160, required=True),
            )


@dataclass(frozen=True, slots=True)
class DocumentRenderCommand:
    template_version_id: str
    render_context: Mapping[str, object]
    academic_year: str
    form_revision_id: str | None
    owning_app_label: str
    owning_model_name: str
    owning_object_id: str
    access_policy_key: str
    output_intent: str
    generated_for_user_id: str | None = None
    system_context: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "template_version_id", _stable_id(self.template_version_id, "template_version_id"))
        object.__setattr__(self, "render_context", MappingProxyType(to_json_object(self.render_context)))
        for field_name in (
            "academic_year",
            "owning_app_label",
            "owning_model_name",
            "owning_object_id",
            "access_policy_key",
            "output_intent",
        ):
            object.__setattr__(
                self,
                field_name,
                _bounded_text(getattr(self, field_name), field_name, maximum=160, required=True),
            )
        if self.form_revision_id is not None:
            object.__setattr__(self, "form_revision_id", _stable_id(self.form_revision_id, "form_revision_id"))
        if self.generated_for_user_id is not None:
            object.__setattr__(self, "generated_for_user_id", _stable_id(self.generated_for_user_id, "generated_for_user_id"))
        if not isinstance(self.system_context, bool):
            raise ValidationError("system_context must be a boolean.")


@dataclass(frozen=True, slots=True)
class DocumentLifecycleCommand:
    document_id: str
    reason_code: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "document_id", _stable_id(self.document_id, "document_id"))
        object.__setattr__(self, "reason_code", _bounded_text(self.reason_code, "reason_code", maximum=100))


@dataclass(frozen=True, slots=True)
class StudentActivationInvitationCommand:
    user_id: str
    source_view: str = ""
    validity_days: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "user_id", _stable_id(self.user_id, "user_id"))
        object.__setattr__(self, "source_view", _bounded_text(self.source_view, "source_view", maximum=160))
        if self.validity_days is not None and (
            isinstance(self.validity_days, bool)
            or not isinstance(self.validity_days, int)
            or self.validity_days < 1
            or self.validity_days > 366
        ):
            raise ValidationError("validity_days is invalid.")


@dataclass(frozen=True, slots=True)
class StudentActivationInvitationReissueCommand:
    """Stable-ID reissue request for the student-activation composition edge."""

    invitation_id: str
    reason: str = "manual_reissue"
    expected_updated_at: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "invitation_id", _stable_id(self.invitation_id, "invitation_id"))
        object.__setattr__(self, "reason", _bounded_text(self.reason, "reason", maximum=80, required=True))
        object.__setattr__(self, "expected_updated_at", _optional_timestamp(self.expected_updated_at, "expected_updated_at"))


@dataclass(frozen=True, slots=True)
class ContactReplyDeliveryCommand:
    delivery_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "delivery_id", _stable_id(self.delivery_id, "delivery_id"))


@dataclass(frozen=True, slots=True)
class ContactReplyDeliveryCancellationCommand:
    """Cancel one contact-reply delivery through the composition boundary."""

    delivery_id: str
    reason_code: str = "request_cancelled"

    def __post_init__(self) -> None:
        object.__setattr__(self, "delivery_id", _stable_id(self.delivery_id, "delivery_id"))
        reason_code = _bounded_text(self.reason_code, "reason_code", maximum=64, required=True)
        if reason_code not in {"request_cancelled", "workflow_cancelled"}:
            raise ValidationError("The contact-reply cancellation reason is invalid.")
        object.__setattr__(self, "reason_code", reason_code)


@dataclass(frozen=True, slots=True)
class ActivationDeliveryCancellationCommand:
    """Cancel activation deliveries for one domain's revoked invitations."""

    template_key: str
    invitation_ids: tuple[str, ...]
    reason_code: str = "invitation_revoked"

    def __post_init__(self) -> None:
        template_key = _bounded_text(self.template_key, "template_key", maximum=64, required=True)
        if template_key not in {"staff_activation", "student_activation"}:
            raise ValidationError("The activation delivery template is invalid.")
        if not isinstance(self.invitation_ids, (tuple, list)):
            raise ValidationError("invitation_ids must be a bounded sequence.")
        if not 1 <= len(self.invitation_ids) <= 500:
            raise ValidationError("invitation_ids must contain between one and five hundred IDs.")
        normalized_ids = tuple(_stable_id(value, "invitation_id") for value in self.invitation_ids)
        reason_code = _bounded_text(self.reason_code, "reason_code", maximum=64, required=True)
        if reason_code not in {"invitation_revoked", "workflow_cancelled"}:
            raise ValidationError("The activation cancellation reason is invalid.")
        object.__setattr__(self, "template_key", template_key)
        object.__setattr__(self, "invitation_ids", normalized_ids)
        object.__setattr__(self, "reason_code", reason_code)


@dataclass(frozen=True, slots=True)
class ReferralCallSlipCommand:
    """Typed input for the referral -> Call Slip composition boundary."""

    referral_reference: str
    reissued_from_reference: str | None = None
    reissue_reason_code: str = ""
    destination_code: str = "GUIDANCE_OFFICE"
    report_to_destination: str = ""
    mode: str = "ONSITE"
    student_safe_location: str = ""
    student_safe_instructions: str = ""
    office_only_remarks: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "referral_reference", _stable_id(self.referral_reference, "referral_reference"))
        if self.reissued_from_reference is not None:
            object.__setattr__(
                self,
                "reissued_from_reference",
                _stable_id(self.reissued_from_reference, "reissued_from_reference"),
            )
        for field_name in ("reissue_reason_code", "destination_code", "mode"):
            object.__setattr__(
                self,
                field_name,
                _bounded_text(getattr(self, field_name), field_name, maximum=64, required=field_name == "destination_code"),
            )
        for field_name in ("report_to_destination", "student_safe_location"):
            object.__setattr__(self, field_name, _bounded_text(getattr(self, field_name), field_name, maximum=255))
        for field_name in ("student_safe_instructions", "office_only_remarks"):
            object.__setattr__(self, field_name, _bounded_text(getattr(self, field_name), field_name, maximum=4000))
