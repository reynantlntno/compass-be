"""Framework-neutral, immutable command boundary for privacy workflows."""

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol


class CommandInput(Protocol):
    """Marker protocol for validated, immutable domain command DTOs."""


@dataclass(frozen=True, slots=True)
class PrivacyReviewerAuthorizationCommand:
    """DPO-issued reviewer scope owned by the privacy domain."""

    authorized_user_id: str
    scopes: tuple[str, ...]
    categories: tuple[str, ...]
    valid_from: datetime
    valid_until: datetime | None = None
    source_reference: str = ""


@dataclass(frozen=True, slots=True)
class PrivacyNoticeAcceptanceCommand:
    notice_identifier: str
    purpose_workflow: str
    locale: str = "en"
    decision: str = "ACCEPTED"
    subject_reference: str = ""
    token: str = ""
    session_reference: str = ""


@dataclass(frozen=True, slots=True)
class DataSubjectRequestCreateCommand:
    request_type: str
    description: str = ""
    target_category: str = ""
    target_record_reference: str = ""
    staff_assisted: bool = False
    subject_reference: str = ""


@dataclass(frozen=True, slots=True)
class PrivacyRequestAssignmentCommand:
    reviewer_id: str


@dataclass(frozen=True, slots=True)
class PrivacyRequestTransitionCommand:
    decision: str
    reason_code: str
    decision_notes: str = ""
    identity_verified: bool = False


@dataclass(frozen=True, slots=True)
class PrivacyRequestFulfillmentCommand:
    protected_file_id: str


@dataclass(frozen=True, slots=True)
class PrivacyIncidentCreateCommand:
    category: str
    severity: str
    affected_workflow: str = ""
    affected_record_category: str = ""
    containment_code: str = ""
    safe_metadata: tuple[tuple[str, str | int], ...] = ()
    notification_decision: str = "PENDING"
    related_event_references: tuple[str, ...] = ()
    safe_summary_code: str = ""

    def metadata_dict(self) -> dict:
        return dict(self.safe_metadata)


@dataclass(frozen=True, slots=True)
class PrivacyIncidentTransitionCommand:
    to_status: str
    reason_code: str
    safe_evidence: tuple[tuple[str, str | int], ...] = ()
    notification_decision: str = ""

    def evidence_dict(self) -> dict:
        return dict(self.safe_evidence)


@dataclass(frozen=True, slots=True)
class PrivacyLegalHoldCreateCommand:
    record_category: str
    reason_code: str
    record_reference: str = ""
    safe_reference: str = ""


@dataclass(frozen=True, slots=True)
class PrivacyLegalHoldReleaseCommand:
    reason_code: str


@dataclass(frozen=True, slots=True)
class RetentionEvaluationCommand:
    environment: str = ""


@dataclass(frozen=True, slots=True)
class PrivacyNoticeRevisionCommand:
    notice_identifier: str
    version: str
    body_markdown: str
    source_reference: str
    effective_at: datetime | None = None
    locale: str = "en"
    purpose_workflow: str = ""
    supersedes_id: str = ""


@dataclass(frozen=True, slots=True)
class PrivacyNoticeRevisionApprovalCommand:
    """Approve one immutable notice revision with bounded evidence."""

    approval_reference: str


@dataclass(frozen=True, slots=True)
class PrivacyNoticeRevisionRetirementCommand:
    """Retire one notice revision without changing its historical content."""

    reason_code: str


@dataclass(frozen=True, slots=True)
class PrivacyWorkflowBindingCommand:
    purpose_workflow: str
    notice_revision_id: str = ""
    status: str = "BLOCKED"
    required: bool = True
    source_reference: str = ""
    block_reason: str = ""
