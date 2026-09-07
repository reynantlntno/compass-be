"""Frozen commands for workflow-specific document operations."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping
from uuid import UUID

from apps.common.contracts import to_json_object
from apps.common.exceptions import ValidationError


def _id(value, field: str) -> str:
    if value in (None, "") or isinstance(value, bool) or not isinstance(value, (str, int, UUID)):
        raise ValidationError(f"{field} is required.")
    normalized = str(value).strip()
    if not normalized or len(normalized) > 128 or any(char.isspace() for char in normalized):
        raise ValidationError(f"{field} is invalid.")
    return normalized


def _text(value, field: str, maximum: int, *, required: bool = False) -> str:
    if value is not None and not isinstance(value, str):
        raise ValidationError(f"{field} must be a string.")
    normalized = "" if value is None else value.strip()
    if required and not normalized:
        raise ValidationError(f"{field} is required.")
    if len(normalized) > maximum:
        raise ValidationError(f"{field} is too long.")
    return normalized


def _json_mapping(value, field: str) -> Mapping:
    if value is None:
        return MappingProxyType({})
    if not isinstance(value, Mapping):
        raise ValidationError(f"{field} must be a JSON object.")
    try:
        return MappingProxyType(to_json_object(value))
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{field} contains unsupported values.") from exc


@dataclass(frozen=True, slots=True)
class DocumentTemplateDraftCommand:
    stable_key: str
    display_name: str
    document_kind: str
    default_output_format: str = "HTML"
    retention_classification: str = "STANDARD"
    access_policy_key: str = ""
    description: str = ""
    source_notes: str = ""
    related_form_family_id: str | None = None
    owner_office_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "stable_key", _text(self.stable_key, "stable_key", 80, required=True))
        object.__setattr__(self, "display_name", _text(self.display_name, "display_name", 255, required=True))
        object.__setattr__(self, "document_kind", _text(self.document_kind, "document_kind", 30, required=True))
        object.__setattr__(self, "default_output_format", _text(self.default_output_format, "default_output_format", 10, required=True))
        object.__setattr__(self, "retention_classification", _text(self.retention_classification, "retention_classification", 30, required=True))
        object.__setattr__(self, "access_policy_key", _text(self.access_policy_key, "access_policy_key", 100))
        object.__setattr__(self, "description", _text(self.description, "description", 4000))
        object.__setattr__(self, "source_notes", _text(self.source_notes, "source_notes", 4000))
        for field in ("related_form_family_id", "owner_office_id"):
            value = getattr(self, field)
            object.__setattr__(self, field, None if value in (None, "") else _id(value, field))


@dataclass(frozen=True, slots=True)
class DocumentTemplateVersionDraftCommand:
    template_id: str
    version_label: str
    template_path: str
    stylesheet_path: str = ""
    related_form_revision_id: str | None = None
    internal_template_version: str = "1"
    renderer_backend: str = "HTML_ONLY"
    output_format: str = "HTML"
    page_size: str = "LETTER"
    page_orientation: str = "portrait"
    page_margins: Mapping | None = None
    required_context_schema: Mapping | None = None
    source_notes: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "template_id", _id(self.template_id, "template_id"))
        for field, maximum in (
            ("version_label", 50), ("template_path", 500), ("stylesheet_path", 500),
            ("internal_template_version", 30), ("renderer_backend", 30),
            ("output_format", 10), ("page_size", 30), ("page_orientation", 20),
            ("source_notes", 4000),
        ):
            object.__setattr__(
                self,
                field,
                _text(getattr(self, field), field, maximum, required=field in {"version_label", "template_path"}),
            )
        if self.related_form_revision_id not in (None, ""):
            object.__setattr__(self, "related_form_revision_id", _id(self.related_form_revision_id, "related_form_revision_id"))
        object.__setattr__(self, "page_margins", _json_mapping(self.page_margins, "page_margins"))
        object.__setattr__(self, "required_context_schema", _json_mapping(self.required_context_schema, "required_context_schema"))


@dataclass(frozen=True, slots=True)
class DocumentTemplateLifecycleCommand:
    """Stable-ID lifecycle command for a document template."""

    template_id: str
    expected_status: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "template_id", _id(self.template_id, "template_id"))
        if self.expected_status is not None:
            object.__setattr__(self, "expected_status", _text(self.expected_status, "expected_status", 30))


@dataclass(frozen=True, slots=True)
class DocumentTemplateVersionLifecycleCommand:
    """Stable-ID lifecycle command for a document template version."""

    version_id: str
    expected_status: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "version_id", _id(self.version_id, "version_id"))
        if self.expected_status is not None:
            object.__setattr__(self, "expected_status", _text(self.expected_status, "expected_status", 30))


@dataclass(frozen=True, slots=True)
class DocumentTemplateCloneCommand:
    """Stable-ID command for cloning an existing template version."""

    source_version_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_version_id", _id(self.source_version_id, "source_version_id"))


@dataclass(frozen=True, slots=True)
class GeneratedDocumentLifecycleCommand:
    """Stable-ID command for generated-document metadata transitions."""

    document_id: str
    reason_code: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "document_id", _id(self.document_id, "document_id"))
        object.__setattr__(self, "reason_code", _text(self.reason_code, "reason_code", 64))


@dataclass(frozen=True, slots=True)
class WorkflowDocumentPreviewCommand:
    """Stable, non-storing preview request for a workflow-owned document."""

    target_reference: str
    stable_key: str
    expected_updated_at: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "target_reference", _id(self.target_reference, "target_reference"))
        object.__setattr__(self, "stable_key", _text(self.stable_key, "stable_key", 80, required=True))
        object.__setattr__(self, "expected_updated_at", _text(self.expected_updated_at, "expected_updated_at", 64))


@dataclass(frozen=True, slots=True)
class WorkflowDocumentGenerateCommand:
    """Idempotent official-generation request using only stable references."""

    target_reference: str
    stable_key: str
    expected_updated_at: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "target_reference", _id(self.target_reference, "target_reference"))
        object.__setattr__(self, "stable_key", _text(self.stable_key, "stable_key", 80, required=True))
        object.__setattr__(self, "expected_updated_at", _text(self.expected_updated_at, "expected_updated_at", 64))


@dataclass(frozen=True, slots=True)
class WorkflowDocumentDownloadCommand:
    """Stable workflow reference used to resolve the latest generated file."""

    target_reference: str
    stable_key: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "target_reference", _id(self.target_reference, "target_reference"))
        object.__setattr__(self, "stable_key", _text(self.stable_key, "stable_key", 80, required=True))
