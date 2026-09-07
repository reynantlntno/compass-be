"""Frozen, framework-neutral commands for institutional configuration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from pathlib import PurePosixPath
from urllib.parse import urlsplit
from uuid import UUID

from apps.common.exceptions import ValidationError


def _text(value, field: str, maximum: int, *, required: bool = False) -> str:
    if value is None:
        normalized = ""
    elif isinstance(value, str):
        normalized = value.strip()
    else:
        raise ValidationError(f"{field} must be text.")
    if required and not normalized:
        raise ValidationError(f"{field} is required.")
    if len(normalized) > maximum:
        raise ValidationError(f"{field} is too long.")
    return normalized


def _id(value, field: str, *, required: bool = True) -> str | None:
    if value in (None, ""):
        if required:
            raise ValidationError(f"{field} is required.")
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int, UUID)):
        raise ValidationError(f"{field} is invalid.")
    normalized = str(value).strip()
    if not normalized or len(normalized) > 128 or any(char.isspace() for char in normalized):
        raise ValidationError(f"{field} is invalid.")
    return normalized


def _storage_name(value) -> str:
    """Validate a storage-boundary name without accepting a filesystem path."""

    normalized = _text(value, "storage_name", 500, required=True).replace("\\", "/")
    path = PurePosixPath(normalized)
    if normalized.startswith("/") or ".." in path.parts:
        raise ValidationError("storage_name is invalid.")
    return normalized


def _date(value, field: str, *, required: bool = False) -> date | None:
    if value in (None, ""):
        if required:
            raise ValidationError(f"{field} is required.")
        return None
    if not isinstance(value, date) or isinstance(value, datetime):
        raise ValidationError(f"{field} must be a date.")
    return value


def _timestamp(value, field: str) -> datetime | None:
    if value in (None, ""):
        return None
    if not isinstance(value, datetime):
        raise ValidationError(f"{field} must be a timestamp.")
    return value


def _url(value, field: str, maximum: int = 2048) -> str:
    normalized = _text(value, field, maximum, required=True)
    parsed = urlsplit(normalized)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise ValidationError(f"{field} must be a safe HTTPS URL.")
    return normalized


@dataclass(frozen=True, slots=True)
class AssetUploadReceipt:
    """Validated storage-boundary receipt; never contains a file object."""

    storage_name: str
    content_type: str
    size_bytes: int
    original_filename: str

    def __post_init__(self):
        object.__setattr__(self, "storage_name", _storage_name(self.storage_name))
        object.__setattr__(self, "content_type", _text(self.content_type, "content_type", 100, required=True))
        object.__setattr__(self, "original_filename", _text(self.original_filename, "original_filename", 255, required=True))
        if isinstance(self.size_bytes, bool) or not isinstance(self.size_bytes, int) or not 0 <= self.size_bytes <= 5 * 1024 * 1024:
            raise ValidationError("size_bytes is invalid.")


@dataclass(frozen=True, slots=True)
class FormOption:
    value: str
    label: str

    def __post_init__(self):
        object.__setattr__(self, "value", _text(self.value, "option.value", 80, required=True))
        object.__setattr__(self, "label", _text(self.label, "option.label", 120, required=True))


@dataclass(frozen=True, slots=True)
class FormFieldSpec:
    key: str
    name: str = ""
    type: str = "text"
    label: str = ""
    required: bool = False
    options: tuple[FormOption, ...] = ()
    max_length: int | None = None

    def __post_init__(self):
        object.__setattr__(self, "key", _text(self.key, "field.key", 80, required=True))
        object.__setattr__(self, "name", _text(self.name, "field.name", 80))
        object.__setattr__(self, "type", _text(self.type, "field.type", 40, required=True))
        object.__setattr__(self, "label", _text(self.label, "field.label", 160))
        if not isinstance(self.required, bool):
            raise ValidationError("field.required is invalid.")
        if not isinstance(self.options, tuple) or any(not isinstance(item, FormOption) for item in self.options):
            raise ValidationError("field.options is invalid.")
        if self.max_length is not None and (isinstance(self.max_length, bool) or not isinstance(self.max_length, int) or not 0 <= self.max_length <= 10000):
            raise ValidationError("field.max_length is invalid.")


def _field_specs(value, field: str) -> tuple[FormFieldSpec, ...]:
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)):
        raise ValidationError(f"{field} must contain typed fields.")
    if len(value) > 100 or any(not isinstance(item, FormFieldSpec) for item in value):
        raise ValidationError(f"{field} contains an invalid field.")
    return tuple(value)


@dataclass(frozen=True, slots=True)
class InstitutionProfileDraftCommand:
    legal_name: str
    short_name: str
    former_name: str = ""
    former_short_name: str = ""
    address: str = ""
    main_campus: str = ""
    primary_brand_color: str = ""
    secondary_brand_color: str = ""
    accent_brand_color: str = ""
    version_label: str = ""
    effective_from: date | None = None
    effective_until: date | None = None
    source_note: str = ""
    expected_updated_at: datetime | None = None

    def __post_init__(self):
        for field, maximum, required in (
            ("legal_name", 255, True), ("short_name", 50, True),
            ("former_name", 255, False), ("former_short_name", 50, False),
            ("address", 2000, False), ("main_campus", 255, False),
            ("primary_brand_color", 30, False), ("secondary_brand_color", 30, False),
            ("accent_brand_color", 30, False), ("version_label", 50, False),
            ("source_note", 2000, False),
        ):
            object.__setattr__(self, field, _text(getattr(self, field), field, maximum, required=required))
        object.__setattr__(self, "effective_from", _date(self.effective_from, "effective_from"))
        object.__setattr__(self, "effective_until", _date(self.effective_until, "effective_until"))
        object.__setattr__(self, "expected_updated_at", _timestamp(self.expected_updated_at, "expected_updated_at"))


@dataclass(frozen=True, slots=True)
class OfficeProfileDraftCommand:
    office_name: str
    office_short_name: str
    institution_id: str | None = None
    legacy_office_name: str = ""
    document_header_name: str = ""
    office_address: str = ""
    contact_email: str = ""
    contact_number: str = ""
    office_hours: str = ""
    default_signatory_name: str = ""
    default_signatory_title: str = ""
    footer_note: str = ""
    version_label: str = ""
    effective_from: date | None = None
    effective_until: date | None = None
    source_note: str = ""
    expected_updated_at: datetime | None = None

    def __post_init__(self):
        for field, maximum, required in (
            ("office_name", 255, True), ("office_short_name", 50, True),
            ("legacy_office_name", 255, False), ("document_header_name", 255, False),
            ("office_address", 2000, False), ("contact_email", 254, False),
            ("contact_number", 50, False), ("office_hours", 255, False),
            ("default_signatory_name", 255, False), ("default_signatory_title", 255, False),
            ("footer_note", 2000, False), ("version_label", 50, False),
            ("source_note", 2000, False),
        ):
            object.__setattr__(self, field, _text(getattr(self, field), field, maximum, required=required))
        object.__setattr__(self, "institution_id", _id(self.institution_id, "institution_id", required=False))
        object.__setattr__(self, "effective_from", _date(self.effective_from, "effective_from"))
        object.__setattr__(self, "effective_until", _date(self.effective_until, "effective_until"))
        object.__setattr__(self, "expected_updated_at", _timestamp(self.expected_updated_at, "expected_updated_at"))


@dataclass(frozen=True, slots=True)
class BrandAssetDraftCommand:
    institution_id: str | None
    office_id: str | None
    asset_type: str
    semantic_role: str
    owner_type: str
    placement: str
    alt_text: str
    display_order: int = 0
    usage_context: str = ""
    background_variant: str = "TRANSPARENT"
    version_label: str = ""
    source_note: str = ""
    effective_from: date | None = None
    effective_until: date | None = None
    upload_receipt_id: str | None = None
    content_type_hint: str = ""
    file_size_bytes: int | None = None
    original_filename: str = ""
    upload_receipt: AssetUploadReceipt | None = None
    expected_updated_at: datetime | None = None

    def __post_init__(self):
        object.__setattr__(self, "institution_id", _id(self.institution_id, "institution_id", required=False))
        object.__setattr__(self, "office_id", _id(self.office_id, "office_id", required=False))
        for field, maximum, required in (
            ("asset_type", 30, True), ("semantic_role", 30, True), ("owner_type", 20, True),
            ("placement", 30, False), ("alt_text", 255, True), ("usage_context", 255, False),
            ("background_variant", 20, True), ("version_label", 50, False),
            ("source_note", 2000, False), ("content_type_hint", 100, False),
            ("original_filename", 255, False),
        ):
            object.__setattr__(self, field, _text(getattr(self, field), field, maximum, required=required))
        if (
            isinstance(self.display_order, bool)
            or not isinstance(self.display_order, int)
            or not 0 <= self.display_order <= 10000
        ):
            raise ValidationError("display_order is invalid.")
        object.__setattr__(self, "upload_receipt_id", _id(self.upload_receipt_id, "upload_receipt_id", required=False))
        if self.upload_receipt is not None and not isinstance(self.upload_receipt, AssetUploadReceipt):
            raise ValidationError("upload_receipt is invalid.")
        if self.file_size_bytes is not None and (isinstance(self.file_size_bytes, bool) or not isinstance(self.file_size_bytes, int) or self.file_size_bytes < 0):
            raise ValidationError("file_size_bytes is invalid.")
        object.__setattr__(self, "effective_from", _date(self.effective_from, "effective_from"))
        object.__setattr__(self, "effective_until", _date(self.effective_until, "effective_until"))
        object.__setattr__(self, "expected_updated_at", _timestamp(self.expected_updated_at, "expected_updated_at"))


@dataclass(frozen=True, slots=True)
class PublicLinkDraftCommand:
    owner_type: str
    link_type: str
    label: str
    url: str
    placement: str
    institution_id: str | None = None
    office_id: str | None = None
    display_order: int = 0
    effective_from: date | None = None
    effective_until: date | None = None
    source_note: str = ""
    expected_updated_at: datetime | None = None

    def __post_init__(self):
        for field, maximum, required in (
            ("owner_type", 20, True), ("link_type", 20, True), ("label", 120, True),
            ("url", 2048, True), ("placement", 20, True), ("source_note", 2000, False),
        ):
            object.__setattr__(self, field, _text(getattr(self, field), field, maximum, required=required))
        object.__setattr__(self, "url", _url(self.url, "url"))
        object.__setattr__(self, "institution_id", _id(self.institution_id, "institution_id", required=False))
        object.__setattr__(self, "office_id", _id(self.office_id, "office_id", required=False))
        if isinstance(self.display_order, bool) or not isinstance(self.display_order, int) or self.display_order < 0 or self.display_order > 10000:
            raise ValidationError("display_order is invalid.")
        object.__setattr__(self, "effective_from", _date(self.effective_from, "effective_from"))
        object.__setattr__(self, "effective_until", _date(self.effective_until, "effective_until"))
        object.__setattr__(self, "expected_updated_at", _timestamp(self.expected_updated_at, "expected_updated_at"))


@dataclass(frozen=True, slots=True)
class AcademicTermDraftCommand:
    academic_year: str
    semester: str
    start_date: date
    end_date: date
    configuration_identifier: str
    source_reference: str = ""
    source_note: str = ""
    expected_updated_at: datetime | None = None

    def __post_init__(self):
        for field, maximum, required in (
            ("academic_year", 20, True), ("semester", 100, True),
            ("configuration_identifier", 160, True), ("source_reference", 255, False),
            ("source_note", 2000, False),
        ):
            object.__setattr__(self, field, _text(getattr(self, field), field, maximum, required=required))
        object.__setattr__(self, "start_date", _date(self.start_date, "start_date", required=True))
        object.__setattr__(self, "end_date", _date(self.end_date, "end_date", required=True))
        object.__setattr__(self, "expected_updated_at", _timestamp(self.expected_updated_at, "expected_updated_at"))
        if self.end_date < self.start_date:
            raise ValidationError("end_date must not precede start_date.")


@dataclass(frozen=True, slots=True)
class FormFamilyDraftCommand:
    stable_key: str
    display_name: str
    description: str = ""
    owner_office_id: str | None = None
    source_notes: str = ""
    expected_updated_at: datetime | None = None

    def __post_init__(self):
        object.__setattr__(self, "stable_key", _text(self.stable_key, "stable_key", 80, required=True))
        for field, maximum in (("display_name", 255), ("description", 4000), ("source_notes", 2000)):
            object.__setattr__(self, field, _text(getattr(self, field), field, maximum, required=field == "display_name"))
        object.__setattr__(self, "owner_office_id", _id(self.owner_office_id, "owner_office_id", required=False))
        object.__setattr__(self, "expected_updated_at", _timestamp(self.expected_updated_at, "expected_updated_at"))


@dataclass(frozen=True, slots=True)
class FormRevisionDraftCommand:
    form_family_id: str
    official_form_code: str
    official_revision: str
    internal_schema_version: str
    internal_template_version: str
    display_title: str
    institution_profile_id: str | None = None
    office_profile_id: str | None = None
    source_document_reference: str = ""
    source_label: str = ""
    schema_summary: tuple[FormFieldSpec, ...] | None = None
    printable_template_path: str = ""
    source_notes: str = ""
    effective_from: date | None = None
    effective_until: date | None = None
    expected_updated_at: datetime | None = None

    def __post_init__(self):
        object.__setattr__(self, "form_family_id", _id(self.form_family_id, "form_family_id"))
        for field, maximum, required in (
            ("official_form_code", 80, True), ("official_revision", 50, True),
            ("internal_schema_version", 80, True), ("internal_template_version", 30, True),
            ("display_title", 255, True), ("source_document_reference", 500, False),
            ("source_label", 255, False), ("printable_template_path", 500, False),
            ("source_notes", 2000, False),
        ):
            object.__setattr__(self, field, _text(getattr(self, field), field, maximum, required=required))
        for field in ("institution_profile_id", "office_profile_id"):
            object.__setattr__(self, field, _id(getattr(self, field), field, required=False))
        object.__setattr__(self, "schema_summary", _field_specs(self.schema_summary, "schema_summary"))
        object.__setattr__(self, "effective_from", _date(self.effective_from, "effective_from"))
        object.__setattr__(self, "effective_until", _date(self.effective_until, "effective_until"))
        object.__setattr__(self, "expected_updated_at", _timestamp(self.expected_updated_at, "expected_updated_at"))


@dataclass(frozen=True, slots=True)
class LifecycleCommand:
    target_id: str
    expected_status: str | None = None
    expected_updated_at: datetime | None = None
    reason_code: str = ""

    def __post_init__(self):
        object.__setattr__(self, "target_id", _id(self.target_id, "target_id"))
        object.__setattr__(self, "expected_status", _text(self.expected_status, "expected_status", 40) if self.expected_status else None)
        object.__setattr__(self, "expected_updated_at", _timestamp(self.expected_updated_at, "expected_updated_at"))
        object.__setattr__(self, "reason_code", _text(self.reason_code, "reason_code", 80))


@dataclass(frozen=True, slots=True)
class RolloverPreviewCommand:
    term_id: str
    prior_term_id: str | None = None

    def __post_init__(self):
        object.__setattr__(self, "term_id", _id(self.term_id, "term_id"))
        object.__setattr__(self, "prior_term_id", _id(self.prior_term_id, "prior_term_id", required=False))


@dataclass(frozen=True, slots=True)
class RollbackCommand:
    term_id: str
    prior_term_id: str
    expected_updated_at: datetime | None = None
    reason_code: str = "TERM_ROLLBACK"

    def __post_init__(self):
        object.__setattr__(self, "term_id", _id(self.term_id, "term_id"))
        object.__setattr__(self, "prior_term_id", _id(self.prior_term_id, "prior_term_id"))
        object.__setattr__(self, "expected_updated_at", _timestamp(self.expected_updated_at, "expected_updated_at"))
        object.__setattr__(self, "reason_code", _text(self.reason_code, "reason_code", 80, required=True))


@dataclass(frozen=True, slots=True)
class FormRevisionSourceCommand:
    revision_id: str
    source_label: str = ""
    upload_receipt_id: str | None = None
    expected_updated_at: datetime | None = None

    def __post_init__(self):
        object.__setattr__(self, "revision_id", _id(self.revision_id, "revision_id"))
        object.__setattr__(self, "source_label", _text(self.source_label, "source_label", 255))
        object.__setattr__(self, "upload_receipt_id", _id(self.upload_receipt_id, "upload_receipt_id", required=False))
        object.__setattr__(self, "expected_updated_at", _timestamp(self.expected_updated_at, "expected_updated_at"))
