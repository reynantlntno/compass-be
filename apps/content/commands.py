"""Typed, framework-neutral commands for the content domain.

Commands are deliberately explicit. API adapters and management commands
construct these types directly; arbitrary field mappings do not cross the
domain boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from datetime import date, datetime
from typing import ClassVar

from apps.content.models import AudienceChoices, ContentStatus, TargetScopeChoices


class _Unset:
    pass


UNSET = _Unset()


class _FieldCommand:
    """Small typed-command helper; it never accepts caller-supplied maps."""

    _excluded_fields: ClassVar[frozenset[str]] = frozenset()

    def to_fields(self) -> dict:
        values = {}
        for item in fields(self):
            if item.name in self._excluded_fields:
                continue
            value = getattr(self, item.name)
            if value is not UNSET:
                values[item.name] = value
        return values

    def get(self, name: str, default=None):
        value = getattr(self, name, UNSET)
        return default if value is UNSET else value


@dataclass(frozen=True, slots=True)
class AnnouncementCreateCommand(_FieldCommand):
    slug: str
    title: str
    summary: str
    body_markdown: str
    audience: str = AudienceChoices.PUBLIC
    target_scope_mode: str = TargetScopeChoices.INSTITUTION_WIDE
    target_campus: str | None = None
    target_college: str | None = None
    target_department: str | None = None
    target_program: str | None = None
    featured: bool = False
    publish_start: datetime | None = None
    publish_end: datetime | None = None
    dashboard_preview_enabled: bool = True
    status: str = ContentStatus.DRAFT


@dataclass(frozen=True, slots=True)
class AnnouncementUpdateCommand(_FieldCommand):
    slug: str | _Unset = UNSET
    title: str | _Unset = UNSET
    summary: str | _Unset = UNSET
    body_markdown: str | _Unset = UNSET
    audience: str | _Unset = UNSET
    target_scope_mode: str | _Unset = UNSET
    target_campus: str | None | _Unset = UNSET
    target_college: str | None | _Unset = UNSET
    target_department: str | None | _Unset = UNSET
    target_program: str | None | _Unset = UNSET
    featured: bool | _Unset = UNSET
    publish_start: datetime | None | _Unset = UNSET
    publish_end: datetime | None | _Unset = UNSET
    dashboard_preview_enabled: bool | _Unset = UNSET
    status: str | _Unset = UNSET


@dataclass(frozen=True, slots=True)
class ResourceCreateCommand(_FieldCommand):
    slug: str
    title: str
    summary: str
    category: str
    resource_type: str
    body_markdown: str | None = None
    external_url: str | None = None
    audience: str = AudienceChoices.PUBLIC
    target_scope_mode: str = TargetScopeChoices.INSTITUTION_WIDE
    target_campus: str | None = None
    target_college: str | None = None
    target_department: str | None = None
    target_program: str | None = None
    publish_start: datetime | None = None
    publish_end: datetime | None = None
    status: str = ContentStatus.DRAFT


@dataclass(frozen=True, slots=True)
class ResourceUpdateCommand(_FieldCommand):
    slug: str | _Unset = UNSET
    title: str | _Unset = UNSET
    summary: str | _Unset = UNSET
    category: str | _Unset = UNSET
    resource_type: str | _Unset = UNSET
    body_markdown: str | None | _Unset = UNSET
    external_url: str | None | _Unset = UNSET
    audience: str | _Unset = UNSET
    target_scope_mode: str | _Unset = UNSET
    target_campus: str | None | _Unset = UNSET
    target_college: str | None | _Unset = UNSET
    target_department: str | None | _Unset = UNSET
    target_program: str | None | _Unset = UNSET
    publish_start: datetime | None | _Unset = UNSET
    publish_end: datetime | None | _Unset = UNSET
    status: str | _Unset = UNSET


@dataclass(frozen=True, slots=True)
class ContentPageCreateCommand(_FieldCommand):
    page_key: str
    title: str
    summary: str = ""
    body_markdown: str = ""
    audience: str = AudienceChoices.PUBLIC
    status: str = ContentStatus.DRAFT


@dataclass(frozen=True, slots=True)
class ContentPageUpdateCommand(_FieldCommand):
    title: str | _Unset = UNSET
    summary: str | _Unset = UNSET
    body_markdown: str | _Unset = UNSET
    audience: str | _Unset = UNSET
    status: str | _Unset = UNSET


@dataclass(frozen=True, slots=True)
class ServiceGuideCreateCommand(_FieldCommand):
    version_label: str
    title: str = "Official Citizen’s Charter / Service Standards"
    summary: str = ""
    effective_date: date | None = None
    publish_start: datetime | None = None
    publish_end: datetime | None = None
    body_markdown: str = ""
    entries_json: list | None = None
    owner_office_id: int | None = None
    audience: str = AudienceChoices.PUBLIC
    status: str = ContentStatus.DRAFT
    guide_key: str = "public-service-guide"

    def __post_init__(self):
        object.__setattr__(self, "entries_json", list(self.entries_json or []))


@dataclass(frozen=True, slots=True)
class ServiceGuideUpdateCommand(_FieldCommand):
    version_label: str | _Unset = UNSET
    title: str | _Unset = UNSET
    summary: str | _Unset = UNSET
    effective_date: date | None | _Unset = UNSET
    publish_start: datetime | None | _Unset = UNSET
    publish_end: datetime | None | _Unset = UNSET
    body_markdown: str | _Unset = UNSET
    entries_json: list | _Unset = UNSET
    owner_office_id: int | None | _Unset = UNSET
    audience: str | _Unset = UNSET
    status: str | _Unset = UNSET

    def __post_init__(self):
        if self.entries_json is not UNSET:
            object.__setattr__(self, "entries_json", list(self.entries_json or []))


@dataclass(frozen=True, slots=True)
class ContentSeedCommand(_FieldCommand):
    """Explicit operational seed input for public content."""

    slug: str | _Unset = UNSET
    page_key: str | _Unset = UNSET
    title: str | _Unset = UNSET
    summary: str | _Unset = UNSET
    body_markdown: str | _Unset = UNSET
    audience: str | _Unset = UNSET
    target_scope_mode: str | _Unset = UNSET
    target_campus: str | None | _Unset = UNSET
    target_college: str | None | _Unset = UNSET
    target_department: str | None | _Unset = UNSET
    target_program: str | None | _Unset = UNSET
    featured: bool | _Unset = UNSET
    publish_start: datetime | None | _Unset = UNSET
    publish_end: datetime | None | _Unset = UNSET
    dashboard_preview_enabled: bool | _Unset = UNSET
    category: str | _Unset = UNSET
    resource_type: str | _Unset = UNSET
    external_url: str | None | _Unset = UNSET
    version_label: str | _Unset = UNSET
    effective_date: date | None | _Unset = UNSET
    owner_office_id: int | None | _Unset = UNSET
    entries_json: list | _Unset = UNSET
    status: str | _Unset = UNSET
    guide_key: str | _Unset = UNSET


@dataclass(frozen=True, slots=True)
class ContactSubmissionCommand:
    submission_type: str = "inquiry"
    name: str = ""
    email: str = ""
    phone: str = ""
    affiliation: str = "visitor"
    subject: str = ""
    message_body: str = ""
    privacy_acknowledged: bool = False
    urgent_support_disclaimer_acknowledged: bool = False


@dataclass(frozen=True, slots=True)
class ContactAssignmentCommand:
    assignee_id: int | None = None


@dataclass(frozen=True, slots=True)
class ContactStatusCommand:
    status: str


@dataclass(frozen=True, slots=True)
class ContactReplyCommand:
    body: str


@dataclass(frozen=True, slots=True)
class ContactNoResponseCommand:
    reason_code: str
    detail: str = ""
