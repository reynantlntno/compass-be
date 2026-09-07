"""Django Ninja schemas shared by all COMPASS API adapters."""

from ninja import Schema
from pydantic import Field


class ApiErrorSchema(Schema):
    detail: str
    code: str
    request_id: str
    error_id: str | None = None
    field_errors: dict[str, list[str]] = Field(default_factory=dict)


class PageResultSchema(Schema):
    page: int
    page_size: int
    total: int
