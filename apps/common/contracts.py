"""Framework-neutral contracts shared by application and API adapters.

The domain layer uses these value objects instead of Django request/response
types.  Adapters may convert them to HTTP-specific representations at the
edge, but a domain projection must remain composed only of JSON-safe values.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time
from decimal import Decimal
from enum import Enum
from typing import Generic, Mapping, Sequence, TypeVar
from uuid import UUID


MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 25


class ContractValidationError(ValueError):
    """Raised when an adapter supplies an invalid framework-neutral value."""


@dataclass(frozen=True, slots=True)
class RequestMetadata:
    """Ephemeral request facts extracted by an HTTP/API adapter.

    Raw values exist only for the duration of a service call.  Domain code
    may hash them for an audit record but never receives a Django request.
    """

    ip_address: str = ""
    user_agent: str = ""
    session_key: str = ""
    captcha_response: str = ""


@dataclass(frozen=True, slots=True)
class PageRequest:
    """Bounded, one-based pagination input."""

    page: int = 1
    page_size: int = DEFAULT_PAGE_SIZE

    def __post_init__(self) -> None:
        if isinstance(self.page, bool) or not isinstance(self.page, int) or self.page < 1:
            raise ContractValidationError("page must be a positive integer")
        if isinstance(self.page_size, bool) or not isinstance(self.page_size, int):
            raise ContractValidationError("page_size must be an integer")
        if self.page_size < 1 or self.page_size > MAX_PAGE_SIZE:
            raise ContractValidationError(f"page_size must be between 1 and {MAX_PAGE_SIZE}")

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size


T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class PageResult(Generic[T]):
    """Immutable result envelope; values are converted to a tuple on input."""

    items: tuple[T, ...]
    page: int
    page_size: int
    total: int

    def __post_init__(self) -> None:
        if not isinstance(self.items, tuple):
            object.__setattr__(self, "items", tuple(self.items))
        PageRequest(self.page, self.page_size)
        if isinstance(self.total, bool) or not isinstance(self.total, int) or self.total < 0:
            raise ContractValidationError("total must be a non-negative integer")

    def as_dict(self) -> dict[str, object]:
        return {
            "items": [to_json_value(item) for item in self.items],
            "page": self.page,
            "page_size": self.page_size,
            "total": self.total,
        }


def to_json_value(value):
    """Convert approved primitive/container values without serializing models.

    Unknown objects deliberately raise instead of being coerced with ``str``.
    This prevents Django models, QuerySets, lazy translation values, and
    arbitrary metadata objects from crossing an output boundary accidentally.
    """

    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if isinstance(value, (UUID, Decimal)):
        return str(value)
    if isinstance(value, Enum):
        return to_json_value(value.value)
    if isinstance(value, Mapping):
        return {str(key): to_json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_json_value(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return [to_json_value(item) for item in sorted(value, key=str)]
    raise TypeError(f"Unsupported projection value: {type(value).__name__}")


def to_json_object(value: Mapping[str, object]) -> dict[str, object]:
    """Return a recursively JSON-safe dictionary with string keys."""

    converted = to_json_value(value)
    if not isinstance(converted, dict):  # pragma: no cover - Mapping guarantees this
        raise TypeError("Projection root must be an object")
    return converted


def page_items(items: Sequence[T], request: PageRequest) -> PageResult[T]:
    """Paginate already-projected values without touching ORM objects."""

    values = tuple(items)
    return PageResult(
        items=values[request.offset: request.offset + request.page_size],
        page=request.page,
        page_size=request.page_size,
        total=len(values),
    )


def page_queryset(queryset, request: PageRequest, projector) -> dict[str, object]:
    """Bound a QuerySet before projecting it into a JSON-safe page."""

    total = queryset.count()
    rows = queryset[request.offset : request.offset + request.page_size]
    return PageResult(
        items=tuple(projector(row) for row in rows),
        page=request.page,
        page_size=request.page_size,
        total=total,
    ).as_dict()
