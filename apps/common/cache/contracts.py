"""JSON-only cache contracts.

Cache entries are deliberately stricter than normal Python return values.
ORM objects, QuerySets, lazy translation values, and arbitrary objects must
never be serialized into a shared cache.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any

from django.db.models import Model, QuerySet
from django.utils.functional import Promise

from apps.common.contracts import to_json_value


class CacheValueError(ValueError):
    """Raised when a value cannot cross the cache projection boundary."""


def json_cache_payload(value: Any, *, max_bytes: int) -> str:
    """Return a bounded JSON string or reject the value.

    JSON strings are used instead of the backend's default Python pickling so
    a cache hit can never resurrect a Django model or another executable
    object.
    """

    if isinstance(value, (Model, QuerySet, Promise)):
        raise CacheValueError("Django models, QuerySets, and lazy values cannot be cached.")
    try:
        converted = to_json_value(value)
        payload = json.dumps(converted, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError, OverflowError) as exc:
        raise CacheValueError("Cache values must be recursively JSON-safe.") from exc
    if len(payload.encode("utf-8")) > max_bytes:
        raise CacheValueError("Cache payload exceeds the registered size limit.")
    return payload


def parse_json_cache_payload(payload: Any) -> Any:
    """Decode one JSON cache string and reject non-JSON backend values."""

    if not isinstance(payload, str):
        raise CacheValueError("Cache entry is not a JSON string.")
    try:
        return json.loads(payload)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise CacheValueError("Cache entry is malformed JSON.") from exc


@dataclass(frozen=True, slots=True)
class CacheExpiry:
    """Optional expiry boundary used to clip a cache TTL."""

    expires_at: datetime | date | None = None
