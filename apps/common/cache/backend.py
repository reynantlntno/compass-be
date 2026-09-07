"""Fail-safe JSON read-through cache backend."""

from __future__ import annotations

import contextlib
import contextvars
import secrets
from datetime import date, datetime
from typing import Any, Callable

from django.core.cache import caches
from django.utils import timezone

from apps.common.cache.contracts import CacheValueError, json_cache_payload, parse_json_cache_payload
from apps.common.cache.keys import cache_key, generation_key, lock_key
from apps.common.cache.registry import get_cache_spec


_CACHE_MISS = object()
_request_memo: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "compass_cache_request_memo",
    default=None,
)


def _backend():
    try:
        return caches["default"]
    except Exception:
        return None


def _safe_get(key: str) -> tuple[bool, Any]:
    backend = _backend()
    if backend is None:
        return False, None
    try:
        return True, backend.get(key)
    except Exception:
        return False, None


def _safe_set(key: str, value: str, timeout: int) -> bool:
    backend = _backend()
    if backend is None:
        return False
    try:
        backend.set(key, value, timeout=timeout)
        return True
    except Exception:
        return False


def _safe_add(key: str, value: str, timeout: int) -> tuple[bool, bool]:
    backend = _backend()
    if backend is None:
        return False, False
    try:
        return True, bool(backend.add(key, value, timeout=timeout))
    except Exception:
        return False, False


def _safe_delete(key: str) -> bool:
    backend = _backend()
    if backend is None:
        return False
    try:
        backend.delete(key)
        return True
    except Exception:
        return False


def _bounded_ttl(namespace: str, ttl: int | None = None, expires_at: datetime | date | Callable[[Any], datetime | date | None] | None = None, cached_value: Any = None) -> int:
    spec = get_cache_spec(namespace)
    ttl_value = spec.max_ttl_seconds if ttl is None else min(int(ttl), spec.max_ttl_seconds)
    if ttl_value <= 0:
        return 0
    if expires_at is None:
        return ttl_value
    if callable(expires_at):
        expires_at = expires_at(cached_value)
    if expires_at is None:
        return ttl_value
    now = timezone.now()
    if isinstance(expires_at, date) and not isinstance(expires_at, datetime):
        expires_at = datetime.combine(expires_at, datetime.min.time(), tzinfo=now.tzinfo)
    if timezone.is_naive(expires_at):
        expires_at = timezone.make_aware(expires_at)
    remaining = int((expires_at - now).total_seconds())
    return max(0, min(ttl_value, remaining))


def _generation_token(namespace: str, target: object) -> tuple[bool, str | None]:
    key = generation_key(namespace, target)
    available, value = _safe_get(key)
    if not available:
        return False, None
    if isinstance(value, str) and value:
        return True, value
    generation = secrets.token_hex(12)
    available, created = _safe_add(key, generation, get_cache_spec(namespace).max_ttl_seconds)
    if not available:
        return False, None
    if created:
        return True, generation
    available, value = _safe_get(key)
    return available and isinstance(value, str) and bool(value), value if isinstance(value, str) else None


def _generation(namespace: str, target: object) -> tuple[bool, str | None]:
    """Return a namespace-wide and target-specific generation pair.

    The namespace generation lets a domain invalidate unknown old keys after
    slug/target changes.  The target generation keeps ordinary writes narrow.
    """
    global_available, global_generation = _generation_token(namespace, "global")
    if target == "global":
        return global_available, global_generation
    target_available, target_generation = _generation_token(namespace, target)
    if not global_available or not target_available:
        return False, None
    return True, f"{global_generation}.{target_generation}"


def _memo_key(namespace: str, target: object, parts: tuple[object, ...]) -> str:
    return cache_key(namespace, "memo", target, *parts)


@contextlib.contextmanager
def request_cache_scope():
    """Create request-local memoization and clear it on exit."""

    token = _request_memo.set({})
    try:
        yield
    finally:
        _request_memo.reset(token)


def clear_request_cache() -> None:
    """Clear the current context's memoized safe reads."""

    memo = _request_memo.get()
    if memo is not None:
        memo.clear()


def cached_read(
    namespace: str,
    target: object,
    parts: tuple[object, ...],
    loader: Callable[[], Any],
    *,
    ttl: int | None = None,
    expires_at: datetime | date | Callable[[Any], datetime | date | None] | None = None,
    memoize: bool = True,
) -> Any:
    """Read a JSON-safe projection through the shared cache.

    A backend outage simply executes ``loader``.  A miss uses a short
    non-blocking lock to reduce stampedes; callers that cannot acquire it
    perform a direct authoritative read instead of receiving an incomplete
    value.
    """

    spec = get_cache_spec(namespace)
    memo = _request_memo.get() if memoize else None
    memo_key = _memo_key(namespace, target, parts)
    if memo is not None and memo_key in memo:
        return memo[memo_key]

    available, generation = _generation(namespace, target)
    if available and generation:
        data_key = cache_key(namespace, generation, target, *parts)
        cache_available, raw = _safe_get(data_key)
        if cache_available and raw is not None:
            try:
                if isinstance(raw, str) and len(raw.encode("utf-8")) > spec.max_payload_bytes:
                    raise CacheValueError("Cache entry exceeds the registered size limit.")
                value = parse_json_cache_payload(raw)
                if memo is not None:
                    memo[memo_key] = value
                return value
            except CacheValueError:
                _safe_delete(data_key)

        lock_available, acquired = _safe_add(lock_key(namespace, generation, target, *parts), secrets.token_hex(8), 2)
        if lock_available and acquired:
            try:
                value = loader()
                payload = json_cache_payload(value, max_bytes=spec.max_payload_bytes)
                normalized = parse_json_cache_payload(payload)
                bounded_ttl = _bounded_ttl(namespace, ttl, expires_at, normalized)
                if bounded_ttl:
                    _safe_set(data_key, payload, bounded_ttl)
                if memo is not None:
                    memo[memo_key] = normalized
                return normalized
            finally:
                _safe_delete(lock_key(namespace, generation, target, *parts))

    value = loader()
    payload = json_cache_payload(value, max_bytes=spec.max_payload_bytes)
    normalized = parse_json_cache_payload(payload)
    if available and generation:
        bounded_ttl = _bounded_ttl(namespace, ttl, expires_at, normalized)
        if bounded_ttl:
            _safe_set(cache_key(namespace, generation, target, *parts), payload, bounded_ttl)
    if memo is not None:
        memo[memo_key] = normalized
    return normalized
