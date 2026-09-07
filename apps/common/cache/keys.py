"""Canonical cache key construction."""

from __future__ import annotations

import hashlib
import re

from apps.common.cache.registry import get_cache_spec


KEY_PREFIX = "compass:cache:v1"
_SAFE_PART = re.compile(r"^[A-Za-z0-9_.:-]{1,120}$")


def _safe_part(value: object) -> str:
    text = str(value or "")
    if text and _SAFE_PART.fullmatch(text):
        return text
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return f"h-{digest}"


def cache_key(namespace: str, *parts: object) -> str:
    """Build a bounded namespaced key without exposing unsafe key material."""

    spec = get_cache_spec(namespace)
    values = [_safe_part(part) for part in parts if str(part or "")]
    key = ":".join((KEY_PREFIX, spec.namespace, *values))
    if len(key) <= 240:
        return key
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return ":".join((KEY_PREFIX, spec.namespace, f"h-{digest}"))


def generation_key(namespace: str, target: object = "global") -> str:
    return cache_key(namespace, "generation", target)


def lock_key(namespace: str, *parts: object) -> str:
    return cache_key(namespace, "lock", *parts)
