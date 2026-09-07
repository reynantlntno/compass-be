"""Post-commit cache invalidation helpers."""

from __future__ import annotations

import secrets

from django.db import transaction

from apps.common.cache.backend import _safe_set
from apps.common.cache.keys import generation_key
from apps.common.cache.registry import get_cache_spec


def invalidate_namespace(namespace: str, target: object = "global") -> bool:
    """Rotate a namespace generation so old keys become unreachable."""

    spec = get_cache_spec(namespace)
    return _safe_set(
        generation_key(namespace, target),
        secrets.token_hex(12),
        spec.max_ttl_seconds,
    )


def invalidate_after_commit(namespace: str, target: object = "global") -> None:
    """Evict eagerly for safety and rotate again after commit.

    Eager invalidation prevents a transaction-local reader (including Django's
    ``TestCase`` transaction) from observing a superseded snapshot. The
    post-commit rotation is still authoritative for other workers and avoids
    serving a value written by a transaction that later rolls back.
    """

    invalidate_namespace(namespace, target)
    transaction.on_commit(lambda: invalidate_namespace(namespace, target))
