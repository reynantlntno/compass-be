"""Shared, fail-safe cache mechanics for safe read projections.

Domain modules own cache contents and invalidation decisions.  This package
owns only backend access, key namespacing, JSON safety, bounded TTLs, and
post-commit mechanics.
"""

from apps.common.cache.backend import cached_read, clear_request_cache, request_cache_scope
from apps.common.cache.invalidation import invalidate_after_commit, invalidate_namespace

__all__ = [
    "cached_read",
    "clear_request_cache",
    "invalidate_after_commit",
    "invalidate_namespace",
    "request_cache_scope",
]
