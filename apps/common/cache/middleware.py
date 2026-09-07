"""Request boundary for cache-local memoization."""

from apps.common.cache.backend import request_cache_scope


class CacheRequestScopeMiddleware:
    """Clear request-local cache values at the end of every request."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        with request_cache_scope():
            return self.get_response(request)
