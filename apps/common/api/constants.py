"""Immutable API boundary limits.

These are mechanics and safety bounds, not tenant or workflow policy.
"""

API_MAX_JSON_BODY_BYTES = 1_048_576
API_MAX_IDEMPOTENCY_KEY_LENGTH = 128
API_MAX_CORRELATION_ID_LENGTH = 100
API_MAX_PAGE_SIZE = 100
