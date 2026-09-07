"""Immutable security boundaries owned by the application source.

These values are not deployment configuration and are not Governance policy
records.  They bound cryptographic payloads, maintenance operations, and
protected-file formats so an environment variable cannot weaken the safety
contract.
"""

FIELD_ENCRYPTION_KEY_CACHE_TTL_SECONDS = 30
FIELD_ENCRYPTION_KEY_CACHE_MAX_ENTRIES = 32
FIELD_ENCRYPTION_MAX_PLAINTEXT_BYTES = 1_048_576
FIELD_ENCRYPTION_CHECKPOINT_MAX_BYTES = 65_536
FIELD_ENCRYPTION_BATCH_SIZE_MAX = 1_000

PROTECTED_STORAGE_ALLOWED_CONTENT_TYPES = frozenset(
    {
        "application/pdf",
        "image/jpeg",
        "image/png",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/msword",
        "text/csv",
        "text/plain",
        "text/html",
    }
)
PROTECTED_STORAGE_ALLOWED_EXTENSIONS = frozenset(
    {".pdf", ".jpg", ".jpeg", ".png", ".docx", ".doc", ".csv", ".txt", ".html"}
)
