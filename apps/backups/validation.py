# Project: COMPASS
# File: apps/backups/validation.py
# Module: apps.backups
# Purpose: Shared safety validation for backup/restore metadata and references

import json
import re
import unicodedata
import uuid
from datetime import datetime, timezone as datetime_timezone
from typing import Any

from django.conf import settings
from apps.common.exceptions import ValidationError


MAX_METADATA_DEPTH = 4
MAX_METADATA_ITEMS = 25
MAX_SAFE_STRING_LENGTH = 100
MAX_SAFE_COLLECTION_STRING_LENGTH = 255

OPAQUE_STORAGE_REFERENCE_RE = re.compile(
    r"^(artifact|backup-artifact):[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
LOWERCASE_SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")
OPS_E_VERSION_RE = re.compile(r"\A[a-z0-9][a-z0-9._-]{0,99}\Z")
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
ABSOLUTE_PATH_RE = re.compile(r"(^/[^/]+)|([A-Za-z]:\\)")
ERROR_ID_RE = re.compile(r"\AERR-[0-9]{4}-[0-9]{6}\Z")

UNSAFE_PATTERNS = [
    r"database_url",
    r"postgres://",
    r"postgresql://",
    r"mongodb://",
    r"mysql://",
    r"db_password",
    r"postgres_password",
    r"secret_key",
    r"audit_hash_secret",
    r"field_encryption",
    r"encryption_key",
    r"api[_ -]?key",
    r"vault[_ -]?token",
    r"minio[_ -]?(access|secret)",
    r"aws[_ -]?(access|secret)",
    r"s3://",
    r"local_demo/",
    r"signed[_ -]?url",
    r"presigned",
    r"private[_ -]?url",
    r"object[_ -]?key",
    r"traceback",
    r"stack trace",
]

SENSITIVE_KEYWORDS = [
    "password",
    "secret",
    "token",
    "api_key",
    "api key",
    "private_key",
    "private key",
    "encryption_key",
    "encryption key",
    "otp",
    "jwt",
    "credential",
    "smtp_password",
    "smtp password",
    "daily",
    "request_body",
    "request body",
    "raw_body",
    "raw body",
    "counseling_notes",
    "counseling notes",
    "counseling note",
    "referral_reason",
    "referral reason",
    "referral reasons",
    "assessment_interpretation",
    "assessment interpretation",
    "support_message",
    "support message",
    "session_key",
    "authorization",
    "cookie",
    "signature",
    "salt",
    "student_number",
    "student number",
    "control_number",
    "control number",
    "email",
    "vault",
    "storage_key",
    "storage key",
    "private_url",
    "private url",
    "signed_url",
    "signed url",
    "presigned_url",
    "presigned url",
    "object_key",
    "object key",
    "health_narrative",
    "health narrative",
    "family_narrative",
    "family narrative",
    "financial_narrative",
    "financial narrative",
    "raw exception",
    "exception",
]

TOP_LEVEL_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "backup_operation_id",
        "archive_identifier",
        "job_type",
        "environment_class",
        "created_at",
        "storage_target_type",
        "included",
        "database_dump",
        "archive_member_allowlist",
        "transient_state_exclusion",
        "protected_file_manifest",
        "public_media_manifest",
        "components",
    }
)
ARCHIVE_MEMBER_KEYS = frozenset(
    {"member_name", "member_class", "required", "sha256", "size_bytes"}
)
ARCHIVE_MEMBER_CLASSES = frozenset(
    {"DATABASE_DUMP", "MANIFEST", "PROTECTED_FILE", "PUBLIC_MEDIA", "COMPONENT"}
)


def _contains_unsafe_text(value: str) -> bool:
    lower = value.lower()
    if EMAIL_RE.search(value):
        return True
    if ABSOLUTE_PATH_RE.search(value):
        return True
    if any(keyword in lower for keyword in SENSITIVE_KEYWORDS):
        return True
    return any(re.search(pattern, lower) for pattern in UNSAFE_PATTERNS)


def assert_safe_text(value: str, *, label: str = "metadata value", max_length: int = MAX_SAFE_COLLECTION_STRING_LENGTH) -> str:
    """Return a bounded safe string or raise without echoing the submitted value."""
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValidationError(f"Invalid {label}.")
    cleaned = value.strip()
    if len(cleaned) > max_length:
        raise ValidationError(f"{label.capitalize()} is too long.")
    if _contains_unsafe_text(cleaned):
        raise ValidationError(f"{label.capitalize()} contains disallowed content.")
    return cleaned


def clean_reason_code(val: str) -> str:
    """Return a bounded reason code, redacting internal operational failures safely."""
    if not val:
        return "unspecified"
    cleaned = str(val).strip()
    if _contains_unsafe_text(cleaned):
        return "redacted_reason_code"
    return cleaned[:MAX_SAFE_STRING_LENGTH]


def validate_strict_reason_code(val: str) -> str:
    """Fail closed for user-submitted high-risk action reason codes."""
    if not val:
        raise ValidationError("A safe reason code is required.")
    return assert_safe_text(str(val), label="reason code", max_length=MAX_SAFE_STRING_LENGTH)


def clean_authorization_reference(val: str) -> str:
    """Validate institutional authorization references without exposing submitted values."""
    if not val:
        return ""
    return assert_safe_text(str(val), label="authorization reference", max_length=255)


def clean_storage_reference(val: str) -> str:
    """Validate opaque internal artifact references only."""
    if not val:
        raise ValidationError("Storage reference is required.")
    cleaned = str(val).strip()
    if not OPAQUE_STORAGE_REFERENCE_RE.match(cleaned):
        raise ValidationError("Storage reference must be an opaque internal artifact reference.")
    if _contains_unsafe_text(cleaned):
        raise ValidationError("Storage reference contains disallowed content.")
    return cleaned


def validate_checksum(checksum: str) -> str:
    """Validate a hex-encoded SHA256 string."""
    if not checksum:
        raise ValidationError("Checksum cannot be empty.")
    checksum = str(checksum).strip()
    if not SHA256_RE.match(checksum):
        raise ValidationError("Invalid checksum format.")
    return checksum.lower()


def validate_size(size: int) -> int:
    """Validate a non-negative integer size."""
    if type(size) is not int or isinstance(size, bool):
        raise ValidationError("Size must be an integer.")
    if size < 0:
        raise ValidationError("Size cannot be negative.")
    return size


def clean_safe_metadata(metadata: Any, *, depth: int = 0) -> Any:
    """Recursively clean safe metadata keys and values, failing closed on leaks."""
    if metadata in ({}, None):
        return {}
    if depth > MAX_METADATA_DEPTH:
        raise ValidationError("Metadata is too deeply nested.")
    if isinstance(metadata, dict):
        if len(metadata) > MAX_METADATA_ITEMS:
            raise ValidationError("Metadata contains too many entries.")
        cleaned = {}
        for key, value in metadata.items():
            safe_key = assert_safe_text(str(key), label="metadata key", max_length=64)
            cleaned[safe_key] = clean_safe_metadata(value, depth=depth + 1)
        return cleaned
    if isinstance(metadata, list):
        if len(metadata) > MAX_METADATA_ITEMS:
            raise ValidationError("Metadata list contains too many entries.")
        return [clean_safe_metadata(item, depth=depth + 1) for item in metadata]
    if isinstance(metadata, bool) or metadata is None:
        return metadata
    if isinstance(metadata, int) and not isinstance(metadata, bool):
        return metadata
    if isinstance(metadata, float):
        if metadata != metadata or metadata in (float("inf"), float("-inf")):
            raise ValidationError("Metadata number is not valid.")
        return metadata
    if isinstance(metadata, str):
        return assert_safe_text(metadata, label="metadata value", max_length=MAX_SAFE_COLLECTION_STRING_LENGTH)
    raise ValidationError("Metadata contains unsupported values.")


def _canonical_uuid_text(value):
    try:
        if type(value) is not str or str(uuid.UUID(value)) != value:
            raise ValueError
    except (TypeError, ValueError, AttributeError):
        raise ValidationError("Backup manifest is invalid.")
    return value


def _canonical_utc_timestamp(value):
    if type(value) is not str or not value.endswith("Z"):
        raise ValidationError("Backup manifest is invalid.")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=datetime_timezone.utc
        )
    except (TypeError, ValueError):
        raise ValidationError("Backup manifest is invalid.")
    if parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ") != value:
        raise ValidationError("Backup manifest is invalid.")
    return value


def validate_archive_member_name(value):
    if (
        type(value) is not str
        or not value
        or value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or unicodedata.normalize("NFC", value) != value
    ):
        raise ValidationError("Archive member is invalid.")
    segments = value.split("/")
    if any(segment in {"", ".", ".."} for segment in segments):
        raise ValidationError("Archive member is invalid.")
    return value


def _bounded_nonnegative_integer(value):
    if type(value) is not int or isinstance(value, bool) or value < 0:
        raise ValidationError("Backup manifest is invalid.")
    return value


def validate_archive_member_allowlist(entries):
    if type(entries) is not list or len(entries) < 1:
        raise ValidationError("Archive allowlist is invalid.")
    names = []
    normalized_names = set()
    manifest_entries = 0
    for entry in entries:
        if type(entry) is not dict or set(entry) != ARCHIVE_MEMBER_KEYS:
            raise ValidationError("Archive allowlist is invalid.")
        name = validate_archive_member_name(entry["member_name"])
        normalized = unicodedata.normalize("NFKC", name)
        if name in names or normalized in normalized_names:
            raise ValidationError("Archive allowlist is invalid.")
        names.append(name)
        normalized_names.add(normalized)
        if entry["member_class"] not in ARCHIVE_MEMBER_CLASSES or type(entry["required"]) is not bool:
            raise ValidationError("Archive allowlist is invalid.")
        if name == "manifest.json":
            manifest_entries += 1
            if entry != {
                "member_name": "manifest.json",
                "member_class": "MANIFEST",
                "required": True,
                "sha256": None,
                "size_bytes": None,
            }:
                raise ValidationError("Archive allowlist is invalid.")
        else:
            if type(entry["sha256"]) is not str or not LOWERCASE_SHA256_RE.fullmatch(entry["sha256"]):
                raise ValidationError("Archive allowlist is invalid.")
            _bounded_nonnegative_integer(entry["size_bytes"])
    if names != sorted(names) or manifest_entries != 1:
        raise ValidationError("Archive allowlist is invalid.")
    return entries


def _validate_json_shape(value):
    if value is None or type(value) in {str, bool}:
        return
    if type(value) is int and not isinstance(value, bool):
        if not -9223372036854775808 <= value <= 9223372036854775807:
            raise ValidationError("Backup manifest is invalid.")
        return
    if type(value) is list:
        for item in value:
            _validate_json_shape(item)
        return
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise ValidationError("Backup manifest is invalid.")
        for item in value.values():
            _validate_json_shape(item)
        return
    raise ValidationError("Backup manifest is invalid.")


def validate_manifest_payload(payload: dict) -> dict:
    if type(payload) is not dict or set(payload) != TOP_LEVEL_MANIFEST_KEYS:
        raise ValidationError("Manifest payload must use the closed v3 schema.")
    _validate_json_shape(payload)
    if payload["schema_version"] != "3.0":
        raise ValidationError("Backup manifest is invalid.")
    _canonical_uuid_text(payload["backup_operation_id"])
    _canonical_uuid_text(payload["archive_identifier"])
    _canonical_utc_timestamp(payload["created_at"])
    if type(payload["job_type"]) is not str or type(payload["environment_class"]) is not str:
        raise ValidationError("Backup manifest is invalid.")
    if type(payload["storage_target_type"]) is not str:
        raise ValidationError("Backup manifest is invalid.")
    if type(payload["included"]) is not dict or set(payload["included"]) != {
        "database", "media", "protected_files", "manifest"
    } or any(type(value) is not bool for value in payload["included"].values()):
        raise ValidationError("Backup manifest is invalid.")
    if payload["included"]["manifest"] is not True:
        raise ValidationError("Backup manifest is invalid.")
    allowlist = validate_archive_member_allowlist(payload["archive_member_allowlist"])
    database_dump = payload["database_dump"]
    if database_dump is None:
        if payload["included"]["database"]:
            raise ValidationError("Backup manifest is invalid.")
    else:
        if type(database_dump) is not dict or set(database_dump) != {
            "member_name", "format", "sha256", "size_bytes"
        }:
            raise ValidationError("Backup manifest is invalid.")
        if database_dump["member_name"] != "database.dump" or database_dump["format"] != "postgresql-custom":
            raise ValidationError("Backup manifest is invalid.")
        if type(database_dump["sha256"]) is not str or not LOWERCASE_SHA256_RE.fullmatch(database_dump["sha256"]):
            raise ValidationError("Backup manifest is invalid.")
        _bounded_nonnegative_integer(database_dump["size_bytes"])
        matching = [entry for entry in allowlist if entry["member_name"] == "database.dump"]
        if len(matching) != 1 or matching[0]["member_class"] != "DATABASE_DUMP" or matching[0]["sha256"] != database_dump["sha256"] or matching[0]["size_bytes"] != database_dump["size_bytes"]:
            raise ValidationError("Backup manifest is invalid.")
    for name in ("protected_file_manifest", "public_media_manifest", "components"):
        if type(payload[name]) is not list:
            raise ValidationError("Backup manifest is invalid.")
        canonical_items = [
            json.dumps(
                item,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
            for item in payload[name]
        ]
        if len(canonical_items) != len(set(canonical_items)):
            raise ValidationError("Backup manifest is invalid.")
    if payload["components"] != sorted(payload["components"]) or any(
        type(component) is not str for component in payload["components"]
    ):
        raise ValidationError("Backup manifest is invalid.")
    return payload


def canonical_manifest_bytes(payload, *, maximum_bytes=None):
    validated = validate_manifest_payload(payload)
    try:
        encoded = json.dumps(
            validated,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise ValidationError("Backup manifest is invalid.")

    if maximum_bytes is not None and len(encoded) > maximum_bytes:
        raise ValidationError("Backup manifest is invalid.")
    return encoded


def _reject_duplicate_object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError("Backup manifest is invalid.")
        result[key] = value
    return result


def parse_canonical_manifest(raw):
    if type(raw) is not bytes:
        raise ValidationError("Backup manifest is invalid.")
    if not raw:
        raise ValidationError("Backup manifest is invalid.")
    try:
        text = raw.decode("utf-8", "strict")
        payload = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_object_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValidationError("Backup manifest is invalid.")
            ),
        )
    except ValidationError:
        raise
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        raise ValidationError("Backup manifest is invalid.")
    if canonical_manifest_bytes(payload) != raw:
        raise ValidationError("Backup manifest is invalid.")
    return payload


def validate_canonical_checkpoint_reference(value, *, allow_none=False):
    """Return a canonical, non-placeholder UUID reference without normalizing it."""
    if value is None and allow_none:
        return None
    try:
        if type(value) is not str:
            raise ValueError
        parsed = uuid.UUID(value)
        if str(parsed) != value or parsed.int == 0:
            raise ValueError
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValidationError("checkpoint_reference_invalid") from exc
    return value


def validate_no_key_material(includes_key_material: bool):
    """This foundation never stores or tracks raw key material in backup metadata."""
    if includes_key_material:
        raise ValidationError("Backup metadata cannot include key material in this foundation.")
