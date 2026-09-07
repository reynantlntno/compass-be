"""Strict, versioned authenticated codec for reusable encrypted model fields."""

import base64
import json
import math
import re

from cryptography.fernet import InvalidToken
from django.utils import timezone

from apps.security.exceptions import (
    FieldEncryptionAuthenticationFailed,
    FieldEncryptionConfigurationError,
    FieldEncryptionContextMismatch,
    FieldEncryptionInnerContractMismatch,
    FieldEncryptionKeyStateInvalid,
    FieldEncryptionKeyUnavailable,
    FieldEncryptionMalformedEnvelope,
    FieldEncryptionPayloadTooLarge,
    FieldEncryptionPayloadInvalid,
    FieldEncryptionPayloadTypeMismatch,
    FieldEncryptionUnsupportedAlgorithm,
    FieldEncryptionUnsupportedVersion,
)
from apps.security.key_sources import load_fernet_for_metadata
from apps.security.models import EncryptionKeyVersion, KeyPurposeChoices, KeyStatusChoices
from apps.security.constants import FIELD_ENCRYPTION_MAX_PLAINTEXT_BYTES

FORMAT = "compass.encrypted-field"
VERSION = 1
ALGORITHM = "fernet-v1"
MODEL_ALGORITHM = "Fernet"
OUTER_KEYS = {"algorithm", "ciphertext", "format", "key_id", "version"}
INNER_KEYS = {"context", "format", "key_id", "payload", "payload_type", "version"}
KEY_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,99}\Z")
CONTEXT_RE = re.compile(r"\A[a-zA-Z0-9_]+\.[A-Za-z0-9_]+\.[a-zA-Z0-9_]+\Z")
MAX_OUTER_ENVELOPE_CHARACTERS = 1_900_000
MAX_TOKEN_CHARACTERS = 1_800_000
MAX_CONTEXT_CHARACTERS = 512
_JSON_ENCODER = json.JSONEncoder(
    sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
)


def canonical_json(value):
    failed = False
    try:
        return _JSON_ENCODER.encode(value)
    except (TypeError, ValueError, UnicodeError):
        failed = True
    if failed:
        raise FieldEncryptionInnerContractMismatch()


def _strict_object(text, expected_keys, malformed_error):
    def pairs_hook(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise malformed_error()
            result[key] = value
        return result

    invalid = False
    try:
        value = json.loads(text, object_pairs_hook=pairs_hook)
    except malformed_error:
        raise
    except Exception:
        invalid = True
    if invalid:
        raise malformed_error()
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise malformed_error()
    return value


def _validate_exact_json(value, active=None):
    value_type = type(value)
    if value_type in {str, int, bool, type(None)}:
        return
    if value_type is float:
        if not math.isfinite(value):
            raise FieldEncryptionInnerContractMismatch()
        return
    if value_type not in {dict, list}:
        raise FieldEncryptionInnerContractMismatch()
    active = active if active is not None else set()
    identity = id(value)
    if identity in active:
        raise FieldEncryptionInnerContractMismatch()
    active.add(identity)
    try:
        if value_type is dict:
            for key, child in value.items():
                if type(key) is not str:
                    raise FieldEncryptionInnerContractMismatch()
                _validate_exact_json(child, active)
        else:
            for child in value:
                _validate_exact_json(child, active)
    finally:
        active.remove(identity)


def _bounded_utf8_length(chunks, ceiling, error_type):
    total = 0
    invalid = False
    try:
        for chunk in chunks:
            for offset in range(0, len(chunk), 8192):
                total += len(chunk[offset : offset + 8192].encode("utf-8"))
                if total > ceiling:
                    raise FieldEncryptionPayloadTooLarge()
    except FieldEncryptionPayloadTooLarge:
        raise
    except (UnicodeEncodeError, TypeError, ValueError):
        invalid = True
    if invalid:
        raise error_type()
    return total


def _payload_utf8_length(payload, payload_type, ceiling):
    if payload_type == "text":
        return _bounded_utf8_length((payload,), ceiling, FieldEncryptionPayloadInvalid)
    total = 0

    def add(size):
        nonlocal total
        total += size
        if total > ceiling:
            raise FieldEncryptionPayloadTooLarge()

    def add_string(value):
        add(2)
        for offset in range(0, len(value), 8192):
            chunk = value[offset : offset + 8192]
            start = 0
            for index, character in enumerate(chunk):
                codepoint = ord(character)
                if character in {'"', "\\"} or codepoint < 0x20 or 0xD800 <= codepoint <= 0xDFFF:
                    if index > start:
                        add(_bounded_utf8_length((chunk[start:index],), ceiling - total, FieldEncryptionInnerContractMismatch))
                    if 0xD800 <= codepoint <= 0xDFFF:
                        raise FieldEncryptionInnerContractMismatch()
                    add(2 if character in {'"', "\\", "\b", "\f", "\n", "\r", "\t"} else 6)
                    start = index + 1
            if start < len(chunk):
                add(_bounded_utf8_length((chunk[start:],), ceiling - total, FieldEncryptionInnerContractMismatch))

    def count(value):
        value_type = type(value)
        if value_type is str:
            add_string(value)
        elif value_type is type(None):
            add(4)
        elif value_type is bool:
            add(4 if value else 5)
        elif value_type is int:
            add(len(str(value)))
        elif value_type is float:
            add(len(_JSON_ENCODER.encode(value)))
        elif value_type is list:
            add(2)
            for index, child in enumerate(value):
                if index:
                    add(1)
                count(child)
        else:
            add(2)
            for index, key in enumerate(sorted(value)):
                if index:
                    add(1)
                add_string(key)
                add(1)
                count(value[key])

    count(payload)
    return total


def _validate_payload(payload, payload_type, ceiling=None):
    if payload_type == "text":
        if type(payload) is not str:
            raise FieldEncryptionPayloadTypeMismatch()
    elif payload_type == "json":
        _validate_exact_json(payload)
    else:
        raise FieldEncryptionPayloadTypeMismatch()
    if ceiling is not None:
        _payload_utf8_length(payload, payload_type, ceiling)


def _resolve_ceiling(value=None):
    raw_ceiling = value if value is not None else FIELD_ENCRYPTION_MAX_PLAINTEXT_BYTES
    if type(raw_ceiling) is not int:
        raise FieldEncryptionConfigurationError()
    ceiling = raw_ceiling
    if not 1 <= ceiling <= FIELD_ENCRYPTION_MAX_PLAINTEXT_BYTES:
        raise FieldEncryptionConfigurationError()
    return ceiling


def _validate_key_window(metadata, now=None):
    now = now or timezone.now()
    if metadata.not_before and now < metadata.not_before:
        raise FieldEncryptionKeyStateInvalid()
    if metadata.not_after and now > metadata.not_after:
        raise FieldEncryptionKeyStateInvalid()
    if metadata.not_before and metadata.not_after and metadata.not_before >= metadata.not_after:
        raise FieldEncryptionKeyStateInvalid()


def _validate_metadata(metadata, allowed_statuses):
    if metadata.key_purpose != KeyPurposeChoices.FIELD_ENCRYPTION:
        raise FieldEncryptionKeyStateInvalid()
    if metadata.status not in allowed_statuses:
        raise FieldEncryptionKeyStateInvalid()
    if metadata.algorithm != MODEL_ALGORITHM:
        raise FieldEncryptionUnsupportedAlgorithm()
    if not KEY_ID_RE.fullmatch(metadata.key_version or ""):
        raise FieldEncryptionConfigurationError()
    _validate_key_window(metadata)
    return metadata


def get_active_field_key():
    rows = list(
        EncryptionKeyVersion.objects.filter(
            key_purpose=KeyPurposeChoices.FIELD_ENCRYPTION,
            status=KeyStatusChoices.ACTIVE,
        )[:2]
    )
    if len(rows) != 1:
        raise FieldEncryptionKeyUnavailable()
    return _validate_metadata(rows[0], {KeyStatusChoices.ACTIVE})


def get_field_key_for_decryption(key_id):
    if not isinstance(key_id, str) or not KEY_ID_RE.fullmatch(key_id):
        raise FieldEncryptionMalformedEnvelope()
    missing = multiple = False
    try:
        metadata = EncryptionKeyVersion.objects.get(key_version=key_id)
    except EncryptionKeyVersion.DoesNotExist:
        missing = True
    except EncryptionKeyVersion.MultipleObjectsReturned:
        multiple = True
    if missing:
        raise FieldEncryptionKeyUnavailable()
    if multiple:
        raise FieldEncryptionKeyStateInvalid()
    return _validate_metadata(
        metadata, {KeyStatusChoices.ACTIVE, KeyStatusChoices.DECRYPT_ONLY}
    )


def parse_outer_envelope(stored):
    if type(stored) is not str or len(stored) > MAX_OUTER_ENVELOPE_CHARACTERS:
        raise FieldEncryptionMalformedEnvelope()
    outer = _strict_object(stored, OUTER_KEYS, FieldEncryptionMalformedEnvelope)
    if outer["format"] != FORMAT:
        raise FieldEncryptionMalformedEnvelope()
    if type(outer["version"]) is not int or outer["version"] != VERSION:
        raise FieldEncryptionUnsupportedVersion()
    if outer["algorithm"] != ALGORITHM:
        raise FieldEncryptionUnsupportedAlgorithm()
    if type(outer["key_id"]) is not str or not KEY_ID_RE.fullmatch(outer["key_id"]):
        raise FieldEncryptionMalformedEnvelope()
    token = outer["ciphertext"]
    if type(token) is not str or not 80 <= len(token) <= MAX_TOKEN_CHARACTERS:
        raise FieldEncryptionMalformedEnvelope()
    invalid_token = False
    try:
        base64.b64decode(token.encode("ascii"), altchars=b"-_", validate=True)
    except Exception:
        invalid_token = True
    if invalid_token:
        raise FieldEncryptionMalformedEnvelope()
    if canonical_json(outer) != stored:
        raise FieldEncryptionMalformedEnvelope()
    return outer


def encrypt_field_value(payload, *, payload_type, context, max_plaintext_bytes=None, key=None):
    if (
        type(context) is not str
        or len(context) > MAX_CONTEXT_CHARACTERS
        or not CONTEXT_RE.fullmatch(context)
    ):
        raise FieldEncryptionConfigurationError()
    ceiling = _resolve_ceiling(max_plaintext_bytes)
    _validate_payload(payload, payload_type, ceiling)
    metadata = key or get_active_field_key()
    _validate_metadata(metadata, {KeyStatusChoices.ACTIVE})
    inner = {
        "context": context,
        "format": FORMAT,
        "key_id": metadata.key_version,
        "payload": payload,
        "payload_type": payload_type,
        "version": VERSION,
    }
    raw = canonical_json(inner).encode("utf-8")
    token = load_fernet_for_metadata(metadata).encrypt(raw).decode("ascii")
    return canonical_json(
        {
            "algorithm": ALGORITHM,
            "ciphertext": token,
            "format": FORMAT,
            "key_id": metadata.key_version,
            "version": VERSION,
        }
    )


def decrypt_field_value(stored, *, payload_type, context, max_plaintext_bytes=None):
    outer = parse_outer_envelope(stored)
    metadata = get_field_key_for_decryption(outer["key_id"])
    invalid_token = False
    other_error = None
    try:
        raw = load_fernet_for_metadata(metadata).decrypt(outer["ciphertext"].encode("ascii"))
    except InvalidToken:
        invalid_token = True
    except FieldEncryptionAuthenticationFailed:
        raise
    except Exception as exc:
        other_error = exc
    if invalid_token:
        raise FieldEncryptionAuthenticationFailed()
    if other_error is not None:
        from apps.security.exceptions import FieldEncryptionError
        if isinstance(other_error, FieldEncryptionError):
            other_error.__cause__ = None
            other_error.__context__ = None
            raise other_error
        raise FieldEncryptionKeyUnavailable()
    ceiling = _resolve_ceiling(max_plaintext_bytes)
    invalid_utf8 = False
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        invalid_utf8 = True
    if invalid_utf8:
        raise FieldEncryptionInnerContractMismatch()
    inner = _strict_object(decoded, INNER_KEYS, FieldEncryptionInnerContractMismatch)
    if canonical_json(inner) != decoded:
        raise FieldEncryptionInnerContractMismatch()
    if inner["format"] != FORMAT or type(inner["version"]) is not int or inner["version"] != VERSION:
        raise FieldEncryptionInnerContractMismatch()
    if inner["key_id"] != outer["key_id"]:
        raise FieldEncryptionInnerContractMismatch()
    if inner["payload_type"] != payload_type:
        raise FieldEncryptionPayloadTypeMismatch()
    if inner["context"] != context:
        raise FieldEncryptionContextMismatch()
    _validate_payload(inner["payload"], payload_type, ceiling)
    return inner["payload"]
