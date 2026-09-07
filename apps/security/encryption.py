# Project: COMPASS
# File: apps/security/encryption.py
# Module: apps.security
# Purpose: Symmetric authenticated field encryption helpers
# Domain boundary and service policy.

import base64
import json
from cryptography.fernet import Fernet
from apps.security.models import EncryptionKeyVersion, KeyPurposeChoices, KeyStatusChoices
from apps.security.key_sources import load_key_material
from apps.security.exceptions import KeyNotFoundError, SecurityError

ENCRYPTED_PAYLOAD_SCHEMA_VERSION = 1
SUPPORTED_ALGORITHM = "Fernet"


def get_active_key_version(purpose: str) -> EncryptionKeyVersion:
    """Retrieves the active key version for a given key purpose."""
    try:
        return EncryptionKeyVersion.objects.get(key_purpose=purpose, status=KeyStatusChoices.ACTIVE)
    except EncryptionKeyVersion.DoesNotExist:
        raise KeyNotFoundError()
    except EncryptionKeyVersion.MultipleObjectsReturned:
        raise SecurityError("field_encryption_key_state_invalid")


def get_key_version_for_decryption(key_version: str) -> EncryptionKeyVersion:
    """Retrieves key metadata for decryption. Blocks access if key is disabled."""
    try:
        key_metadata = EncryptionKeyVersion.objects.get(key_version=key_version)
        if key_metadata.key_purpose != KeyPurposeChoices.FIELD_ENCRYPTION:
            raise SecurityError("field_encryption_key_state_invalid")
        if key_metadata.status == KeyStatusChoices.DISABLED:
            raise SecurityError("field_encryption_key_state_invalid")
        return key_metadata
    except EncryptionKeyVersion.DoesNotExist:
        raise KeyNotFoundError()


def encrypt_value(plaintext: str, purpose: str) -> str:
    """
    Encrypts a plaintext string using the active key for the specified purpose.
    Returns a versioned JSON envelope encoded in base64.
    """
    if plaintext is None:
        return None

    if not isinstance(plaintext, str):
        raise SecurityError("field_encryption_payload_invalid")

    key_metadata = get_active_key_version(purpose)

    # Load raw key material
    key_material = load_key_material(
        key_metadata.key_version,
        key_metadata.secret_reference,
        source_alias=key_metadata.source_alias,
    )

    failed = False
    try:
        f = Fernet(key_material)
        ciphertext = f.encrypt(plaintext.encode("utf-8")).decode("utf-8")
    except Exception:
        failed = True
    if failed:
        raise SecurityError("field_encryption_operation_failed")

    payload = {
        "version": ENCRYPTED_PAYLOAD_SCHEMA_VERSION,
        "algorithm": SUPPORTED_ALGORITHM,
        "key_version": key_metadata.key_version,
        "ciphertext": ciphertext
    }

    return base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")


def decrypt_value(encrypted_payload: str) -> str:
    """
    Decrypts a versioned base64 payload.
    Supports active, decrypt_only, and retired keys. Blocks disabled keys.
    """
    if encrypted_payload is None:
        return None

    if not isinstance(encrypted_payload, str):
        raise SecurityError("field_encryption_malformed")

    malformed = False
    try:
        decoded_bytes = base64.b64decode(encrypted_payload.encode("utf-8"), validate=True)
        payload = json.loads(decoded_bytes.decode("utf-8"))
    except Exception:
        malformed = True
    if malformed:
        raise SecurityError("field_encryption_malformed")

    required_fields = {"version", "algorithm", "key_version", "ciphertext"}
    if not isinstance(payload, dict) or not required_fields.issubset(payload):
        raise SecurityError("field_encryption_malformed")

    if payload["version"] != ENCRYPTED_PAYLOAD_SCHEMA_VERSION:
        raise SecurityError("field_encryption_version_unsupported")

    if payload["algorithm"] != SUPPORTED_ALGORITHM:
        raise SecurityError("field_encryption_algorithm_unsupported")

    key_version = payload["key_version"]
    ciphertext = payload["ciphertext"]

    key_metadata = get_key_version_for_decryption(key_version)

    # Load raw key material
    key_material = load_key_material(
        key_metadata.key_version,
        key_metadata.secret_reference,
        source_alias=key_metadata.source_alias,
    )

    failed = False
    try:
        f = Fernet(key_material)
        plaintext = f.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
        return plaintext
    except Exception:
        failed = True
    if failed:
        raise SecurityError("field_encryption_auth_failed")
