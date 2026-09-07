# Project: COMPASS
# File: apps/security/key_sources.py
# Module: apps.security
# Purpose: Key source abstraction for loading key material without database storage
# Domain boundary and service policy.

import base64
import binascii
import os
import re
import time
from collections import OrderedDict
from pathlib import Path
from django.conf import settings
from cryptography.fernet import Fernet
from apps.security.constants import (
    FIELD_ENCRYPTION_KEY_CACHE_MAX_ENTRIES,
    FIELD_ENCRYPTION_KEY_CACHE_TTL_SECONDS,
)
from apps.security.exceptions import (
    FieldEncryptionConfigurationError,
    FieldEncryptionKeySourceUnavailable,
    KeyMalformedError,
    KeyNotFoundError,
    SecurityError,
)

SUPPORTED_KEY_SOURCE_ALIASES = frozenset({"env", "podman_secret"})
ENVIRONMENT_KEY_ALLOWED_ENVIRONMENTS = frozenset(
    {"development", "dev", "test", "testing"}
)
_KEY_CACHE = OrderedDict()
_FERNET_KEY_RE = re.compile(rb"\A[A-Za-z0-9_-]{43}=\Z")
_ENV_REFERENCE_RE = re.compile(r"\A[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_SECRET_NAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")


def validate_fernet_key(key_bytes: bytes | str) -> bytes:
    """Validates that key_bytes is a valid 32-byte URL-safe base64 key suitable for Fernet."""
    invalid = False
    try:
        if type(key_bytes) is str:
            canonical = key_bytes.encode("ascii")
        elif type(key_bytes) is bytes:
            canonical = key_bytes
        else:
            raise ValueError
        if not _FERNET_KEY_RE.fullmatch(canonical):
            raise ValueError
        decoded = base64.b64decode(canonical, altchars=b"-_", validate=True)
        if len(decoded) != 32 or base64.urlsafe_b64encode(decoded) != canonical:
            raise ValueError
        Fernet(canonical)
        return canonical
    except (UnicodeError, ValueError, TypeError, binascii.Error):
        invalid = True
    if invalid:
        raise KeyMalformedError()


def validate_aes256_key(key_bytes: bytes | str) -> bytes:
    """Return exactly 32 raw AES key bytes without retaining an encoded form."""
    try:
        if type(key_bytes) is bytes and len(key_bytes) == 32:
            return key_bytes
        if type(key_bytes) is str:
            canonical = key_bytes.encode("ascii")
        elif type(key_bytes) is bytes:
            canonical = key_bytes
        else:
            raise ValueError
        decoded = base64.b64decode(canonical, altchars=b"-_", validate=True)
        if len(decoded) != 32 or base64.urlsafe_b64encode(decoded) != canonical:
            raise ValueError
        return decoded
    except (UnicodeError, ValueError, TypeError, binascii.Error):
        raise KeyMalformedError()


class BaseKeySource:
    def get_key(self, key_version: str, secret_reference: str) -> bytes:
        raise NotImplementedError("Subclasses must implement get_key()")


class EnvironmentKeySource(BaseKeySource):
    """Loads encryption keys from environment variables."""
    def get_key(self, key_version: str, secret_reference: str) -> bytes:
        environment = getattr(settings, "COMPASS_ENVIRONMENT", None)
        if type(environment) is not str or environment.lower() not in ENVIRONMENT_KEY_ALLOWED_ENVIRONMENTS:
            raise FieldEncryptionConfigurationError()
        if type(secret_reference) is not str or not _ENV_REFERENCE_RE.fullmatch(secret_reference):
            raise FieldEncryptionConfigurationError()
        val = os.environ.get(secret_reference)
        if not val:
            raise KeyNotFoundError()
        return validate_fernet_key(val)


class PodmanSecretKeySource(BaseKeySource):
    """Loads encryption keys from Podman/Docker mounted secrets files."""
    def get_key(self, key_version: str, secret_reference: str) -> bytes:
        if type(secret_reference) is not str or not _SECRET_NAME_RE.fullmatch(secret_reference):
            raise FieldEncryptionConfigurationError()
        secrets_dir = Path(settings.KEY_SOURCE_PODMAN_SECRETS_DIR)
        secret_file = secrets_dir / secret_reference

        # Prevent directory traversal attacks
        try:
            secret_file.resolve().relative_to(secrets_dir.resolve())
        except ValueError:
            raise FieldEncryptionKeySourceUnavailable()

        if not secret_file.exists() or not secret_file.is_file():
            raise KeyNotFoundError()

        unavailable = False
        try:
            with open(secret_file, "rb") as f:
                content = f.read(129)
            if len(content) > 128:
                raise KeyMalformedError()
            return validate_fernet_key(content)
        except KeyMalformedError:
            raise
        except Exception:
            unavailable = True
        if unavailable:
            raise FieldEncryptionKeySourceUnavailable()


def get_key_source_provider(source_alias=None) -> BaseKeySource:
    """Factory to get the configured key source provider based on django settings."""
    configured = (
        getattr(settings, "KEY_SOURCE_PROVIDER", None)
        if source_alias is None
        else source_alias
    )
    if type(configured) is not str or configured != configured.strip().lower():
        raise FieldEncryptionConfigurationError()
    provider_name = configured
    if provider_name == "env":
        return EnvironmentKeySource()
    elif provider_name == "podman_secret":
        return PodmanSecretKeySource()
    raise FieldEncryptionConfigurationError()


def load_key_material(key_version: str, secret_reference: str, source_alias=None) -> bytes:
    """Convenience function to load and validate key material using active provider."""
    provider = get_key_source_provider(source_alias)
    return provider.get_key(key_version, secret_reference)


def _safe_reference_identity(source_alias, secret_reference):
    """Return a process-local identity; never expose the source reference itself."""
    return hash((str(source_alias).lower(), str(secret_reference)))


def invalidate_field_key_cache():
    _KEY_CACHE.clear()


def load_fernet_for_metadata(key_metadata):
    """Resolve one metadata row through its declared source with a bounded cache."""
    source_alias = key_metadata.source_alias
    if type(source_alias) is not str or source_alias != source_alias.strip().lower():
        raise FieldEncryptionConfigurationError()
    environment = getattr(settings, "COMPASS_ENVIRONMENT", None)
    if source_alias not in SUPPORTED_KEY_SOURCE_ALIASES:
        raise FieldEncryptionConfigurationError()
    if source_alias == "env" and (
        type(environment) is not str
        or environment.lower() not in ENVIRONMENT_KEY_ALLOWED_ENVIRONMENTS
    ):
        raise FieldEncryptionConfigurationError()
    ttl = FIELD_ENCRYPTION_KEY_CACHE_TTL_SECONDS
    maximum = FIELD_ENCRYPTION_KEY_CACHE_MAX_ENTRIES
    if (
        type(ttl) is not int
        or type(maximum) is not int
        or not 1 <= ttl <= 300
        or not 1 <= maximum <= 128
    ):
        raise FieldEncryptionConfigurationError()
    cache_key = (
        key_metadata.key_purpose,
        key_metadata.key_version,
        source_alias,
        _safe_reference_identity(source_alias, key_metadata.secret_reference),
    )
    now = time.monotonic()
    cached = _KEY_CACHE.get(cache_key)
    if cached and cached[0] > now:
        _KEY_CACHE.move_to_end(cache_key)
        return cached[1]
    _KEY_CACHE.pop(cache_key, None)
    unavailable = False
    try:
        material = load_key_material(
            key_metadata.key_version,
            key_metadata.secret_reference,
            source_alias=source_alias,
        )
        fernet = Fernet(validate_fernet_key(material))
    except (KeyNotFoundError, KeyMalformedError, FieldEncryptionKeySourceUnavailable):
        raise
    except Exception:
        unavailable = True
    if unavailable:
        raise FieldEncryptionKeySourceUnavailable()
    _KEY_CACHE[cache_key] = (now + ttl, fernet)
    while len(_KEY_CACHE) > maximum:
        _KEY_CACHE.popitem(last=False)
    return fernet


def _load_external_value(source_alias, secret_reference):
    """Load bounded external bytes without applying Fernet-specific decoding."""
    if type(source_alias) is not str or source_alias != source_alias.strip().lower():
        raise FieldEncryptionConfigurationError()
    if source_alias == "env":
        environment = getattr(settings, "COMPASS_ENVIRONMENT", None)
        if (
            type(environment) is not str
            or environment.lower() not in ENVIRONMENT_KEY_ALLOWED_ENVIRONMENTS
            or type(secret_reference) is not str
            or not _ENV_REFERENCE_RE.fullmatch(secret_reference)
        ):
            raise FieldEncryptionConfigurationError()
        value = os.environ.get(secret_reference)
        if not value:
            raise KeyNotFoundError()
        return value
    if source_alias == "podman_secret":
        if type(secret_reference) is not str or not _SECRET_NAME_RE.fullmatch(secret_reference):
            raise FieldEncryptionConfigurationError()
        root = Path(settings.KEY_SOURCE_PODMAN_SECRETS_DIR)
        path = root / secret_reference
        try:
            path.resolve().relative_to(root.resolve())
            value = path.read_bytes()
        except FileNotFoundError:
            raise KeyNotFoundError()
        except Exception:
            raise FieldEncryptionKeySourceUnavailable()
        if len(value) > 128:
            raise KeyMalformedError()
        return value
    raise FieldEncryptionConfigurationError()
