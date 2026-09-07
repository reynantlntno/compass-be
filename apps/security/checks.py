"""Reusable settings-only validation for encrypted-field foundations."""

import os
import re
from pathlib import Path

from django.conf import settings
from django.core import checks

from apps.security.constants import (
    FIELD_ENCRYPTION_BATCH_SIZE_MAX,
    FIELD_ENCRYPTION_CHECKPOINT_MAX_BYTES,
    FIELD_ENCRYPTION_KEY_CACHE_MAX_ENTRIES,
    FIELD_ENCRYPTION_KEY_CACHE_TTL_SECONDS,
    FIELD_ENCRYPTION_MAX_PLAINTEXT_BYTES,
)
from apps.security.key_sources import (
    ENVIRONMENT_KEY_ALLOWED_ENVIRONMENTS,
    SUPPORTED_KEY_SOURCE_ALIASES,
)


def validate_field_encryption_settings():
    """Return stable safe error codes; never inspect the database or key material."""
    errors = []
    source = getattr(settings, "KEY_SOURCE_PROVIDER", None)
    environment = getattr(settings, "COMPASS_ENVIRONMENT", None)
    checkpoint_dir = getattr(settings, "FIELD_ENCRYPTION_CHECKPOINT_DIR", None)

    if type(source) is not str or source != source.strip().lower():
        errors.append(("security.E001", "Key source provider is invalid."))
    elif source not in SUPPORTED_KEY_SOURCE_ALIASES:
        errors.append(("security.E001", "Key source provider is unavailable."))

    environment_valid = type(environment) is str and environment == environment.strip()
    normalized_environment = environment.lower() if environment_valid else ""
    if not environment_valid or not normalized_environment:
        errors.append(("security.E002", "Field encryption environment is invalid."))
    elif source == "env" and normalized_environment not in ENVIRONMENT_KEY_ALLOWED_ENVIRONMENTS:
        errors.append(("security.E002", "Environment key source provider is unsafe."))
    elif normalized_environment in {"production", "prod", "staging", "stage"} and source != "podman_secret":
        errors.append(("security.E002", "Deployment key source provider is unsafe."))

    if not 1 <= FIELD_ENCRYPTION_KEY_CACHE_TTL_SECONDS <= 300:
        errors.append(("security.E003", "Field key cache TTL is unsafe."))
    if not 1 <= FIELD_ENCRYPTION_MAX_PLAINTEXT_BYTES <= 1_048_576:
        errors.append(("security.E004", "Field payload ceiling is unsafe."))

    if type(checkpoint_dir) is not str or not checkpoint_dir or checkpoint_dir != checkpoint_dir.strip():
        errors.append(("security.E005", "Field checkpoint directory is unsafe."))
    else:
        path = Path(checkpoint_dir)
        if not path.is_absolute() or os.path.normpath(checkpoint_dir) != checkpoint_dir:
            errors.append(("security.E005", "Field checkpoint directory is unsafe."))
        elif ".." in path.parts:
            errors.append(("security.E005", "Field checkpoint directory is unsafe."))

    if not 1 <= FIELD_ENCRYPTION_KEY_CACHE_MAX_ENTRIES <= 128:
        errors.append(("security.E006", "Field key cache size is unsafe."))
    if not 1024 <= FIELD_ENCRYPTION_CHECKPOINT_MAX_BYTES <= 1_048_576:
        errors.append(("security.E007", "Field checkpoint maximum is unsafe."))
    if not 1 <= FIELD_ENCRYPTION_BATCH_SIZE_MAX <= 1000:
        errors.append(("security.E008", "Field batch size maximum is unsafe."))
    return tuple(errors)


@checks.register(checks.Tags.security)
def field_encryption_settings_check(app_configs, **kwargs):
    return [checks.Error(message, id=code) for code, message in validate_field_encryption_settings()]
