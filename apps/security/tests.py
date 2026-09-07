"""Focused tests for immutable security configuration boundaries."""

from pathlib import Path

from django.test import SimpleTestCase, override_settings

from apps.security.constants import (
    FIELD_ENCRYPTION_BATCH_SIZE_MAX,
    FIELD_ENCRYPTION_CHECKPOINT_MAX_BYTES,
    FIELD_ENCRYPTION_KEY_CACHE_MAX_ENTRIES,
    FIELD_ENCRYPTION_KEY_CACHE_TTL_SECONDS,
    FIELD_ENCRYPTION_MAX_PLAINTEXT_BYTES,
    PROTECTED_STORAGE_ALLOWED_CONTENT_TYPES,
    PROTECTED_STORAGE_ALLOWED_EXTENSIONS,
)


class ImmutableSecurityConfigurationTests(SimpleTestCase):
    def test_source_owned_limits_are_bounded(self):
        self.assertEqual(FIELD_ENCRYPTION_KEY_CACHE_TTL_SECONDS, 30)
        self.assertEqual(FIELD_ENCRYPTION_KEY_CACHE_MAX_ENTRIES, 32)
        self.assertEqual(FIELD_ENCRYPTION_MAX_PLAINTEXT_BYTES, 1_048_576)
        self.assertEqual(FIELD_ENCRYPTION_CHECKPOINT_MAX_BYTES, 65_536)
        self.assertEqual(FIELD_ENCRYPTION_BATCH_SIZE_MAX, 1_000)
        self.assertIn("application/pdf", PROTECTED_STORAGE_ALLOWED_CONTENT_TYPES)
        self.assertIn(".pdf", PROTECTED_STORAGE_ALLOWED_EXTENSIONS)

    def test_environment_values_cannot_override_source_owned_limits(self):
        from apps.security.field_encryption import _resolve_ceiling

        with override_settings(
            FIELD_ENCRYPTION_KEY_CACHE_TTL_SECONDS=1,
            FIELD_ENCRYPTION_KEY_CACHE_MAX_ENTRIES=1,
            FIELD_ENCRYPTION_MAX_PLAINTEXT_BYTES=1,
            FIELD_ENCRYPTION_CHECKPOINT_MAX_BYTES=1024,
            FIELD_ENCRYPTION_BATCH_SIZE_MAX=1,
            PROTECTED_STORAGE_ALLOWED_CONTENT_TYPES=frozenset(),
            PROTECTED_STORAGE_ALLOWED_EXTENSIONS=frozenset(),
        ):
            self.assertEqual(_resolve_ceiling(), FIELD_ENCRYPTION_MAX_PLAINTEXT_BYTES)
            self.assertIn("application/pdf", PROTECTED_STORAGE_ALLOWED_CONTENT_TYPES)
            self.assertIn(".pdf", PROTECTED_STORAGE_ALLOWED_EXTENSIONS)

    def test_runtime_modules_do_not_read_numeric_encryption_limits_from_settings(self):
        source_root = Path(__file__).resolve().parent
        forbidden_names = (
            "FIELD_ENCRYPTION_KEY_CACHE_TTL_SECONDS",
            "FIELD_ENCRYPTION_KEY_CACHE_MAX_ENTRIES",
            "FIELD_ENCRYPTION_MAX_PLAINTEXT_BYTES",
            "FIELD_ENCRYPTION_CHECKPOINT_MAX_BYTES",
            "FIELD_ENCRYPTION_BATCH_SIZE_MAX",
            "PROTECTED_STORAGE_ALLOWED_CONTENT_TYPES",
            "PROTECTED_STORAGE_ALLOWED_EXTENSIONS",
        )
        runtime_files = (
            "field_encryption.py",
            "fields.py",
            "key_sources.py",
            "field_operations.py",
            "file_services.py",
        )
        for filename in runtime_files:
            source = (source_root / filename).read_text()
            for name in forbidden_names:
                self.assertNotIn(f'getattr(settings, "{name}"', source)
