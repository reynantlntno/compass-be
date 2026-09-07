from datetime import timedelta
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone
from django.utils.translation import gettext_lazy

from apps.accounts.models import User
from apps.common.cache.backend import cached_read, clear_request_cache
from apps.common.cache.contracts import CacheValueError, json_cache_payload
from apps.common.cache.keys import cache_key
from apps.common.cache.registry import get_cache_spec, validate_cache_registry


class CacheContractTests(TestCase):
    def setUp(self):
        cache.clear()
        clear_request_cache()

    def tearDown(self):
        cache.clear()
        clear_request_cache()

    def test_registry_has_bounded_namespaced_specs(self):
        self.assertEqual(validate_cache_registry(), [])
        self.assertTrue(cache_key("governance_policy", "target").startswith("compass:cache:v1:governance_policy:"))
        self.assertNotEqual(cache_key("content_public", "one"), cache_key("content_public", "two"))

    def test_models_querysets_lazy_values_and_oversized_values_are_rejected(self):
        user = User(email="cache@example.test")
        with self.assertRaises(CacheValueError):
            json_cache_payload({"user": user}, max_bytes=4096)
        with self.assertRaises(CacheValueError):
            json_cache_payload({"users": User.objects.all()}, max_bytes=4096)
        with self.assertRaises(CacheValueError):
            json_cache_payload({"lazy": gettext_lazy("lazy")}, max_bytes=4096)
        with self.assertRaises(CacheValueError):
            json_cache_payload({"body": "x" * 100}, max_bytes=20)

    def test_cache_miss_populates_json_snapshot_and_hit_avoids_loader(self):
        calls = []

        def loader():
            calls.append(True)
            return {"id": 7, "when": timezone.now(), "nested": ["safe"]}

        first = cached_read("catalog_reference", "test", ("snapshot",), loader)
        second = cached_read("catalog_reference", "test", ("snapshot",), loader)
        self.assertEqual(first, second)
        self.assertEqual(len(calls), 1)
        self.assertIsInstance(first["when"], str)

    def test_backend_failure_falls_back_to_normalized_loader_value(self):
        with patch("apps.common.cache.backend._backend", return_value=None):
            value = cached_read(
                "catalog_reference",
                "failure",
                ("fallback",),
                lambda: {"value": 3},
            )
        self.assertEqual(value, {"value": 3})

    def test_ttl_is_clipped_to_namespace_and_expiry(self):
        captured = {}

        def capture(key, value, timeout):
            captured["timeout"] = timeout
            return True

        expires = timezone.now() + timedelta(seconds=2)
        with patch("apps.common.cache.backend._safe_set", side_effect=capture):
            cached_read(
                "governance_policy",
                "ttl",
                ("value",),
                lambda: {"value": True},
                ttl=999,
                expires_at=expires,
            )
        self.assertLessEqual(captured["timeout"], get_cache_spec("governance_policy").max_ttl_seconds)
        self.assertLessEqual(captured["timeout"], 2)
