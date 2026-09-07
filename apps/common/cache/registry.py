"""Code-owned cache namespaces and safety bounds."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True, slots=True)
class CacheSpec:
    namespace: str
    max_ttl_seconds: int
    max_payload_bytes: int = 256 * 1024
    scope: str = "global"
    sensitivity: str = "safe_metadata"


CACHE_SPECS = MappingProxyType(
    {
        "governance_policy": CacheSpec(
            namespace="governance_policy",
            max_ttl_seconds=30,
            scope="target",
            sensitivity="governed_configuration",
        ),
        "organization_identity": CacheSpec(
            namespace="organization_identity",
            max_ttl_seconds=300,
            scope="institution",
        ),
        "organization_branding": CacheSpec(
            namespace="organization_branding",
            max_ttl_seconds=300,
            scope="institution",
            max_payload_bytes=64 * 1024,
        ),
        "content_public": CacheSpec(
            namespace="content_public",
            max_ttl_seconds=60,
            scope="public",
            max_payload_bytes=512 * 1024,
        ),
        "document_metadata": CacheSpec(
            namespace="document_metadata",
            max_ttl_seconds=300,
            scope="resource",
        ),
        "form_metadata": CacheSpec(
            namespace="form_metadata",
            max_ttl_seconds=300,
            scope="resource",
        ),
        "notification_template": CacheSpec(
            namespace="notification_template",
            max_ttl_seconds=300,
            scope="template",
            max_payload_bytes=256 * 1024,
        ),
        "catalog_reference": CacheSpec(
            namespace="catalog_reference",
            max_ttl_seconds=900,
            scope="catalog",
            max_payload_bytes=512 * 1024,
        ),
    }
)


def validate_cache_registry() -> list[str]:
    """Return configuration errors for the code-owned cache catalog."""

    errors: list[str] = []
    expected_ttls = {
        "governance_policy": 30,
        "content_public": 60,
        "organization_identity": 300,
        "organization_branding": 300,
        "document_metadata": 300,
        "form_metadata": 300,
        "notification_template": 300,
        "catalog_reference": 900,
    }
    for name, spec in CACHE_SPECS.items():
        if name != spec.namespace:
            errors.append(f"cache namespace mismatch: {name}")
        if not spec.namespace or spec.max_ttl_seconds <= 0 or spec.max_payload_bytes <= 0:
            errors.append(f"cache spec has unsafe bounds: {name}")
        if expected_ttls.get(name) != spec.max_ttl_seconds:
            errors.append(f"cache spec has an unapproved TTL profile: {name}")
        if not spec.sensitivity:
            errors.append(f"cache spec has no sensitivity classification: {name}")
        if spec.scope not in {"global", "target", "institution", "public", "resource", "template", "catalog"}:
            errors.append(f"cache spec has unknown scope: {name}")
    return errors


def get_cache_spec(namespace: str) -> CacheSpec:
    try:
        return CACHE_SPECS[str(namespace)]
    except KeyError as exc:
        raise KeyError(f"Unknown cache namespace: {namespace!r}") from exc
