"""Cached, immutable snapshots for effective Governance policies."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from django.utils.dateparse import parse_datetime

from apps.common.cache.backend import cached_read
from apps.common.cache.invalidation import invalidate_after_commit


@dataclass(frozen=True, slots=True)
class ResolvedPolicySnapshot:
    """Model-free policy value returned by the runtime resolver.

    Attribute names intentionally mirror the small read-only surface consumed
    by existing domain evaluators.  The cache stores the JSON form only.
    """

    id: str
    key: str
    schema_version: str
    target_type: str
    target_reference: str
    status: str
    configuration_json: dict[str, Any]
    effective_from: datetime | None
    effective_until: datetime | None
    source_reference: str
    created_at: datetime
    updated_at: datetime
    approved_by_id: int | None
    approved_at: datetime | None
    activated_by_id: int | None
    activated_at: datetime | None
    retired_at: datetime | None

    @property
    def pk(self) -> str:
        return self.id

    def as_cache_value(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "key": self.key,
            "schema_version": self.schema_version,
            "target_type": self.target_type,
            "target_reference": self.target_reference,
            "status": self.status,
            "configuration_json": self.configuration_json,
            "effective_from": self.effective_from.isoformat() if self.effective_from else None,
            "effective_until": self.effective_until.isoformat() if self.effective_until else None,
            "source_reference": self.source_reference,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "approved_by_id": self.approved_by_id,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "activated_by_id": self.activated_by_id,
            "activated_at": self.activated_at.isoformat() if self.activated_at else None,
            "retired_at": self.retired_at.isoformat() if self.retired_at else None,
        }

    @classmethod
    def from_cache_value(cls, value: Any) -> "ResolvedPolicySnapshot | None":
        if value is None:
            return None
        if not isinstance(value, dict):
            return None
        required = {
            "id", "key", "schema_version", "target_type", "target_reference",
            "status", "configuration_json", "created_at", "updated_at",
        }
        if not required.issubset(value) or not isinstance(value.get("configuration_json"), dict):
            return None

        def dt(name: str) -> datetime | None:
            raw = value.get(name)
            if raw in (None, ""):
                return None
            parsed = parse_datetime(str(raw))
            if parsed is None:
                raise ValueError(f"Malformed policy timestamp: {name}")
            return parsed

        try:
            created_at = dt("created_at")
            updated_at = dt("updated_at")
            effective_from = dt("effective_from")
            effective_until = dt("effective_until")
            approved_at = dt("approved_at")
            activated_at = dt("activated_at")
            retired_at = dt("retired_at")
        except (TypeError, ValueError):
            return None
        if created_at is None or updated_at is None:
            return None
        return cls(
            id=str(value["id"]),
            key=str(value["key"]),
            schema_version=str(value["schema_version"]),
            target_type=str(value.get("target_type") or ""),
            target_reference=str(value.get("target_reference") or ""),
            status=str(value["status"]),
            configuration_json=dict(value["configuration_json"]),
            effective_from=effective_from,
            effective_until=effective_until,
            source_reference=str(value.get("source_reference") or ""),
            created_at=created_at,
            updated_at=updated_at,
            approved_by_id=value.get("approved_by_id"),
            approved_at=approved_at,
            activated_by_id=value.get("activated_by_id"),
            activated_at=activated_at,
            retired_at=retired_at,
        )


def snapshot_from_policy(policy) -> ResolvedPolicySnapshot:
    return ResolvedPolicySnapshot(
        id=str(policy.pk),
        key=policy.key,
        schema_version=policy.schema_version,
        target_type=policy.target_type,
        target_reference=policy.target_reference,
        status=policy.status,
        configuration_json=dict(policy.configuration_json or {}),
        effective_from=policy.effective_from,
        effective_until=policy.effective_until,
        source_reference=policy.source_reference,
        created_at=policy.created_at,
        updated_at=policy.updated_at,
        approved_by_id=policy.approved_by_id,
        approved_at=policy.approved_at,
        activated_by_id=policy.activated_by_id,
        activated_at=policy.activated_at,
        retired_at=policy.retired_at,
    )


def policy_cache_target(policy_key: str, target_type: str = "", target_reference: str = "") -> str:
    return f"{policy_key}|{target_type}|{target_reference}"


def invalidate_policy_after_commit(policy_key: str, target_type: str = "", target_reference: str = "") -> None:
    invalidate_after_commit(
        "governance_policy",
        policy_cache_target(policy_key, target_type, target_reference),
    )
