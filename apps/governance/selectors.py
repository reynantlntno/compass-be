from django.db.models import Q
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from apps.governance.choices import (
    DPOAppointmentStatus,
    PolicyEffectivenessChoices,
    PolicyLifecycleStatus,
)
from apps.governance.models import DPOAppointment, PolicyRecord
from apps.governance.projections import project_dpo_appointment, project_policy
from apps.governance.registry import POLICY_SPECS, get_policy_spec
from apps.governance.cache import ResolvedPolicySnapshot, policy_cache_target, snapshot_from_policy
from apps.common.cache.backend import cached_read


def _policy_cache_expiry(value):
    if not isinstance(value, dict):
        return None
    raw = value.get("effective_until")
    return parse_datetime(str(raw)) if raw else None


def policy_catalog():
    from apps.governance.projections import project_policy_spec
    from apps.governance.registry import POLICY_SPECS

    return [project_policy_spec(spec) for spec in POLICY_SPECS]


def policies_visible_to(actor):
    """Return safe policy metadata for an actor with a current owner plane."""
    from apps.governance.policy_lifecycle import can_manage_policy

    if actor is None:
        return PolicyRecord.objects.none()
    allowed_keys = [spec.key for spec in POLICY_SPECS if can_manage_policy(actor, spec.key)]
    if not allowed_keys:
        return PolicyRecord.objects.none()
    return PolicyRecord.objects.filter(key__in=allowed_keys).filter(_valid_target_scope_query()).order_by("key", "-created_at")


def _valid_target_scope_query():
    """Build a query that excludes malformed target metadata from reads."""
    valid = Q(pk__in=[])
    for spec in POLICY_SPECS:
        if spec.target_required:
            valid |= Q(key=spec.key, target_type=spec.target_type) & ~Q(target_reference="")
        else:
            valid |= Q(key=spec.key, target_type="", target_reference="")
    return valid


def effective_policies_visible_to(actor, *, at=None):
    """Return all currently effective policy versions the actor may inspect.

    Target-scoped policies are intentionally returned as separate rows.  A
    blank target is never treated as an office-wide fallback for a
    target-required policy.
    """
    current = at or timezone.now()
    visible = policies_visible_to(actor)
    return (
        visible.filter(_valid_target_scope_query())
        .filter(
            status=PolicyLifecycleStatus.ACTIVE,
            effectiveness=PolicyEffectivenessChoices.EFFECTIVE,
            activated_at__isnull=False,
        )
        .filter(Q(effective_from__isnull=True) | Q(effective_from__lte=current))
        .filter(Q(effective_until__isnull=True) | Q(effective_until__gte=current))
        .order_by("key", "target_type", "target_reference", "-activated_at", "-created_at")
    )


def effective_policy(policy_key: str, *, target=None, target_type: str = "", target_reference: str = "", at=None):
    current = at or timezone.now()
    spec = get_policy_spec(policy_key)
    if spec is None:
        return None
    if target is not None:
        target_type = f"{target._meta.app_label}.{target.__class__.__name__}"
        target_reference = str(target.pk)
    if spec.target_required and (target_type != spec.target_type or not target_reference):
        return None
    if not spec.target_required and (target_type or target_reference):
        return None
    cache_target = policy_cache_target(spec.key, target_type, target_reference)
    time_part = current.isoformat() if at is not None else "now"

    def load_snapshot():
        policy = (
            PolicyRecord.objects.filter(
                key=spec.key,
                status=PolicyLifecycleStatus.ACTIVE,
                effectiveness=PolicyEffectivenessChoices.EFFECTIVE,
                activated_at__isnull=False,
                target_type=target_type,
                target_reference=target_reference,
            )
            .filter(Q(effective_from__isnull=True) | Q(effective_from__lte=current))
            .filter(Q(effective_until__isnull=True) | Q(effective_until__gte=current))
            .order_by("-activated_at", "-created_at")
            .first()
        )
        if policy is None:
            return None
        # Runtime reads fail closed if a row was malformed outside the typed
        # Governance service (for example, by an administrative DB operation).
        try:
            from apps.governance.policy_lifecycle import _validate_persisted_configuration

            _validate_persisted_configuration(policy)
        except Exception:
            return None
        return snapshot_from_policy(policy).as_cache_value()

    cached = cached_read(
        "governance_policy",
        cache_target,
        (spec.key, target_type, target_reference, time_part),
        load_snapshot,
        expires_at=_policy_cache_expiry,
    )
    return ResolvedPolicySnapshot.from_cache_value(cached)


def effective_policy_snapshots(policy_key: str, *, target_type: str = "", at=None):
    """Return validated, immutable snapshots for an exact target family.

    This is the collection counterpart to ``resolve_effective_policy``.  It is
    intentionally owned by Governance so domains do not query PolicyRecord
    directly when they need to evaluate all target-scoped policies.
    """

    current = at or timezone.now()
    spec = get_policy_spec(policy_key)
    if spec is None or not spec.target_required or target_type != spec.target_type:
        return ()
    rows = (
        PolicyRecord.objects.filter(
            key=policy_key,
            target_type=target_type,
            status=PolicyLifecycleStatus.ACTIVE,
            effectiveness=PolicyEffectivenessChoices.EFFECTIVE,
            activated_at__isnull=False,
        )
        .filter(Q(effective_from__isnull=True) | Q(effective_from__lte=current))
        .filter(Q(effective_until__isnull=True) | Q(effective_until__gte=current))
        .order_by("target_reference", "-activated_at", "-created_at")
    )
    snapshots = []
    for row in rows:
        try:
            from apps.governance.policy_lifecycle import _validate_persisted_configuration

            _validate_persisted_configuration(row)
        except Exception:
            continue
        snapshot = snapshot_from_policy(row)
        if not any(item.target_reference == snapshot.target_reference for item in snapshots):
            snapshots.append(snapshot)
    return tuple(snapshots)


def resolve_effective_policy(policy_key: str, *, target=None, target_type: str = "", target_reference: str = "", at=None):
    """Canonical typed-policy read boundary used by domain applications."""

    return effective_policy(
        policy_key,
        target=target,
        target_type=target_type,
        target_reference=target_reference,
        at=at,
    )


def resolve_feature_flag(name: str, *, at=None) -> bool:
    """Read one centrally stored feature flag with a fail-closed default."""
    normalized = str(name or "").strip()
    if not normalized or len(normalized) > 120:
        return False
    policy = resolve_effective_policy(
        "system.feature_flags",
        target_type="system.FeatureFlag",
        target_reference=normalized,
        at=at,
    )
    if policy is None:
        return False
    configuration = policy.configuration_json or {}
    value = configuration.get("is_enabled")
    if not isinstance(value, bool):
        return False
    return value


def current_policy_projection(policy_key: str, *, target=None, target_type: str = "", target_reference: str = "", at=None):
    return project_policy(resolve_effective_policy(policy_key, target=target, target_type=target_type, target_reference=target_reference, at=at))


def active_dpo_appointment(*, at=None):
    current = at or timezone.now()
    return (
        DPOAppointment.objects.filter(
            status=DPOAppointmentStatus.ACTIVE,
            valid_from__lte=current,
            holder__is_active=True,
            holder__is_superuser=False,
        )
        .filter(Q(valid_until__isnull=True) | Q(valid_until__gte=current))
        .select_related("holder")
        .first()
    )


def current_dpo_projection(*, at=None):
    return project_dpo_appointment(active_dpo_appointment(at=at))


def policy_projection_list(actor):
    return [project_policy(row) for row in policies_visible_to(actor)]
