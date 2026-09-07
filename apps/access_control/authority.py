"""Per-account workflow-authority resolution and mutation services."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from enum import Enum

from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from apps.accounts.models import RoleChoices
from apps.access_control.capabilities import (
    ALL_DELEGABLE_CAPABILITIES,
    AuthoritySource,
    Capability,
    effective_fixed_capabilities,
    get_capability_spec,
)
from apps.access_control.choices import GrantReasonCode, GrantSourceType, GrantStatus, RevocationReasonCode, ScopeMode
from apps.access_control.models import CounselorCoverage, WorkflowAuthorityGrant
from apps.access_control.rules import is_active_nonlegacy_actor, is_head_guidance
from apps.audit.services import audit_log
from apps.common.exceptions import PermissionDeniedError as PermissionDenied, ValidationError


SCOPE_FIELDS = ("campus", "college", "department", "program")
MAX_GRANT_DAYS = 366


@dataclass(frozen=True)
class AuthorityContext:
    actor_id: int | None
    role: str | None
    is_authenticated: bool
    is_active: bool
    is_legacy_superuser: bool
    is_head_guidance: bool
    fixed_capabilities: frozenset[Capability]
    coverages: tuple
    grants: tuple
    as_of: date


class AuthorityReason(str, Enum):
    COUNSELOR_BASELINE = "COUNSELOR_BASELINE"
    HEAD_FIXED = "HEAD_FIXED"
    IT_FIXED = "IT_FIXED"
    ACCOUNT_GRANT = "ACCOUNT_GRANT"
    INACTIVE = "INACTIVE"
    LEGACY_SUPERUSER = "LEGACY_SUPERUSER"
    UNKNOWN_CAPABILITY = "UNKNOWN_CAPABILITY"
    INELIGIBLE_ROLE = "INELIGIBLE_ROLE"
    MISSING_GRANT = "MISSING_GRANT"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"


@dataclass(frozen=True)
class AuthorityDecision:
    allowed: bool
    reason_code: str
    capability: str | None = None
    source: str | None = None


def _coerce_capability(value):
    try:
        return value if isinstance(value, Capability) else Capability(value)
    except (TypeError, ValueError):
        return None


def _target_scope_value(target, field):
    value = getattr(target, field, None)
    return value if value is not None else getattr(target, f"target_{field}", None)


def build_authority_context(actor, *, on_date=None) -> AuthorityContext:
    """Take one bounded snapshot of the actor's fixed authority, coverage and grants."""
    as_of = on_date or timezone.localdate()
    if actor is None:
        return AuthorityContext(None, None, False, False, False, False, frozenset(), (), (), as_of)
    authenticated = bool(getattr(actor, "is_authenticated", False))
    active = bool(getattr(actor, "is_active", False))
    legacy = bool(getattr(actor, "is_superuser", False))
    if not authenticated or not active or legacy:
        return AuthorityContext(
            getattr(actor, "pk", None), getattr(actor, "role", None), authenticated,
            active, legacy, False, frozenset(), (), (), as_of,
        )
    head = is_head_guidance(actor)
    coverages = tuple(CounselorCoverage.objects.filter(
        counselor_id=actor.pk, counselor__is_active=True, is_active=True,
        starts_at__lte=as_of,
    ).filter(Q(ends_at__isnull=True) | Q(ends_at__gte=as_of))) if actor.role == RoleChoices.COUNSELOR else ()
    grants = ()
    # Ordinary grants are deliberately not loaded for Head, Student, or IT
    # contexts. Their authority is fixed or domain-specific.
    if actor.role in {RoleChoices.COUNSELOR, RoleChoices.GCO_STAFF}:
        grants = tuple(WorkflowAuthorityGrant.objects.filter(
            grantee_id=actor.pk, grantee__is_active=True, status=GrantStatus.ACTIVE,
            valid_from__lte=as_of,
        ).filter(Q(valid_until__isnull=True) | Q(valid_until__gte=as_of)))
    return AuthorityContext(
        actor.pk, actor.role, authenticated, active, legacy, head,
        effective_fixed_capabilities(actor.role, is_head_guidance=head), coverages, grants, as_of,
    )


def _scope_matches(grant, target) -> bool:
    if target is None:
        return True
    if grant.scope_mode == ScopeMode.OFFICE_WIDE:
        return True
    if grant.scope_mode == ScopeMode.ASSIGNED_RECORDS:
        owner_id = (
            getattr(target, "assigned_counselor_id", None)
            or getattr(target, "assigned_reviewer_id", None)
            or getattr(target, "assigned_to_id", None)
            or getattr(target, "reviewed_by_id", None)
        )
        # An assignment-scoped grant is never a blanket student/profile grant.
        # Callers that authorize an assigned workflow record must pass that
        # record (or an equivalent target carrying its owner id).
        return owner_id is not None and owner_id == grant.grantee_id
    for field in SCOPE_FIELDS:
        value = getattr(grant, field, None)
        # Content projections store their organization target under a
        # target_* field. The helper compares the same canonical organization
        # dimension and never trusts a caller's unstructured metadata.
        target_value = _target_scope_value(target, field)
        if value and value != target_value:
            return False
    return True


def _coverage_matches(context: AuthorityContext, target) -> bool:
    if target is None:
        return bool(context.coverages)
    return any(all(
        not getattr(coverage, field, None)
        or getattr(coverage, field, None) == _target_scope_value(target, field)
        for field in SCOPE_FIELDS
    ) for coverage in context.coverages)


def matching_grants(context: AuthorityContext, capability, *, target=None):
    """Return current grant snapshots that match capability and optional scope."""
    cap = _coerce_capability(capability)
    if cap is None:
        return ()
    matched = []
    for grant in context.grants:
        if grant.capability != cap.value:
            continue
        if grant.scope_mode == ScopeMode.COUNSELOR_COVERAGE.value:
            if not _coverage_matches(context, target) or not _scope_matches(grant, target):
                continue
        elif not _scope_matches(grant, target):
            continue
        matched.append(grant)
    return tuple(matched)


def evaluate_capability(context_or_actor, capability, *, target=None, on_date=None) -> AuthorityDecision:
    """Return a safe, non-sensitive explanation for one capability decision."""
    context = context_or_actor if isinstance(context_or_actor, AuthorityContext) else build_authority_context(context_or_actor, on_date=on_date)
    if not context.is_authenticated or not context.is_active:
        return AuthorityDecision(False, AuthorityReason.INACTIVE.value)
    if context.is_legacy_superuser:
        return AuthorityDecision(False, AuthorityReason.LEGACY_SUPERUSER.value)
    cap = _coerce_capability(capability)
    if cap is None:
        return AuthorityDecision(False, AuthorityReason.UNKNOWN_CAPABILITY.value)
    spec = get_capability_spec(cap)
    if spec is None:
        return AuthorityDecision(False, AuthorityReason.UNKNOWN_CAPABILITY.value, cap.value)
    if cap in context.fixed_capabilities:
        if context.role == RoleChoices.IT_ADMIN and AuthoritySource.IT_FIXED in spec.authority_sources:
            reason = AuthorityReason.IT_FIXED
            source = AuthoritySource.IT_FIXED
        elif context.is_head_guidance and AuthoritySource.HEAD_FIXED in spec.authority_sources:
            reason = AuthorityReason.HEAD_FIXED
            source = AuthoritySource.HEAD_FIXED
        elif context.role == RoleChoices.COUNSELOR and AuthoritySource.COUNSELOR_BASELINE in spec.authority_sources:
            reason = AuthorityReason.COUNSELOR_BASELINE
            source = AuthoritySource.COUNSELOR_BASELINE
        else:
            reason = AuthorityReason.HEAD_FIXED
            source = None
        return AuthorityDecision(True, reason.value, cap.value, source.value if source else None)
    if AuthoritySource.ACCOUNT_GRANT not in spec.authority_sources:
        return AuthorityDecision(False, AuthorityReason.INELIGIBLE_ROLE.value, cap.value)
    if context.role not in spec.grant_eligible_roles:
        return AuthorityDecision(False, AuthorityReason.INELIGIBLE_ROLE.value, cap.value)
    matches = matching_grants(context, cap, target=target)
    if matches:
        return AuthorityDecision(True, AuthorityReason.ACCOUNT_GRANT.value, cap.value, AuthoritySource.ACCOUNT_GRANT.value)
    has_capability_grant = any(grant.capability == cap.value for grant in context.grants)
    reason = AuthorityReason.SCOPE_MISMATCH if has_capability_grant and target is not None else AuthorityReason.MISSING_GRANT
    return AuthorityDecision(False, reason.value, cap.value)


def resolve_capability(context_or_actor, capability, *, target=None, on_date=None) -> bool:
    """Boolean policy interface over :func:`evaluate_capability`."""
    return evaluate_capability(context_or_actor, capability, target=target, on_date=on_date).allowed


def has_capability(actor, capability, *, on_date=None, target=None) -> bool:
    return resolve_capability(build_authority_context(actor, on_date=on_date), capability, target=target)


def has_fixed_capability(actor, capability, *, on_date=None) -> bool:
    """Return only code-owned fixed authority, excluding account grants."""

    context = build_authority_context(actor, on_date=on_date)
    try:
        cap = capability if isinstance(capability, Capability) else Capability(capability)
    except (TypeError, ValueError):
        return False
    return bool(
        context.is_authenticated
        and context.is_active
        and not context.is_legacy_superuser
        and cap in context.fixed_capabilities
    )


def _strict_audit(**kwargs):
    entry = audit_log(**kwargs)
    if entry is None:
        raise RuntimeError("Authority audit could not be recorded.")
    return entry


def _validate_expiry(spec, scope_mode, valid_from, valid_until):
    if not valid_until and (scope_mode == ScopeMode.OFFICE_WIDE or spec.expiry_required):
        raise ValidationError("This authority requires an expiry date.")
    if valid_until and valid_until < valid_from:
        raise ValidationError("valid_until must be on or after valid_from.")
    if valid_until and valid_until > valid_from + timedelta(days=MAX_GRANT_DAYS):
        raise ValidationError(f"Authority validity may not exceed {MAX_GRANT_DAYS} days.")


@transaction.atomic
def create_authority_grant(actor, *, grantee, capability, scope_mode, valid_from, valid_until=None,
                           organization=None, reason_code=GrantReasonCode.LOCAL_WORKFLOW,
                           reason_note="", source_type=GrantSourceType.MANUAL, source_reference=""):
    """Create one immutable account grant, with overlap protection and strict audit."""
    if not resolve_capability(actor, Capability.WORKFLOW_AUTHORITY_MANAGE):
        raise PermissionDenied("Only Head Guidance may manage workflow authority.")
    if not is_active_nonlegacy_actor(grantee) or grantee.role not in {RoleChoices.COUNSELOR, RoleChoices.GCO_STAFF}:
        raise ValidationError("The grantee must be an active, non-legacy counselor or GCO Staff account.")
    cap = _coerce_capability(capability)
    spec = get_capability_spec(cap)
    if cap not in ALL_DELEGABLE_CAPABILITIES or spec is None or grantee.role not in spec.grant_eligible_roles:
        raise ValidationError("Capability is not eligible for this grantee account.")
    try:
        mode = ScopeMode(scope_mode)
    except (TypeError, ValueError) as exc:
        raise ValidationError("Scope mode is not registered.") from exc
    if mode not in spec.grant_scope_modes:
        raise ValidationError("Scope mode is not permitted for this capability.")
    if grantee.role == RoleChoices.COUNSELOR and mode not in {ScopeMode.COUNSELOR_COVERAGE, ScopeMode.ASSIGNED_RECORDS}:
        raise ValidationError("Counselor grants must be coverage- or assignment-scoped.")
    if grantee.role == RoleChoices.GCO_STAFF and mode not in {
        ScopeMode.EXPLICIT_ORGANIZATION,
        ScopeMode.ASSIGNED_RECORDS,
        ScopeMode.OFFICE_WIDE,
    }:
        raise ValidationError("GCO Staff grants must be organization-, assignment-, or approved office-wide-scoped.")
    if grantee.role == RoleChoices.GCO_STAFF and mode == ScopeMode.OFFICE_WIDE and not spec.office_wide_grant_allowed:
        raise ValidationError("This GCO Staff capability cannot be office-wide.")
    _validate_expiry(spec, mode, valid_from, valid_until)
    organization = organization or {}
    locked_grantee = type(grantee).objects.select_for_update().get(pk=grantee.pk)
    filters = {"grantee": locked_grantee, "capability": cap.value, "status": GrantStatus.ACTIVE}
    existing = WorkflowAuthorityGrant.objects.filter(**filters)
    requested = {field: organization.get(field) for field in SCOPE_FIELDS}
    for prior in existing:
        if prior.valid_until and prior.valid_until < valid_from:
            continue
        if valid_until and prior.valid_from > valid_until:
            continue
        if (
            prior.scope_mode == mode.value
            and all(getattr(prior, f) == requested[f] for f in SCOPE_FIELDS)
        ):
            raise ValidationError("An overlapping authority grant already exists for this exact scope.")
    grant = WorkflowAuthorityGrant(
        grantee=locked_grantee, capability=cap.value, scope_mode=mode.value,
        valid_from=valid_from, valid_until=valid_until,
        granted_by=actor, grant_reason_code=reason_code, grant_reason_note=reason_note,
        source_type=source_type, source_reference=source_reference, **requested,
    )
    grant.save()
    _strict_audit(
        action_type="WORKFLOW_AUTHORITY_GRANTED", event_category="AUTHORIZATION",
        target_model="access_control.WorkflowAuthorityGrant", target_object_id=str(grant.pk),
        actor_user=actor, source_app="access_control", metadata={
            "capability": cap.value, "scope_mode": mode.value, "grantee_id": grantee.pk,
            "grant_reason_code": reason_code, "source_type": source_type,
        },
    )
    return grant


@transaction.atomic
def revoke_authority_grant(actor, grant, *, reason_code=RevocationReasonCode.NO_LONGER_NEEDED):
    if not resolve_capability(actor, Capability.WORKFLOW_AUTHORITY_MANAGE):
        raise PermissionDenied("Only Head Guidance may revoke workflow authority.")
    if reason_code not in RevocationReasonCode.values:
        raise ValidationError("The revocation reason is not recognized.")
    current = WorkflowAuthorityGrant.objects.select_for_update().get(pk=grant.pk)
    if current.status == GrantStatus.REVOKED:
        return current
    current.status = GrantStatus.REVOKED
    current.revoked_by = actor
    current.revoked_at = timezone.now()
    current.revocation_reason_code = reason_code
    current.save(update_fields=["status", "revoked_by", "revoked_at", "revocation_reason_code", "updated_at"])
    _strict_audit(
        action_type="WORKFLOW_AUTHORITY_REVOKED", event_category="AUTHORIZATION",
        target_model="access_control.WorkflowAuthorityGrant", target_object_id=str(current.pk),
        actor_user=actor, source_app="access_control", metadata={
            "capability": current.capability, "revocation_reason_code": reason_code,
        },
    )
    return current
