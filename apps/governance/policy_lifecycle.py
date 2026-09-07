"""Central policy lifecycle over domain-registered policy contracts."""

from __future__ import annotations

from datetime import datetime, timezone as datetime_timezone

from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from apps.access_control.authority import has_fixed_capability
from apps.access_control.capabilities import Capability
from apps.access_control.rules import is_active_nonlegacy_actor, is_head_guidance
from apps.audit.services import audit_log
from apps.common.exceptions import GovernanceError, PermissionDeniedError, ValidationError
from apps.common.lifecycle import LifecycleContract, LifecycleRequest
from apps.common.policy import PolicyChangeRequest
from apps.governance.choices import (
    PolicyEffectivenessChoices,
    PolicyLifecycleStatus,
    PolicyTransitionAction,
    PolicyPlane,
)
from apps.governance.models import PolicyRecord, PolicyTransition
from apps.governance.registry import get_policy_definition, get_policy_spec


_POLICY_LIFECYCLE_CONTRACT = LifecycleContract(
    "governance.policy",
    {
        "": {PolicyLifecycleStatus.DRAFT},
        PolicyLifecycleStatus.DRAFT: {
            PolicyLifecycleStatus.DRAFT,
            PolicyLifecycleStatus.PENDING_APPROVAL,
            PolicyLifecycleStatus.ACTIVE,
        },
        PolicyLifecycleStatus.PENDING_APPROVAL: {
            PolicyLifecycleStatus.PENDING_APPROVAL,
            PolicyLifecycleStatus.DRAFT,
            PolicyLifecycleStatus.ACTIVE,
        },
        PolicyLifecycleStatus.ACTIVE: {PolicyLifecycleStatus.RETIRED},
        PolicyLifecycleStatus.RETIRED: set(),
    },
)


def _json_value(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    return value


def _request_configuration(request: PolicyChangeRequest) -> dict:
    if not isinstance(request, PolicyChangeRequest):
        raise ValidationError("A generic policy change request is required.")
    normalized = _json_value(dict(request.configuration))
    definition = get_policy_definition(request.key)
    if definition is None:
        raise ValidationError("The policy key is not registered.")
    try:
        return definition.normalize_configuration(normalized)
    except (TypeError, ValueError, ValidationError) as exc:
        if isinstance(exc, ValidationError):
            raise
        raise ValidationError(str(exc)) from exc


def _validate_request(request: PolicyChangeRequest):
    if not isinstance(request, PolicyChangeRequest):
        raise ValidationError("A generic policy change request is required.")
    spec = get_policy_spec(request.key)
    if spec is None:
        raise ValidationError("The policy key is not registered.")
    if not request.source_reference.strip():
        raise ValidationError("A bounded source reference is required.")
    if request.effective_from and request.effective_until and request.effective_until < request.effective_from:
        raise ValidationError("Effective end cannot precede effective start.")
    if spec.requires_effective_dates and not request.effective_from:
        raise ValidationError("This policy requires an effective start date.")
    if spec.target_required:
        if request.target_type != spec.target_type or not request.target_reference.strip():
            raise ValidationError("This policy requires an exact target resource.")
    elif request.target_type or request.target_reference:
        raise ValidationError("This policy does not accept a resource target.")

    configuration = _request_configuration(request)
    definition = get_policy_definition(request.key)
    try:
        definition.validate_request(request, configuration)
    except (TypeError, ValueError, ValidationError) as exc:
        if isinstance(exc, ValidationError):
            raise
        raise ValidationError(str(exc)) from exc
    return spec


def _windows_overlap(left_start, left_end, right_start, right_end) -> bool:
    minimum = datetime.min.replace(tzinfo=datetime_timezone.utc)
    maximum = datetime.max.replace(tzinfo=datetime_timezone.utc)
    left_start = left_start or minimum
    left_end = left_end or maximum
    right_start = right_start or minimum
    right_end = right_end or maximum
    return left_start <= right_end and right_start <= left_end


def _assert_no_overlapping_effective_window(
    *,
    key: str,
    target_type: str,
    target_reference: str,
    effective_from,
    effective_until,
    exclude_pk=None,
) -> None:
    # Marker and runtime-setting policies without effective dates are governed
    # by the single-active-row rule, not by an artificial open-ended window.
    # Date-governed policies always provide an effective start before reaching
    # this helper, so their bounded windows still receive overlap protection.
    if effective_from is None and effective_until is None:
        return
    candidates = PolicyRecord.objects.select_for_update().filter(
        key=key,
        target_type=target_type,
        target_reference=target_reference,
        effectiveness=PolicyEffectivenessChoices.EFFECTIVE,
    ).exclude(status=PolicyLifecycleStatus.RETIRED)
    if exclude_pk is not None:
        candidates = candidates.exclude(pk=exclude_pk)
    for candidate in candidates.only("effective_from", "effective_until"):
        if _windows_overlap(
            candidate.effective_from,
            candidate.effective_until,
            effective_from,
            effective_until,
        ):
            raise GovernanceError("Another non-retired policy overlaps this effective window.")


def _plane_authorized(actor, spec, *, system_context=False) -> bool:
    if system_context:
        return True
    if not is_active_nonlegacy_actor(actor):
        return False
    if str(spec.owner_plane) == PolicyPlane.HEAD_BUSINESS:
        return bool(is_head_guidance(actor) and has_fixed_capability(actor, Capability.ORGANIZATION_GOVERNANCE_MANAGE))
    if str(spec.owner_plane) == PolicyPlane.IT_TECHNICAL:
        return bool(has_fixed_capability(actor, Capability.SYSTEM_OPERATIONS_MANAGE))
    if str(spec.owner_plane) == PolicyPlane.DPO_PRIVACY:
        from apps.governance.dpo_services import is_current_dpo

        return is_current_dpo(actor)
    return False


def can_manage_policy(actor, key: str) -> bool:
    spec = get_policy_spec(key)
    return bool(spec and _plane_authorized(actor, spec))


def _transition(policy, *, action, actor, from_status, to_status, reason_code, evidence=None):
    request = LifecycleRequest(reason_code=reason_code, evidence=evidence or {})
    _POLICY_LIFECYCLE_CONTRACT.validate_transition(
        str(from_status or ""),
        str(to_status),
    )
    transition = PolicyTransition.objects.create(
        policy=policy,
        action=action,
        from_status=from_status or "",
        to_status=to_status,
        actor_user=actor,
        reason_code=request.reason_code,
        safe_evidence=request.evidence,
    )
    event = audit_log(
        action_type=f"POLICY_{action}",
        event_category="GOVERNANCE",
        target_model="governance.PolicyRecord",
        target_object_id=str(policy.pk),
        actor_user=actor,
        source_app="apps.governance",
        metadata={"key": policy.key, "from_status": from_status or "", "to_status": to_status, "reason_code": reason_code},
    )
    if event is None:
        raise GovernanceError("Policy transition audit could not be recorded.")
    return transition


@transaction.atomic
def create_policy_draft(actor, command: PolicyChangeRequest, *, system_context=False) -> PolicyRecord:
    spec = _validate_request(command)
    if not _plane_authorized(actor, spec, system_context=system_context):
        raise PermissionDeniedError("The actor is not authorized for this policy plane.")
    _assert_no_overlapping_effective_window(
        key=spec.key,
        target_type=command.target_type.strip(),
        target_reference=command.target_reference.strip(),
        effective_from=command.effective_from,
        effective_until=command.effective_until,
    )
    policy = PolicyRecord.objects.create(
        key=spec.key,
        status=PolicyLifecycleStatus.DRAFT,
        configuration_json=_request_configuration(command),
        effective_from=command.effective_from,
        effective_until=command.effective_until,
        source_reference=command.source_reference.strip(),
        target_type=command.target_type.strip(),
        target_reference=command.target_reference.strip(),
        schema_version="v1",
        created_by=actor,
    )
    _transition(policy, action=PolicyTransitionAction.DRAFT_CREATED, actor=actor, from_status="", to_status=policy.status, reason_code="DRAFT_CREATED")
    return policy

@transaction.atomic
def update_policy_draft(actor, policy: PolicyRecord, command: PolicyChangeRequest) -> PolicyRecord:
    spec = _validate_request(command)
    if policy.key != spec.key or policy.status != PolicyLifecycleStatus.DRAFT or not _plane_authorized(actor, spec):
        raise GovernanceError("Only an authorized owner may update a matching draft.")
    current = PolicyRecord.objects.select_for_update().get(pk=policy.pk)
    _assert_no_overlapping_effective_window(
        key=spec.key,
        target_type=command.target_type.strip(),
        target_reference=command.target_reference.strip(),
        effective_from=command.effective_from,
        effective_until=command.effective_until,
        exclude_pk=current.pk,
    )
    current.configuration_json = _request_configuration(command)
    current.effective_from = command.effective_from
    current.effective_until = command.effective_until
    current.source_reference = command.source_reference.strip()
    current.target_type = command.target_type.strip()
    current.target_reference = command.target_reference.strip()
    current.save(update_fields=["configuration_json", "effective_from", "effective_until", "source_reference", "target_type", "target_reference", "updated_at"])
    _transition(current, action=PolicyTransitionAction.DRAFT_UPDATED, actor=actor, from_status=current.status, to_status=current.status, reason_code="DRAFT_UPDATED")
    return current


@transaction.atomic
def submit_policy(actor, policy: PolicyRecord) -> PolicyRecord:
    current = PolicyRecord.objects.select_for_update().get(pk=policy.pk)
    spec = get_policy_spec(current.key)
    if not spec or not _plane_authorized(actor, spec) or current.status != PolicyLifecycleStatus.DRAFT:
        raise GovernanceError("Only an authorized owner may submit a draft.")
    current.status = PolicyLifecycleStatus.PENDING_APPROVAL
    current.submitted_by = actor
    current.submitted_at = timezone.now()
    current.save(update_fields=["status", "submitted_by", "submitted_at", "updated_at"])
    _transition(current, action=PolicyTransitionAction.SUBMITTED, actor=actor, from_status=PolicyLifecycleStatus.DRAFT, to_status=current.status, reason_code="SUBMITTED")
    return current


@transaction.atomic
def approve_policy(actor, policy: PolicyRecord) -> PolicyRecord:
    current = PolicyRecord.objects.select_for_update().get(pk=policy.pk)
    spec = get_policy_spec(current.key)
    if not spec or not spec.approval_required or not _plane_authorized(actor, spec):
        raise GovernanceError("The actor cannot approve this policy.")
    if current.status != PolicyLifecycleStatus.PENDING_APPROVAL:
        raise GovernanceError("Only pending policies can be approved.")
    _validate_persisted_configuration(current)
    current.approved_by = actor
    current.approved_at = timezone.now()
    current.save(update_fields=["approved_by", "approved_at", "updated_at"])
    _transition(current, action=PolicyTransitionAction.APPROVED, actor=actor, from_status=current.status, to_status=current.status, reason_code="APPROVED")
    return current


@transaction.atomic
def reject_policy(actor, policy: PolicyRecord, *, reason_code: str) -> PolicyRecord:
    current = PolicyRecord.objects.select_for_update().get(pk=policy.pk)
    spec = get_policy_spec(current.key)
    if not spec or not _plane_authorized(actor, spec):
        raise PermissionDeniedError("The actor cannot reject this policy.")
    if current.status != PolicyLifecycleStatus.PENDING_APPROVAL:
        raise GovernanceError("Only pending policies can be rejected.")
    reason_code = str(reason_code or "").strip()[:80]
    if not reason_code:
        raise ValidationError("A bounded rejection reason is required.")
    current.status = PolicyLifecycleStatus.DRAFT
    current.rejected_by = actor
    current.rejected_at = timezone.now()
    current.rejection_reason_code = reason_code
    current.save(update_fields=["status", "rejected_by", "rejected_at", "rejection_reason_code", "updated_at"])
    _transition(current, action=PolicyTransitionAction.REJECTED, actor=actor, from_status=PolicyLifecycleStatus.PENDING_APPROVAL, to_status=current.status, reason_code=reason_code)
    return current


def _validate_persisted_configuration(policy):
    config = policy.configuration_json or {}
    spec = get_policy_spec(policy.key)
    if spec is None:
        raise ValidationError("The policy is no longer registered.")
    request = PolicyChangeRequest(
        key=policy.key,
        configuration=config,
        effective_from=policy.effective_from,
        effective_until=policy.effective_until,
        source_reference=policy.source_reference,
        target_type=policy.target_type,
        target_reference=policy.target_reference,
    )
    _validate_request(request)


def _verify_runtime_reader(policy: PolicyRecord) -> None:
    """Prove that the canonical reader can see the just-activated policy.

    The persisted PolicyRecord remains the runtime source of truth. Future-dated policies
    are probed at their inclusive effective boundary.
    """
    from apps.governance.selectors import resolve_effective_policy

    probe_at = policy.effective_from or timezone.now()
    resolved = resolve_effective_policy(
        policy.key,
        target_type=policy.target_type,
        target_reference=policy.target_reference,
        at=probe_at,
    )
    if resolved is None or str(resolved.pk) != str(policy.pk):
        raise GovernanceError("The active policy is not visible through its canonical runtime reader.")


def _assert_stricter_update(spec, current: PolicyRecord | None, new_configuration: dict) -> None:
    """Prevent a target policy replacement from weakening a safety floor."""
    if current is None or not spec.stricter_only:
        return
    previous = current.configuration_json or {}
    definition = get_policy_definition(spec.key)
    if definition is not None:
        definition.assert_stricter_update(previous, new_configuration)


@transaction.atomic
def activate_policy(actor, policy: PolicyRecord) -> PolicyRecord:
    current = PolicyRecord.objects.select_for_update().get(pk=policy.pk)
    spec = get_policy_spec(current.key)
    if not spec or not _plane_authorized(actor, spec):
        raise PermissionDeniedError("The actor is not authorized to activate this policy.")
    if current.status != PolicyLifecycleStatus.PENDING_APPROVAL or (spec.approval_required and not current.approved_at):
        raise GovernanceError("Only an approved pending policy can be activated.")
    if current.effectiveness != PolicyEffectivenessChoices.EFFECTIVE:
        raise GovernanceError("Deprecated policy records are retained for audit and cannot become runtime-effective.")
    if PolicyRecord.objects.filter(
        key=current.key,
        target_type=current.target_type,
        target_reference=current.target_reference,
        status=PolicyLifecycleStatus.ACTIVE,
        effectiveness=PolicyEffectivenessChoices.EFFECTIVE,
    ).exclude(pk=current.pk).exists():
        raise GovernanceError("An active policy already exists for this key.")
    _assert_no_overlapping_effective_window(
        key=current.key,
        target_type=current.target_type,
        target_reference=current.target_reference,
        effective_from=current.effective_from,
        effective_until=current.effective_until,
        exclude_pk=current.pk,
    )
    _validate_persisted_configuration(current)
    now = timezone.now()
    current.status = PolicyLifecycleStatus.ACTIVE
    current.activated_by = actor
    current.activated_at = now
    current.save(update_fields=["status", "activated_by", "activated_at", "updated_at"])
    _verify_runtime_reader(current)
    _transition(current, action=PolicyTransitionAction.ACTIVATED, actor=actor, from_status=PolicyLifecycleStatus.PENDING_APPROVAL, to_status=current.status, reason_code="ACTIVATED")
    return current


@transaction.atomic
def retire_policy(actor, policy: PolicyRecord) -> PolicyRecord:
    current = PolicyRecord.objects.select_for_update().get(pk=policy.pk)
    spec = get_policy_spec(current.key)
    if not spec or not _plane_authorized(actor, spec) or current.status != PolicyLifecycleStatus.ACTIVE:
        raise GovernanceError("Only an authorized owner may retire an active policy.")
    current.status = PolicyLifecycleStatus.RETIRED
    current.retired_by = actor
    current.retired_at = timezone.now()
    current.save(update_fields=["status", "retired_by", "retired_at", "updated_at"])
    _transition(current, action=PolicyTransitionAction.RETIRED, actor=actor, from_status=PolicyLifecycleStatus.ACTIVE, to_status=current.status, reason_code="RETIRED")
    return current


@transaction.atomic
def ensure_active_policy_for_target(actor, command: PolicyChangeRequest, *, system_context=False) -> PolicyRecord:
    """Create the initial active configuration for a newly-created resource.

    This is the only bootstrap path for resource defaults. It is still
    audited, scope-aware, and owned by Governance; domain services do not
    write ``PolicyRecord`` directly.
    """

    spec = _validate_request(command)
    if not _plane_authorized(actor, spec, system_context=system_context):
        raise PermissionDeniedError("The actor is not authorized for this policy plane.")
    existing = PolicyRecord.objects.select_for_update().filter(
        key=spec.key,
        target_type=command.target_type.strip(),
        target_reference=command.target_reference.strip(),
        status=PolicyLifecycleStatus.ACTIVE,
        effectiveness=PolicyEffectivenessChoices.EFFECTIVE,
    ).first()
    if existing:
        return existing
    _assert_no_overlapping_effective_window(
        key=spec.key,
        target_type=command.target_type.strip(),
        target_reference=command.target_reference.strip(),
        effective_from=command.effective_from,
        effective_until=command.effective_until,
    )
    now = timezone.now()
    policy = PolicyRecord(
        key=spec.key,
        schema_version="v1",
        target_type=command.target_type.strip(),
        target_reference=command.target_reference.strip(),
        status=PolicyLifecycleStatus.ACTIVE,
        configuration_json=_request_configuration(command),
        effective_from=command.effective_from,
        effective_until=command.effective_until,
        source_reference=command.source_reference.strip(),
        created_by=actor,
        submitted_by=actor,
        submitted_at=now,
        approved_by=actor if spec.approval_required else None,
        approved_at=now if spec.approval_required else None,
        activated_by=actor,
        activated_at=now,
    )
    # Resource bootstrap uses the same explicit registered policy definition as
    # the draft/approval path. A default may not enter the active state merely
    # because its JSON happened to validate at the model boundary.
    _validate_persisted_configuration(policy)
    policy.save(force_insert=True)
    _verify_runtime_reader(policy)
    _transition(policy, action=PolicyTransitionAction.DRAFT_CREATED, actor=actor, from_status="", to_status=PolicyLifecycleStatus.DRAFT, reason_code="RESOURCE_DEFAULT_CREATED")
    _transition(policy, action=PolicyTransitionAction.ACTIVATED, actor=actor, from_status=PolicyLifecycleStatus.DRAFT, to_status=PolicyLifecycleStatus.ACTIVE, reason_code="RESOURCE_DEFAULT_ACTIVATED")
    return policy
@transaction.atomic
def replace_active_policy_for_target(actor, command: PolicyChangeRequest, *, system_context=False) -> PolicyRecord:
    """Replace a target policy through an append-only Governance transition.

    Resource services use this boundary when a draft resource's controls are
    edited. The previous active version is retired and a new typed active
    version is created; no domain model writes a policy record directly.
    """

    spec = _validate_request(command)
    if not _plane_authorized(actor, spec, system_context=system_context):
        raise PermissionDeniedError("The actor is not authorized for this policy plane.")
    target_type = command.target_type.strip()
    target_reference = command.target_reference.strip()
    current = PolicyRecord.objects.select_for_update().filter(
        key=spec.key,
        target_type=target_type,
        target_reference=target_reference,
        status=PolicyLifecycleStatus.ACTIVE,
        effectiveness=PolicyEffectivenessChoices.EFFECTIVE,
    ).first()
    new_configuration = _request_configuration(command)
    _assert_stricter_update(spec, current, new_configuration)
    _assert_no_overlapping_effective_window(
        key=spec.key,
        target_type=target_type,
        target_reference=target_reference,
        effective_from=command.effective_from,
        effective_until=command.effective_until,
        exclude_pk=current.pk if current else None,
    )
    if (
        current
        and current.configuration_json == new_configuration
        and current.effective_from == command.effective_from
        and current.effective_until == command.effective_until
    ):
        return current
    now = timezone.now()
    if current:
        current.status = PolicyLifecycleStatus.RETIRED
        current.retired_by = actor
        current.retired_at = now
        current.save(update_fields=["status", "retired_by", "retired_at", "updated_at"])
        _transition(
            current,
            action=PolicyTransitionAction.RETIRED,
            actor=actor,
            from_status=PolicyLifecycleStatus.ACTIVE,
            to_status=PolicyLifecycleStatus.RETIRED,
            reason_code="TARGET_POLICY_REPLACED",
        )
    policy = PolicyRecord(
        key=spec.key,
        schema_version="v1",
        target_type=target_type,
        target_reference=target_reference,
        status=PolicyLifecycleStatus.ACTIVE,
        configuration_json=new_configuration,
        effective_from=command.effective_from,
        effective_until=command.effective_until,
        source_reference=command.source_reference.strip(),
        created_by=actor,
        submitted_by=actor,
        submitted_at=now,
        approved_by=actor if spec.approval_required else None,
        approved_at=now if spec.approval_required else None,
        activated_by=actor,
        activated_at=now,
    )
    _validate_persisted_configuration(policy)
    policy.save(force_insert=True)
    _verify_runtime_reader(policy)
    _transition(policy, action=PolicyTransitionAction.DRAFT_CREATED, actor=actor, from_status="", to_status=PolicyLifecycleStatus.DRAFT, reason_code="TARGET_POLICY_REPLACED")
    _transition(policy, action=PolicyTransitionAction.ACTIVATED, actor=actor, from_status=PolicyLifecycleStatus.DRAFT, to_status=PolicyLifecycleStatus.ACTIVE, reason_code="TARGET_POLICY_REPLACED")
    return policy

# End of module.
