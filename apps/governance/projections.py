"""Model-free projections for the Policy Center."""

from apps.governance.registry import get_policy_spec


def project_policy(policy):
    if policy is None:
        return None
    spec = get_policy_spec(policy.key)
    if spec is None:
        return None
    return {
        "id": str(policy.pk),
        "key": policy.key,
        "schema_version": policy.schema_version,
        "owner_plane": getattr(spec.owner_plane, "value", spec.owner_plane),
        "target_type": policy.target_type,
        "target_reference": policy.target_reference,
        "sensitivity": spec.sensitivity,
        "status": policy.status,
        "effectiveness": policy.effectiveness,
        "effective_from": policy.effective_from.isoformat() if policy.effective_from else None,
        "effective_until": policy.effective_until.isoformat() if policy.effective_until else None,
        "source_reference": policy.source_reference,
        "configuration": {
            key: policy.configuration_json.get(key)
            for key in spec.projection_fields
            if key in policy.configuration_json
        },
        "created_at": policy.created_at.isoformat(),
        "updated_at": policy.updated_at.isoformat(),
        "approved_at": policy.approved_at.isoformat() if policy.approved_at else None,
        "activated_at": policy.activated_at.isoformat() if policy.activated_at else None,
        "retired_at": policy.retired_at.isoformat() if policy.retired_at else None,
        "approval_evidence": {
            "approved": bool(policy.approved_by_id and policy.approved_at),
            "reason_code": policy.rejection_reason_code or "",
        },
    }

def project_policy_spec(spec):
    return {
        "key": spec.key,
        "owner_plane": getattr(spec.owner_plane, "value", spec.owner_plane),
        "sensitivity": spec.sensitivity,
        "lifecycle_actions": list(spec.lifecycle_actions),
        "approval_required": spec.approval_required,
        "requires_effective_dates": spec.requires_effective_dates,
        "projection_fields": list(spec.projection_fields),
        "configuration_fields": list(spec.configuration_fields),
        "target_type": spec.target_type,
        "target_required": spec.target_required,
        "runtime_reader": spec.runtime_reader,
        "runtime_consumer": spec.runtime_consumer,
        "stricter_only": spec.stricter_only,
    }
def project_dpo_appointment(appointment):
    if appointment is None:
        return None
    return {
        "id": str(appointment.pk),
        "holder_id": appointment.holder_id,
        "valid_from": appointment.valid_from.isoformat(),
        "valid_until": appointment.valid_until.isoformat() if appointment.valid_until else None,
        "appointment_reference": appointment.appointment_reference,
        "contact_email": appointment.contact_email,
        "status": appointment.status,
        "appointed_at": appointment.appointed_at.isoformat(),
        "retired_at": appointment.retired_at.isoformat() if appointment.retired_at else None,
    }

# End of module.
