"""Fixed, model-free privacy projections."""

from apps.common.rich_text import RichTextProfile, RichTextValidationError, render_rich_text


def notice_projection(notice):
    """Return the public display projection for a published notice.

    Governance identifiers and the Markdown source remain deliberately
    outside this boundary.  Invalid source content fails closed so a malformed
    revision cannot become public merely because it was approved upstream.
    """
    if notice is None:
        return None
    try:
        body_html = render_rich_text(
            notice.body_markdown,
            profile=RichTextProfile.PRIVACY_NOTICE,
        )
    except RichTextValidationError:
        return None
    return {
        "version": notice.version,
        "effective_at": notice.effective_at.isoformat() if notice.effective_at else None,
        "body_html": body_html,
    }


def acceptance_projection(event):
    if event is None:
        return None
    return {
        "id": str(event.pk),
        "purpose_workflow": event.purpose_workflow,
        "decision": event.decision,
        "notice_version": event.notice_revision.version,
        "decided_at": event.decided_at.isoformat(),
    }


def request_projection(request):
    if request is None:
        return None
    return {
        "reference_code": request.reference_code,
        "request_type": request.request_type,
        "target_category": request.target_category,
        "status": request.status,
        "submitted_at": request.submitted_at.isoformat() if request.submitted_at else None,
        "identity_verified": bool(request.identity_verified_at),
        "assigned": bool(request.assigned_reviewer_id),
        "fulfilled": bool(request.fulfilled_at or request.protected_fulfillment_file_id),
        "withdrawn_at": request.withdrawn_at.isoformat() if request.withdrawn_at else None,
        "closed_at": request.closed_at.isoformat() if request.closed_at else None,
    }


def request_sensitive_projection(request):
    if request is None:
        return None
    return {
        "reference_code": request.reference_code,
        "description": request.description_encrypted or "",
        "decision_notes": request.decision_notes_encrypted or "",
        "decision_reason_code": request.decision_reason_code,
    }


def incident_projection(incident, *, technical_only: bool = False):
    if incident is None:
        return None
    result = {
        "incident_code": incident.incident_code,
        "category": incident.category,
        "severity": incident.severity,
        "affected_workflow": incident.affected_workflow,
        "affected_record_category": incident.affected_record_category,
        "status": incident.status,
        "discovered_at": incident.discovered_at.isoformat() if incident.discovered_at else None,
        "containment_code": incident.containment_code,
        "safe_summary_code": incident.safe_summary_code,
    }
    if not technical_only:
        result["notification_decision"] = incident.notification_decision
    return result


def incident_transition_projection(transition, *, technical_only: bool = False):
    result = {
        "from_status": transition.from_status,
        "to_status": transition.to_status,
        "reason_code": transition.reason_code,
        "occurred_at": transition.occurred_at.isoformat() if transition.occurred_at else None,
    }
    if not technical_only:
        result["safe_evidence"] = dict(transition.safe_evidence or {})
    return result


def legal_hold_projection(hold):
    if hold is None:
        return None
    return {
        "id": str(hold.pk),
        "record_category": hold.record_category,
        "status": hold.status,
        "reason_code": hold.reason_code,
        "safe_reference_present": bool(hold.safe_reference),
        "placed_at": hold.placed_at.isoformat() if hold.placed_at else None,
        "released_at": hold.released_at.isoformat() if hold.released_at else None,
    }


def retention_policy_projection(policy):
    if policy is None:
        return None
    config = policy.configuration_json or {}
    return {
        "policy_id": str(policy.pk),
        "record_category": policy.target_reference,
        "retention_trigger": config.get("retention_trigger"),
        "retention_period_days": config.get("retention_period_days"),
        "review_due_at": config.get("review_due_at"),
        "legal_basis": config.get("legal_basis"),
        "owner_role": config.get("owner_role"),
        "legal_hold_behavior": config.get("legal_hold_behavior"),
        "disposal_method": config.get("disposal_method"),
        "evidence_requirement": config.get("evidence_requirement"),
        "exception_status": config.get("exception_status"),
        "effective_from": policy.effective_from.isoformat() if policy.effective_from else None,
        "effective_until": policy.effective_until.isoformat() if policy.effective_until else None,
        "source_reference": policy.source_reference,
    }


def retention_evaluation_projection(row):
    metadata = row.safe_metadata or {}
    return {
        "id": str(row.pk),
        "environment": row.environment,
        "evaluated_at": row.evaluated_at.isoformat() if row.evaluated_at else None,
        "record_category": row.record_category,
        "candidate_count": row.candidate_count,
        "hold_count": row.hold_count,
        "result_code": row.result_code,
        "metadata_only": bool(metadata.get("metadata_only", True)),
        "policy_id": str(metadata.get("policy_id", "")),
    }


def reviewer_authorization_projection(authorization):
    if authorization is None:
        return None
    raw_scopes = authorization.scopes if isinstance(authorization.scopes, dict) else {
        "scopes": authorization.scopes or [],
        "categories": [],
    }
    return {
        "id": str(authorization.pk),
        "authorized_user_id": authorization.authorized_user_id,
        "scopes": [str(value)[:120] for value in raw_scopes.get("scopes", [])[:30]],
        "categories": [str(value)[:120] for value in raw_scopes.get("categories", [])[:100]],
        "valid_from": authorization.valid_from.isoformat(),
        "valid_until": authorization.valid_until.isoformat() if authorization.valid_until else None,
        "source_reference": authorization.source_reference,
        "status": authorization.status,
        "authorized_at": authorization.created_at.isoformat(),
        "revoked_at": authorization.revoked_at.isoformat() if authorization.revoked_at else None,
    }


def notice_revision_projection(revision):
    if revision is None:
        return None
    return {
        "id": str(revision.pk),
        "notice_identifier": revision.notice_identifier,
        "version": revision.version,
        "locale": revision.locale,
        "purpose_workflow": revision.purpose_workflow,
        "body_markdown": revision.body_markdown,
        "revision_hash": revision.revision_hash,
        "source_reference": revision.source_reference,
        "effective_at": revision.effective_at.isoformat() if revision.effective_at else None,
        "status": revision.status,
        "approval_state": revision.approval_state,
        "approval_reference": revision.approval_reference,
        "approved_at": revision.approved_at.isoformat() if revision.approved_at else None,
        "created_at": revision.created_at.isoformat(),
    }


def workflow_binding_projection(binding):
    if binding is None:
        return None
    return {
        "id": str(binding.pk),
        "purpose_workflow": binding.purpose_workflow,
        "notice_revision_id": str(binding.notice_revision_id) if binding.notice_revision_id else None,
        "status": binding.status,
        "required": bool(binding.required),
        "source_reference": binding.source_reference,
        "block_reason": binding.block_reason,
        "created_at": binding.created_at.isoformat(),
        "updated_at": binding.updated_at.isoformat(),
    }
