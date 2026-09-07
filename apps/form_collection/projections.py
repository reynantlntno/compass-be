"""Fixed JSON projections for safe Form Collection reads."""

from apps.common.contracts import to_json_value


def collection(value):
    return {
        "id": str(value.pk),
        "name": value.name,
        "description": value.description,
        "audience": value.audience,
        "status": value.status,
        "start_at": to_json_value(value.start_at),
        "end_at": to_json_value(value.end_at),
        "form_type": value.form_type,
        "form_family_id": str(value.form_family_id) if value.form_family_id else None,
        "form_revision_id": str(value.form_revision_id) if value.form_revision_id else None,
        "created_at": to_json_value(value.created_at),
        "launched_at": to_json_value(value.launched_at),
        "closed_at": to_json_value(value.closed_at),
    }


def invitation_batch(value):
    return {
        "id": str(value.pk),
        "collection_id": str(value.collection_id),
        "name": value.invitation_batch_name,
        "source_type": value.source_type,
        "status": value.status,
        "total_requested": value.total_requested,
        "total_issued": value.total_issued,
        "total_failed": value.total_failed,
        "issued_at": to_json_value(value.issued_at),
        "created_at": to_json_value(value.created_at),
    }


def invitation_metadata(value):
    return {
        "id": str(value.pk),
        "selector": value.selector,
        "collection_id": str(value.collection_id),
        "invitation_batch_id": str(value.invitation_batch_id) if value.invitation_batch_id else None,
        "target_form_key": value.target_form_key,
        "intended_recipient_name": value.intended_recipient_name,
        "status": value.status,
        "expires_at": to_json_value(value.expires_at),
        "max_uses": value.max_uses,
        "used_count": value.used_count,
        "verified_at": to_json_value(value.verified_at),
        "submitted_at": to_json_value(value.submitted_at),
        "linked_student": bool(value.linked_student_id),
        "created_at": to_json_value(value.created_at),
    }


def verified_access(value):
    return {
        "invitation_id": str(value.pk),
        "collection_id": str(value.collection_id),
        "target_form_key": value.target_form_key,
        "form_type": value.collection.form_type,
        "form_revision_id": str(value.collection.form_revision_id) if value.collection.form_revision_id else None,
        "recipient_name": value.intended_recipient_name,
        "status": value.status,
        "expires_at": to_json_value(value.expires_at),
    }


def manual_match(value):
    return {
        "id": str(value.pk),
        "source_collection_id": str(value.source_collection_id) if value.source_collection_id else None,
        "source_invitation_id": str(value.source_invitation_id) if value.source_invitation_id else None,
        "name_snapshot": value.name_snapshot,
        "program_snapshot": value.program_snapshot,
        "student_match_status": value.student_match_status,
        "matched_at": to_json_value(value.matched_at),
        "linked_at": to_json_value(value.linked_at),
        "reviewed_at": to_json_value(value.reviewed_at),
    }
