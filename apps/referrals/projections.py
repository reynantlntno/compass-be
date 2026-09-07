"""Fixed JSON projection boundary for the referrals domain.

Only named projection functions with explicit allowlists may be added here.
Raw model instances, QuerySets, encrypted fields, secrets, and arbitrary
metadata must not be returned to a client.
"""

from apps.common.contracts import to_json_object


def project_referral_queue_item(actor, referral) -> dict | None:
    """Return bounded queue metadata for an already scoped Referral."""
    from apps.referrals.policies import can_view_referral_safe_metadata
    from apps.referrals.models import ReferralStatusChoices
    from apps.referrals.selectors import _age_bucket, _safe_choice_display

    if referral is None or not can_view_referral_safe_metadata(actor, referral):
        return None
    return to_json_object({
        "reference_code": referral.reference_code,
        "status_code": referral.status,
        "status_label": _safe_choice_display(
            referral, "status", referral.status, ReferralStatusChoices.values,
        ),
        "age_bucket": _age_bucket(referral),
        "assignment_state": "Assigned" if referral.assigned_counselor_id else "Unassigned",
        "updated_at": referral.updated_at,
    })


def project_referral_detail(actor, referral) -> dict | None:
    """Return the purpose-specific Referral detail projection."""
    if referral is None:
        return None
    from apps.referrals.selectors import get_referral_sensitive_detail

    value = get_referral_sensitive_detail(actor, referral.reference_code)
    return to_json_object(value) if value is not None else None


def project_reassignment_request(actor, request) -> dict | None:
    """Return safe reassignment metadata without confidential detail."""
    if request is None:
        return None
    from apps.referrals.selectors import get_reassignment_request_dto

    return to_json_object(get_reassignment_request_dto(actor, request))
