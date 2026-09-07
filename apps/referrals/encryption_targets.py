"""Temporary source-backed referral targets for Release 1 only."""

from apps.referrals.models import (
    Referral,
    ReferralAction,
    ReferralAssignmentHistory,
    ReferralReassignmentRequest,
    ReferralStatusHistory,
)
from apps.security.exceptions import FieldEncryptionUnknownTarget
from apps.security.field_operations import FieldOperationTarget, register_target, registered_targets


TARGET_SPECS = (
    ("referrals.referral.reason_text.backfill", Referral, "reason_text", "reason_text_encrypted"),
    ("referrals.referralaction.remarks.backfill", ReferralAction, "remarks", "remarks_encrypted"),
    (
        "referrals.referralstatushistory.reason_detail.backfill",
        ReferralStatusHistory,
        "reason_detail",
        "reason_detail_encrypted",
    ),
    (
        "referrals.referralassignmenthistory.detail.backfill",
        ReferralAssignmentHistory,
        "detail",
        "detail_encrypted",
    ),
    (
        "referrals.referralreassignmentrequest.request_detail.backfill",
        ReferralReassignmentRequest,
        "request_detail",
        "request_detail_encrypted",
    ),
    (
        "referrals.referralreassignmentrequest.decision_detail.backfill",
        ReferralReassignmentRequest,
        "decision_detail",
        "decision_detail_encrypted",
    ),
)


def register_referral_encryption_targets():
    existing = {target.identifier: target for target in registered_targets()}
    registered = []
    for identifier, model, source, destination in TARGET_SPECS:
        target = FieldOperationTarget(
            identifier=identifier,
            model=model,
            source_field=source,
            destination_field=destination,
            payload_type="text",
            invalid_row_policy="STOP",
            allowed_operations=frozenset({"backfill", "rotation", "verify"}),
        )
        current = existing.get(identifier)
        if current is not None:
            if current != target:
                raise FieldEncryptionUnknownTarget()
            registered.append(current)
            continue
        registered.append(register_target(target))
    return tuple(registered)
