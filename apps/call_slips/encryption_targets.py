"""Temporary source-backed Call Slip targets for Release 1 only."""

from apps.call_slips.models import CallSlip, CallSlipAssignmentHistory, CallSlipRescheduleRequest
from apps.security.exceptions import FieldEncryptionUnknownTarget
from apps.security.field_operations import FieldOperationTarget, register_target, registered_targets


TARGET_SPECS = (
    ("call_slips.callslip.student_safe_instructions.backfill", CallSlip, "student_safe_instructions", "student_safe_instructions_encrypted"),
    ("call_slips.callslip.office_only_remarks.backfill", CallSlip, "office_only_remarks", "office_only_remarks_encrypted"),
    ("call_slips.callslip.cancellation_detail.backfill", CallSlip, "cancellation_detail", "cancellation_detail_encrypted"),
    ("call_slips.callslip.no_show_detail.backfill", CallSlip, "no_show_detail", "no_show_detail_encrypted"),
    ("call_slips.assignment_history.detail.backfill", CallSlipAssignmentHistory, "detail", "detail_encrypted"),
    ("call_slips.reschedule.student_reason.backfill", CallSlipRescheduleRequest, "student_reason", "student_reason_encrypted"),
    ("call_slips.reschedule.decision_detail.backfill", CallSlipRescheduleRequest, "decision_detail", "decision_detail_encrypted"),
)


def register_call_slip_encryption_targets():
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
