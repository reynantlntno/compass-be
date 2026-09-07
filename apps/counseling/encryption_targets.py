"""Temporary source-backed counseling targets for Release 1 only."""

from apps.counseling.models import CounselingSession, CounselingSessionNote, RoutineInterviewRecord
from apps.security.exceptions import FieldEncryptionUnknownTarget
from apps.security.field_operations import FieldOperationTarget, register_target, registered_targets


TARGET_SPECS = (
    ("counseling.session.concern_summary.backfill", CounselingSession, "concern_summary"),
    ("counseling.session.ended_early_reason.backfill", CounselingSession, "ended_early_reason"),
    ("counseling.session.cancellation_reason.backfill", CounselingSession, "cancellation_reason"),
    ("counseling.note.student_visible_summary.backfill", CounselingSessionNote, "student_visible_summary"),
    ("counseling.note.counselor_narrative.backfill", CounselingSessionNote, "counselor_narrative"),
    ("counseling.note.recommendations.backfill", CounselingSessionNote, "recommendations"),
    ("counseling.note.special_concerns.backfill", CounselingSessionNote, "special_concerns"),
    ("counseling.note.follow_up_notes.backfill", CounselingSessionNote, "follow_up_notes"),
    *tuple(
        (f"counseling.routine.{name}.backfill", RoutineInterviewRecord, name)
        for name in (
            "coping_challenges", "coping_remarks", "ucn_experience", "reason_for_coming",
            "difficulties_encountered", "stress_anxiety_causes", "stress_anxiety_management",
            "family_background_notes", "concerns_explanation", "college_adjustment",
            "academic_goals", "career_goals", "concern_others_text", "rating_others_label",
            "special_concern", "recommendations", "reopen_reason",
        )
    ),
)


def register_counseling_encryption_targets():
    existing = {target.identifier: target for target in registered_targets()}
    registered = []
    for identifier, model, source in TARGET_SPECS:
        target = FieldOperationTarget(
            identifier=identifier,
            model=model,
            source_field=source,
            destination_field=f"{source}_encrypted",
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
