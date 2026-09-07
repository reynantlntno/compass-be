"""Side-effect-free scoped selectors for assessment reads."""

from django.db import models

from apps.access_control.rules import is_active_nonlegacy_actor, is_counselor, is_student
from apps.access_control.authority import has_fixed_capability
from apps.access_control.capabilities import Capability
from apps.access_control.selectors import get_students_visible_to
from apps.assessments.choices import AssessmentRecordStatus
from apps.assessments.models import AssessmentInstrument, StudentAssessmentRecord


def get_assessment_records_visible_to(actor) -> models.QuerySet:
    """Return counselor/Head records in the actor's current student scope."""
    if not is_active_nonlegacy_actor(actor) or not is_counselor(actor):
        return StudentAssessmentRecord.objects.none()
    visible_students = get_students_visible_to(actor)
    return (
        StudentAssessmentRecord.objects.filter(student_profile__in=visible_students)
        .select_related("student_profile", "instrument", "protected_file")
        .defer("interpretation_text_encrypted", "metadata_json")
        .order_by("-administered_at", "-id")
    )


def get_assessment_record_for_actor(actor, record_id) -> StudentAssessmentRecord | None:
    """Return one scoped record or ``None`` for both missing and denied."""
    try:
        record_id = int(record_id)
    except (TypeError, ValueError):
        return None
    if record_id < 1:
        return None
    return get_assessment_records_visible_to(actor).filter(pk=record_id).first()


def get_assessment_records_for_student(actor, student_profile) -> models.QuerySet:
    if not is_active_nonlegacy_actor(actor) or not is_counselor(actor) or student_profile is None:
        return StudentAssessmentRecord.objects.none()
    return get_assessment_records_visible_to(actor).filter(student_profile=student_profile)


def get_assessment_review_queue(actor) -> models.QuerySet:
    return get_assessment_records_visible_to(actor).filter(status=AssessmentRecordStatus.UNDER_REVIEW)


def get_assessment_instrument_catalog(actor) -> models.QuerySet:
    if not is_active_nonlegacy_actor(actor) or not is_counselor(actor):
        return AssessmentInstrument.objects.none()
    return AssessmentInstrument.objects.filter(is_active=True).order_by("category", "title", "id")


def get_student_released_assessments(actor) -> models.QuerySet:
    if not is_active_nonlegacy_actor(actor) or not is_student(actor):
        return StudentAssessmentRecord.objects.none()
    return (
        StudentAssessmentRecord.objects.filter(
            student_profile__user_id=actor.pk,
            released_to_student=True,
            status=AssessmentRecordStatus.RELEASED_TO_STUDENT,
        )
        .select_related("instrument", "student_profile")
        .defer("metadata_json", "protected_file")
        .order_by("-released_to_student_at", "-id")
    )


def get_assessment_file_metadata_for_actor(actor, record) -> dict | None:
    """Return allowlisted protected-file metadata, never storage coordinates."""
    if record is None or not record.protected_file:
        return None
    from apps.assessments.policies import can_view_assessment_file_metadata

    if not can_view_assessment_file_metadata(actor, record):
        return None
    file = record.protected_file
    return {
        "id": str(file.id),
        "filename": file.original_filename_display,
        "content_type": file.content_type,
        "size_bytes": file.file_size_bytes,
        "classification": file.classification,
        "purpose": file.purpose,
        "status": file.status,
    }


def get_assessment_record_for_file_metadata(actor, record_id) -> StudentAssessmentRecord | None:
    """Allow IT's fixed technical capability to reach metadata only."""
    if has_fixed_capability(actor, Capability.PROTECTED_FILES_METADATA_INSPECT):
        try:
            return (
                StudentAssessmentRecord.objects.select_related("protected_file")
                .filter(pk=int(record_id))
                .first()
            )
        except (TypeError, ValueError):
            return None
    return get_assessment_record_for_actor(actor, record_id)


def get_assessment_aggregate_rows(actor, filters=None) -> list:
    """Delegate aggregate output to the existing Reports-owned builder."""
    from apps.assessments.services import build_assessment_aggregate_dataset

    return build_assessment_aggregate_dataset(actor, filters)
