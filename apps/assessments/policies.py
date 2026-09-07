"""Authorization policies for the assessment client boundary."""

from apps.access_control.authority import has_capability, has_fixed_capability
from apps.access_control.capabilities import Capability
from apps.access_control.rules import (
    is_active_nonlegacy_actor,
    is_counselor,
    is_it_admin,
    is_student,
)
from apps.access_control.selectors import get_students_visible_to
from apps.profiles.models import StudentProfile
from apps.assessments.choices import AssessmentRecordStatus


def can_view_assessment_destination(actor) -> bool:
    """Assessment records are a counselor/Head-only business destination."""
    if not is_active_nonlegacy_actor(actor) or not is_counselor(actor):
        return False
    if has_capability(actor, Capability.STUDENT_RECORDS_VIEW_INSTITUTION):
        return True
    return get_students_visible_to(actor).exists()


def _can_access_student(actor, student_profile: StudentProfile | None) -> bool:
    if not is_active_nonlegacy_actor(actor) or student_profile is None:
        return False
    if not is_counselor(actor):
        return False
    return get_students_visible_to(actor).filter(pk=student_profile.pk).exists()


def can_view_assessment_record(actor, assessment) -> bool:
    return bool(
        assessment is not None
        and _can_access_student(actor, getattr(assessment, "student_profile", None))
    )


def can_view_assessment_interpretation(actor, assessment) -> bool:
    """Sensitive interpretation access remains counselor/Head and scoped."""
    return bool(
        can_view_assessment_record(actor, assessment)
        and assessment.status not in {
            AssessmentRecordStatus.VOIDED,
            AssessmentRecordStatus.ARCHIVED,
        }
    )


def can_create_assessment_record(actor, student_profile: StudentProfile | None) -> bool:
    return bool(is_counselor(actor) and _can_access_student(actor, student_profile))


def can_update_assessment_record(actor, assessment) -> bool:
    return bool(
        can_view_assessment_record(actor, assessment)
        and assessment.status in {
            AssessmentRecordStatus.DRAFT,
            AssessmentRecordStatus.RECORDED,
        }
    )


def can_record_assessment(actor, assessment) -> bool:
    return bool(can_update_assessment_record(actor, assessment))


def can_submit_assessment_for_review(actor, assessment) -> bool:
    return bool(
        can_view_assessment_record(actor, assessment)
        and assessment.status == AssessmentRecordStatus.RECORDED
    )


def can_review_assessment_record(actor, assessment) -> bool:
    return bool(
        can_view_assessment_record(actor, assessment)
        and has_capability(actor, Capability.ASSESSMENTS_REVIEW, target=assessment.student_profile)
    )


def can_void_assessment_record(actor, assessment) -> bool:
    return bool(
        can_view_assessment_record(actor, assessment)
        and assessment.status in {
            AssessmentRecordStatus.RECORDED,
            AssessmentRecordStatus.UNDER_REVIEW,
            AssessmentRecordStatus.REVIEWED,
            AssessmentRecordStatus.RELEASED_TO_STUDENT,
        }
        and has_capability(actor, Capability.ASSESSMENTS_LIFECYCLE_MANAGE, target=assessment.student_profile)
    )


def can_supersede_assessment_record(actor, assessment) -> bool:
    return bool(
        can_view_assessment_record(actor, assessment)
        and assessment.status in {
            AssessmentRecordStatus.REVIEWED,
            AssessmentRecordStatus.RELEASED_TO_STUDENT,
        }
        and has_capability(actor, Capability.ASSESSMENTS_LIFECYCLE_MANAGE, target=assessment.student_profile)
    )


def can_archive_assessment_record(actor, assessment) -> bool:
    return bool(
        can_view_assessment_record(actor, assessment)
        and assessment.status in {
            AssessmentRecordStatus.VOIDED,
            AssessmentRecordStatus.SUPERSEDED,
            AssessmentRecordStatus.RELEASED_TO_STUDENT,
        }
        and has_capability(actor, Capability.ASSESSMENTS_LIFECYCLE_MANAGE, target=assessment.student_profile)
    )


def can_release_assessment_to_student(actor, assessment) -> bool:
    return bool(
        can_view_assessment_record(actor, assessment)
        and assessment.status == AssessmentRecordStatus.REVIEWED
        and has_capability(actor, Capability.ASSESSMENTS_RELEASE, target=assessment.student_profile)
    )


def can_view_student_summary(actor, assessment) -> bool:
    if not is_student(actor) or assessment is None:
        return False
    return bool(
        assessment.released_to_student
        and assessment.status == AssessmentRecordStatus.RELEASED_TO_STUDENT
        and getattr(assessment.student_profile, "user_id", None) == actor.pk
    )


def can_attach_assessment_file(actor, assessment) -> bool:
    return can_update_assessment_record(actor, assessment)


def can_download_assessment_file(actor, assessment) -> bool:
    """Only scoped counselors/Head can read assessment file content."""
    return bool(can_view_assessment_record(actor, assessment) and not is_it_admin(actor))


def can_view_assessment_file_metadata(actor, assessment) -> bool:
    if assessment is None or not getattr(assessment, "protected_file_id", None):
        return False
    if has_fixed_capability(actor, Capability.PROTECTED_FILES_METADATA_INSPECT):
        return True
    return can_view_assessment_record(actor, assessment)


def can_view_assessment_aggregate(actor, filters=None) -> bool:
    """Aggregate output remains owned by Reports, but this helper is retained."""
    return can_view_assessment_destination(actor)


def assessment_result_file_policy(user, protected_file, action: str) -> bool:
    """Protected-file callback; technical actors receive metadata only."""
    if not user or not user.is_authenticated or not user.is_active or getattr(user, "is_superuser", False):
        return False
    if action in ("read_metadata", "inspect") and has_fixed_capability(
        user, Capability.PROTECTED_FILES_METADATA_INSPECT
    ):
        return True

    from apps.assessments.models import StudentAssessmentRecord

    record = (
        StudentAssessmentRecord.objects.select_related("student_profile")
        .filter(protected_file=protected_file)
        .first()
    )
    if record is None:
        return False
    if action == "read_content":
        return can_download_assessment_file(user, record)
    if action in ("read_metadata", "inspect"):
        return can_view_assessment_file_metadata(user, record)
    return False
