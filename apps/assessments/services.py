"""Application services for the assessment workflow.

The public boundary accepts an actor, stable identifiers, and frozen commands.
Every mutation reloads its targets under a transaction lock before checking
scope, capability, lifecycle, and optimistic-concurrency state.
"""

from __future__ import annotations

from django.core import exceptions as django_exceptions
from django.db import transaction
from django.utils import timezone

from apps.assessments.choices import AssessmentInterpretationVisibility, AssessmentRecordStatus
from apps.assessments.commands import (
    AssessmentArchiveCommand,
    AssessmentCreateCommand,
    AssessmentFileUploadReceipt,
    AssessmentRecordCommand,
    AssessmentReleaseCommand,
    AssessmentReviewCommand,
    AssessmentSubmitReviewCommand,
    AssessmentSupersedeCommand,
    AssessmentUpdateCommand,
    AssessmentVoidCommand,
)
from apps.assessments.models import AssessmentInstrument, StudentAssessmentRecord
from apps.assessments.policies import (
    can_archive_assessment_record,
    can_attach_assessment_file,
    can_create_assessment_record,
    can_record_assessment,
    can_release_assessment_to_student,
    can_review_assessment_record,
    can_submit_assessment_for_review,
    can_supersede_assessment_record,
    can_update_assessment_record,
    can_view_assessment_interpretation,
    can_view_assessment_destination,
    can_view_assessment_record,
    can_view_student_summary,
    can_void_assessment_record,
)
from apps.audit.services import audit_log, audit_sensitive_view
from apps.common.exceptions import (
    DependencyFailureError,
    LifecycleConflictError,
    NotFoundError,
    PermissionDeniedError,
    StaleStateError,
    ValidationError,
)
from apps.profiles.models import StudentProfile
from apps.security.models import FileStatusChoices, ProtectedFile, PurposeChoices


def _record(record_id: int, *, for_update: bool = True) -> StudentAssessmentRecord:
    queryset = StudentAssessmentRecord.objects.select_related("student_profile", "instrument")
    if for_update:
        queryset = queryset.select_for_update()
    else:
        queryset = queryset.select_related("protected_file")
    try:
        return queryset.get(pk=record_id)
    except (StudentAssessmentRecord.DoesNotExist, TypeError, ValueError) as exc:
        raise NotFoundError() from exc


def _student(student_id: int) -> StudentProfile:
    try:
        return StudentProfile.objects.select_for_update().get(pk=student_id)
    except (StudentProfile.DoesNotExist, TypeError, ValueError) as exc:
        raise NotFoundError() from exc


def _instrument(instrument_id: int) -> AssessmentInstrument:
    try:
        return AssessmentInstrument.objects.select_for_update().get(pk=instrument_id)
    except (AssessmentInstrument.DoesNotExist, TypeError, ValueError) as exc:
        raise NotFoundError() from exc


def _expected_updated_at(record, expected_updated_at) -> None:
    if expected_updated_at is not None and record.updated_at != expected_updated_at:
        raise StaleStateError()


def _validation_error(exc: django_exceptions.ValidationError) -> ValidationError:
    return ValidationError("The assessment data is invalid.")


def _audit(
    actor,
    action: str,
    record: StudentAssessmentRecord | None = None,
    *,
    reason_code: str | None = None,
    has_notes: bool | None = None,
    replacement_record_id: str | None = None,
    file_id: str | None = None,
) -> None:
    safe_metadata = {}
    if reason_code is not None:
        safe_metadata["reason_code"] = reason_code
    if has_notes is not None:
        safe_metadata["has_notes"] = bool(has_notes)
    if replacement_record_id is not None:
        safe_metadata["replacement_record_id"] = str(replacement_record_id)
    if file_id is not None:
        safe_metadata["file_id"] = str(file_id)
    if record is not None:
        safe_metadata.setdefault("assessment_id", str(record.pk))
        safe_metadata.setdefault("student_profile_id", str(record.student_profile_id))
        safe_metadata.setdefault("instrument_id", str(record.instrument_id))
        safe_metadata.setdefault("instrument_key", record.instrument.key)
        safe_metadata.setdefault("status", record.status)
    audit_log(
        action_type=action,
        event_category="DATA_ACCESS",
        severity="INFO",
        target_model="StudentAssessmentRecord",
        target_object_id=str(record.pk) if record is not None else "",
        actor_user=actor,
        metadata=safe_metadata,
    )


def _deny(actor, action: str, record: StudentAssessmentRecord | None = None) -> None:
    _audit(actor, "assessment_record_access_denied", record, reason_code=action)
    raise PermissionDeniedError()


def _validate_record(record: StudentAssessmentRecord) -> None:
    try:
        record.full_clean()
    except django_exceptions.ValidationError as exc:
        raise _validation_error(exc) from exc


def _apply_result_fields(record: StudentAssessmentRecord, command: AssessmentRecordCommand | AssessmentUpdateCommand) -> None:
    fields = set(command.fields)
    if "raw_score" in fields:
        record.raw_score = command.raw_score
    if "scaled_score" in fields:
        record.scaled_score = command.scaled_score
    if "score_label" in fields:
        record.score_label = command.score_label
    if "interpretation_text" in fields:
        if not record.instrument.allows_interpretation:
            raise ValidationError("This instrument does not allow interpretation text.")
        record.interpretation_text = command.interpretation_text
    if "interpretation_visibility" in fields:
        if command.interpretation_visibility is None:
            raise ValidationError("interpretation_visibility is required when supplied.")
        record.interpretation_visibility = command.interpretation_visibility


def _apply_update_fields(record: StudentAssessmentRecord, command: AssessmentUpdateCommand) -> None:
    fields = set(command.fields)
    if "administered_at" in fields:
        record.administered_at = command.administered_at
    if "source_form_reference" in fields:
        record.source_form_reference = command.source_form_reference
    _apply_result_fields(record, command)


def create_assessment_record(actor, command: AssessmentCreateCommand) -> StudentAssessmentRecord:
    if not isinstance(command, AssessmentCreateCommand):
        raise ValidationError("Assessment creation requires a typed command.")
    with transaction.atomic():
        student = _student(command.student_profile_id)
        instrument = _instrument(command.instrument_id)
        if not can_create_assessment_record(actor, student):
            _deny(actor, "create")
        if not instrument.is_active:
            raise LifecycleConflictError()
        if command.expected_instrument_updated_at and instrument.updated_at != command.expected_instrument_updated_at:
            raise StaleStateError()
        record = StudentAssessmentRecord(
            student_profile=student,
            instrument=instrument,
            status=AssessmentRecordStatus.DRAFT,
            administered_at=command.administered_at or timezone.now(),
            administered_by=actor,
            source_form_reference=command.source_form_reference,
        )
        _validate_record(record)
        record.save()
        _audit(actor, "assessment_record_created", record)
        return record


def update_assessment_record(actor, record_id: int, command: AssessmentUpdateCommand) -> StudentAssessmentRecord:
    if not isinstance(command, AssessmentUpdateCommand):
        raise ValidationError("Assessment updates require a typed command.")
    with transaction.atomic():
        record = _record(record_id)
        if not can_update_assessment_record(actor, record):
            _deny(actor, "update", record)
        _expected_updated_at(record, command.expected_updated_at)
        _apply_update_fields(record, command)
        _validate_record(record)
        record.save()
        _audit(actor, "assessment_record_updated", record)
        return record


def record_assessment_result(actor, record_id: int, command: AssessmentRecordCommand) -> StudentAssessmentRecord:
    if not isinstance(command, AssessmentRecordCommand):
        raise ValidationError("Assessment results require a typed command.")
    with transaction.atomic():
        record = _record(record_id)
        if not can_record_assessment(actor, record):
            _deny(actor, "record", record)
        if record.status != AssessmentRecordStatus.DRAFT:
            raise LifecycleConflictError()
        _expected_updated_at(record, command.expected_updated_at)
        _apply_result_fields(record, command)
        record.status = AssessmentRecordStatus.RECORDED
        _validate_record(record)
        record.save()
        _audit(actor, "assessment_record_recorded", record)
        return record


def submit_assessment_for_review(actor, record_id: int, command: AssessmentSubmitReviewCommand) -> StudentAssessmentRecord:
    if not isinstance(command, AssessmentSubmitReviewCommand):
        raise ValidationError("Assessment review submission requires a typed command.")
    with transaction.atomic():
        record = _record(record_id)
        if not can_submit_assessment_for_review(actor, record):
            _deny(actor, "submit_review", record)
        _expected_updated_at(record, command.expected_updated_at)
        record.status = AssessmentRecordStatus.UNDER_REVIEW
        _validate_record(record)
        record.save()
        _audit(actor, "assessment_record_submitted_for_review", record)
        return record


def review_assessment_record(actor, record_id: int, command: AssessmentReviewCommand) -> StudentAssessmentRecord:
    if not isinstance(command, AssessmentReviewCommand):
        raise ValidationError("Assessment review requires a typed command.")
    with transaction.atomic():
        record = _record(record_id)
        if not can_review_assessment_record(actor, record):
            _deny(actor, "review", record)
        if record.status != AssessmentRecordStatus.UNDER_REVIEW:
            raise LifecycleConflictError()
        _expected_updated_at(record, command.expected_updated_at)
        record.status = AssessmentRecordStatus.REVIEWED
        record.reviewed_by = actor
        record.reviewed_at = timezone.now()
        _validate_record(record)
        record.save()
        _audit(actor, "assessment_record_reviewed", record, has_notes=bool(command.notes))
        return record


def release_assessment_to_student(actor, record_id: int, command: AssessmentReleaseCommand) -> StudentAssessmentRecord:
    if not isinstance(command, AssessmentReleaseCommand):
        raise ValidationError("Assessment release requires a typed command.")
    with transaction.atomic():
        record = _record(record_id)
        if not can_release_assessment_to_student(actor, record):
            _deny(actor, "release", record)
        if record.interpretation_visibility != AssessmentInterpretationVisibility.RELEASED_TO_STUDENT_SAFE_SUMMARY:
            raise ValidationError("The assessment is not marked as a safe student summary.")
        _expected_updated_at(record, command.expected_updated_at)
        record.status = AssessmentRecordStatus.RELEASED_TO_STUDENT
        record.released_to_student = True
        record.released_to_student_at = timezone.now()
        record.released_to_student_by = actor
        _validate_record(record)
        record.save()
        _audit(actor, "assessment_record_released", record)
        return record


def void_assessment_record(actor, record_id: int, command: AssessmentVoidCommand) -> StudentAssessmentRecord:
    if not isinstance(command, AssessmentVoidCommand):
        raise ValidationError("Assessment void requires a typed command.")
    with transaction.atomic():
        record = _record(record_id)
        if not can_void_assessment_record(actor, record):
            _deny(actor, "void", record)
        _expected_updated_at(record, command.expected_updated_at)
        record.status = AssessmentRecordStatus.VOIDED
        _store_reason(record, "void_reason", command.reason_code)
        _validate_record(record)
        record.save()
        _audit(actor, "assessment_record_voided", record, reason_code=command.reason_code)
        return record


def supersede_assessment_record(actor, record_id: int, command: AssessmentSupersedeCommand) -> StudentAssessmentRecord:
    if not isinstance(command, AssessmentSupersedeCommand):
        raise ValidationError("Assessment supersession requires a typed command.")
    with transaction.atomic():
        record = _record(record_id)
        replacement = _record(command.replacement_record_id)
        if not can_supersede_assessment_record(actor, record):
            _deny(actor, "supersede", record)
        if replacement.pk == record.pk or replacement.student_profile_id != record.student_profile_id:
            raise ValidationError("The replacement must belong to the same student and be different.")
        if replacement.status in {AssessmentRecordStatus.VOIDED, AssessmentRecordStatus.ARCHIVED}:
            raise LifecycleConflictError()
        _expected_updated_at(record, command.expected_updated_at)
        record.status = AssessmentRecordStatus.SUPERSEDED
        _store_reason(record, "supersede_reason", command.reason_code)
        _store_reason(record, "superseded_by_id", str(replacement.pk))
        _validate_record(record)
        record.save()
        _audit(actor, "assessment_record_superseded", record, reason_code=command.reason_code, replacement_record_id=str(replacement.pk))
        return record


def archive_assessment_record(actor, record_id: int, command: AssessmentArchiveCommand) -> StudentAssessmentRecord:
    if not isinstance(command, AssessmentArchiveCommand):
        raise ValidationError("Assessment archival requires a typed command.")
    with transaction.atomic():
        record = _record(record_id)
        if not can_archive_assessment_record(actor, record):
            _deny(actor, "archive", record)
        _expected_updated_at(record, command.expected_updated_at)
        record.status = AssessmentRecordStatus.ARCHIVED
        _store_reason(record, "archival_reason", command.reason_code)
        _validate_record(record)
        record.save()
        _audit(actor, "assessment_record_archived", record, reason_code=command.reason_code)
        return record


def _store_reason(record: StudentAssessmentRecord, key: str, value: str | None) -> None:
    if not value:
        return
    existing = record.metadata_json if isinstance(record.metadata_json, dict) else {}
    record.metadata_json = {**existing, key: value}


def attach_protected_assessment_file(actor, record_id: int, receipt: AssessmentFileUploadReceipt) -> StudentAssessmentRecord:
    if not isinstance(receipt, AssessmentFileUploadReceipt):
        raise ValidationError("Assessment files require a typed upload receipt.")
    with transaction.atomic():
        record = _record(record_id)
        if not can_attach_assessment_file(actor, record):
            _deny(actor, "file_attach", record)
        try:
            protected_file = ProtectedFile.objects.select_for_update().get(pk=receipt.protected_file_id)
        except ProtectedFile.DoesNotExist as exc:
            raise NotFoundError() from exc
        if (
            protected_file.purpose != PurposeChoices.ASSESSMENT_RESULT_FILE
            or protected_file.status != FileStatusChoices.ACTIVE
            or protected_file.owning_app_label != "assessments"
            or protected_file.owning_model_name != "StudentAssessmentRecord"
            or protected_file.owning_object_id != str(record.pk)
        ):
            raise PermissionDeniedError()
        record.protected_file = protected_file
        record.save(update_fields=["protected_file", "updated_at"])
        _audit(actor, "assessment_file_attached", record, file_id=str(protected_file.pk))
        return record


def authorized_assessment_file_id(actor, record_id: int):
    with transaction.atomic():
        record = _record(record_id, for_update=False)
        if not can_view_assessment_record(actor, record) or not record.protected_file_id:
            raise NotFoundError()
        return record.protected_file_id


def assessment_sensitive_projection_for_actor(actor, record_id: int) -> dict:
    from apps.assessments.projections import assessment_sensitive_projection

    record = _record(record_id, for_update=False)
    if not can_view_assessment_interpretation(actor, record):
        raise NotFoundError()
    try:
        value = assessment_sensitive_projection(record)
    except Exception as exc:
        raise DependencyFailureError() from exc
    audit_sensitive_view(
        actor_user=actor,
        target_model="StudentAssessmentRecord",
        target_object_id=str(record.pk),
        metadata={"instrument_key": record.instrument.key, "context": "assessment_interpretation"},
    )
    return value


def audit_assessment_sensitive_view(actor, record_id: int, context: str | None = None) -> None:
    record = _record(record_id, for_update=False)
    if not can_view_assessment_interpretation(actor, record):
        raise NotFoundError()
    audit_sensitive_view(
        actor_user=actor,
        target_model="StudentAssessmentRecord",
        target_object_id=str(record.pk),
        metadata={"instrument_key": record.instrument.key, "context": context or "assessment"},
    )


def build_assessment_aggregate_dataset(actor, filters: dict | None = None) -> list:
    """Reports-owned aggregate helper with existing suppression semantics."""
    if not can_view_assessment_record(actor, None) and not can_view_assessment_destination(actor):
        raise PermissionDeniedError()
    from django.db.models import Count
    from apps.access_control.selectors import get_students_visible_to
    from apps.reports.suppression import MIN_SUPPRESSION_THRESHOLD, SUPPRESSION_LABEL

    queryset = StudentAssessmentRecord.objects.filter(student_profile__in=get_students_visible_to(actor))
    if isinstance(filters, dict):
        category = filters.get("category")
        status = filters.get("status")
        if category:
            queryset = queryset.filter(instrument__category=category)
        if status:
            queryset = queryset.filter(status=status)
    aggregates = queryset.values("instrument__category", "status").annotate(count=Count("id"))
    result = []
    for aggregate in aggregates:
        count = aggregate["count"]
        result.append({
            "instrument__category": aggregate["instrument__category"],
            "status": aggregate["status"],
            "count": SUPPRESSION_LABEL if 0 < count < MIN_SUPPRESSION_THRESHOLD else count,
        })
    return result
