"""Release 1 group-local boundary for counseling confidential text."""

from dataclasses import dataclass
from types import MappingProxyType

from django.db import connection

from apps.access_control.authority import has_fixed_capability
from apps.access_control.capabilities import Capability
from apps.access_control.rules import is_active_nonlegacy_actor, is_student, owns_user
from apps.counseling.checks import validate_counseling_compatibility_settings
from apps.security.exceptions import (
    FieldEncryptionError,
    FieldEncryptionKeySourceUnavailable,
    FieldEncryptionKeyStateInvalid,
    FieldEncryptionKeyUnavailable,
)
from apps.security.field_encryption import decrypt_field_value


SESSION_CONCERN = "SESSION-CONCERN"
SESSION_EARLY_END = "SESSION-EARLY-END"
SESSION_CANCEL = "SESSION-CANCEL"
NOTE_SHARED = "NOTE-SHARED"
NOTE_COUNSELOR = "NOTE-COUNSELOR"
ROUTINE_INTAKE = "ROUTINE-INTAKE"
ROUTINE_EVALUATION = "ROUTINE-EVALUATION"
ROUTINE_CORRECTION = "ROUTINE-CORRECTION"


@dataclass(frozen=True)
class ConfidentialGroup:
    identifier: str
    model_name: str
    source_fields: tuple[str, ...]

    @property
    def destination_fields(self):
        return tuple(f"{name}_encrypted" for name in self.source_fields)


GROUPS = MappingProxyType(
    {
        SESSION_CONCERN: ConfidentialGroup(SESSION_CONCERN, "CounselingSession", ("concern_summary",)),
        SESSION_EARLY_END: ConfidentialGroup(SESSION_EARLY_END, "CounselingSession", ("ended_early_reason",)),
        SESSION_CANCEL: ConfidentialGroup(SESSION_CANCEL, "CounselingSession", ("cancellation_reason",)),
        NOTE_SHARED: ConfidentialGroup(NOTE_SHARED, "CounselingSessionNote", ("student_visible_summary",)),
        NOTE_COUNSELOR: ConfidentialGroup(
            NOTE_COUNSELOR,
            "CounselingSessionNote",
            ("counselor_narrative", "recommendations", "special_concerns", "follow_up_notes"),
        ),
        ROUTINE_INTAKE: ConfidentialGroup(
            ROUTINE_INTAKE,
            "RoutineInterviewRecord",
            (
                "coping_challenges", "coping_remarks", "ucn_experience", "reason_for_coming",
                "difficulties_encountered", "stress_anxiety_causes", "stress_anxiety_management",
                "family_background_notes", "concerns_explanation", "college_adjustment",
                "academic_goals", "career_goals", "concern_others_text",
            ),
        ),
        ROUTINE_EVALUATION: ConfidentialGroup(
            ROUTINE_EVALUATION,
            "RoutineInterviewRecord",
            ("rating_others_label", "special_concern", "recommendations"),
        ),
        ROUTINE_CORRECTION: ConfidentialGroup(
            ROUTINE_CORRECTION, "RoutineInterviewRecord", ("reopen_reason",)
        ),
    }
)

ALL_SOURCE_FIELDS = tuple(
    dict.fromkeys(name for group in GROUPS.values() for name in group.source_fields)
)
ALL_DESTINATION_FIELDS = tuple(f"{name}_encrypted" for name in ALL_SOURCE_FIELDS)
SESSION_CONFIDENTIAL_FIELDS = tuple(
    name for group in GROUPS.values() if group.model_name == "CounselingSession"
    for name in (*group.source_fields, *group.destination_fields)
)
NOTE_CONFIDENTIAL_FIELDS = tuple(
    name for group in GROUPS.values() if group.model_name == "CounselingSessionNote"
    for name in (*group.source_fields, *group.destination_fields)
)
ROUTINE_CONFIDENTIAL_FIELDS = tuple(
    name for group in GROUPS.values() if group.model_name == "RoutineInterviewRecord"
    for name in (*group.source_fields, *group.destination_fields)
)


class CounselingEncryptionError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _code(group_id, suffix):
    return f"counseling_confidential_{group_id.lower().replace('-', '_')}_{suffix}"


def _group(group_id, instance=None):
    try:
        group = GROUPS[group_id]
    except (KeyError, TypeError):
        raise CounselingEncryptionError("counseling_confidential_group_invalid") from None
    if instance is not None and type(instance).__name__ != group.model_name:
        raise CounselingEncryptionError(_code(group_id, "target_invalid"))
    return group


def _validate_values(group, values):
    if not isinstance(values, dict) or set(values) != set(group.source_fields):
        raise CounselingEncryptionError(_code(group.identifier, "payload_invalid"))
    for source in group.source_fields:
        value = values[source]
        if type(value) is not str:
            raise CounselingEncryptionError(_code(group.identifier, "payload_invalid"))
        field = _model_for_group(group)._meta.get_field(f"{source}_encrypted")
        try:
            size = len(value.encode("utf-8"))
        except UnicodeEncodeError:
            raise CounselingEncryptionError(_code(group.identifier, "payload_invalid")) from None
        if size > field.max_plaintext_bytes or (
            field.max_length is not None and len(value) > field.max_length
        ):
            raise CounselingEncryptionError(_code(group.identifier, "payload_too_large"))
    return MappingProxyType(dict(values))


def _model_for_group(group):
    from apps.counseling.models import CounselingSession, CounselingSessionNote, RoutineInterviewRecord

    return {
        "CounselingSession": CounselingSession,
        "CounselingSessionNote": CounselingSessionNote,
        "RoutineInterviewRecord": RoutineInterviewRecord,
    }[group.model_name]


def _raw_group_values(instance, group):
    model = type(instance)
    table = connection.ops.quote_name(model._meta.db_table)
    names = (*group.source_fields, *group.destination_fields)
    columns = ", ".join(
        connection.ops.quote_name(model._meta.get_field(name).column) for name in names
    )
    pk_column = connection.ops.quote_name(model._meta.pk.column)
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT {columns} FROM {table} WHERE {pk_column} = %s", [instance.pk])
        row = cursor.fetchone()
    if row is None:
        raise CounselingEncryptionError(_code(group.identifier, "target_missing"))
    count = len(group.source_fields)
    sources = dict(zip(group.source_fields, row[:count]))
    destinations = dict(zip(group.destination_fields, row[count:]))
    return sources, destinations


def _lifecycle_initialized(instance, group, sources):
    from apps.counseling.models import RoutineInterviewStatusChoices, SessionStatusChoices

    if group.identifier == SESSION_CONCERN:
        return True
    if group.identifier == SESSION_EARLY_END:
        return bool(instance.ended_early_flag or any(sources.values()))
    if group.identifier == SESSION_CANCEL:
        return bool(instance.status == SessionStatusChoices.CANCELLED or any(sources.values()))
    if group.identifier in {NOTE_SHARED, NOTE_COUNSELOR}:
        return True
    if group.identifier == ROUTINE_INTAKE:
        return bool(
            instance.status != RoutineInterviewStatusChoices.NOT_STARTED
            or instance.submitted_at
            or any(sources.values())
        )
    if group.identifier == ROUTINE_EVALUATION:
        return bool(
            instance.evaluated_at
            or instance.evaluated_by_id
            or instance.status in {
                RoutineInterviewStatusChoices.EVALUATION_DRAFT,
                RoutineInterviewStatusChoices.COMPLETED,
                RoutineInterviewStatusChoices.FINALIZED,
                RoutineInterviewStatusChoices.LOCKED,
            }
            or any(sources.values())
        )
    return bool(
        instance.reopened_at
        or instance.reopened_by_id
        or instance.status == RoutineInterviewStatusChoices.REOPENED_FOR_CORRECTION
        or any(sources.values())
    )


def _decrypt_destinations(group, raw_destinations):
    model = _model_for_group(group)
    values = {}
    try:
        for source, destination in zip(group.source_fields, group.destination_fields):
            field = model._meta.get_field(destination)
            values[source] = decrypt_field_value(
                raw_destinations[destination],
                payload_type="text",
                context=field.encryption_context,
                max_plaintext_bytes=field.max_plaintext_bytes,
            )
    except (FieldEncryptionKeyUnavailable, FieldEncryptionKeyStateInvalid, FieldEncryptionKeySourceUnavailable):
        raise CounselingEncryptionError(_code(group.identifier, "key_unavailable")) from None
    except FieldEncryptionError:
        raise CounselingEncryptionError(_code(group.identifier, "payload_invalid")) from None
    return _validate_values(group, values)


def classify_group(instance, group_id, *, authenticate_migrated_empty=True):
    group = _group(group_id, instance)
    sources, raw_destinations = _raw_group_values(instance, group)
    source_values = _validate_values(group, sources)
    present = tuple(raw_destinations[name] is not None for name in group.destination_fields)
    initialized = _lifecycle_initialized(instance, group, source_values)
    if not any(present):
        return _code(group_id, "legacy_only" if initialized else "uninitialized")
    if not all(present):
        return _code(group_id, "partial")
    if not initialized and not any(source_values.values()) and not authenticate_migrated_empty:
        return _code(group_id, "migrated_empty")
    destinations = _decrypt_destinations(group, raw_destinations)
    if destinations != source_values:
        return _code(group_id, "twin_mismatch")
    if not initialized and not any(source_values.values()):
        return _code(group_id, "migrated_empty")
    return _code(group_id, "migrated")


def _read_group(instance, group_id, *, permit_uninitialized=False):
    group = _group(group_id, instance)
    sources, raw_destinations = _raw_group_values(instance, group)
    source_values = _validate_values(group, sources)
    present = tuple(raw_destinations[name] is not None for name in group.destination_fields)
    initialized = _lifecycle_initialized(instance, group, source_values)
    if not any(present):
        if not initialized and permit_uninitialized:
            return MappingProxyType({name: "" for name in group.source_fields})
        configuration = validate_counseling_compatibility_settings()
        if not configuration.permits_legacy_fallback:
            raise CounselingEncryptionError(configuration.result_code)
        return source_values
    if not all(present):
        raise CounselingEncryptionError(_code(group_id, "partial"))
    if not initialized and not any(source_values.values()):
        return MappingProxyType({name: "" for name in group.source_fields})
    destinations = _decrypt_destinations(group, raw_destinations)
    if destinations != source_values:
        raise CounselingEncryptionError(_code(group_id, "twin_mismatch"))
    return destinations


def prepare_group_write(instance, group_id, values):
    """Validate one owned group and set exact source/destination twins in memory."""
    group = _group(group_id, instance)
    values = _validate_values(group, values)
    if instance.pk:
        state = classify_group(instance, group_id)
        allowed = {
            _code(group_id, "uninitialized"),
            _code(group_id, "legacy_only"),
            _code(group_id, "migrated_empty"),
            _code(group_id, "migrated"),
        }
        if state not in allowed:
            raise CounselingEncryptionError(state)
    fields = []
    for source in group.source_fields:
        setattr(instance, source, values[source])
        setattr(instance, f"{source}_encrypted", values[source])
        fields.extend((source, f"{source}_encrypted"))
    return tuple(fields)


def initialize_group(instance, group_id, values):
    """Set exact twins on an unsaved object for an authorized creation workflow."""
    if instance.pk:
        raise CounselingEncryptionError(_code(group_id, "already_persisted"))
    return prepare_group_write(instance, group_id, values)


def _session_metadata(pk):
    from apps.counseling.models import CounselingSession

    return CounselingSession.objects.defer(*SESSION_CONFIDENTIAL_FIELDS).select_related(
        "student", "assigned_counselor"
    ).get(pk=pk)


def _record_metadata(pk):
    from apps.counseling.models import RoutineInterviewRecord

    return RoutineInterviewRecord.objects.defer(*ROUTINE_CONFIDENTIAL_FIELDS).select_related(
        "session", "session__student", "session__assigned_counselor"
    ).get(pk=pk)


def _fail_closed(user) -> bool:
    """Fail closed for anonymous, deactivated, and legacy-superuser actors.

    Thin domain-local alias delegating to the single source of truth
    ``access_control.rules.is_active_nonlegacy_actor`` so confidential
    plaintext is never released to an inactive account or a legacy superuser,
    even when a role predicate alone would pass. The guard runs before any
    database read in each reader.
    """
    return not is_active_nonlegacy_actor(user)


def read_student_visible_summary(user, session):
    from apps.counseling.models import CounselingSessionNote
    from apps.counseling.policies import can_view_counseling_notes

    if _fail_closed(user):
        raise CounselingEncryptionError(_code(NOTE_SHARED, "access_denied"))
    session = _session_metadata(session.pk)
    allowed = bool(
        (is_student(user) and owns_user(user, session.student_id))
        or can_view_counseling_notes(user, session)
    )
    if not allowed:
        raise CounselingEncryptionError(_code(NOTE_SHARED, "access_denied"))
    note = CounselingSessionNote.objects.defer(*NOTE_CONFIDENTIAL_FIELDS).filter(session=session).first()
    if note is None:
        return ""
    return _read_group(note, NOTE_SHARED)["student_visible_summary"]


def read_counselor_note(user, session):
    from apps.counseling.models import CounselingSessionNote
    from apps.counseling.policies import can_view_counseling_notes

    if _fail_closed(user):
        raise CounselingEncryptionError(_code(NOTE_COUNSELOR, "access_denied"))
    session = _session_metadata(session.pk)
    if not can_view_counseling_notes(user, session):
        raise CounselingEncryptionError(_code(NOTE_COUNSELOR, "access_denied"))
    note = CounselingSessionNote.objects.defer(*NOTE_CONFIDENTIAL_FIELDS).filter(session=session).first()
    if note is None:
        return None
    values = dict(_read_group(note, NOTE_SHARED))
    values.update(_read_group(note, NOTE_COUNSELOR))
    values["follow_up_needed"] = note.follow_up_needed
    return MappingProxyType(values)


_INTAKE_METADATA = (
    "visit_date", "visit_time", "duration_minutes", "nature_of_visit",
    "concern_academic", "concern_friends", "concern_classmates", "concern_vices",
    "concern_love_life", "concern_sleeping_problems", "concern_family", "concern_financial",
    "concern_suicidal_thought", "concern_dorm_boarding_house",
    "concern_past_painful_experience", "concern_others", "submitted_at",
)
_EVALUATION_METADATA = (
    "rating_emotionally", "rating_academically", "rating_physically", "rating_socially",
    "rating_spiritually", "rating_financially", "rating_others",
    "assigned_counselor_confirmation", "evaluation_date", "evaluated_at",
)


def read_routine_intake(user, record):
    from apps.counseling.policies import can_view_routine_interview_intake

    if _fail_closed(user) or not record or not can_view_routine_interview_intake(user, record):
        raise CounselingEncryptionError(_code(ROUTINE_INTAKE, "access_denied"))
    record = _record_metadata(record.pk)
    if not can_view_routine_interview_intake(user, record):
        raise CounselingEncryptionError(_code(ROUTINE_INTAKE, "access_denied"))
    values = {name: getattr(record, name) for name in _INTAKE_METADATA}
    values.update(_read_group(record, ROUTINE_INTAKE, permit_uninitialized=True))
    return MappingProxyType(values)


def read_routine_evaluation(user, record):
    from apps.counseling.policies import can_view_routine_interview_evaluation

    if _fail_closed(user) or not record or not can_view_routine_interview_evaluation(user, record):
        raise CounselingEncryptionError(_code(ROUTINE_EVALUATION, "access_denied"))
    record = _record_metadata(record.pk)
    if not can_view_routine_interview_evaluation(user, record):
        raise CounselingEncryptionError(_code(ROUTINE_EVALUATION, "access_denied"))
    values = {name: getattr(record, name) for name in _EVALUATION_METADATA}
    values.update(_read_group(record, ROUTINE_EVALUATION, permit_uninitialized=True))
    return MappingProxyType(values)


def read_routine_correction(user, record):
    # Fail closed before any database read so inactive/legacy actors never
    # even trigger the record lookup.
    if _fail_closed(user) or not has_fixed_capability(user, Capability.ROUTINE_INTERVIEW_REOPEN):
        raise CounselingEncryptionError(_code(ROUTINE_CORRECTION, "access_denied"))
    record = _record_metadata(record.pk)
    values = dict(_read_group(record, ROUTINE_CORRECTION, permit_uninitialized=True))
    values.update(
        reopen_target=record.reopen_target,
        reopened_at=record.reopened_at,
        reopened_by_id=record.reopened_by_id,
    )
    return MappingProxyType(values)
