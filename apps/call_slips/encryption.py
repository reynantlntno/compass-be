"""Release 1 singleton-group boundary for confidential Call Slip narratives."""

from dataclasses import dataclass
from types import MappingProxyType

from django.db import connection

from apps.call_slips.checks import validate_call_slip_compatibility_settings
from apps.security.exceptions import (
    FieldEncryptionError,
    FieldEncryptionKeySourceUnavailable,
    FieldEncryptionKeyStateInvalid,
    FieldEncryptionKeyUnavailable,
    FieldEncryptionPayloadTooLarge,
)
from apps.security.field_encryption import decrypt_field_value
from apps.access_control.rules import is_active_nonlegacy_actor, is_student, owns_user


CS_INSTRUCTIONS = "CS-INSTRUCTIONS"
CS_OFFICE_REMARKS = "CS-OFFICE-REMARKS"
CS_CANCELLATION = "CS-CANCELLATION"
CS_NO_SHOW = "CS-NO-SHOW"
CS_ASSIGNMENT = "CS-ASSIGNMENT"
CS_RESCHEDULE_REQUEST = "CS-RESCHEDULE-REQUEST"
CS_RESCHEDULE_DECISION = "CS-RESCHEDULE-DECISION"


@dataclass(frozen=True)
class ConfidentialGroup:
    identifier: str
    model_name: str
    source_field: str
    destination_field: str


GROUPS = MappingProxyType(
    {
        CS_INSTRUCTIONS: ConfidentialGroup(CS_INSTRUCTIONS, "CallSlip", "student_safe_instructions", "student_safe_instructions_encrypted"),
        CS_OFFICE_REMARKS: ConfidentialGroup(CS_OFFICE_REMARKS, "CallSlip", "office_only_remarks", "office_only_remarks_encrypted"),
        CS_CANCELLATION: ConfidentialGroup(CS_CANCELLATION, "CallSlip", "cancellation_detail", "cancellation_detail_encrypted"),
        CS_NO_SHOW: ConfidentialGroup(CS_NO_SHOW, "CallSlip", "no_show_detail", "no_show_detail_encrypted"),
        CS_ASSIGNMENT: ConfidentialGroup(CS_ASSIGNMENT, "CallSlipAssignmentHistory", "detail", "detail_encrypted"),
        CS_RESCHEDULE_REQUEST: ConfidentialGroup(CS_RESCHEDULE_REQUEST, "CallSlipRescheduleRequest", "student_reason", "student_reason_encrypted"),
        CS_RESCHEDULE_DECISION: ConfidentialGroup(CS_RESCHEDULE_DECISION, "CallSlipRescheduleRequest", "decision_detail", "decision_detail_encrypted"),
    }
)

CALL_SLIP_CONFIDENTIAL_FIELDS = (
    "student_safe_instructions", "student_safe_instructions_encrypted",
    "office_only_remarks", "office_only_remarks_encrypted",
    "cancellation_detail", "cancellation_detail_encrypted",
    "no_show_detail", "no_show_detail_encrypted",
)
ASSIGNMENT_CONFIDENTIAL_FIELDS = ("detail", "detail_encrypted")
RESCHEDULE_CONFIDENTIAL_FIELDS = (
    "student_reason", "student_reason_encrypted",
    "decision_detail", "decision_detail_encrypted",
)
ALL_CONFIDENTIAL_FIELDS_BY_MODEL = MappingProxyType(
    {
        "CallSlip": CALL_SLIP_CONFIDENTIAL_FIELDS,
        "CallSlipAssignmentHistory": ASSIGNMENT_CONFIDENTIAL_FIELDS,
        "CallSlipRescheduleRequest": RESCHEDULE_CONFIDENTIAL_FIELDS,
    }
)

STORAGE_STATES = (
    "destination-null", "legacy-only", "migrated-empty", "migrated",
    "conflict", "malformed", "unavailable-key", "oversize", "partial",
)
BLOCKER_STATES = ("conflict", "malformed", "unavailable-key", "oversize", "partial")


class CallSlipEncryptionError(Exception):
    """Content-free Call Slip storage failure safe for callers and logs."""

    def __init__(self, code="call_slips_confidential_state_invalid"):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class GroupClassification:
    group_id: str
    lifecycle_state: str
    storage_state: str
    valid_combination: bool

    @property
    def result_code(self):
        group = self.group_id.lower().replace("-", "_")
        storage = self.storage_state.replace("-", "_")
        return f"call_slips_confidential_{group}_{self.lifecycle_state}_{storage}"


def _group(group_id, instance=None):
    try:
        group = GROUPS[group_id]
    except (KeyError, TypeError):
        raise CallSlipEncryptionError("call_slips_confidential_group_invalid") from None
    if instance is not None and type(instance).__name__ != group.model_name:
        raise CallSlipEncryptionError("call_slips_confidential_target_invalid")
    return group


def _model_for_group(group):
    from apps.call_slips.models import CallSlip, CallSlipAssignmentHistory, CallSlipRescheduleRequest

    return {
        "CallSlip": CallSlip,
        "CallSlipAssignmentHistory": CallSlipAssignmentHistory,
        "CallSlipRescheduleRequest": CallSlipRescheduleRequest,
    }[group.model_name]


def confidential_fields_for_model(model_or_instance):
    model = model_or_instance if isinstance(model_or_instance, type) else type(model_or_instance)
    return ALL_CONFIDENTIAL_FIELDS_BY_MODEL.get(model.__name__, ())


def defer_confidential_fields(queryset):
    return queryset.defer(*confidential_fields_for_model(queryset.model))


def _validate_text(group, value):
    if type(value) is not str:
        raise CallSlipEncryptionError("call_slips_confidential_payload_malformed")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        raise CallSlipEncryptionError("call_slips_confidential_payload_malformed") from None
    field = _model_for_group(group)._meta.get_field(group.destination_field)
    if size > field.max_plaintext_bytes:
        raise CallSlipEncryptionError("call_slips_confidential_payload_oversize")
    return value


def validate_group_text(group_id, value):
    return _validate_text(_group(group_id), value)


def _raw_group_values(instance, group):
    model = type(instance)
    table = connection.ops.quote_name(model._meta.db_table)
    source = connection.ops.quote_name(model._meta.get_field(group.source_field).column)
    destination = connection.ops.quote_name(model._meta.get_field(group.destination_field).column)
    pk = connection.ops.quote_name(model._meta.pk.column)
    with connection.cursor() as cursor:
        cursor.execute(
            f"SELECT {source}, {destination} FROM {table} WHERE {pk} = %s",
            [instance.pk],
        )
        row = cursor.fetchone()
    if row is None:
        raise CallSlipEncryptionError("call_slips_confidential_target_missing")
    return row


def _event_lifecycle(instance, *, status, at_field, actor_field, code_field, valid_codes):
    status_matches = instance.status == status
    at_present = getattr(instance, at_field) is not None
    actor_present = getattr(instance, f"{actor_field}_id") is not None
    code = getattr(instance, code_field)
    evidence_present = at_present or actor_present or bool(code)
    if status_matches:
        return "initialized" if at_present and actor_present and code in valid_codes else "invalid"
    return "invalid" if evidence_present else "uninitialized"


def lifecycle_state(instance, group_id):
    from apps.call_slips.models import (
        CallSlipRescheduleRequestStatusChoices,
        CallSlipStatusChoices,
        CallSlipWorkflowReasonChoices,
    )

    group = _group(group_id, instance)
    if group.identifier in {CS_INSTRUCTIONS, CS_OFFICE_REMARKS, CS_ASSIGNMENT, CS_RESCHEDULE_REQUEST}:
        return "initialized" if instance.pk else "uninitialized"
    if group.identifier == CS_CANCELLATION:
        return _event_lifecycle(
            instance, status=CallSlipStatusChoices.CANCELLED,
            at_field="cancelled_at", actor_field="cancelled_by",
            code_field="cancel_reason_code", valid_codes=CallSlipWorkflowReasonChoices.values,
        )
    if group.identifier == CS_NO_SHOW:
        return _event_lifecycle(
            instance, status=CallSlipStatusChoices.NO_SHOW,
            at_field="no_show_at", actor_field="no_show_by",
            code_field="no_show_reason_code", valid_codes=CallSlipWorkflowReasonChoices.values,
        )
    if group.identifier == CS_RESCHEDULE_DECISION:
        pending = instance.status == CallSlipRescheduleRequestStatusChoices.PENDING
        actor = instance.decider_id is not None
        decided_at = instance.decided_at is not None
        code = instance.decision_code
        if pending:
            return "uninitialized" if not actor and not decided_at and code == "" else "invalid"
        if instance.status in {
            CallSlipRescheduleRequestStatusChoices.APPROVED,
            CallSlipRescheduleRequestStatusChoices.DECLINED,
        }:
            return "initialized" if actor and decided_at and code in CallSlipWorkflowReasonChoices.values else "invalid"
        return "invalid"
    raise CallSlipEncryptionError("call_slips_confidential_group_invalid")


def _decrypt(group, raw):
    field = _model_for_group(group)._meta.get_field(group.destination_field)
    try:
        value = decrypt_field_value(
            raw,
            payload_type="text",
            context=field.encryption_context,
            max_plaintext_bytes=field.max_plaintext_bytes,
        )
    except (FieldEncryptionKeyUnavailable, FieldEncryptionKeyStateInvalid, FieldEncryptionKeySourceUnavailable):
        raise CallSlipEncryptionError("call_slips_confidential_payload_unavailable_key") from None
    except FieldEncryptionPayloadTooLarge:
        raise CallSlipEncryptionError("call_slips_confidential_payload_oversize") from None
    except FieldEncryptionError:
        raise CallSlipEncryptionError("call_slips_confidential_payload_malformed") from None
    return _validate_text(group, value)


def _combination_valid(group_id, lifecycle, storage):
    if lifecycle == "invalid" or storage in BLOCKER_STATES:
        return False
    if group_id in {CS_CANCELLATION, CS_NO_SHOW}:
        if lifecycle == "uninitialized":
            return storage in {"destination-null", "migrated-empty"}
        return storage in {"legacy-only", "migrated-empty", "migrated"}
    if group_id == CS_RESCHEDULE_DECISION:
        if lifecycle == "uninitialized":
            return storage in {"destination-null", "migrated-empty"}
        return storage in {"legacy-only", "migrated-empty", "migrated"}
    if group_id == CS_RESCHEDULE_REQUEST:
        return lifecycle == "initialized" and storage in {"legacy-only", "migrated"}
    return lifecycle == "initialized" and storage in {"legacy-only", "migrated-empty", "migrated"}


def _inspect_group(instance, group_id):
    group = _group(group_id, instance)
    lifecycle = lifecycle_state(instance, group_id)
    try:
        source, raw_destination = _raw_group_values(instance, group)
        source = _validate_text(group, source)
        if raw_destination is None:
            storage = "destination-null" if lifecycle == "uninitialized" and source == "" else "legacy-only"
            value = source
        else:
            destination = _decrypt(group, raw_destination)
            if destination != source:
                storage = "conflict"
            elif destination == "":
                storage = "migrated-empty"
            else:
                storage = "migrated"
            value = destination
    except CallSlipEncryptionError as exc:
        if exc.code.endswith("unavailable_key"):
            storage = "unavailable-key"
        elif exc.code.endswith("oversize"):
            storage = "oversize"
        else:
            storage = "malformed"
        value = None
    classification = GroupClassification(
        group_id, lifecycle, storage, _combination_valid(group_id, lifecycle, storage)
    )
    return classification, value


def classify_group(instance, group_id):
    return _inspect_group(instance, group_id)[0]


def _metadata_instance(instance, group):
    model = type(instance)
    queryset = defer_confidential_fields(model.objects.all())
    if group.model_name == "CallSlip":
        queryset = queryset.select_related("student", "student__student_profile", "assigned_counselor")
    elif group.model_name == "CallSlipRescheduleRequest":
        queryset = queryset.select_related(
            "call_slip", "call_slip__student", "call_slip__student__student_profile",
            "call_slip__assigned_counselor",
        ).defer(*(f"call_slip__{name}" for name in CALL_SLIP_CONFIDENTIAL_FIELDS))
    return queryset.get(pk=instance.pk)


def read_group(user, instance, group_id):
    """Authorize on safe metadata before fetching or decrypting one singleton group."""
    from apps.call_slips.policies import (
        can_decide_reschedule,
        can_student_view_call_slip,
        can_view_call_slip_sensitive_detail,
    )

    group = _group(group_id, instance)
    metadata = _metadata_instance(instance, group)
    if group_id == CS_INSTRUCTIONS:
        allowed = can_student_view_call_slip(user, metadata) or can_view_call_slip_sensitive_detail(user, metadata)
    elif group_id == CS_OFFICE_REMARKS:
        allowed = can_view_call_slip_sensitive_detail(user, metadata)
    elif group_id == CS_RESCHEDULE_REQUEST:
        allowed = can_decide_reschedule(user, metadata)
    else:
        allowed = False
    if not allowed:
        raise CallSlipEncryptionError("call_slips_confidential_access_denied")
    classification, value = _inspect_group(metadata, group_id)
    if not classification.valid_combination:
        raise CallSlipEncryptionError(classification.result_code)
    if classification.storage_state in {"destination-null", "legacy-only"}:
        configuration = validate_call_slip_compatibility_settings()
        if not configuration.permits_legacy_fallback:
            raise CallSlipEncryptionError(configuration.result_code)
    return value


def read_owned_request_for_retry(user, instance):
    """Read only the exact same-key request after owning-student authorization."""
    group = _group(CS_RESCHEDULE_REQUEST, instance)
    metadata = _metadata_instance(instance, group)
    if (
        not is_active_nonlegacy_actor(user)
        or not is_student(user)
        or not owns_user(user, metadata.student_id)
        or not owns_user(user, metadata.call_slip.student_id)
    ):
        raise CallSlipEncryptionError("call_slips_confidential_access_denied")
    classification, value = _inspect_group(metadata, CS_RESCHEDULE_REQUEST)
    if not classification.valid_combination:
        raise CallSlipEncryptionError(classification.result_code)
    if classification.storage_state in {"destination-null", "legacy-only"}:
        configuration = validate_call_slip_compatibility_settings()
        if not configuration.permits_legacy_fallback:
            raise CallSlipEncryptionError(configuration.result_code)
    return value


def prepare_group_write(instance, group_id, value):
    group = _group(group_id, instance)
    value = _validate_text(group, value)
    if instance.pk:
        classification = classify_group(instance, group_id)
        if not classification.valid_combination:
            raise CallSlipEncryptionError(classification.result_code)
    setattr(instance, group.source_field, value)
    setattr(instance, group.destination_field, value)
    return (group.source_field, group.destination_field)


def initialize_group(instance, group_id, value):
    if instance.pk:
        raise CallSlipEncryptionError("call_slips_confidential_already_persisted")
    return prepare_group_write(instance, group_id, value)


def compare_release1_twins(instance, group_id):
    classification = classify_group(instance, group_id)
    return classification.valid_combination and classification.storage_state in {"migrated-empty", "migrated"}
