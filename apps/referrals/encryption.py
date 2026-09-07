"""Release 1 group-local boundary for confidential referral narratives."""

from dataclasses import dataclass
from types import MappingProxyType

from django.db import connection

from apps.referrals.checks import validate_referral_compatibility_settings
from apps.security.exceptions import (
    FieldEncryptionError,
    FieldEncryptionKeySourceUnavailable,
    FieldEncryptionKeyStateInvalid,
    FieldEncryptionKeyUnavailable,
    FieldEncryptionPayloadTooLarge,
)
from apps.security.field_encryption import decrypt_field_value


REFERRAL_SUBMISSION = "REFERRAL-SUBMISSION"
REFERRAL_ACTION = "REFERRAL-ACTION"
STATUS_DETAIL = "STATUS-DETAIL"
ASSIGNMENT_DETAIL = "ASSIGNMENT-DETAIL"
REASSIGNMENT_REQUEST = "REASSIGNMENT-REQUEST"
REASSIGNMENT_DECISION = "REASSIGNMENT-DECISION"


@dataclass(frozen=True)
class ConfidentialGroup:
    identifier: str
    model_name: str
    source_field: str
    destination_field: str


GROUPS = MappingProxyType(
    {
        REFERRAL_SUBMISSION: ConfidentialGroup(
            REFERRAL_SUBMISSION, "Referral", "reason_text", "reason_text_encrypted"
        ),
        REFERRAL_ACTION: ConfidentialGroup(
            REFERRAL_ACTION, "ReferralAction", "remarks", "remarks_encrypted"
        ),
        STATUS_DETAIL: ConfidentialGroup(
            STATUS_DETAIL,
            "ReferralStatusHistory",
            "reason_detail",
            "reason_detail_encrypted",
        ),
        ASSIGNMENT_DETAIL: ConfidentialGroup(
            ASSIGNMENT_DETAIL,
            "ReferralAssignmentHistory",
            "detail",
            "detail_encrypted",
        ),
        REASSIGNMENT_REQUEST: ConfidentialGroup(
            REASSIGNMENT_REQUEST,
            "ReferralReassignmentRequest",
            "request_detail",
            "request_detail_encrypted",
        ),
        REASSIGNMENT_DECISION: ConfidentialGroup(
            REASSIGNMENT_DECISION,
            "ReferralReassignmentRequest",
            "decision_detail",
            "decision_detail_encrypted",
        ),
    }
)

REFERRAL_CONFIDENTIAL_FIELDS = ("reason_text", "reason_text_encrypted")
ACTION_CONFIDENTIAL_FIELDS = ("remarks", "remarks_encrypted")
STATUS_HISTORY_CONFIDENTIAL_FIELDS = ("reason_detail", "reason_detail_encrypted")
ASSIGNMENT_HISTORY_CONFIDENTIAL_FIELDS = ("detail", "detail_encrypted")
REASSIGNMENT_CONFIDENTIAL_FIELDS = (
    "request_detail",
    "request_detail_encrypted",
    "decision_detail",
    "decision_detail_encrypted",
)
ALL_CONFIDENTIAL_FIELDS_BY_MODEL = MappingProxyType(
    {
        "Referral": REFERRAL_CONFIDENTIAL_FIELDS,
        "ReferralAction": ACTION_CONFIDENTIAL_FIELDS,
        "ReferralStatusHistory": STATUS_HISTORY_CONFIDENTIAL_FIELDS,
        "ReferralAssignmentHistory": ASSIGNMENT_HISTORY_CONFIDENTIAL_FIELDS,
        "ReferralReassignmentRequest": REASSIGNMENT_CONFIDENTIAL_FIELDS,
    }
)

STORAGE_STATES = (
    "destination-null",
    "migrated-empty",
    "migrated",
    "legacy-only",
    "conflict",
    "malformed",
    "unavailable-key",
    "oversize",
    "partial",
)
LIFECYCLE_STATES = ("uninitialized", "initialized", "invalid")


class ReferralEncryptionError(Exception):
    """Content-free referral storage failure safe for callers and logs."""

    def __init__(self, code="referrals_confidential_state_invalid"):
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
        normalized_group = self.group_id.lower().replace("-", "_")
        normalized_storage = self.storage_state.replace("-", "_")
        return (
            f"referrals_confidential_{normalized_group}_"
            f"{self.lifecycle_state}_{normalized_storage}"
        )


def _group(group_id, instance=None):
    try:
        group = GROUPS[group_id]
    except (KeyError, TypeError):
        raise ReferralEncryptionError("referrals_confidential_group_invalid") from None
    if instance is not None and type(instance).__name__ != group.model_name:
        raise ReferralEncryptionError("referrals_confidential_target_invalid")
    return group


def _model_for_group(group):
    from apps.referrals.models import (
        Referral,
        ReferralAction,
        ReferralAssignmentHistory,
        ReferralReassignmentRequest,
        ReferralStatusHistory,
    )

    return {
        "Referral": Referral,
        "ReferralAction": ReferralAction,
        "ReferralStatusHistory": ReferralStatusHistory,
        "ReferralAssignmentHistory": ReferralAssignmentHistory,
        "ReferralReassignmentRequest": ReferralReassignmentRequest,
    }[group.model_name]


def confidential_fields_for_model(model_or_instance):
    model = model_or_instance if isinstance(model_or_instance, type) else type(model_or_instance)
    return ALL_CONFIDENTIAL_FIELDS_BY_MODEL.get(model.__name__, ())


def defer_confidential_fields(queryset):
    return queryset.defer(*confidential_fields_for_model(queryset.model))


def _validate_text(group, value):
    if type(value) is not str:
        raise ReferralEncryptionError("referrals_confidential_payload_malformed")
    field = _model_for_group(group)._meta.get_field(group.destination_field)
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        raise ReferralEncryptionError("referrals_confidential_payload_malformed") from None
    if size > field.max_plaintext_bytes:
        raise ReferralEncryptionError("referrals_confidential_payload_oversize")
    return value


def _raw_group_values(instance, group):
    model = type(instance)
    table = connection.ops.quote_name(model._meta.db_table)
    source_column = connection.ops.quote_name(
        model._meta.get_field(group.source_field).column
    )
    destination_column = connection.ops.quote_name(
        model._meta.get_field(group.destination_field).column
    )
    pk_column = connection.ops.quote_name(model._meta.pk.column)
    with connection.cursor() as cursor:
        cursor.execute(
            f"SELECT {source_column}, {destination_column} "
            f"FROM {table} WHERE {pk_column} = %s",
            [instance.pk],
        )
        row = cursor.fetchone()
    if row is None:
        raise ReferralEncryptionError("referrals_confidential_target_missing")
    return row


def _submission_lifecycle(instance):
    from apps.referrals.models import ReferralStatusChoices, SUBMITTED_OR_LATER_STATUSES

    status = instance.status
    submitted_at = instance.submitted_at is not None
    submitted_by = instance.submitted_by_id is not None
    if submitted_at != submitted_by:
        return "invalid"
    if status == ReferralStatusChoices.DRAFT:
        return "invalid" if submitted_at else "uninitialized"
    if status == ReferralStatusChoices.CANCELLED:
        return "initialized" if submitted_at else "uninitialized"
    if status in SUBMITTED_OR_LATER_STATUSES:
        return "initialized" if submitted_at else "invalid"
    return "invalid"


def _decision_lifecycle(instance):
    from apps.referrals.models import ReferralReassignmentStatusChoices

    actor = instance.decider_id is not None
    decided_at = instance.decided_at is not None
    code = instance.decision_code
    if instance.status == ReferralReassignmentStatusChoices.PENDING:
        return "uninitialized" if not actor and not decided_at and code == "" else "invalid"
    if instance.status in {
        ReferralReassignmentStatusChoices.APPROVED,
        ReferralReassignmentStatusChoices.DECLINED,
        ReferralReassignmentStatusChoices.CANCELLED,
    }:
        return "initialized" if actor and decided_at and bool(code) else "invalid"
    return "invalid"


def lifecycle_state(instance, group_id):
    group = _group(group_id, instance)
    if group.identifier == REFERRAL_SUBMISSION:
        return _submission_lifecycle(instance)
    if group.identifier == REASSIGNMENT_DECISION:
        return _decision_lifecycle(instance)
    return "initialized"


def _decrypt(group, raw):
    field = _model_for_group(group)._meta.get_field(group.destination_field)
    try:
        value = decrypt_field_value(
            raw,
            payload_type="text",
            context=field.encryption_context,
            max_plaintext_bytes=field.max_plaintext_bytes,
        )
    except (
        FieldEncryptionKeyUnavailable,
        FieldEncryptionKeyStateInvalid,
        FieldEncryptionKeySourceUnavailable,
    ):
        raise ReferralEncryptionError("referrals_confidential_payload_unavailable_key") from None
    except FieldEncryptionPayloadTooLarge:
        raise ReferralEncryptionError("referrals_confidential_payload_oversize") from None
    except FieldEncryptionError:
        raise ReferralEncryptionError("referrals_confidential_payload_malformed") from None
    return _validate_text(group, value)


def _combination_valid(group_id, lifecycle, storage):
    if lifecycle == "invalid" or storage in {
        "conflict", "malformed", "unavailable-key", "oversize", "partial"
    }:
        return False
    if group_id == REFERRAL_SUBMISSION:
        if lifecycle == "uninitialized":
            return storage in {"destination-null", "legacy-only", "migrated-empty", "migrated"}
        return storage in {"legacy-only", "migrated"}
    if group_id == REASSIGNMENT_DECISION:
        if lifecycle == "uninitialized":
            return storage in {"destination-null", "migrated-empty"}
        return storage in {"legacy-only", "migrated-empty", "migrated"}
    return lifecycle == "initialized" and storage in {
        "legacy-only", "migrated-empty", "migrated"
    }


def _inspect_group(instance, group_id):
    group = _group(group_id, instance)
    lifecycle = lifecycle_state(instance, group_id)
    try:
        source, raw_destination = _raw_group_values(instance, group)
        source = _validate_text(group, source)
        if raw_destination is None:
            storage = (
                "destination-null"
                if lifecycle == "uninitialized" and source == ""
                else "legacy-only"
            )
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
    except ReferralEncryptionError as exc:
        suffix = exc.code.rsplit("_", 1)[-1]
        storage = {
            "key": "unavailable-key",
            "oversize": "oversize",
            "malformed": "malformed",
        }.get(suffix, "malformed")
        value = None
    classification = GroupClassification(
        group_id,
        lifecycle,
        storage,
        _combination_valid(group_id, lifecycle, storage),
    )
    return classification, value


def classify_group(instance, group_id):
    """Classify lifecycle and storage independently with no content output."""
    return _inspect_group(instance, group_id)[0]


def _metadata_instance(instance, group):
    model = type(instance)
    queryset = defer_confidential_fields(model.objects.all())
    if group.model_name == "Referral":
        queryset = queryset.select_related(
            "student", "student__student_profile", "assigned_counselor"
        )
    elif group.model_name == "ReferralAction":
        queryset = queryset.select_related(
            "referral",
            "referral__student",
            "referral__student__student_profile",
            "referral__assigned_counselor",
        ).defer(*(f"referral__{name}" for name in REFERRAL_CONFIDENTIAL_FIELDS))
    return queryset.get(pk=instance.pk)


def read_group(user, instance, group_id):
    """Authorize on safe metadata before fetching or decrypting one group."""
    from apps.referrals.policies import (
        can_view_referral_action_narrative,
        can_view_referral_submission_narrative,
    )

    group = _group(group_id, instance)
    metadata = _metadata_instance(instance, group)
    if group_id == REFERRAL_SUBMISSION:
        allowed = can_view_referral_submission_narrative(user, metadata)
    elif group_id == REFERRAL_ACTION:
        allowed = can_view_referral_action_narrative(user, metadata)
    else:
        allowed = False
    if not allowed:
        raise ReferralEncryptionError("referrals_confidential_access_denied")
    classification, value = _inspect_group(metadata, group_id)
    if not classification.valid_combination:
        raise ReferralEncryptionError(classification.result_code)
    if classification.storage_state in {"destination-null", "legacy-only"}:
        configuration = validate_referral_compatibility_settings()
        if not configuration.permits_legacy_fallback:
            raise ReferralEncryptionError(configuration.result_code)
    return value


def prepare_group_write(instance, group_id, value):
    """Validate one authorized group and set exact source/destination twins."""
    group = _group(group_id, instance)
    value = _validate_text(group, value)
    if instance.pk:
        classification = classify_group(instance, group_id)
        if not classification.valid_combination:
            raise ReferralEncryptionError(classification.result_code)
    setattr(instance, group.source_field, value)
    setattr(instance, group.destination_field, value)
    return (group.source_field, group.destination_field)


def initialize_group(instance, group_id, value):
    if instance.pk:
        raise ReferralEncryptionError("referrals_confidential_already_persisted")
    return prepare_group_write(instance, group_id, value)


def compare_release1_twins(instance, group_id):
    classification = classify_group(instance, group_id)
    return classification.valid_combination and classification.storage_state in {
        "migrated-empty", "migrated"
    }
