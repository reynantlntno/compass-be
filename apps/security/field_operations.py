"""Approved-target-only backfill, rotation, checkpoint, and raw-proof primitives."""

from dataclasses import dataclass, field as dataclass_field
from datetime import datetime, timezone as datetime_timezone
import json
import os
from pathlib import Path
import re
import tempfile

from django.conf import settings
from django.core.exceptions import FieldDoesNotExist
from django.db import connection, models, transaction
from django.db.models.base import ModelBase

from apps.access_control.authority import has_fixed_capability
from apps.access_control.capabilities import Capability
from apps.accounts.models import User
from apps.audit.services import audit_log
from apps.security.exceptions import (
    FieldEncryptionCheckpointInvalid,
    FieldEncryptionConcurrentMutation,
    FieldEncryptionError,
    FieldEncryptionPayloadInvalid,
    FieldEncryptionUnknownTarget,
    FieldEncryptionUnsafeCommand,
)
from apps.security.constants import (
    FIELD_ENCRYPTION_BATCH_SIZE_MAX,
    FIELD_ENCRYPTION_CHECKPOINT_MAX_BYTES,
)
from apps.security.field_encryption import (
    KEY_ID_RE,
    decrypt_field_value,
    get_active_field_key,
    get_field_key_for_decryption,
    parse_outer_envelope,
)
from apps.security.key_sources import load_fernet_for_metadata
from apps.security.fields import (
    EncryptedJSONField,
    EncryptedTextField,
    _ENCRYPTED_JSON_NULL,
)

TARGET_ID_RE = re.compile(r"\A[a-z][a-z0-9_.-]{2,63}\Z")
IDENTITY_RE = re.compile(r"\A[^\s]{1,254}\Z")
CHECKPOINT_NAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]{2,63}\Z")
CHECKPOINT_PK_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
CHECKPOINT_VERSION = 1
MAX_COUNTER = 9_223_372_036_854_775_807
COUNTER_KEYS = {"processed", "changed", "skipped", "invalid", "conflicts"}
CHECKPOINT_KEYS = {
    "version",
    "operation",
    "target",
    "active_key_id",
    "last_committed_pk",
    "counters",
    "status",
    "updated_at",
}


@dataclass(frozen=True)
class FieldOperationTarget:
    identifier: str
    model: type[models.Model]
    source_field: str
    destination_field: str
    payload_type: str
    invalid_row_policy: str = "STOP"
    allowed_operations: frozenset = dataclass_field(
        default_factory=lambda: frozenset({"backfill", "rotation", "verify"})
    )

    def validate(self):
        if type(self.identifier) is not str or not TARGET_ID_RE.fullmatch(self.identifier):
            raise FieldEncryptionUnknownTarget()
        source = _registered_model_field(self.model, self.source_field)
        destination = _registered_model_field(self.model, self.destination_field)
        expected = EncryptedTextField if self.payload_type == "text" else EncryptedJSONField
        if self.payload_type not in {"text", "json"} or not isinstance(destination, expected):
            raise FieldEncryptionUnknownTarget()
        if isinstance(source, (EncryptedTextField, EncryptedJSONField)):
            raise FieldEncryptionUnknownTarget()
        if self.payload_type == "text" and not isinstance(source, (models.CharField, models.TextField)):
            raise FieldEncryptionUnknownTarget()
        if self.payload_type == "json" and not isinstance(source, models.JSONField):
            raise FieldEncryptionUnknownTarget()
        if self.payload_type == "json" and source.null:
            # A nullable JSONField cannot distinguish SQL NULL from JSON null at
            # the Python boundary. Require unambiguous JSON semantics.
            raise FieldEncryptionUnknownTarget()
        expected_context = f"{self.model._meta.app_label}.{self.model.__name__}.{self.destination_field}"
        try:
            context_matches = destination.encryption_context == expected_context
            operations_valid = self.allowed_operations <= {
                "backfill",
                "rotation",
                "verify",
            }
        except Exception:
            raise FieldEncryptionUnknownTarget() from None
        if not context_matches:
            raise FieldEncryptionUnknownTarget()
        if not operations_valid:
            raise FieldEncryptionUnknownTarget()
        if self.invalid_row_policy != "STOP":
            raise FieldEncryptionUnknownTarget()
        return self


@dataclass(frozen=True)
class EncryptedFieldRotationTarget:
    identifier: str
    model: type[models.Model]
    destination_field: str
    payload_type: str
    invalid_row_policy: str = dataclass_field(default="STOP", init=False)
    allowed_operations: frozenset = dataclass_field(
        default_factory=lambda: frozenset({"rotation", "verify"}), init=False
    )
    target_kind: str = dataclass_field(default="rotation_only", init=False)
    checkpoint_namespace: str = dataclass_field(init=False)

    def __post_init__(self):
        object.__setattr__(self, "checkpoint_namespace", self.identifier)

    def validate(self):
        if type(self.identifier) is not str or not TARGET_ID_RE.fullmatch(self.identifier):
            raise FieldEncryptionUnknownTarget()
        destination = _registered_model_field(self.model, self.destination_field)
        expected = {
            "text": EncryptedTextField,
            "json": EncryptedJSONField,
        }.get(self.payload_type)
        if expected is None or type(destination) is not expected:
            raise FieldEncryptionUnknownTarget()
        expected_context = (
            f"{self.model._meta.app_label}.{self.model.__name__}.{self.destination_field}"
        )
        try:
            context_matches = destination.encryption_context == expected_context
        except Exception:
            raise FieldEncryptionUnknownTarget() from None
        if not context_matches:
            raise FieldEncryptionUnknownTarget()
        if (
            self.invalid_row_policy != "STOP"
            or self.allowed_operations != frozenset({"rotation", "verify"})
            or type(self.allowed_operations) is not frozenset
            or self.target_kind != "rotation_only"
            or self.checkpoint_namespace != self.identifier
        ):
            raise FieldEncryptionUnknownTarget()
        return self


def _registered_model_field(model, field_name):
    if (
        not isinstance(model, ModelBase)
        or not issubclass(model, models.Model)
        or type(field_name) is not str
        or not field_name
    ):
        raise FieldEncryptionUnknownTarget()
    try:
        field = model._meta.get_field(field_name)
    except (AttributeError, FieldDoesNotExist, TypeError, ValueError):
        raise FieldEncryptionUnknownTarget() from None
    if field.name != field_name:
        raise FieldEncryptionUnknownTarget()
    return field


@dataclass
class OperationCheckpoint:
    target: str
    operation: str
    active_key_id: str | None = None
    last_committed_pk: int | str | None = None
    counters: dict = dataclass_field(
        default_factory=lambda: {
            "processed": 0,
            "changed": 0,
            "skipped": 0,
            "invalid": 0,
            "conflicts": 0,
        }
    )
    status: str = "in_progress"
    updated_at: str = ""
    version: int = CHECKPOINT_VERSION

    @property
    def last_pk(self):
        return self.last_committed_pk

    @last_pk.setter
    def last_pk(self, value):
        self.last_committed_pk = value

    @property
    def scanned(self):
        return self.counters["processed"]

    @property
    def written(self):
        return self.counters["changed"]

    @property
    def skipped(self):
        return self.counters["skipped"]

    @property
    def conflicts(self):
        return self.counters["conflicts"]

    @property
    def errors(self):
        return self.counters["invalid"]

    @property
    def state(self):
        return "complete" if self.status == "completed" else "ready"

    def touch(self):
        self.updated_at = datetime.now(datetime_timezone.utc).isoformat()

    def serialize(self):
        self.touch()
        raw = json.dumps(
            {
                "version": self.version,
                "operation": self.operation,
                "target": self.target,
                "active_key_id": self.active_key_id,
                "last_committed_pk": self.last_committed_pk,
                "counters": self.counters,
                "status": self.status,
                "updated_at": self.updated_at,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        if len(raw.encode("utf-8")) > _checkpoint_max_bytes():
            raise FieldEncryptionCheckpointInvalid()
        return raw

    @classmethod
    def parse(cls, raw, *, target, operation, active_key_id=None):
        if type(raw) is not str:
            raise FieldEncryptionCheckpointInvalid()
        encoded_size = 0
        invalid_encoding = False
        try:
            for offset in range(0, len(raw), 4096):
                encoded_size += len(raw[offset : offset + 4096].encode("utf-8"))
                if encoded_size > _checkpoint_max_bytes():
                    raise FieldEncryptionCheckpointInvalid()
        except UnicodeEncodeError:
            invalid_encoding = True
        if invalid_encoding:
            raise FieldEncryptionCheckpointInvalid()

        def pairs_hook(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise FieldEncryptionCheckpointInvalid()
                result[key] = value
            return result

        invalid_json = False
        try:
            data = json.loads(raw, object_pairs_hook=pairs_hook)
        except FieldEncryptionCheckpointInvalid:
            raise
        except Exception:
            invalid_json = True
        if invalid_json:
            raise FieldEncryptionCheckpointInvalid()
        if type(data) is not dict or set(data) != CHECKPOINT_KEYS:
            raise FieldEncryptionCheckpointInvalid()
        if type(data["version"]) is not int or data["version"] != CHECKPOINT_VERSION:
            raise FieldEncryptionCheckpointInvalid()
        if data["target"] != target or data["operation"] != operation:
            raise FieldEncryptionCheckpointInvalid()
        if operation not in {"backfill", "rotation"}:
            raise FieldEncryptionCheckpointInvalid()
        if operation == "rotation":
            if type(active_key_id) is not str or data["active_key_id"] != active_key_id:
                raise FieldEncryptionCheckpointInvalid()
        elif data["active_key_id"] is not None:
            raise FieldEncryptionCheckpointInvalid()
        counters = data["counters"]
        if type(counters) is not dict or set(counters) != COUNTER_KEYS:
            raise FieldEncryptionCheckpointInvalid()
        if any(type(value) is not int or not 0 <= value <= MAX_COUNTER for value in counters.values()):
            raise FieldEncryptionCheckpointInvalid()
        last_pk = data["last_committed_pk"]
        if last_pk is not None and not (
            (type(last_pk) is int and 0 <= last_pk <= MAX_COUNTER)
            or (type(last_pk) is str and CHECKPOINT_PK_RE.fullmatch(last_pk))
        ):
            raise FieldEncryptionCheckpointInvalid()
        if data["status"] not in {"in_progress", "completed", "failed"}:
            raise FieldEncryptionCheckpointInvalid()
        if type(data["updated_at"]) is not str or not 1 <= len(data["updated_at"]) <= 64:
            raise FieldEncryptionCheckpointInvalid()
        invalid_timestamp = False
        try:
            parsed_timestamp = datetime.fromisoformat(data["updated_at"])
        except ValueError:
            invalid_timestamp = True
        if invalid_timestamp:
            raise FieldEncryptionCheckpointInvalid()
        if parsed_timestamp.tzinfo is None:
            raise FieldEncryptionCheckpointInvalid()
        return cls(
            target=data["target"],
            operation=data["operation"],
            active_key_id=data["active_key_id"],
            last_committed_pk=last_pk,
            counters=dict(counters),
            status=data["status"],
            updated_at=data["updated_at"],
            version=data["version"],
        )


_TARGETS: dict[str, FieldOperationTarget | EncryptedFieldRotationTarget] = {}


def register_target(target):
    if type(target) not in {FieldOperationTarget, EncryptedFieldRotationTarget}:
        raise FieldEncryptionUnknownTarget()
    target.validate()
    if target.identifier in _TARGETS:
        raise FieldEncryptionUnknownTarget()
    _TARGETS[target.identifier] = target
    return target


def unregister_target(identifier):
    _TARGETS.pop(identifier, None)


def registered_targets():
    return tuple(_TARGETS[key] for key in sorted(_TARGETS))


def get_target(identifier, operation=None):
    missing = False
    try:
        target = _TARGETS[identifier]
    except KeyError:
        missing = True
    if missing:
        raise FieldEncryptionUnknownTarget()
    if operation and operation not in target.allowed_operations:
        raise FieldEncryptionUnsafeCommand()
    return target


def resolve_command_actor(identity):
    if type(identity) is not str or not IDENTITY_RE.fullmatch(identity):
        raise FieldEncryptionUnsafeCommand()
    missing = False
    try:
        if identity.isascii() and identity.isdecimal():
            actor = User.objects.get(pk=int(identity))
        else:
            actor = User.objects.get(email__iexact=identity)
    except (User.DoesNotExist, User.MultipleObjectsReturned, ValueError):
        missing = True
    if missing:
        raise FieldEncryptionUnsafeCommand()
    if not has_fixed_capability(actor, Capability.FIELD_ENCRYPTION_OPERATE):
        record_operation_audit(
            actor,
            "FIELD_ENCRYPTION_AUTHORIZATION_DENIED",
            "authorization",
            result_code="field_encryption_command_unauthorized",
            severity="WARNING",
        )
        raise FieldEncryptionUnsafeCommand()
    return actor


def validate_execution(execute, confirmation, target, identity):
    actor = resolve_command_actor(identity)
    if execute and confirmation != f"EXECUTE:{target}":
        record_operation_audit(
            actor,
            "FIELD_ENCRYPTION_AUTHORIZATION_DENIED",
            target,
            result_code="field_encryption_confirmation_invalid",
            severity="WARNING",
        )
        raise FieldEncryptionUnsafeCommand()
    return actor


def record_operation_audit(actor, action_type, target, *, operation=None, mode=None, result_code=None, counters=None, checkpoint_id=None, severity="INFO"):
    metadata = {}
    for key, value in {
        "operation": operation,
        "mode": mode,
        "result_code": result_code,
        "checkpoint_id": checkpoint_id,
    }.items():
        if value is not None:
            metadata[key] = value
    if counters is not None:
        metadata["counts"] = {key: int(counters[key]) for key in sorted(COUNTER_KEYS)}
    entry = audit_log(
        action_type=action_type,
        event_category="SECURITY",
        target_model="FieldEncryptionOperation",
        target_object_id=target,
        severity=severity,
        actor_user=actor,
        source_app="security",
        source_view="management_command",
        metadata=metadata,
    )
    if entry is None:
        raise FieldEncryptionUnsafeCommand()
    return entry


def _checkpoint_max_bytes():
    value = FIELD_ENCRYPTION_CHECKPOINT_MAX_BYTES
    if type(value) is not int or not 1024 <= value <= 1_048_576:
        raise FieldEncryptionCheckpointInvalid()
    return value


def resolve_checkpoint_path(name):
    if type(name) is not str or not CHECKPOINT_NAME_RE.fullmatch(name):
        raise FieldEncryptionCheckpointInvalid()
    configured = getattr(settings, "FIELD_ENCRYPTION_CHECKPOINT_DIR", None)
    if type(configured) is not str or not configured or not Path(configured).is_absolute():
        raise FieldEncryptionCheckpointInvalid()
    root_input = Path(configured)
    if ".." in root_input.parts or root_input.is_symlink():
        raise FieldEncryptionCheckpointInvalid()
    root = root_input.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = root / f"{name}.json"
    if path.is_symlink():
        raise FieldEncryptionCheckpointInvalid()
    escaped = False
    try:
        path.resolve().relative_to(root)
    except ValueError:
        escaped = True
    if escaped:
        raise FieldEncryptionCheckpointInvalid()
    return path


def read_checkpoint(path, *, target, operation, active_key_id=None):
    if path.is_symlink():
        raise FieldEncryptionCheckpointInvalid()
    invalid = False
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            raw = os.read(descriptor, _checkpoint_max_bytes() + 1)
        finally:
            os.close(descriptor)
        if len(raw) > _checkpoint_max_bytes():
            raise FieldEncryptionCheckpointInvalid()
        text = raw.decode("utf-8")
    except FieldEncryptionCheckpointInvalid:
        raise
    except (OSError, UnicodeError):
        invalid = True
    if invalid:
        raise FieldEncryptionCheckpointInvalid()
    return OperationCheckpoint.parse(
        text, target=target, operation=operation, active_key_id=active_key_id
    )


def write_checkpoint_atomic(path, checkpoint):
    raw = checkpoint.serialize().encode("utf-8")
    if path.is_symlink() or len(raw) > _checkpoint_max_bytes():
        raise FieldEncryptionCheckpointInvalid()
    descriptor = None
    temporary_name = None
    failed = False
    try:
        descriptor, temporary_name = tempfile.mkstemp(prefix=".field-checkpoint-", dir=path.parent)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
        temporary_name = None
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError:
        failed = True
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass
    if failed:
        raise FieldEncryptionCheckpointInvalid()


def _base_queryset(target, checkpoint):
    pk_name = target.model._meta.pk.name
    queryset = target.model._default_manager.order_by(pk_name)
    if checkpoint.last_committed_pk is not None:
        queryset = queryset.filter(**{f"{pk_name}__gt": checkpoint.last_committed_pk})
    return queryset


def _safe_checkpoint_pk(pk):
    if type(pk) is int and 0 <= pk <= MAX_COUNTER:
        return pk
    rendered = str(pk)
    if not CHECKPOINT_PK_RE.fullmatch(rendered):
        raise FieldEncryptionCheckpointInvalid()
    return rendered


def _new_checkpoint(target_id, operation, active_key_id=None):
    return OperationCheckpoint(target_id, operation, active_key_id=active_key_id)


def _apply_committed_batch(checkpoint, *, processed, changed, skipped, invalid, conflicts, last_pk, completed):
    increments = {
        "processed": processed,
        "changed": changed,
        "skipped": skipped,
        "invalid": invalid,
        "conflicts": conflicts,
    }
    for key, increment in increments.items():
        total = checkpoint.counters[key] + increment
        if total > MAX_COUNTER:
            raise FieldEncryptionCheckpointInvalid()
        checkpoint.counters[key] = total
    checkpoint.last_committed_pk = last_pk
    checkpoint.status = "completed" if completed else "in_progress"
    checkpoint.touch()
    return checkpoint


def _validate_batch_size(batch_size):
    maximum = FIELD_ENCRYPTION_BATCH_SIZE_MAX
    if type(batch_size) is not int or type(maximum) is not int or not 1 <= batch_size <= maximum <= 1000:
        raise FieldEncryptionUnsafeCommand()


def run_backfill(target_id, *, execute=False, batch_size=100, checkpoint=None):
    target = get_target(target_id, "backfill")
    if type(target) is not FieldOperationTarget:
        raise FieldEncryptionUnsafeCommand()
    _validate_batch_size(batch_size)
    checkpoint = checkpoint or _new_checkpoint(target_id, "backfill")
    if checkpoint.target != target_id or checkpoint.operation != "backfill" or checkpoint.active_key_id is not None:
        raise FieldEncryptionCheckpointInvalid()
    pk_name = target.model._meta.pk.name
    candidates = list(
        _base_queryset(target, checkpoint).values_list(pk_name, target.source_field)[:batch_size]
    )
    if not candidates:
        checkpoint.status = "completed"
        checkpoint.touch()
        return checkpoint
    if not execute:
        return _apply_committed_batch(
            checkpoint,
            processed=len(candidates),
            changed=0,
            skipped=len(candidates),
            invalid=0,
            conflicts=0,
            last_pk=_safe_checkpoint_pk(candidates[-1][0]),
            completed=len(candidates) < batch_size,
        )

    observed = {pk: source for pk, source in candidates}
    changed = skipped = 0
    with transaction.atomic():
        locked_rows = list(
            target.model._default_manager.select_for_update().filter(
                **{f"{pk_name}__in": list(observed)}
            ).order_by(pk_name)
        )
        if len(locked_rows) != len(candidates):
            raise FieldEncryptionConcurrentMutation(
                safe_metadata={"target": target_id, "reason_code": "row_set_changed"}
            )
        for locked in locked_rows:
            pk = getattr(locked, pk_name)
            current_source = getattr(locked, target.source_field)
            if current_source != observed[pk]:
                raise FieldEncryptionConcurrentMutation(
                    safe_metadata={"target": target_id, "object_id": str(pk)}
                )
            current_destination_raw = _raw_value(target, pk)
            source_is_absent = current_source is None and (
                target.payload_type != "json"
                or target.model._meta.get_field(target.source_field).null
            )
            if current_destination_raw is not None or source_is_absent:
                skipped += 1
            else:
                destination_value = (
                    _ENCRYPTED_JSON_NULL
                    if target.payload_type == "json" and current_source is None
                    else current_source
                )
                setattr(locked, target.destination_field, destination_value)
                # Model-level immutable-field policies must still permit this
                # explicitly authorized, audited field-operation write. The
                # marker is in-memory only and is removed before the row is
                # returned to ordinary application code.
                locked._allow_immutable_field_operation = True
                try:
                    locked.save(update_fields=[target.destination_field])
                finally:
                    del locked._allow_immutable_field_operation
                changed += 1
    return _apply_committed_batch(
        checkpoint,
        processed=len(candidates),
        changed=changed,
        skipped=skipped,
        invalid=0,
        conflicts=0,
        last_pk=_safe_checkpoint_pk(candidates[-1][0]),
        completed=len(candidates) < batch_size,
    )


def _raw_value(target, pk):
    table = connection.ops.quote_name(target.model._meta.db_table)
    column = connection.ops.quote_name(target.model._meta.get_field(target.destination_field).column)
    pk_field = target.model._meta.pk
    pk_column = connection.ops.quote_name(pk_field.column)
    prepared_pk = pk_field.get_db_prep_value(pk, connection, prepared=False)
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT {column} FROM {table} WHERE {pk_column} = %s", [prepared_pk])
        row = cursor.fetchone()
    return None if row is None else row[0]


def _authenticated_value(target, raw):
    destination = target.model._meta.get_field(target.destination_field)
    return decrypt_field_value(
        raw,
        payload_type=target.payload_type,
        context=destination.encryption_context,
        max_plaintext_bytes=destination.max_plaintext_bytes,
    )


def _rotation_value_and_action(target, raw, *, active_key_id, from_key_id):
    destination = target.model._meta.get_field(target.destination_field)
    if raw is None:
        if not destination.null:
            raise FieldEncryptionPayloadInvalid()
        return None, "skip"
    envelope = parse_outer_envelope(raw)
    value = _authenticated_value(target, raw)
    if envelope["key_id"] == active_key_id or (
        from_key_id is not None and envelope["key_id"] != from_key_id
    ):
        return value, "skip"
    return value, "change"


def run_rotation(target_id, *, execute=False, batch_size=100, checkpoint=None, from_key_id=None):
    target = get_target(target_id, "rotation")
    _validate_batch_size(batch_size)
    if from_key_id is not None and (
        type(from_key_id) is not str or not KEY_ID_RE.fullmatch(from_key_id)
    ):
        raise FieldEncryptionUnsafeCommand()
    active_key = get_active_field_key()
    checkpoint = checkpoint or _new_checkpoint(target_id, "rotation", active_key.key_version)
    if (
        checkpoint.target != target_id
        or checkpoint.operation != "rotation"
        or checkpoint.active_key_id != active_key.key_version
    ):
        raise FieldEncryptionCheckpointInvalid()
    pk_name = target.model._meta.pk.name
    pks = list(_base_queryset(target, checkpoint).values_list(pk_name, flat=True)[:batch_size])
    if not pks:
        checkpoint.status = "completed"
        checkpoint.touch()
        return checkpoint

    observed = {}
    for pk in pks:
        raw = _raw_value(target, pk)
        _rotation_value_and_action(
            target,
            raw,
            active_key_id=active_key.key_version,
            from_key_id=from_key_id,
        )
        observed[pk] = raw
    if not execute:
        return _apply_committed_batch(
            checkpoint,
            processed=len(pks),
            changed=0,
            skipped=len(pks),
            invalid=0,
            conflicts=0,
            last_pk=_safe_checkpoint_pk(pks[-1]),
            completed=len(pks) < batch_size,
        )

    changed = skipped = 0
    with transaction.atomic():
        locked_rows = list(
            target.model._default_manager.select_for_update().filter(
                **{f"{pk_name}__in": pks}
            ).order_by(pk_name).only(pk_name)
        )
        if len(locked_rows) != len(pks):
            raise FieldEncryptionConcurrentMutation(
                safe_metadata={"target": target_id, "reason_code": "row_set_changed"}
            )
        for locked in locked_rows:
            pk = getattr(locked, pk_name)
            raw = _raw_value(target, pk)
            if raw != observed[pk]:
                raise FieldEncryptionConcurrentMutation(
                    safe_metadata={"target": target_id, "object_id": str(pk)}
                )
            value, action = _rotation_value_and_action(
                target,
                raw,
                active_key_id=active_key.key_version,
                from_key_id=from_key_id,
            )
            if action == "skip":
                skipped += 1
                continue
            setattr(locked, target.destination_field, value)
            locked._allow_immutable_field_operation = True
            try:
                locked.save(update_fields=[target.destination_field])
            finally:
                del locked._allow_immutable_field_operation
            changed += 1
    return _apply_committed_batch(
        checkpoint,
        processed=len(pks),
        changed=changed,
        skipped=skipped,
        invalid=0,
        conflicts=0,
        last_pk=_safe_checkpoint_pk(pks[-1]),
        completed=len(pks) < batch_size,
    )


def verify_raw_envelope(target_id, pk):
    target = get_target(target_id, "verify")
    raw = _raw_value(target, pk)
    if raw is None:
        if not target.model._meta.get_field(target.destination_field).null:
            raise FieldEncryptionPayloadInvalid()
        return None
    return parse_outer_envelope(raw)


def inspect_required_historical_keys(target):
    """Validate every distinct routed key for a registered target safely."""
    table = connection.ops.quote_name(target.model._meta.db_table)
    destination = target.model._meta.get_field(target.destination_field)
    column = connection.ops.quote_name(destination.column)
    key_ids = set()
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT {column} FROM {table}")
        while True:
            rows = cursor.fetchmany(500)
            if not rows:
                break
            for (raw,) in rows:
                if raw is None:
                    if not destination.null:
                        raise FieldEncryptionPayloadInvalid()
                    continue
                key_ids.add(parse_outer_envelope(raw)["key_id"])
                if len(key_ids) > 128:
                    raise FieldEncryptionUnsafeCommand()
    for key_id in key_ids:
        load_fernet_for_metadata(get_field_key_for_decryption(key_id))
    return len(key_ids)
