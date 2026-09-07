from django.core.management.base import BaseCommand, CommandError

from apps.security.checks import validate_field_encryption_settings
from apps.security.exceptions import FieldEncryptionUnknownTarget, SecurityError
from apps.security.field_encryption import get_active_field_key
from apps.security.field_operations import (
    EncryptedFieldRotationTarget,
    FieldOperationTarget,
    inspect_required_historical_keys,
    record_operation_audit,
    registered_targets,
    resolve_command_actor,
)
from apps.security.key_sources import load_fernet_for_metadata


class Command(BaseCommand):
    help = "Validate encrypted-field deployment readiness without exposing secrets."

    def add_arguments(self, parser):
        parser.add_argument("--system-identity", required=True)

    def handle(self, *args, **options):
        actor = None
        try:
            setting_errors = validate_field_encryption_settings()
            if setting_errors:
                raise CommandError(setting_errors[0][0])
            actor = resolve_command_actor(options["system_identity"])
            record_operation_audit(
                actor,
                "FIELD_ENCRYPTION_READINESS_REQUESTED",
                "readiness",
                operation="readiness",
                mode="check",
                result_code="requested",
            )
            key = get_active_field_key()
            load_fernet_for_metadata(key)
            targets = registered_targets()
            historical_key_count = 0
            source_backed_target_count = 0
            rotation_only_target_count = 0
            for target in targets:
                if type(target) is FieldOperationTarget:
                    source_backed_target_count += 1
                elif type(target) is EncryptedFieldRotationTarget:
                    rotation_only_target_count += 1
                else:
                    raise FieldEncryptionUnknownTarget()
                target.validate()
                historical_key_count += inspect_required_historical_keys(target)
            record_operation_audit(
                actor,
                "FIELD_ENCRYPTION_READINESS_COMPLETED",
                "readiness",
                operation="readiness",
                mode="check",
                result_code="ready",
                counters={
                    "processed": len(targets),
                    "changed": 0,
                    "skipped": 0,
                    "invalid": 0,
                    "conflicts": 0,
                },
            )
        except SecurityError as exc:
            if actor is not None:
                record_operation_audit(
                    actor,
                    "FIELD_ENCRYPTION_READINESS_FAILED",
                    "readiness",
                    operation="readiness",
                    mode="check",
                    result_code=str(exc),
                    severity="WARNING",
                )
            raise CommandError(str(exc)) from None
        self.stdout.write(
            f"field_encryption_readiness=ready active_key_count=1 target_count={len(targets)} "
            f"source_backed_target_count={source_backed_target_count} "
            f"rotation_only_target_count={rotation_only_target_count} "
            f"historical_key_count={historical_key_count}"
        )
