from django.core.management.base import BaseCommand, CommandError

from apps.security.exceptions import SecurityError
from apps.security.field_operations import (
    OperationCheckpoint,
    read_checkpoint,
    record_operation_audit,
    resolve_checkpoint_path,
    run_backfill,
    validate_execution,
    write_checkpoint_atomic,
)


class Command(BaseCommand):
    help = "Backfill one explicitly registered encrypted-field target."

    def add_arguments(self, parser):
        parser.add_argument("--target", required=True)
        parser.add_argument("--batch-size", type=int, default=100)
        parser.add_argument("--system-identity", required=True)
        parser.add_argument("--checkpoint")
        parser.add_argument("--execute", action="store_true")
        parser.add_argument("--confirm", default="")

    def handle(self, *args, **options):
        target_id = options["target"]
        actor = None
        mode = "execute" if options["execute"] else "dry_run"
        try:
            actor = validate_execution(
                options["execute"], options["confirm"], target_id, options["system_identity"]
            )
            checkpoint_path = (
                resolve_checkpoint_path(options["checkpoint"])
                if options["checkpoint"]
                else None
            )
            checkpoint = None
            if checkpoint_path and checkpoint_path.exists():
                checkpoint = read_checkpoint(
                    checkpoint_path,
                    target=target_id,
                    operation="backfill",
                )
                record_operation_audit(
                    actor,
                    "FIELD_ENCRYPTION_OPERATION_RESUMED",
                    target_id,
                    operation="backfill",
                    mode=mode,
                    result_code="checkpoint_loaded",
                    checkpoint_id=options["checkpoint"],
                )
            record_operation_audit(
                actor,
                "FIELD_ENCRYPTION_EXECUTION_STARTED" if options["execute"] else "FIELD_ENCRYPTION_DRY_RUN_REQUESTED",
                target_id,
                operation="backfill",
                mode=mode,
                result_code="started",
                checkpoint_id=options["checkpoint"],
            )
            while True:
                result = run_backfill(
                    target_id,
                    execute=options["execute"],
                    batch_size=options["batch_size"],
                    checkpoint=checkpoint,
                )
                if checkpoint_path and options["execute"]:
                    write_checkpoint_atomic(checkpoint_path, result)
                if result.state == "complete":
                    break
                checkpoint = result
            record_operation_audit(
                actor,
                "FIELD_ENCRYPTION_OPERATION_COMPLETED",
                target_id,
                operation="backfill",
                mode=mode,
                result_code="completed",
                counters=result.counters,
                checkpoint_id=options["checkpoint"],
            )
        except (SecurityError, OSError) as exc:
            code = (
                str(exc)
                if isinstance(exc, SecurityError)
                else "field_encryption_checkpoint_invalid"
            )
            if actor is not None:
                record_operation_audit(
                    actor,
                    "FIELD_ENCRYPTION_OPERATION_FAILED",
                    target_id,
                    operation="backfill",
                    mode=mode,
                    result_code=code,
                    checkpoint_id=options.get("checkpoint"),
                    severity="WARNING",
                )
            raise CommandError(code) from None
        self.stdout.write(
            f"backfill_status=ok mode={mode} scanned={result.scanned} written={result.written} "
            f"skipped={result.skipped} conflicts={result.conflicts} errors={result.errors}"
        )
