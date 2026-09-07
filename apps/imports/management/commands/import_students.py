"""Operational adapter for the canonical student onboarding flow."""

from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from apps.accounts.models import User
from apps.common.request_dedup import hash_request_key
from apps.imports.commands import (
    ImportBatchCreateCommand,
    ImportBatchExecuteCommand,
    ImportBatchLifecycleCommand,
)
from apps.imports.models import RowValidationStatus, StudentImportBatchStatus
from apps.imports.onboarding import (
    execute_onboarding_batch_by_id,
    stage_onboarding_batch,
    validate_onboarding_batch_by_id,
)
from apps.imports.policies import can_manage_student_imports


class Command(BaseCommand):
    help = "Validates or executes a governed student onboarding CSV."

    def add_arguments(self, parser):
        parser.add_argument("--file", type=str, required=True)
        parser.add_argument("--actor-email", type=str)
        parser.add_argument("--actor-id", type=int)
        parser.add_argument("--source", type=str, default="CLI Import")
        parser.add_argument("--academic-year", type=str, default="2026-2027")
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--execute", action="store_true")
        parser.add_argument("--no-input", action="store_true")

    def handle(self, *args, **options):
        if not options.get("actor_email") and not options.get("actor_id"):
            raise CommandError("Either --actor-email or --actor-id must be provided.")
        if not options.get("dry_run") and not options.get("execute"):
            raise CommandError("Either --dry-run or --execute must be specified.")

        try:
            actor = (
                User.objects.get(pk=options["actor_id"])
                if options.get("actor_id")
                else User.objects.get(email__iexact=options["actor_email"].strip())
            )
        except User.DoesNotExist as exc:
            raise CommandError("Actor user does not exist.") from exc
        if not actor.is_active or not can_manage_student_imports(actor):
            raise CommandError("Actor is not authorized to manage student imports.")

        path = Path(options["file"])
        if not path.is_file():
            raise CommandError("The CSV file could not be found.")
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise CommandError("The CSV file could not be read safely.") from exc

        try:
            batch = stage_onboarding_batch(
                actor_user=actor,
                command=ImportBatchCreateCommand(
                    source_name=options["source"],
                    academic_year=options["academic_year"],
                    filename=path.name,
                    content_type="text/csv",
                ),
                upload=raw,
            )
            batch = validate_onboarding_batch_by_id(
                actor_user=actor,
                batch_id=str(batch.pk),
                command=ImportBatchLifecycleCommand(),
            )
        except Exception as exc:
            raise CommandError("student_onboarding validation failed safely.") from exc

        valid = batch.rows.filter(validation_status=RowValidationStatus.VALID).count()
        review = batch.rows.exclude(validation_status=RowValidationStatus.VALID).count()
        self.stdout.write(self.style.NOTICE(f"student_onboarding validation complete: {valid} valid rows, {review} rows requiring review."))
        if options.get("dry_run"):
            self.stdout.write(self.style.SUCCESS("student_onboarding dry-run complete. No accounts or invitations were created."))
            return
        if batch.status != StudentImportBatchStatus.APPROVED:
            raise CommandError("Execution requires an unchanged Head-approved batch.")
        if not options.get("no_input"):
            answer = input("Execute this Head-approved onboarding batch? (y/N): ")
            if answer.strip().lower() not in {"y", "yes"}:
                self.stdout.write(self.style.WARNING("Execution cancelled."))
                return
        digest = hash_request_key(
            f"cli:student_onboarding:{batch.pk}",
            purpose="imports.batch.execute",
        )
        try:
            result = execute_onboarding_batch_by_id(
                actor_user=actor,
                batch_id=str(batch.pk),
                command=ImportBatchExecuteCommand(request_key_digest=digest),
            )
        except Exception as exc:
            raise CommandError("student_onboarding execution was blocked safely; no partial provisioning was retained.") from exc
        self.stdout.write(self.style.SUCCESS(
            f"student_onboarding execution complete. Provisioned: {result.get('success', 0)}; "
            f"reconciled: {result.get('reconciled', 0)}; excluded: {result.get('excluded', 0)}."
        ))
