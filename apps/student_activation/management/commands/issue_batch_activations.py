"""Operational adapter for post-execution student invitation delivery."""

from django.core.management.base import BaseCommand, CommandError

from apps.accounts.models import User
from apps.imports.models import StudentImportBatch
from apps.imports.commands import ActivationInvitationIssueCommand
from apps.imports.onboarding import issue_onboarding_invitations_by_batch_id
from apps.student_activation.policies import can_manage_activation_invitations


class Command(BaseCommand):
    help = "Issue safe student activation deliveries for an executed student onboarding batch."

    def add_arguments(self, parser):
        parser.add_argument("--batch-id", type=int, required=True)
        parser.add_argument("--actor-email", type=str)
        parser.add_argument("--actor-id", type=int)
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--execute", action="store_true")
        parser.add_argument("--no-input", action="store_true")

    def handle(self, *args, **options):
        if not options.get("actor_email") and not options.get("actor_id"):
            raise CommandError("Either --actor-email or --actor-id must be provided.")
        if not options.get("dry_run") and not options.get("execute"):
            raise CommandError("Either --dry-run or --execute must be specified.")
        if options.get("dry_run") and options.get("execute"):
            raise CommandError("Cannot specify both --dry-run and --execute.")

        try:
            actor = (
                User.objects.get(pk=options["actor_id"])
                if options.get("actor_id")
                else User.objects.get(email__iexact=options["actor_email"].strip())
            )
            batch = StudentImportBatch.objects.get(pk=options["batch_id"])
        except (User.DoesNotExist, StudentImportBatch.DoesNotExist) as exc:
            raise CommandError("The actor or import batch was not found.") from exc
        if not actor.is_active or not can_manage_activation_invitations(actor):
            raise CommandError("Actor is not authorized to issue activation invitations.")
        if batch.template_version != "student_onboarding-v1":
            raise CommandError("Only the governed student onboarding flow can issue student invitations.")

        if options.get("dry_run"):
            eligible = batch.rows.filter(validation_status="PROVISIONED", provisioned_user__is_active=False).count()
            self.stdout.write(self.style.NOTICE(f"Eligible inactive student accounts: {eligible}"))
            return
        if not options.get("no_input"):
            answer = input("Issue eligible student activation deliveries? (y/N): ")
            if answer.strip().lower() not in {"y", "yes"}:
                self.stdout.write(self.style.WARNING("Execution cancelled."))
                return
        try:
            result = issue_onboarding_invitations_by_batch_id(
                actor_user=actor,
                batch_id=str(batch.pk),
                command=ActivationInvitationIssueCommand(),
            )
        except Exception as exc:
            raise CommandError("Activation invitation issuance was blocked safely.") from exc
        self.stdout.write(self.style.SUCCESS(
            f"Activation delivery complete. Issued: {result.get('issued', 0)}; skipped: {result.get('skipped', 0)}."
        ))
