from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from apps.access_control.authority import resolve_capability
from apps.access_control.capabilities import Capability
from apps.reports.choices import ExportStatusChoices
from apps.reports.export_services import expire_due_report_exports
from apps.reports.models import ReportExportRequest


CONFIRMATION = "expire_report_exports"


class Command(BaseCommand):
    help = "Dry-run or execute expiry of due generated report exports."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true", help="Show due exports without changing them.")
        parser.add_argument("--execute", action="store_true", help="Expire due exports and revoke their files.")
        parser.add_argument("--actor-user-id", help="Active Head Guidance or IT Admin actor for execution.")
        parser.add_argument("--confirm", default="", help=f"Execution confirmation; must equal {CONFIRMATION!r}.")

    def handle(self, *args, **options):
        if options["dry_run"] and options["execute"]:
            raise CommandError("Cannot combine --dry-run and --execute.")

        due = ReportExportRequest.objects.filter(
            status__in=(ExportStatusChoices.GENERATED, ExportStatusChoices.DOWNLOADED),
            expires_at__isnull=False,
            expires_at__lte=timezone.now(),
        )
        count = due.count()
        if not options["execute"]:
            self.stdout.write(f"[DRY-RUN] due report exports={count}; no changes made")
            return

        actor_id = options.get("actor_user_id")
        if not actor_id:
            raise CommandError("--actor-user-id is required with --execute.")
        if options.get("confirm") != CONFIRMATION:
            raise CommandError(f"Execution requires --confirm {CONFIRMATION!r}.")

        User = get_user_model()
        try:
            actor = User.objects.get(pk=actor_id, is_active=True)
        except (User.DoesNotExist, ValueError):
            raise CommandError("--actor-user-id must identify an active authorized user.")
        if not (
            resolve_capability(actor, Capability.REPORTS_EXPORT_OPERATE)
            or resolve_capability(actor, Capability.REPORTS_EXPORT_MAINTAIN)
        ):
            raise CommandError("--actor-user-id must be Head Guidance or IT Admin.")

        expired = expire_due_report_exports(actor)
        self.stdout.write(self.style.SUCCESS(f"[LIVE] expired report exports={expired}"))
