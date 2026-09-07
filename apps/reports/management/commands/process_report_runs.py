"""Process bounded asynchronous aggregate report runs."""

from django.core.management.base import BaseCommand, CommandError

from apps.common.exceptions import CompassError
from apps.reports.choices import ReportRunStatus
from apps.reports.models import ReportRun
from apps.reports.services import execute_pending_report_run


class Command(BaseCommand):
    help = "Process pending governed report runs using each run's original requester authority."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=10)

    def handle(self, *args, **options):
        limit = options["limit"]
        if isinstance(limit, bool) or limit < 1 or limit > 100:
            raise CommandError("--limit must be between 1 and 100.")

        run_ids = list(
            ReportRun.objects.filter(
                status=ReportRunStatus.PENDING,
                requested_by__isnull=False,
            )
            .order_by("created_at")
            .values_list("id", flat=True)[:limit]
        )
        completed = 0
        failed = 0
        for run_id in run_ids:
            run = ReportRun.objects.select_related("requested_by").filter(id=run_id).first()
            if run is None or run.requested_by is None:
                continue
            try:
                execute_pending_report_run(run.requested_by, str(run_id))
                completed += 1
            except CompassError:
                failed += 1

        self.stdout.write(
            self.style.SUCCESS(
                f"Processed pending report runs: completed={completed}, failed={failed}, selected={len(run_ids)}"
            )
        )
