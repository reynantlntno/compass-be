"""Build the non-identifying profiling projection for existing Inventory rows."""

from django.core.management.base import BaseCommand, CommandError

from apps.inventory.models import InventoryStatusChoices, StudentInventorySnapshot
from apps.profiles.models import StudentAcademicCohort
from apps.reports.profiling import materialize_profiling_fact


class Command(BaseCommand):
    help = "Materialize privacy-safe Students' Profile facts from submitted Inventory snapshots."

    def add_arguments(self, parser):
        parser.add_argument("--academic-year", required=True)
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, *args, **options):
        academic_year = options["academic_year"].strip()
        if not academic_year:
            raise CommandError("Academic year is required.")
        snapshots = StudentInventorySnapshot.objects.filter(
            academic_year=academic_year,
            status__in=(InventoryStatusChoices.SUBMITTED, InventoryStatusChoices.REOPENED_FOR_CORRECTION),
        ).only(
            "id", "student_profile_id", "academic_year", "status", "schema_key", "schema_version"
        ).order_by("id")
        summary = {"ready": 0, "unreadable": 0, "invalid": 0, "reopened": 0, "missing_cohort": 0}
        for snapshot in snapshots.iterator(chunk_size=200):
            if not StudentAcademicCohort.objects.filter(
                student_profile_id=snapshot.student_profile_id,
                academic_year=academic_year,
            ).exists():
                summary["missing_cohort"] += 1
                continue
            if options["dry_run"]:
                summary["ready"] += 1
                continue
            fact = materialize_profiling_fact(snapshot)
            summary[fact.status.lower()] += 1
        self.stdout.write(
            self.style.SUCCESS(
                "Profiling materialization complete: " + ", ".join(f"{key}={value}" for key, value in summary.items())
            )
        )
