"""Read-only backup destination readiness; never executes a backup."""

from django.core.management.base import BaseCommand, CommandError

from apps.backups.readiness_services import collect_backup_readiness
from apps.system.readiness_services import ReadinessCheck, build_report, render_report


class Command(BaseCommand):
    help = "Check backup authorization and destination readiness without creating a backup."

    def add_arguments(self, parser):
        parser.add_argument(
            "--system-identity",
            required=True,
            help="Existing operator email or numeric user ID; lookup is read-only.",
        )
        parser.add_argument(
            "--probe-external",
            action="store_true",
            help="Opt in to a read-only S3 head_bucket probe.",
        )
        parser.add_argument(
            "--strict",
            action="store_true",
            help="Treat required warnings and pending evidence as failures.",
        )
        parser.add_argument(
            "--format",
            choices=("text", "json"),
            default="text",
            help="Output format; JSON contains only safe readiness metadata.",
        )

    def handle(self, *args, **options):
        strict = bool(options["strict"])
        try:
            checks = collect_backup_readiness(
                system_identity=options["system_identity"],
                probe_external=bool(options["probe_external"]),
            )
        except Exception:
            checks = [
                ReadinessCheck(
                    name="backup_collection",
                    status="FAIL",
                    required=True,
                    reason_code="BACKUP_COLLECTION_FAILED",
                    message="Backup readiness checks failed safely before completion.",
                    evidence_type="read_only_query",
                )
            ]
        report = build_report(
            "backup_dry_run",
            checks,
            strict=strict,
            probe_external=bool(options["probe_external"]),
        )
        render_report(report, output_format=options["format"], stdout=self.stdout)
        if not report["passed"]:
            raise CommandError("backup_readiness_failed")
