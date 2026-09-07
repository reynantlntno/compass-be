"""Strictly read-only field-encryption deployment evidence."""

from django.core.management.base import BaseCommand, CommandError

from apps.security.readiness_services import collect_encryption_readiness
from apps.system.readiness_services import ReadinessCheck, build_report, render_report


class Command(BaseCommand):
    help = "Check encryption configuration and raw envelope status without mutation."

    def add_arguments(self, parser):
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
            checks = collect_encryption_readiness()
        except Exception:
            checks = [
                ReadinessCheck(
                    name="encryption_collection",
                    status="FAIL",
                    required=True,
                    reason_code="ENCRYPTION_COLLECTION_FAILED",
                    message="Encryption readiness checks failed safely before completion.",
                    evidence_type="read_only_query",
                )
            ]
        report = build_report(
            "check_encryption_status",
            checks,
            strict=strict,
            probe_external=False,
        )
        render_report(report, output_format=options["format"], stdout=self.stdout)
        if not report["passed"]:
            raise CommandError("encryption_readiness_failed")
