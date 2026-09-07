from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from apps.reports.models import ReportDefinition
from apps.reports.seed_data import REPORT_DEFINITIONS
from apps.common.policy import PolicyChangeRequest
from apps.governance.policy_lifecycle import ensure_active_policy_for_target
from apps.system.operations import record_operational_command_run
from apps.system.readiness_services import is_deployment_environment


class Command(BaseCommand):
    help = "Create or synchronize the approved aggregate report-definition catalog."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show the catalog changes without writing report definitions.",
        )
        parser.add_argument("--reason-code", default="REPORT_DEFINITION_RECONCILIATION")
        parser.add_argument("--configuration-identifier", default="reports.catalog")
        parser.add_argument("--acknowledge-environment", action="store_true")

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        if is_deployment_environment() and not dry_run and not options.get("acknowledge_environment"):
            raise CommandError("Writes in staging or production require --acknowledge-environment.")
        mode = "DRY-RUN" if dry_run else "LIVE"
        changed = 0
        policy_fields = {
            "requires_suppression",
            "default_suppression_threshold",
            "suppression_mode",
        }

        for definition in REPORT_DEFINITIONS:
            key = definition["key"]
            existing = ReportDefinition.objects.filter(key=key).first()
            catalog_values = {
                field: value
                for field, value in definition.items()
                if field not in policy_fields
            }
            if existing is None:
                action = "create"
                changed += 1
            else:
                action = "update"
                values_changed = any(
                    getattr(existing, field) != value
                    for field, value in catalog_values.items()
                )
                changed += int(values_changed)

            self.stdout.write(f"[{mode}] {action} {key}")
            if dry_run:
                continue

            if existing is None:
                existing = ReportDefinition.objects.create(
                    **catalog_values,
                    is_active=True,
                )
            else:
                for field, value in catalog_values.items():
                    setattr(existing, field, value)
                existing.is_active = True
                existing.save()

            ensure_active_policy_for_target(
                None,
                PolicyChangeRequest(
                    key="reports.suppression",
                    configuration={
                        "report_key": existing.key,
                        "mode": str(definition["suppression_mode"]),
                        "requires_suppression": bool(definition["requires_suppression"]),
                        "default_threshold": int(definition["default_suppression_threshold"]),
                        "threshold": int(definition["default_suppression_threshold"]),
                        "sensitive_categories": [],
                    },
                    target_type="reports.ReportDefinition",
                    target_reference=str(existing.pk),
                    source_reference=f"REPORT_DEFINITION:{existing.key}:CATALOG",
                    effective_from=timezone.now(),
                ),
                system_context=True,
            )

        self.stdout.write(
            self.style.SUCCESS(
                f"[{mode}] report definition catalog complete; changed={changed}, total={len(REPORT_DEFINITIONS)}"
            )
        )
        record_operational_command_run(
            command_key="seed_report_definitions", mode="dry-run" if dry_run else "execute",
            reason_code=options["reason_code"], configuration_identifier=options["configuration_identifier"],
            outcome="DRY_RUN" if dry_run else "COMPLETED",
            outcome_reason_code="NO_BUSINESS_WRITE" if dry_run else "CATALOG_RECONCILED",
            summary={"changed": changed, "total": len(REPORT_DEFINITIONS)},
        )
