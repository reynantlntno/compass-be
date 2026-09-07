from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from apps.organizations.governance_services import seed_activation_register
from apps.common.policy import PolicyChangeRequest
from apps.governance.models import PolicyRecord
from apps.governance.policy_lifecycle import create_policy_draft
from apps.system.operations import record_operational_command_run
from apps.system.readiness_services import is_deployment_environment


class Command(BaseCommand):
    help = "Seed governance.catalog draft policy metadata and activation-register catalog without activation."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--reason-code", default="governance.catalog")
        parser.add_argument("--configuration-identifier", default="governance.catalog")
        parser.add_argument("--acknowledge-environment", action="store_true")

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        if is_deployment_environment() and not dry_run and not options.get("acknowledge_environment"):
            raise CommandError("Writes in staging or production require --acknowledge-environment.")
        policy_exists = PolicyRecord.objects.filter(
            key="good_moral.exit_prerequisite",
            status__in=("DRAFT", "ACTIVE"),
        ).filter(configuration_json__effective_academic_year="2026-2027").exists()
        register_count = 0
        if not dry_run:
            with transaction.atomic():
                if not policy_exists:
                    create_policy_draft(
                        None,
                        PolicyChangeRequest(
                            key="good_moral.exit_prerequisite",
                            configuration={
                                "enforcement_enabled": False,
                                "effective_graduation_year": 2026,
                                "effective_academic_year": "2026-2027",
                                "qualifying_exit_statuses": ["SUBMITTED", "ARCHIVED"],
                                "counselor_acknowledgment_required": False,
                                "enforce_on_submission": False,
                                "enforce_on_approval": True,
                                "enforce_on_generation": True,
                                "enforce_on_release": True,
                                "grandfather_existing_requests": True,
                                "reopen_void_behavior": "BLOCK_FINAL_BOUNDARY",
                                "decision_record_reference": "good_moral.exit_prerequisite.decision",
                            },
                            source_reference="governance.seed",
                        ),
                        system_context=True,
                    )
                register_count = seed_activation_register()
        self.stdout.write(self.style.SUCCESS(
            f"[{'DRY-RUN' if dry_run else 'LIVE'}] Governance catalog: "
            f"policy={'exists' if policy_exists else 'would create'}; register entries={register_count if not dry_run else 'would reconcile'}"
        ))
        record_operational_command_run(
            command_key="seed_governance_catalog", mode="dry-run" if dry_run else "execute",
            reason_code=options["reason_code"], configuration_identifier=options["configuration_identifier"],
            outcome="DRY_RUN" if dry_run else "COMPLETED",
            outcome_reason_code="NO_ACTIVATION" if dry_run else "DRAFT_CATALOG_CREATED",
            summary={"policy_exists": policy_exists, "register_entries": register_count},
        )
