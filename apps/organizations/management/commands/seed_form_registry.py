# Project: COMPASS
# File: apps/organizations/management/commands/seed_form_registry.py
# Module: organizations
# Purpose: Idempotent management command to seed the form family and revision registry.
# Domain boundary and service policy.
# Notes:
#   --dry-run must be supported and writes nothing.
#   Re-running must not mutate active/used revisions unsafely.
#   Unknown official codes remain unknown - no invention.

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from apps.organizations.models import (
    FormFamily,
    FormRevision,
    GovernanceStatusChoices,
)
from apps.system.operations import record_operational_command_run
from apps.system.readiness_services import is_deployment_environment


# Known form families and their initial revision metadata.
# Official codes/revisions that are unknown are left blank.
FORM_REGISTRY_SEED = [
    {
        "stable_key": "referral_slip",
        "display_name": "Referral Slip",
        "source_notes": "Source spec present; workflow implemented.",
        "revision": {
            "official_form_code": "CNSC-OP-GTA-01F9",
            "official_revision": "1",
            "internal_schema_version": "1",
            "display_title": "Referral Slip",
            "source_notes": "Implemented workflow. Source spec present.",
        },
    },
    {
        "stable_key": "call_slip",
        "display_name": "Interview Permit / Call Slip",
        "source_notes": "Source spec present; workflow implemented.",
        "revision": {
            "official_form_code": "CNSC-OP-GTA-01F8",
            "official_revision": "0",
            "internal_schema_version": "1",
            "display_title": "Interview Permit / Call Slip",
            "source_notes": "Implemented workflow. Source spec present.",
        },
    },
    {
        "stable_key": "routine_interview",
        "display_name": "Routine Interview Form",
        "source_notes": "Source spec present; metadata-only registry entry.",
        "revision": {
            "official_form_code": "CNSC-OP-GTA-01F11",
            "official_revision": "0",
            "internal_schema_version": "1.0.0",
            "display_title": "Routine Interview Form",
            "source_notes": "Governance-controlled draft; activate only after Head Guidance approval.",
        },
    },
    {
        "stable_key": "student_inventory",
        "display_name": "Individual Inventory",
        "source_notes": "Source spec present; inventory workflow implemented.",
        "revision": {
            "official_form_code": "CNSC-OP-GCO-01F5",
            "official_revision": "0",
            "internal_schema_version": "1",
            "display_title": "Individual Inventory",
            "source_notes": "Governance-controlled draft; activate only after Head Guidance approval.",
        },
    },
    {
        "stable_key": "students_profile",
        "display_name": "Students' Profile Report",
        "source_notes": (
            "COMPASS-native reusable Students' Profile report. The historical CCMS PDF is "
            "a structural reference only; CCMS is never the canonical report identity."
        ),
        "revision": {
            "official_form_code": "COMPASS-RPT-STUDENTS-PROFILE",
            "official_revision": "1.0",
            "internal_schema_version": "1",
            "display_title": "Students' Profile Report",
            "source_notes": (
                "COMPASS-native report control identifier, not a legacy GCO form code. "
                "Activate only after GCO approval and effective-date metadata are recorded."
            ),
        },
    },
    {
        "stable_key": "good_moral_student",
        "display_name": "Good Moral Character - Student",
        "source_notes": ".docx source present; code/revision per human instruction.",
        "revision": {
            "official_form_code": "CNSC-OP-GCO-01F4",
            "official_revision": "0",
            "internal_schema_version": "1",
            "display_title": "Good Moral Character - Student",
            "source_notes": "Future workflow. Metadata-only.",
        },
    },
    {
        "stable_key": "good_moral_graduate",
        "display_name": "Good Moral Character - Graduate",
        "source_notes": ".docx source present; code/revision per human instruction.",
        "revision": {
            "official_form_code": "CNSC-OP-GCO-01F6",
            "official_revision": "0",
            "internal_schema_version": "1",
            "display_title": "Good Moral Character - Graduate",
            "source_notes": "Future workflow. Metadata-only.",
        },
    },
    {
        "stable_key": "customer_feedback_csm",
        "display_name": "Customer Feedback / Client Satisfaction Measurement",
        "source_notes": "Source spec present; future workflow only.",
        "revision": {
            "official_form_code": "CNSC-OP-GTA-01F14",
            "official_revision": "0",
            "internal_schema_version": "1",
            "display_title": "Customer Feedback / Client Satisfaction Measurement",
            "source_notes": "Future workflow. Metadata-only.",
        },
    },
    {
        "stable_key": "exit_interview",
        "display_name": "Exit Interview",
        "source_notes": "Source spec present. Implemented in apps.exit_interviews.",
        "revision": {
            "official_form_code": "CNSC-OP-GTA-01F12",
            "official_revision": "0",
            "internal_schema_version": "1",
            "display_title": "Exit Interview",
            "source_notes": "Governance-controlled draft; activate only after Head Guidance approval.",
        },
    },
    {
        "stable_key": "graduate_tracer_survey",
        "display_name": "Graduate Tracer Survey",
        "source_notes": "Source spec present. Implemented in apps.graduate_tracer.",
        "revision": {
            "official_form_code": "CNSC-OP-GTA-01F10",
            "official_revision": "0",
            "internal_schema_version": "1",
            "display_title": "Graduate Tracer Survey",
            "source_notes": "Governance-controlled draft; activate only after Head Guidance approval.",
        },
    },
]


class Command(BaseCommand):
    help = "Seed the form family and revision registry idempotently."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            default=False,
            help="Preview what would be created or skipped without writing.",
        )
        parser.add_argument("--reason-code", default="FORM_REGISTRY_RECONCILIATION")
        parser.add_argument("--configuration-identifier", default="forms.catalog")
        parser.add_argument("--acknowledge-environment", action="store_true")

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        if is_deployment_environment() and not dry_run and not options.get("acknowledge_environment"):
            raise CommandError("Writes in staging or production require --acknowledge-environment.")
        created_families = 0
        skipped_families = 0
        created_revisions = 0
        skipped_revisions = 0
        refused_revisions = 0

        for entry in FORM_REGISTRY_SEED:
            stable_key = entry["stable_key"]
            existing_family = FormFamily.objects.filter(stable_key=stable_key).first()

            if existing_family:
                skipped_families += 1
                self.stdout.write(f"  [SKIP] Family '{stable_key}' already exists (pk={existing_family.pk}).")
                family = existing_family
            else:
                if dry_run:
                    self.stdout.write(f"  [DRY-RUN] Would create family '{stable_key}'.")
                    created_families += 1
                    continue  # Skip revision creation in dry-run for new families
                else:
                    family = FormFamily.objects.create(
                        stable_key=stable_key,
                        display_name=entry["display_name"],
                        source_notes=entry.get("source_notes", ""),
                        status=GovernanceStatusChoices.DRAFT,
                    )
                    created_families += 1
                    self.stdout.write(self.style.SUCCESS(
                        f"  [CREATED] Family '{stable_key}' (pk={family.pk})."
                    ))

            # Handle revision
            rev_data = entry.get("revision")
            if not rev_data:
                continue

            existing_revision = FormRevision.objects.filter(
                form_family=family,
                official_form_code=rev_data.get("official_form_code", ""),
                official_revision=rev_data.get("official_revision", ""),
                internal_schema_version=rev_data.get("internal_schema_version", "1"),
            ).first()

            if existing_revision:
                if existing_revision.is_used or existing_revision.status in (
                    GovernanceStatusChoices.ACTIVE,
                    GovernanceStatusChoices.RETIRED,
                    GovernanceStatusChoices.ARCHIVED,
                ):
                    refused_revisions += 1
                    self.stdout.write(self.style.WARNING(
                        f"  [REFUSED] Revision for '{stable_key}' is "
                        f"{existing_revision.status}/used - not mutated."
                    ))
                else:
                    skipped_revisions += 1
                    self.stdout.write(
                        f"  [SKIP] Draft revision for '{stable_key}' already exists "
                        f"(pk={existing_revision.pk})."
                    )
            else:
                if dry_run:
                    self.stdout.write(
                        f"  [DRY-RUN] Would create revision for '{stable_key}'."
                    )
                    created_revisions += 1
                else:
                    FormRevision.objects.create(
                        form_family=family,
                        official_form_code=rev_data.get("official_form_code", ""),
                        official_revision=rev_data.get("official_revision", ""),
                        internal_schema_version=rev_data.get("internal_schema_version", "1"),
                        internal_template_version=rev_data.get("internal_template_version", ""),
                        display_title=rev_data.get("display_title", ""),
                        source_notes=rev_data.get("source_notes", ""),
                        status=GovernanceStatusChoices.DRAFT,
                    )
                    created_revisions += 1
                    self.stdout.write(self.style.SUCCESS(
                        f"  [CREATED] Revision for '{stable_key}'."
                    ))

        mode = "DRY-RUN" if dry_run else "LIVE"
        self.stdout.write(self.style.SUCCESS(
            f"\n[{mode}] Summary: "
            f"families created={created_families} skipped={skipped_families} | "
            f"revisions created={created_revisions} skipped={skipped_revisions} "
            f"refused={refused_revisions}"
        ))
        record_operational_command_run(
            command_key="seed_form_registry", mode="dry-run" if dry_run else "execute",
            reason_code=options["reason_code"], configuration_identifier=options["configuration_identifier"],
            outcome="DRY_RUN" if dry_run else "COMPLETED",
            outcome_reason_code="NO_BUSINESS_WRITE" if dry_run else "CATALOG_RECONCILED",
            summary={"families_created": created_families, "revisions_created": created_revisions,
                     "refused_revisions": refused_revisions},
        )
