# Project: COMPASS
# File: apps/documents/management/commands/seed_document_templates.py
# Module: apps.documents
# Purpose: Idempotent seed command for document template metadata
# Domain boundary and service policy.
# Notes:
#   Creates metadata-only DRAFT DocumentTemplate and DocumentTemplateVersion records.
#   Does NOT:
#   - Activate template versions automatically
#   - Create GeneratedDocument rows
#   - Render files
#   - Store files
#   - Require Playwright/Chromium
#   - Require MinIO/S3/protected storage
#   - Invent missing official codes/revisions
#   - Mutate active/used template versions

from copy import deepcopy

from django.core.management.base import BaseCommand, CommandError

from apps.documents.models import (
    DocumentKindChoices,
    DocumentTemplate,
    DocumentTemplateVersion,
    OutputFormatChoices,
    RendererBackendChoices,
    RetentionClassificationChoices,
    TemplateStatusChoices,
)
from apps.organizations.models import FormFamily, FormRevision
from apps.documents.shells import DocumentShellKey, TEMPLATE_SHELL_KEYS
from apps.system.operations import record_operational_command_run
from apps.system.readiness_services import is_deployment_environment


GOVERNED_FORM_SEEDS = {
    "good_moral_student": {
        "family_key": "good_moral_student",
        "official_form_code": "CNSC-OP-GCO-01F4",
    },
    "good_moral_graduate": {
        "family_key": "good_moral_graduate",
        "official_form_code": "CNSC-OP-GCO-01F6",
    },
    "students_profile": {
        "family_key": "students_profile",
        "official_form_code": "COMPASS-RPT-STUDENTS-PROFILE",
    },
    "student_inventory": {"family_key": "student_inventory", "official_form_code": "CNSC-OP-GCO-01F5"},
    "call_slip": {"family_key": "call_slip", "official_form_code": "CNSC-OP-GTA-01F8"},
    "referral_slip": {"family_key": "referral_slip", "official_form_code": "CNSC-OP-GTA-01F9"},
    "routine_interview": {"family_key": "routine_interview", "official_form_code": "CNSC-OP-GTA-01F11"},
    "exit_interview": {"family_key": "exit_interview", "official_form_code": "CNSC-OP-GTA-01F12"},
    "graduate_tracer_survey": {"family_key": "graduate_tracer_survey", "official_form_code": "CNSC-OP-GTA-01F10"},
    "customer_feedback_csm": {"family_key": "customer_feedback_csm", "official_form_code": "CNSC-OP-GTA-01F14"},
}


def _governed_form_relations(stable_key):
    seed = GOVERNED_FORM_SEEDS.get(stable_key)
    if not seed:
        return None, None
    family = FormFamily.objects.filter(stable_key=seed["family_key"]).first()
    if not family:
        return None, None
    revision = FormRevision.objects.filter(
        form_family=family,
        official_form_code=seed["official_form_code"],
    ).first()
    return family, revision


def _version_seed_with_shell(stable_key, version_seed):
    """Add the code-owned shell key without mutating active/used versions."""
    seed = deepcopy(version_seed)
    schema = seed.get("required_context_schema_json")
    schema = deepcopy(schema) if isinstance(schema, dict) else {}
    print_options = schema.get("print_options")
    print_options = deepcopy(print_options) if isinstance(print_options, dict) else {}
    shell_key = TEMPLATE_SHELL_KEYS.get(stable_key, DocumentShellKey.COMPACT_FORM)
    print_options.setdefault("shell_key", shell_key.value)
    schema["print_options"] = print_options
    seed["required_context_schema_json"] = schema
    return seed

# Template metadata registry - no invented form codes
TEMPLATE_SEEDS = [
    {
        "stable_key": "students_profile",
        "display_name": "Students' Profile Report",
        "document_kind": DocumentKindChoices.REPORT_EXPORT,
        "default_output_format": OutputFormatChoices.PDF,
        "retention_classification": RetentionClassificationChoices.OFFICIAL_RECORD,
        "access_policy_key": "REPORT_EXPORT",
        "description": "Official UCN/GCO multi-college aggregate Students' Profile report.",
        "versions": [
            {
                "version_label": "v1.0",
                "internal_template_version": "1",
                "template_path": "documents/print/students_profile/v1.html",
                "stylesheet_path": "documents/css/governed_print.css",
                "renderer_backend": RendererBackendChoices.PLAYWRIGHT_PDF,
                "output_format": OutputFormatChoices.PDF,
                "page_size": "A4",
                "page_orientation": "portrait",
                # Let the controlled renderer reserve physical A4 margins and
                # its repeating header/footer while the report tables flow
                # naturally across pages.
                "page_margins_json": {"top": 16, "right": 14, "bottom": 16, "left": 14},
                "required_context_schema_json": {
                    "print_options": {
                        "page_number_footer": True,
                        "page_number_footer_mode": "renderer",
                    },
                    "allowed": [
                        "report_context", "sections", "generated_at",
                        "prepared_by", "approved_by", "confidentiality_notice"
                    ],
                    "required": [
                        "report_context.academic_year", "report_context.college", "sections",
                        "generated_at", "institution.legal_name", "office.office_name",
                        "form_revision.official_form_code", "form_revision.official_revision",
                        "form_revision.effective_from"
                    ],
                },
            },
            {
                "version_label": "v1.1",
                "internal_template_version": "2",
                "template_path": "documents/print/students_profile/v1.html",
                "stylesheet_path": "documents/css/governed_print.css",
                "renderer_backend": RendererBackendChoices.PLAYWRIGHT_PDF,
                "output_format": OutputFormatChoices.PDF,
                "page_size": "A4",
                "page_orientation": "portrait",
                "page_margins_json": {"top": 16, "right": 14, "bottom": 16, "left": 14},
                "required_context_schema_json": {
                    "print_options": {"page_number_footer": True, "page_number_footer_mode": "renderer"},
                    "allowed": ["report_context", "sections", "generated_at", "prepared_by", "approved_by", "confidentiality_notice"],
                    "required": ["report_context.academic_year", "report_context.college", "sections", "generated_at"],
                },
            },
        ],
    },
    {
        "stable_key": "good_moral_student",
        "display_name": "Good Moral Certificate (Current Student)",
        "document_kind": DocumentKindChoices.CERTIFICATE,
        "default_output_format": OutputFormatChoices.PDF,
        "retention_classification": RetentionClassificationChoices.OFFICIAL_RECORD,
        "access_policy_key": "good_moral_request",
        "description": "Good moral certificate for currently enrolled students.",
        "versions": [
            {
                "version_label": "v1.0",
                "internal_template_version": "1",
                "template_path": "documents/print/good_moral_student/v1.html",
                "stylesheet_path": "documents/css/governed_print.css",
                "renderer_backend": RendererBackendChoices.PLAYWRIGHT_PDF,
                "output_format": OutputFormatChoices.PDF,
                "page_size": "A4",
                "page_orientation": "portrait",
                "required_context_schema_json": {
                    "print_options": {"page_number_footer": True, "page_number_footer_mode": "renderer"},
                    "allowed": [
                        "applicant_display_name", "applicant_year_level", "applicant_college",
                        "applicant_program_degree", "applicant_major", "applicant_semester",
                        "applicant_academic_year", "purpose_text", "issue_purpose", "official_receipt_number",
                        "official_receipt_date", "official_receipt_amount",
                        "approval_signatory_name", "approval_signatory_title",
                        "issue_day", "issue_month", "issue_year", "form_code", "form_revision",
                        "institution", "office"
                    ],
                    "required": [
                        "applicant_display_name", "applicant_year_level", "applicant_college",
                        "applicant_program_degree", "applicant_semester",
                        "applicant_academic_year", "purpose_text",
                        "approval_signatory_name", "approval_signatory_title",
                        "issue_day", "issue_month", "issue_year",
                        "institution.legal_name", "office.office_name"
                    ]
                },
            },
        ],
    },
    {
        "stable_key": "good_moral_graduate",
        "display_name": "Good Moral Certificate (Graduate)",
        "document_kind": DocumentKindChoices.CERTIFICATE,
        "default_output_format": OutputFormatChoices.PDF,
        "retention_classification": RetentionClassificationChoices.OFFICIAL_RECORD,
        "access_policy_key": "good_moral_request",
        "description": "Good moral certificate for graduates.",
        "versions": [
            {
                "version_label": "v1.0",
                "internal_template_version": "1",
                "template_path": "documents/print/good_moral_graduate/v1.html",
                "stylesheet_path": "documents/css/governed_print.css",
                "renderer_backend": RendererBackendChoices.PLAYWRIGHT_PDF,
                "output_format": OutputFormatChoices.PDF,
                "page_size": "A4",
                "page_orientation": "portrait",
                "required_context_schema_json": {
                    "print_options": {"page_number_footer": True, "page_number_footer_mode": "renderer"},
                    "allowed": [
                        "applicant_display_name", "applicant_program_degree", "applicant_major",
                        "applicant_graduation_date", "purpose_text", "issue_purpose", "official_receipt_number",
                        "official_receipt_date", "official_receipt_amount",
                        "approval_signatory_name", "approval_signatory_title",
                        "issue_day", "issue_month", "issue_year", "form_code", "form_revision",
                        "institution", "office"
                    ],
                    "required": [
                        "applicant_display_name", "applicant_program_degree", "applicant_graduation_date",
                        "purpose_text", "approval_signatory_name", "approval_signatory_title",
                        "issue_day", "issue_month", "issue_year",
                        "institution.legal_name", "office.office_name"
                    ]
                },
            },
        ],
    },
    {
        "stable_key": "call_slip",
        "display_name": "Call Slip / Interview Permit",
        "document_kind": DocumentKindChoices.OFFICIAL_FORM,
        "default_output_format": OutputFormatChoices.PDF,
        "retention_classification": RetentionClassificationChoices.STANDARD,
        "access_policy_key": "generated_document",
        "description": "Call slip / interview permit form.",
        "versions": [
            {
                "version_label": "v1.0",
                "internal_template_version": "1",
                "template_path": "documents/print/call_slip/v1.html",
                "renderer_backend": RendererBackendChoices.PLAYWRIGHT_PDF,
                "output_format": OutputFormatChoices.PDF,
                "stylesheet_path": "documents/css/governed_print.css",
                "page_size": "A4",
                "page_orientation": "portrait",
                "required_context_schema_json": {"print_options": {"page_number_footer": True, "page_number_footer_mode": "renderer"}},
            },
        ],
    },
    {
        "stable_key": "referral_slip",
        "display_name": "Referral Slip",
        "document_kind": DocumentKindChoices.OFFICIAL_FORM,
        "default_output_format": OutputFormatChoices.PDF,
        "retention_classification": RetentionClassificationChoices.STANDARD,
        "access_policy_key": "generated_document",
        "description": "Referral slip form.",
        "versions": [
            {
                "version_label": "v1.0",
                "internal_template_version": "1",
                "template_path": "documents/print/referral_slip/v1.html",
                "renderer_backend": RendererBackendChoices.PLAYWRIGHT_PDF,
                "output_format": OutputFormatChoices.PDF,
                "stylesheet_path": "documents/css/governed_print.css",
                "page_size": "A4",
                "page_orientation": "portrait",
                "required_context_schema_json": {"print_options": {"page_number_footer": True, "page_number_footer_mode": "renderer"}},
            },
        ],
    },
    {
        "stable_key": "customer_feedback_csm",
        "display_name": "Customer Feedback / CSM Form",
        "document_kind": DocumentKindChoices.OFFICIAL_FORM,
        "default_output_format": OutputFormatChoices.PDF,
        "retention_classification": RetentionClassificationChoices.STANDARD,
        "access_policy_key": "generated_document",
        "description": "Customer feedback / customer satisfaction measurement form.",
        "versions": [
            {
                "version_label": "v1.0",
                "internal_template_version": "1",
                "template_path": "documents/print/customer_feedback_csm/v1.html",
                "renderer_backend": RendererBackendChoices.PLAYWRIGHT_PDF,
                "output_format": OutputFormatChoices.PDF,
                "stylesheet_path": "documents/css/governed_print.css",
                "page_size": "A4",
                "page_orientation": "portrait",
                "required_context_schema_json": {"print_options": {"page_number_footer": True, "page_number_footer_mode": "renderer"}},
            },
        ],
    },
    {
        "stable_key": "student_inventory",
        "display_name": "Individual Inventory",
        "document_kind": DocumentKindChoices.OFFICIAL_FORM,
        "default_output_format": OutputFormatChoices.PDF,
        "retention_classification": RetentionClassificationChoices.CONFIDENTIAL,
        "access_policy_key": "generated_document",
        "description": "Authenticated, governed Individual Inventory preview.",
        "versions": [{
            "version_label": "v1.0", "internal_template_version": "1",
            "template_path": "documents/print/student_inventory/v1.html",
            "stylesheet_path": "documents/css/governed_print.css",
            "renderer_backend": RendererBackendChoices.PLAYWRIGHT_PDF,
            "output_format": OutputFormatChoices.PDF, "page_size": "A4", "page_orientation": "portrait",
            "page_margins_json": {"top": 16, "right": 16, "bottom": 14, "left": 16},
            "required_context_schema_json": {"print_options": {"page_number_footer": True, "page_number_footer_mode": "renderer"}},
        }],
    },
    {
        "stable_key": "routine_interview",
        "display_name": "Routine Interview",
        "document_kind": DocumentKindChoices.OFFICIAL_FORM,
        "default_output_format": OutputFormatChoices.PDF,
        "retention_classification": RetentionClassificationChoices.CONFIDENTIAL,
        "access_policy_key": "generated_document",
        "description": "Authenticated, policy-scoped Routine Interview preview.",
        "versions": [{
            "version_label": "v1.0", "internal_template_version": "1",
            "template_path": "documents/print/routine_interview/v1.html",
            "stylesheet_path": "documents/css/governed_print.css",
            "renderer_backend": RendererBackendChoices.PLAYWRIGHT_PDF,
            "output_format": OutputFormatChoices.PDF, "page_size": "A4", "page_orientation": "portrait",
            "page_margins_json": {"top": 16, "right": 16, "bottom": 14, "left": 16},
            "required_context_schema_json": {"print_options": {"page_number_footer": True, "page_number_footer_mode": "renderer"}},
        }],
    },
    {
        "stable_key": "exit_interview",
        "display_name": "Exit Interview",
        "document_kind": DocumentKindChoices.OFFICIAL_FORM,
        "default_output_format": OutputFormatChoices.PDF,
        "retention_classification": RetentionClassificationChoices.CONFIDENTIAL,
        "access_policy_key": "generated_document",
        "description": "Authenticated, policy-scoped Exit Interview preview.",
        "versions": [{
            "version_label": "v1.0", "internal_template_version": "1",
            "template_path": "documents/print/exit_interview/v1.html",
            "stylesheet_path": "documents/css/governed_print.css",
            "renderer_backend": RendererBackendChoices.PLAYWRIGHT_PDF,
            "output_format": OutputFormatChoices.PDF, "page_size": "A4", "page_orientation": "portrait",
            "page_margins_json": {"top": 16, "right": 16, "bottom": 14, "left": 16},
            "required_context_schema_json": {"print_options": {"page_number_footer": True, "page_number_footer_mode": "renderer"}},
        }],
    },
    {
        "stable_key": "graduate_tracer_survey",
        "display_name": "Graduate Tracer Survey",
        "document_kind": DocumentKindChoices.OFFICIAL_FORM,
        "default_output_format": OutputFormatChoices.PDF,
        "retention_classification": RetentionClassificationChoices.CONFIDENTIAL,
        "access_policy_key": "generated_document",
        "description": "Authenticated, policy-scoped Graduate Tracer output.",
        "versions": [{
            "version_label": "v1.0", "internal_template_version": "1",
            "template_path": "documents/print/graduate_tracer_survey/v1.html",
            "stylesheet_path": "documents/css/governed_print.css",
            "renderer_backend": RendererBackendChoices.PLAYWRIGHT_PDF,
            "output_format": OutputFormatChoices.PDF, "page_size": "A4", "page_orientation": "portrait",
            "page_margins_json": {"top": 16, "right": 16, "bottom": 14, "left": 16},
            "required_context_schema_json": {"print_options": {"page_number_footer": True, "page_number_footer_mode": "renderer"}},
        }],
    },
    {
        "stable_key": "public_service_guide",
        "display_name": "Public Service Guide",
        "document_kind": DocumentKindChoices.SUMMARY,
        "default_output_format": OutputFormatChoices.PDF,
        "retention_classification": RetentionClassificationChoices.TEMPORARY,
        "access_policy_key": "public_service_guide",
        "description": "Governed preview of the canonical public service guide.",
        "versions": [{
            "version_label": "v1.0", "internal_template_version": "1",
            "template_path": "documents/print/public_service_guide/v1.html",
            "stylesheet_path": "documents/css/governed_print.css",
            "renderer_backend": RendererBackendChoices.PLAYWRIGHT_PDF,
            "output_format": OutputFormatChoices.PDF, "page_size": "A4", "page_orientation": "portrait",
            "page_margins_json": {"top": 16, "right": 16, "bottom": 14, "left": 16},
            "required_context_schema_json": {
                "print_options": {"page_number_footer": True, "page_number_footer_mode": "renderer"},
                "allowed": ["public_service_guide"],
                "required": ["public_service_guide"],
            },
        }],
    },
]


class Command(BaseCommand):
    help = "Seed document template metadata (DRAFT only, no activation, no generated documents)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Preview changes without writing to the database.",
        )
        parser.add_argument("--reason-code", default="DOCUMENT_TEMPLATE_RECONCILIATION")
        parser.add_argument("--configuration-identifier", default="documents.catalog")
        parser.add_argument("--acknowledge-environment", action="store_true")

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        if is_deployment_environment() and not dry_run and not options.get("acknowledge_environment"):
            raise CommandError("Writes in staging or production require --acknowledge-environment.")
        prefix = "[DRY-RUN]" if dry_run else "[LIVE]"

        templates_created = 0
        templates_skipped = 0
        versions_created = 0
        versions_skipped = 0
        refused = 0

        for seed in TEMPLATE_SEEDS:
            stable_key = seed["stable_key"]
            existing = DocumentTemplate.objects.filter(stable_key=stable_key).first()
            form_family, form_revision = _governed_form_relations(stable_key)
            template_seed = {key: value for key, value in seed.items() if key != "versions"}
            if form_family:
                template_seed["related_form_family"] = form_family

            if existing:
                templates_skipped += 1
                self.stdout.write(f"  {prefix} Template '{stable_key}' already exists, skipping.")
                template_is_safe_to_update = (
                    existing.status == TemplateStatusChoices.DRAFT
                    and not existing.versions.filter(status=TemplateStatusChoices.ACTIVE).exists()
                    and not existing.versions.filter(is_used=True).exists()
                )
                if template_is_safe_to_update:
                    update_fields = {
                        key: value for key, value in template_seed.items()
                        if key != "stable_key"
                    }
                    if form_family:
                        update_fields["related_form_family"] = form_family
                    if not dry_run and update_fields:
                        for key, value in update_fields.items():
                            setattr(existing, key, value)
                        existing.save(update_fields=[*update_fields.keys(), "updated_at"])
                    self.stdout.write(
                        f"  {prefix} Updated draft template '{stable_key}' metadata."
                    )

                # Check versions for existing template
                for raw_version_seed in seed.get("versions", []):
                    version_seed = _version_seed_with_shell(stable_key, raw_version_seed)
                    version_label = version_seed["version_label"]
                    internal_ver = version_seed["internal_template_version"]
                    existing_version = DocumentTemplateVersion.objects.filter(
                        template=existing,
                        version_label=version_label,
                        internal_template_version=internal_ver,
                    ).first()

                    if existing_version:
                        if existing_version.status in (
                            TemplateStatusChoices.ACTIVE,
                        ) or existing_version.is_used:
                            refused += 1
                            self.stdout.write(
                                f"  {prefix} REFUSED: Version '{version_label}' for "
                                f"'{stable_key}' is active/used - will not mutate."
                            )
                        else:
                            # Draft/unused seed-managed metadata may be brought
                            # onto the shared A4 foundation. Active or used
                            # revisions are handled by the refusal branch above.
                            update_fields = {
                                key: value for key, value in version_seed.items()
                                if key not in {"version_label", "internal_template_version"}
                            }
                            if form_revision:
                                update_fields["related_form_revision"] = form_revision
                            if not dry_run and update_fields:
                                for key, value in update_fields.items():
                                    setattr(existing_version, key, value)
                                existing_version.save(update_fields=[*update_fields.keys(), "updated_at"])
                            self.stdout.write(
                                f"  {prefix} Updated draft version '{version_label}' for '{stable_key}'."
                            )
                            versions_skipped += 1
                            self.stdout.write(
                                f"  {prefix} Version '{version_label}' for "
                                f"'{stable_key}' already exists, skipping."
                            )
                    else:
                        if not dry_run:
                            version_data = dict(version_seed)
                            if form_revision:
                                version_data["related_form_revision"] = form_revision
                            DocumentTemplateVersion.objects.create(
                                template=existing,
                                status=TemplateStatusChoices.DRAFT,
                                **version_data,
                            )
                        versions_created += 1
                        self.stdout.write(
                            f"  {prefix} Created version '{version_label}' for '{stable_key}'."
                        )
            else:
                version_seeds = [
                    _version_seed_with_shell(stable_key, version_seed)
                    for version_seed in seed.get("versions", [])
                ]
                if not dry_run:
                    template = DocumentTemplate.objects.create(
                        status=TemplateStatusChoices.DRAFT,
                        **template_seed,
                    )
                    for version_seed in version_seeds:
                        version_data = dict(version_seed)
                        if form_revision:
                            version_data["related_form_revision"] = form_revision
                        DocumentTemplateVersion.objects.create(
                            template=template,
                            status=TemplateStatusChoices.DRAFT,
                            **version_data,
                        )
                        versions_created += 1
                else:
                    for version_seed in version_seeds:
                        versions_created += 1

                templates_created += 1
                self.stdout.write(f"  {prefix} Created template '{stable_key}'.")

        self.stdout.write(
            f"\n{prefix} Summary: "
            f"templates created={templates_created} skipped={templates_skipped} | "
            f"versions created={versions_created} skipped={versions_skipped} "
            f"refused={refused}"
        )
        record_operational_command_run(
            command_key="seed_document_templates", mode="dry-run" if dry_run else "execute",
            reason_code=options["reason_code"], configuration_identifier=options["configuration_identifier"],
            outcome="DRY_RUN" if dry_run else "COMPLETED",
            outcome_reason_code="NO_BUSINESS_WRITE" if dry_run else "CATALOG_RECONCILED",
            summary={"templates_created": templates_created, "versions_created": versions_created,
                     "refused": refused},
        )
