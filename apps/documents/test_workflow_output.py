from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase, mock

from django.conf import settings

from apps.common.exceptions import ValidationError
from apps.documents.commands import (
    WorkflowDocumentDownloadCommand,
    WorkflowDocumentGenerateCommand,
    WorkflowDocumentPreviewCommand,
)
from apps.documents.governance import (
    DOCUMENT_FAMILY_REGISTRY,
    build_document_branding_context,
    validate_document_family_registry,
)
from apps.documents.shells import DocumentShellKey, SHELL_DEFINITIONS, resolve_document_shell
from apps.documents.template_context import build_generation_context_snapshot
from apps.documents.workflow_output import _expected_stable_key, _text_sections


class WorkflowDocumentCommandTests(TestCase):
    def test_workflow_commands_are_frozen_and_reject_non_stable_references(self):
        commands = (
            WorkflowDocumentPreviewCommand(target_reference="CALL-1", stable_key="call_slip"),
            WorkflowDocumentGenerateCommand(target_reference="CALL-1", stable_key="call_slip"),
            WorkflowDocumentDownloadCommand(target_reference="CALL-1", stable_key="call_slip"),
        )
        for command in commands:
            with self.subTest(command=type(command).__name__):
                with self.assertRaises((AttributeError, TypeError)):
                    command.target_reference = "changed"

        for invalid in ({"id": "CALL-1"}, object(), BytesIO(b"csv")):
            with self.subTest(invalid=type(invalid).__name__):
                with self.assertRaises(ValidationError):
                    WorkflowDocumentPreviewCommand(target_reference=invalid, stable_key="call_slip")

    def test_expected_workflow_families_are_explicit(self):
        self.assertEqual(
            {
                domain: _expected_stable_key(domain)
                for domain in (
                    "call_slips", "referrals", "routine_interviews",
                    "inventory", "exit_interviews", "graduate_tracer",
                )
            },
            {
                "call_slips": "call_slip",
                "referrals": "referral_slip",
                "routine_interviews": "routine_interview",
                "inventory": "student_inventory",
                "exit_interviews": "exit_interview",
                "graduate_tracer": "graduate_tracer_survey",
            },
        )


class WorkflowDocumentGovernanceTests(TestCase):
    def test_registry_contains_all_six_source_form_mappings(self):
        expected = {
            "student_inventory": ("CNSC-OP-GCO-01F5", "0"),
            "graduate_tracer_survey": ("CNSC-OP-GTA-01F10", "0"),
            "routine_interview": ("CNSC-OP-GTA-01F11", "0"),
            "exit_interview": ("CNSC-OP-GTA-01F12", "0"),
            "call_slip": ("CNSC-OP-GTA-01F8", "0"),
            "referral_slip": ("CNSC-OP-GTA-01F9", "1"),
        }
        for stable_key, (code, revision) in expected.items():
            family = DOCUMENT_FAMILY_REGISTRY[stable_key]
            self.assertEqual((family.official_form_code, family.official_revision), (code, revision))
            self.assertTrue((Path(settings.BASE_DIR) / family.source_path).is_file())

        self.assertEqual(validate_document_family_registry(), [])

    def test_inventory_context_filter_accepts_named_sections_only(self):
        sections = _text_sections(
            {
                "personal_data": {"nickname": "A", "metadata_json": {"secret": "x"}},
                "unapproved_section": {"should_not_render": "no"},
            },
            title="Answer",
            allowed_sections=("personal_data",),
        )
        self.assertEqual(len(sections), 1)
        self.assertEqual([field["label"] for field in sections[0]["fields"]], ["Nickname"])

    def test_shell_mapping_is_allowlisted_and_unknown_values_fail_closed(self):
        expected = {
            "students_profile": DocumentShellKey.CERTIFICATE_REPORT,
            "good_moral_student": DocumentShellKey.CERTIFICATE_REPORT,
            "good_moral_graduate": DocumentShellKey.CERTIFICATE_REPORT,
            "public_service_guide": DocumentShellKey.FULL_INSTITUTIONAL,
            "call_slip": DocumentShellKey.CONTROLLED_FORM,
            "referral_slip": DocumentShellKey.CONTROLLED_FORM,
            "routine_interview": DocumentShellKey.CONTROLLED_FORM,
            "student_inventory": DocumentShellKey.CONTROLLED_FORM,
            "exit_interview": DocumentShellKey.CONTROLLED_FORM,
            "graduate_tracer_survey": DocumentShellKey.CONTROLLED_FORM,
            "customer_feedback_csm": DocumentShellKey.CONTROLLED_FORM,
        }
        for stable_key, shell_key in expected.items():
            version = SimpleNamespace(
                template=SimpleNamespace(stable_key=stable_key),
                required_context_schema_json={"print_options": {"shell_key": shell_key.value}},
            )
            self.assertEqual(resolve_document_shell(version).key, shell_key)

        invalid = SimpleNamespace(
            template=SimpleNamespace(stable_key="call_slip"),
            required_context_schema_json={"print_options": {"shell_key": "invented_shell"}},
        )
        self.assertIsNone(resolve_document_shell(invalid))

    def test_render_snapshot_excludes_inline_branding_data(self):
        version = SimpleNamespace(
            pk=1,
            template=SimpleNamespace(stable_key="call_slip"),
            version_label="v1",
            internal_template_version="1",
            template_path="documents/print/call_slip/v1.html",
            template_checksum="safe-checksum",
            renderer_backend="PLAYWRIGHT_PDF",
            output_format="PDF",
            page_size="A4",
            page_orientation="portrait",
            status="ACTIVE",
        )
        snapshot = build_generation_context_snapshot(
            template_version=version,
            renderer=None,
            document_control={
                "logo_data_uri": "data:image/png;base64,secret",
                "logo_alt": "Example",
                "brand_asset_metadata": {"primary": {"id": "asset-1"}},
            },
        )
        self.assertNotIn("logo_data_uri", snapshot["document_control"])
        self.assertNotIn("data:image", repr(snapshot))
        self.assertTrue(snapshot["document_control"]["primary_brand_asset_present"])

    def test_document_contact_rows_contain_only_approved_contact_fields(self):
        office = SimpleNamespace(
            contact_email="guidance@example.test",
            contact_number="09170000000",
        )
        with mock.patch(
            "apps.documents.governance.select_document_brand_assets",
            return_value={
                "primary": None,
                "secondary": [],
                "footer": {},
            },
        ):
            render, _metadata = build_document_branding_context(
                shell=SHELL_DEFINITIONS[DocumentShellKey.FULL_INSTITUTIONAL],
                office=office,
            )

        self.assertEqual(
            render["contact_rows"],
            [
                {"label": "Email", "value": "guidance@example.test"},
                {"label": "Contact", "value": "09170000000"},
            ],
        )
