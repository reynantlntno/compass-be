from unittest import TestCase

from apps.common.exceptions import ValidationError
from apps.documents.commands import (
    DocumentTemplateCloneCommand,
    DocumentTemplateDraftCommand,
    DocumentTemplateLifecycleCommand,
    DocumentTemplateVersionDraftCommand,
    DocumentTemplateVersionLifecycleCommand,
    GeneratedDocumentLifecycleCommand,
)


class DocumentCommandContractTests(TestCase):
    def test_template_commands_are_immutable_and_json_safe(self):
        command = DocumentTemplateDraftCommand(
            stable_key="good_moral_student",
            display_name="Good Moral Student",
            document_kind="CERTIFICATE",
        )
        with self.assertRaises((AttributeError, TypeError)):
            command.stable_key = "changed"

        version = DocumentTemplateVersionDraftCommand(
            template_id="1",
            version_label="v1",
            template_path="documents/print/good_moral_student/v1.html",
            page_margins={"top": 25},
        )
        self.assertEqual(dict(version.page_margins), {"top": 25})

    def test_template_commands_reject_model_like_or_unsafe_values(self):
        with self.assertRaises(ValidationError):
            DocumentTemplateDraftCommand(
                stable_key="good_moral_student",
                display_name=object(),
                document_kind="CERTIFICATE",
            )
        with self.assertRaises(ValidationError):
            DocumentTemplateVersionDraftCommand(
                template_id="1",
                version_label="v1",
                template_path="../../private.html",
                page_margins={"top": object()},
            )

    def test_lifecycle_commands_use_stable_ids_and_are_immutable(self):
        commands = (
            DocumentTemplateLifecycleCommand(template_id="template-1", expected_status="DRAFT"),
            DocumentTemplateVersionLifecycleCommand(version_id="version-1"),
            DocumentTemplateCloneCommand(source_version_id="version-1"),
            GeneratedDocumentLifecycleCommand(document_id="document-1", reason_code="superseded"),
        )
        for command in commands:
            with self.subTest(command=type(command).__name__):
                with self.assertRaises((AttributeError, TypeError)):
                    command.__setattr__(next(iter(command.__dataclass_fields__)), "changed")
