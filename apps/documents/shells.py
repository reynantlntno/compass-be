"""Code-owned print-shell profiles for governed document output.

Shell selection is deliberately small and immutable.  Template metadata may
select one of these keys, but it cannot invent a new composition or decide
which branding assets are authoritative.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType


class DocumentShellKey(StrEnum):
    FULL_INSTITUTIONAL = "full_institutional"
    COMPACT_FORM = "compact_form"
    CONTROLLED_FORM = "controlled_form"
    CERTIFICATE_REPORT = "certificate_report"


@dataclass(frozen=True, slots=True)
class DocumentShellDefinition:
    key: DocumentShellKey
    show_secondary_header_mark: bool
    show_contact_row: bool
    show_footer_marks: bool
    show_control_metadata: bool
    show_page_number: bool
    require_primary_header: bool = True


SHELL_DEFINITIONS = MappingProxyType({
    DocumentShellKey.FULL_INSTITUTIONAL: DocumentShellDefinition(
        key=DocumentShellKey.FULL_INSTITUTIONAL,
        show_secondary_header_mark=True,
        show_contact_row=True,
        show_footer_marks=True,
        show_control_metadata=True,
        show_page_number=True,
    ),
    DocumentShellKey.COMPACT_FORM: DocumentShellDefinition(
        key=DocumentShellKey.COMPACT_FORM,
        show_secondary_header_mark=False,
        show_contact_row=False,
        show_footer_marks=False,
        show_control_metadata=False,
        show_page_number=False,
    ),
    DocumentShellKey.CONTROLLED_FORM: DocumentShellDefinition(
        key=DocumentShellKey.CONTROLLED_FORM,
        show_secondary_header_mark=False,
        show_contact_row=False,
        show_footer_marks=False,
        show_control_metadata=True,
        show_page_number=True,
    ),
    DocumentShellKey.CERTIFICATE_REPORT: DocumentShellDefinition(
        key=DocumentShellKey.CERTIFICATE_REPORT,
        show_secondary_header_mark=True,
        show_contact_row=True,
        show_footer_marks=True,
        show_control_metadata=True,
        show_page_number=True,
    ),
})


TEMPLATE_SHELL_KEYS = MappingProxyType({
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
})


def resolve_document_shell(template_version) -> DocumentShellDefinition | None:
    """Resolve a governed shell without allowing arbitrary runtime values."""
    stable_key = str(getattr(getattr(template_version, "template", None), "stable_key", "") or "")
    expected = TEMPLATE_SHELL_KEYS.get(stable_key)
    options = getattr(template_version, "required_context_schema_json", {}) or {}
    print_options = options.get("print_options", {}) if isinstance(options, dict) else {}
    configured = print_options.get("shell_key") if isinstance(print_options, dict) else None
    if configured:
        try:
            configured_key = DocumentShellKey(str(configured))
        except ValueError:
            return None
        if expected and configured_key != expected:
            return None
        return SHELL_DEFINITIONS.get(configured_key)
    if expected:
        return SHELL_DEFINITIONS.get(expected)
    return SHELL_DEFINITIONS[DocumentShellKey.COMPACT_FORM]

