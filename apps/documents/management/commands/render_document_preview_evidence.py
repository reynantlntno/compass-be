"""Render nine synthetic document preview PDFs without creating document records."""

from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from apps.documents.governance import get_preview_template_version
from apps.documents.services import DocumentServiceError, render_document_preview


def _rows(title, count=12):
    return {
        "title": title,
        "fields": [
            {"label": f"Field {index}", "value": f"Synthetic governed value {index}"}
            for index in range(1, count + 1)
        ],
    }


def _contexts():
    return {
        "good_moral_student": {
            "applicant_display_name": "Synthetic Student",
            "applicant_year_level": "4th",
            "applicant_college": "Synthetic College",
            "applicant_program_degree": "Bachelor of Arts",
            "applicant_major": "",
            "applicant_semester": "Second",
            "applicant_academic_year": "2025–2026",
            "purpose_text": "Synthetic purpose",
            "issue_purpose": "the stated purpose",
            "issue_day": "11th", "issue_month": "August", "issue_year": "2026",
            "official_receipt_number": "OR-0001", "official_receipt_date": "2026-08-11", "official_receipt_amount": "₱0.00",
            "approval_signatory_name": "Synthetic Signatory", "approval_signatory_title": "Guidance Counselor",
        },
        "good_moral_graduate": {
            "applicant_display_name": "Synthetic Graduate",
            "applicant_program_degree": "Bachelor of Science",
            "applicant_major": "",
            "applicant_graduation_date": "2026-06-30",
            "purpose_text": "Synthetic purpose",
            "issue_purpose": "the stated purpose",
            "issue_day": "11th", "issue_month": "August", "issue_year": "2026",
            "official_receipt_number": "OR-0002", "official_receipt_date": "2026-08-11", "official_receipt_amount": "₱0.00",
            "approval_signatory_name": "Synthetic Signatory", "approval_signatory_title": "Head Guidance",
        },
        "student_inventory": {"sections": [_rows("Personal Data", 10), _rows("Family Data", 8), _rows("Educational Background", 14)]},
        "call_slip": {"fields": [{"label": "Reference", "value": "CS-SYNTHETIC"}, {"label": "Status", "value": "Issued"}, {"label": "Scheduled start", "value": "2026-08-11 09:00"}, {"label": "Purpose", "value": "Routine interview"}, {"label": "Instructions", "value": "Please report to the Guidance Office."}]},
        "referral_slip": {"fields": [{"label": "Reference", "value": "REF-SYNTHETIC"}, {"label": "Status", "value": "Submitted"}, {"label": "Reason category", "value": "Academic"}, {"label": "Reason", "value": "Synthetic authorized narrative"}, {"label": "Course", "value": "Bachelor of Arts"}], "actions": [{"action": "Monitoring", "outcome": "Recorded", "performed_at": "2026-08-11"}]},
        "customer_feedback_csm": {"sections": [_rows("Your visit", 6), _rows("Service quality", 12), _rows("Comments", 3)]},
        "exit_interview": {"sections": [_rows("Response summary", 6), _rows("Self-assessment", 15), _rows("Feedback to the college", 18)]},
        "students_profile": {
            "report_context": {"report_title": "Students' Profile Report", "academic_year": "2025–2026", "college": "Synthetic College", "campus": "Main Campus"},
            "sections": [
                {"title": "Enrollment by program", "row_heading": "Program", "columns": [{"key": "count", "label": "Count"}, {"key": "share", "label": "Share"}], "rows": [{"label": f"Synthetic program {i}", "values": [str(i * 3), f"{i * 2}%"], "is_total": i == 12} for i in range(1, 25)]},
                {"title": "Student Support Needs", "row_heading": "Support Need", "columns": [{"key": "count", "label": "Count"}], "rows": [{"label": f"Support Need {i}", "values": ["Suppressed for privacy" if i % 4 == 0 else str(i)]} for i in range(1, 18)]},
            ],
            "generated_at": timezone.now(), "prepared_by": "Guidance and Counseling Office", "approved_by": "",
            "confidentiality_notice": "CONFIDENTIAL — Synthetic local evidence only.",
        },
        "referral_slip_copy": {"fields": []},
        "routine_interview": {"sections": [_rows("Routine interview intake", 16), _rows("Counselor evaluation", 8)]},
    }


FAMILY_OUTPUTS = (
    ("good_moral_student", "good-moral-student.pdf"),
    ("student_inventory", "individual-inventory.pdf"),
    ("good_moral_graduate", "good-moral-graduate.pdf"),
    ("call_slip", "call-slip.pdf"),
    ("customer_feedback_csm", "customer-feedback-csm.pdf"),
    ("exit_interview", "exit-interview.pdf"),
    ("students_profile", "students-profile.pdf"),
    ("referral_slip", "referral-slip.pdf"),
    ("routine_interview", "routine-interview.pdf"),
)


class Command(BaseCommand):
    help = "Render nine synthetic governed document preview PDFs (no database writes)."

    def add_arguments(self, parser):
        parser.add_argument("--output-dir", default="output/pdf/document_preview")

    def handle(self, *args, **options):
        output_dir = Path(options["output_dir"]).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        contexts = _contexts()
        for stable_key, filename in FAMILY_OUTPUTS:
            version = get_preview_template_version(stable_key)
            if not version:
                raise CommandError(f"No preview template configured for {stable_key}.")
            context = contexts[stable_key]
            try:
                content, content_type = render_document_preview(
                    template_version=version,
                    render_context=context,
                    form_revision=version.related_form_revision,
                )
            except Exception as exc:
                raise CommandError(f"Could not render {stable_key}: {type(exc).__name__}: {exc}") from exc
            if content_type != "application/pdf":
                raise CommandError(f"{stable_key} is not configured as a PDF preview.")
            path = output_dir / filename
            path.write_bytes(content)
            self.stdout.write(self.style.SUCCESS(f"[RENDERED] {path}"))
