# Project: COMPASS
# File: apps/good_moral/template_context.py
# Module: apps.good_moral
# Purpose: Build context dictionaries for Good Moral document rendering
# Domain boundary and service policy.

import calendar
from django.utils import timezone


def _get_issue_date_components(request):
    dt = request.approved_at or timezone.now()
    return {
        "issue_day": str(dt.day),
        "issue_month": calendar.month_name[dt.month],
        "issue_year": str(dt.year),
    }


def build_student_gmc_context(request) -> dict:
    """Build the context payload for a student Good Moral certificate (CNSC-OP-GCO-01F4)."""
    date_components = _get_issue_date_components(request)
    receipt_date_str = (
        request.official_receipt_date.strftime("%Y-%m-%d")
        if request.official_receipt_date
        else ""
    )
    receipt_amount_str = (
        f"{request.official_receipt_amount:.2f}"
        if request.official_receipt_amount is not None
        else ""
    )

    return {
        "applicant_display_name": request.applicant_display_name,
        "applicant_year_level": request.applicant_year_level,
        "applicant_college": request.applicant_college,
        "applicant_program_degree": request.applicant_program_degree,
        "applicant_major": request.applicant_major,
        "applicant_semester": request.applicant_semester,
        "applicant_academic_year": request.applicant_academic_year,
        "purpose_text": request.purpose_text,
        "official_receipt_number": request.official_receipt_number,
        "official_receipt_date": receipt_date_str,
        "official_receipt_amount": receipt_amount_str,
        "approval_signatory_name": request.approval_signatory_name,
        "approval_signatory_title": request.approval_signatory_title,
        "issue_day": date_components["issue_day"],
        "issue_month": date_components["issue_month"],
        "issue_year": date_components["issue_year"],
        "form_code": "CNSC-OP-GCO-01F4",
        "form_revision": "0",
    }


def build_graduate_gmc_context(request) -> dict:
    """Build the context payload for a graduate Good Moral certificate (CNSC-OP-GCO-01F6)."""
    date_components = _get_issue_date_components(request)
    receipt_date_str = (
        request.official_receipt_date.strftime("%Y-%m-%d")
        if request.official_receipt_date
        else ""
    )
    receipt_amount_str = (
        f"{request.official_receipt_amount:.2f}"
        if request.official_receipt_amount is not None
        else ""
    )
    grad_date_str = (
        request.applicant_graduation_date.strftime("%B %d, %Y")
        if request.applicant_graduation_date
        else ""
    )

    return {
        "applicant_display_name": request.applicant_display_name,
        "applicant_program_degree": request.applicant_program_degree,
        "applicant_major": request.applicant_major,
        "applicant_graduation_date": grad_date_str,
        "purpose_text": request.purpose_text,
        "official_receipt_number": request.official_receipt_number,
        "official_receipt_date": receipt_date_str,
        "official_receipt_amount": receipt_amount_str,
        "approval_signatory_name": request.approval_signatory_name,
        "approval_signatory_title": request.approval_signatory_title,
        "issue_day": date_components["issue_day"],
        "issue_month": date_components["issue_month"],
        "issue_year": date_components["issue_year"],
        "form_code": "CNSC-OP-GCO-01F6",
        "form_revision": "0",
    }
