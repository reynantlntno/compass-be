# Project: COMPASS
# File: apps/reports/choices.py
# Module: apps.reports
# Purpose: TextChoices for report families, sensitivity levels, run status, and classification

from django.db import models


class ReportFamilyChoices(models.TextChoices):
    STUDENT_PROFILE_INVENTORY = "student_profile_inventory", "Institutional Student Profiling & Inventory"
    FEEDBACK_CSM = "feedback_csm", "Client Satisfaction Measurement (CSM) / Feedback"
    EXIT_INTERVIEW = "exit_interview", "Exit Interview Completion"
    GRADUATE_TRACER = "graduate_tracer", "Graduate Tracer Survey"
    FORM_COLLECTION_PROGRESS = "form_collection_progress", "Form Collection Progress"
    DOCUMENT_REQUESTS = "document_requests", "Good Moral & Document Requests"
    APPOINTMENTS_COUNSELING_WORKLOAD = "appointments_counseling_workload", "Appointments & Counseling Workload"
    REFERRALS_CALL_SLIPS = "referrals_call_slips", "Referrals & Call Slips"
    PUBLIC_CONTACT = "public_contact", "Public Contact / Suggestion Box"
    WORKFLOW_NOTIFICATIONS = "workflow_notifications", "Workflow & Notification Metrics"
    AUDIT_REPORT_ACCESS = "audit_report_access", "Audit & Report Access Logs"


class SensitivityLevel(models.TextChoices):
    PUBLIC = "PUBLIC", "Public (unrestricted internal/external view)"
    INTERNAL = "INTERNAL", "Internal (general guidance office view)"
    SENSITIVE = "SENSITIVE", "Sensitive (restricted categories, suppressed cells)"
    RESTRICTED = "RESTRICTED", "Restricted (elevated role + approval required)"
    FORBIDDEN = "FORBIDDEN", "Forbidden (never expose in reports/queries)"


class ReportRunStatus(models.TextChoices):
    PENDING = "PENDING", "Pending"
    RUNNING = "RUNNING", "Running"
    COMPLETED = "COMPLETED", "Completed"
    FAILED = "FAILED", "Failed"


class SuppressionMode(models.TextChoices):
    """Authoritative suppression rule applied to a report definition's output.

    This is the single governing mode for how suppression is applied; it is
    validated per report definition and read directly by the suppression
    service. It formalizes the previously implicit per-family branching.
    """

    NONE = "NONE", "No small-count suppression (operational metadata)"
    CELL = "CELL", "Cell-level small-count suppression with complementary protection"
    DISCLOSURE_SET = "DISCLOSURE_SET", "Whole fixed disclosure-set suppression"
    SECTION = "SECTION", "Whole dynamic matrix section suppression"



class FieldSensitivity(models.TextChoices):
    PUBLIC = "PUBLIC", "Public"
    INTERNAL = "INTERNAL", "Internal"
    SENSITIVE = "SENSITIVE", "Sensitive"
    RESTRICTED = "RESTRICTED", "Restricted"
    FORBIDDEN = "FORBIDDEN", "Forbidden"


class ExportTypeChoices(models.TextChoices):
    AGGREGATE = "aggregate", "Aggregate"
    SENSITIVE_AGGREGATE = "sensitive_aggregate", "Sensitive Aggregate"
    IDENTIFIABLE = "identifiable", "Identifiable"
    ADMINISTRATIVE_OPERATIONAL = "administrative_operational", "Administrative/Operational"
    OFFICIAL_TEMPLATE = "official_template", "Official Template"
    DENIED_DEFERRED = "denied_deferred", "Denied/Deferred"


class ExportFormatChoices(models.TextChoices):
    CSV = "csv", "CSV"
    PDF = "pdf", "PDF"
    DEFERRED_EXCEL = "deferred_excel", "Deferred Excel"
    DEFERRED_PDF = "deferred_pdf", "Deferred PDF"
    DEFERRED_DOCX = "deferred_docx", "Deferred DOCX"
    HTML_PREVIEW = "html_preview", "HTML Preview"


ACTIVE_EXPORT_FORMAT_CHOICES = (
    (ExportFormatChoices.CSV, ExportFormatChoices.CSV.label),
)

DEFERRED_EXPORT_FORMAT_VALUES = {
    ExportFormatChoices.DEFERRED_EXCEL,
    ExportFormatChoices.DEFERRED_PDF,
    ExportFormatChoices.DEFERRED_DOCX,
    ExportFormatChoices.HTML_PREVIEW,
}


class ExportStatusChoices(models.TextChoices):
    REQUESTED = "requested", "Requested"
    PENDING_APPROVAL = "pending_approval", "Pending Approval"
    APPROVED = "approved", "Approved"
    DENIED = "denied", "Denied"
    GENERATING = "generating", "Generating"
    GENERATED = "generated", "Generated"
    GENERATION_FAILED = "generation_failed", "Generation Failed"
    DOWNLOADED = "downloaded", "Downloaded"
    EXPIRED = "expired", "Expired"
    CANCELLED = "cancelled", "Cancelled"
    ARCHIVED = "archived", "Archived"
