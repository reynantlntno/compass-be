"""Fixed JSON projection boundary for the Good Moral domain."""

from apps.common.contracts import to_json_object


def document_projection(document) -> dict | None:
    if not document:
        return None
    template_version = getattr(document, "template_version", None)
    template = getattr(template_version, "template", None)
    protected = getattr(document, "protected_file", None)
    return to_json_object({
        "reference_code": document.reference_code,
        "document_status": document.document_status,
        "template_key": getattr(template, "stable_key", ""),
        "template_version": getattr(template_version, "version_label", ""),
        "output_format": getattr(template_version, "output_format", ""),
        "content_type": getattr(protected, "content_type", "application/pdf") if protected else "application/pdf",
        "generated_at": document.generated_at,
        "released_at": document.released_at,
    })


def student_request_projection(request) -> dict:
    """Own-record projection; no staff actors or raw receipt details."""
    return to_json_object({
        "reference_code": request.reference_code,
        "request_type": request.request_type,
        "status": request.status,
        "applicant_lifecycle_status": request.applicant_lifecycle_status,
        "applicant_academic_year": request.applicant_academic_year,
        "applicant_graduation_date": request.applicant_graduation_date,
        "purpose_text": request.purpose_text,
        "receipt_status": request.receipt_status,
        "dry_seal_status": request.dry_seal_status,
        "dry_seal_confirmation_method": request.dry_seal_confirmation_method or None,
        "generated_document": document_projection(request.generated_document),
        "created_at": request.created_at,
        "updated_at": request.updated_at,
    })


def staff_request_projection(request) -> dict:
    """Operational projection without OR values, notes, or actor relations."""
    return to_json_object({
        "reference_code": request.reference_code,
        "request_type": request.request_type,
        "status": request.status,
        "applicant_display_name": request.applicant_display_name,
        "applicant_lifecycle_status": request.applicant_lifecycle_status,
        "applicant_campus": request.applicant_campus,
        "applicant_college": request.applicant_college,
        "applicant_department": request.applicant_department,
        "applicant_program_degree": request.applicant_program_degree,
        "applicant_year_level": request.applicant_year_level,
        "applicant_academic_year": request.applicant_academic_year,
        "applicant_graduation_date": request.applicant_graduation_date,
        "receipt_status": request.receipt_status,
        "ossd_verification_status": request.ossd_verification_status,
        "approved_at": request.approved_at,
        "generated_at": request.generated_at,
        "printed_at": request.printed_at,
        "released_at": request.released_at,
        "dry_seal_status": request.dry_seal_status,
        "dry_seal_confirmation_method": request.dry_seal_confirmation_method or None,
        "generated_document": document_projection(request.generated_document),
        "created_at": request.created_at,
        "updated_at": request.updated_at,
    })


def request_projection(request, actor) -> dict:
    from apps.access_control.rules import is_student

    if is_student(actor) and request.requester_user_id == getattr(actor, "pk", None):
        return student_request_projection(request)
    return staff_request_projection(request)


def mutation_result(request) -> dict:
    """Small safe mutation result used for idempotent API responses."""
    return to_json_object({
        "reference_code": request.reference_code,
        "status": request.status,
        "receipt_status": request.receipt_status,
        "dry_seal_status": request.dry_seal_status,
        "updated_at": request.updated_at,
    })
