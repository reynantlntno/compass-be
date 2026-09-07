"""Governed HTML/PDF rendering boundary for the Students' Profile report."""

from django.utils import timezone

from apps.documents.models import OutputFormatChoices, RendererBackendChoices
from apps.documents.governance import DocumentOutputIntent, get_preview_template_version
from apps.documents.selectors import get_active_template_version
from apps.documents.services import DocumentServiceError
from apps.common.exceptions import ValidationError
from apps.orchestration.commands import DocumentRenderCommand
from apps.orchestration.use_cases import render_document_for_composition
from apps.reports.choices import ExportFormatChoices


STUDENTS_PROFILE_TEMPLATE_KEY = "students_profile"
SUPPRESSION_LABEL = "Suppressed for privacy"
SAFE_CONTEXT_KEYS = (
    "report_title",
    "academic_year",
    "college",
    "campus",
    "department",
    "year_level",
    "program",
)


def _safe_text(value, *, maximum=160, blank="-"):
    if value in (None, ""):
        return blank
    if isinstance(value, (str, int, float)) and not isinstance(value, bool):
        return str(value).strip()[:maximum] or blank
    raise ValidationError("Profiling PDF context contains an invalid display value.")


def _safe_matrix_sections(value):
    if not isinstance(value, list):
        raise ValidationError("Profiling PDF output requires a matrix section list.")

    sections = []
    for section in value:
        if not isinstance(section, dict):
            raise ValidationError("Profiling PDF output contains an invalid section.")
        raw_rows = section.get("rows")
        if not isinstance(raw_rows, list):
            raise ValidationError("Profiling PDF section must contain rows.")

        raw_columns = section.get("columns")
        if not isinstance(raw_columns, list):
            raise ValidationError("Profiling PDF section must contain columns.")
        columns = []
        column_keys = []
        for column in raw_columns:
            if not isinstance(column, dict):
                raise ValidationError("Profiling PDF section contains an invalid column.")
            key = column.get("key")
            if not isinstance(key, str) or not key.strip():
                raise ValidationError("Profiling PDF section contains an invalid column key.")
            columns.append({"label": _safe_text(column.get("label"), maximum=90)})
            column_keys.append(key)

        rows = []
        for row in raw_rows:
            if not isinstance(row, dict):
                raise ValidationError("Profiling PDF section contains an invalid row.")
            values = row.get("values")
            if isinstance(values, dict):
                values = [values.get(column_key, "-") for column_key in column_keys]
            if not isinstance(values, list):
                raise ValidationError("Profiling PDF section contains an invalid row.")
            if len(values) != len(columns):
                raise ValidationError("Profiling PDF row does not reconcile with its program columns.")
            rows.append({
                "label": _safe_text(row.get("label"), maximum=160),
                "values": [
                    SUPPRESSION_LABEL if item == SUPPRESSION_LABEL else _safe_text(item, maximum=80)
                    for item in values
                ],
                "is_total": bool(row.get("is_total")),
            })

        sections.append({
            "title": _safe_text(section.get("title"), maximum=180),
            "row_heading": _safe_text(section.get("row_heading"), maximum=80, blank="Category"),
            "columns": columns,
            "rows": rows,
        })
    return sections


def build_students_profile_render_context(dataset: dict, export_request) -> dict:
    """Convert only the finalized, suppressed profiling projection into template data."""
    payload = dataset.get("profiling_report", dataset) if isinstance(dataset, dict) else None
    if not isinstance(payload, dict):
        raise ValidationError("Profiling PDF output is unavailable.")

    raw_context = payload.get("report_context")
    if not isinstance(raw_context, dict):
        raise ValidationError("Profiling PDF reporting context is unavailable.")
    report_context = {
        key: _safe_text(raw_context.get(key), maximum=160)
        for key in SAFE_CONTEXT_KEYS
        if raw_context.get(key) not in (None, "")
    }
    if not report_context.get("academic_year") or not report_context.get("college"):
        raise ValidationError("Profiling PDF requires academic-year and college context.")
    report_context.setdefault("report_title", "Students' Profile Report")

    sections = _safe_matrix_sections(payload.get("sections"))

    return {
        "report_context": report_context,
        "sections": sections,
        "generated_at": timezone.now(),
        "prepared_by": "Guidance and Counseling Office",
        "approved_by": "Head Guidance" if export_request.approved_by_id else "",
        "confidentiality_notice": "CONFIDENTIAL - For authorized Guidance and Counseling Office use only.",
    }


def render_students_profile_export(*, actor, export_request, dataset):
    """Render and protect an approved Students' Profile PDF through document governance."""
    if export_request.export_format != ExportFormatChoices.PDF:
        raise ValidationError("Students' Profile PDF rendering requires PDF export format.")

    metadata = export_request.report_definition.metadata_json or {}
    if metadata.get("document_template_key") != STUDENTS_PROFILE_TEMPLATE_KEY:
        raise ValidationError("Students' Profile document template is not governed for this report.")

    # Keep the legacy selector as a narrowly scoped fallback for callers/tests
    # that provide an active revision directly.  Governed environments resolve
    # the preview-capable draft/active version first; no legacy template is
    # selected when a governed version exists.
    template_version = get_preview_template_version(STUDENTS_PROFILE_TEMPLATE_KEY)
    if template_version is None:
        template_version = get_active_template_version(STUDENTS_PROFILE_TEMPLATE_KEY)
    if not template_version:
        raise DocumentServiceError("A draft or active Students' Profile document template is required.")
    if template_version.output_format != OutputFormatChoices.PDF:
        raise DocumentServiceError("Students' Profile template must be configured for PDF output.")
    if template_version.renderer_backend != RendererBackendChoices.PLAYWRIGHT_PDF:
        raise DocumentServiceError("Students' Profile template must use the governed PDF renderer.")
    revision = template_version.related_form_revision

    context = build_students_profile_render_context(dataset, export_request)
    return render_document_for_composition(
        actor,
        DocumentRenderCommand(
            template_version_id=str(template_version.pk),
            render_context=context,
            academic_year=context["report_context"]["academic_year"],
            form_revision_id=str(revision.pk) if revision is not None else None,
            owning_app_label="reports",
            owning_model_name="ReportExportRequest",
            owning_object_id=str(export_request.id),
            access_policy_key="REPORT_EXPORT",
            output_intent=DocumentOutputIntent.PREVIEW.value,
        ),
    )
