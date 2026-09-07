"""Actor-aware query boundary for the assessments API."""

from apps.assessments.choices import AssessmentInstrumentCategory, AssessmentRecordStatus
from apps.assessments.projections import (
    assessment_staff_projection,
    instrument_projection,
    student_summary_projection,
)
from apps.assessments.selectors import (
    get_assessment_instrument_catalog,
    get_assessment_record_for_actor,
    get_assessment_records_visible_to,
    get_student_released_assessments,
)
from apps.common.contracts import PageRequest, page_queryset


def _choice(value: str | None, enum_type):
    if not value:
        return None
    try:
        return enum_type(value)
    except ValueError:
        return None


def instrument_page(actor, page_request: PageRequest):
    return page_queryset(get_assessment_instrument_catalog(actor), page_request, instrument_projection)


def assessment_page(actor, page_request: PageRequest, *, status: str = "", category: str = ""):
    queryset = get_assessment_records_visible_to(actor)
    status_value = _choice(status, AssessmentRecordStatus)
    category_value = _choice(category, AssessmentInstrumentCategory)
    if status:
        if status_value is None:
            return page_queryset(queryset.none(), page_request, assessment_staff_projection)
        queryset = queryset.filter(status=status_value.value)
    if category:
        if category_value is None:
            return page_queryset(queryset.none(), page_request, assessment_staff_projection)
        queryset = queryset.filter(instrument__category=category_value.value)
    return page_queryset(queryset, page_request, assessment_staff_projection)


def assessment_detail(actor, record_id):
    record = get_assessment_record_for_actor(actor, record_id)
    return assessment_staff_projection(record) if record is not None else None


def assessment_object(actor, record_id):
    return get_assessment_record_for_actor(actor, record_id)


def student_summary_page(actor, page_request: PageRequest):
    return page_queryset(get_student_released_assessments(actor), page_request, student_summary_projection)


def student_summary_detail(actor, record_id):
    try:
        record_id = int(record_id)
    except (TypeError, ValueError):
        return None
    record = get_student_released_assessments(actor).filter(pk=record_id).first()
    return student_summary_projection(record) if record is not None else None
