"""Staff-safe Exit Interview queue queries and projections."""

from __future__ import annotations

from django.db.models import Q

from apps.access_control.authority import has_capability
from apps.access_control.capabilities import Capability
from apps.access_control.display import safe_student_display_label
from apps.common.contracts import PageRequest, PageResult, to_json_value
from apps.common.exceptions import ValidationError
from apps.exit_interviews import selectors
from apps.exit_interviews.models import ExitResponseStatus
from apps.exit_interviews.policies import can_view_exit_free_text


QUEUE_STATUSES = frozenset(value for value, _label in ExitResponseStatus.choices)
QUEUE_ORDERS = frozenset({"recent", "oldest"})
MAX_QUERY_LENGTH = 120
MAX_FILTER_LENGTH = 100


def _clean(value: str | None, *, limit: int = MAX_FILTER_LENGTH) -> str:
    value = " ".join(str(value or "").split()).strip()
    if len(value) > limit:
        raise ValidationError()
    return value


def _statuses(value: str | None) -> tuple[str, ...]:
    values = tuple(dict.fromkeys(item.strip().upper() for item in str(value or "").split(",") if item.strip()))
    if any(item not in QUEUE_STATUSES for item in values):
        raise ValidationError()
    return values


def _queue_queryset(actor):
    # Queue visibility is intentionally narrower than the existing response
    # reader/process capability.  In particular, a GCO account must have the
    # explicit queue grant before metadata rows are exposed.
    if not has_capability(actor, Capability.EXIT_INTERVIEWS_QUEUE_VIEW):
        return selectors.list_exit_responses_for_actor(actor).none()
    return selectors.list_exit_responses_for_actor(actor).select_related(
        "student__user", "form_revision", "form_revision__form_family"
    )


def _revision_fields(response) -> tuple[str, str, str]:
    revision = response.form_revision
    family = getattr(revision, "form_family", None)
    code = str(getattr(revision, "official_form_code", "") or getattr(family, "stable_key", ""))[:50]
    label = str(getattr(revision, "official_revision", "") or "?")[:20]
    title = str(getattr(revision, "display_title", "") or getattr(family, "display_name", "") or "Exit Interview")[:255]
    return code, label, title


def _project_row(response) -> dict:
    code, revision, title = _revision_fields(response)
    profile = response.student
    return {
        "reference_code": response.reference_code,
        "student_display_name": safe_student_display_label(profile),
        "student_number": str(profile.student_number).strip()[:50] if profile.student_number else None,
        "academic_year": response.academic_year,
        "graduation_year_snapshot": response.graduation_year_snapshot,
        "form_code": code,
        "form_revision": revision,
        "form_title": title,
        "status": response.status,
        "submitted_at": to_json_value(response.submitted_at),
        "counselor_acknowledged_at": to_json_value(response.counselor_acknowledged_at),
        "created_at": to_json_value(response.created_at),
        "updated_at": to_json_value(response.updated_at),
    }


def _project_detail(response, *, answers: dict | None = None) -> dict:
    payload = _project_row(response)
    if answers is not None:
        payload["answers"] = to_json_value(answers)
    return payload


def queue_page(
    actor,
    page: PageRequest,
    *,
    query: str | None = None,
    statuses: str | None = None,
    academic_year: str | None = None,
    revision: str | None = None,
    order: str = "recent",
) -> dict[str, object]:
    query = _clean(query, limit=MAX_QUERY_LENGTH)
    academic_year = _clean(academic_year)
    revision = _clean(revision)
    order = _clean(order, limit=20).lower() or "recent"
    if order not in QUEUE_ORDERS:
        raise ValidationError()
    status_values = _statuses(statuses)

    queryset = _queue_queryset(actor)
    if status_values:
        queryset = queryset.filter(status__in=status_values)
    if academic_year:
        queryset = queryset.filter(academic_year=academic_year)
    if revision:
        queryset = queryset.filter(
            Q(form_revision__official_form_code__iexact=revision)
            | Q(form_revision__official_revision__iexact=revision)
            | Q(form_revision__internal_schema_version__iexact=revision)
        )
    if query:
        queryset = queryset.filter(
            Q(reference_code__icontains=query)
            | Q(student__student_number__icontains=query)
            | Q(student__user__first_name__icontains=query)
            | Q(student__user__last_name__icontains=query)
        )

    ordering = ("updated_at", "pk") if order == "oldest" else ("-updated_at", "-pk")
    queryset = queryset.order_by(*ordering)
    total = queryset.count()
    rows = queryset[page.offset : page.offset + page.page_size]
    return PageResult(
        items=tuple(_project_row(row) for row in rows),
        page=page.page,
        page_size=page.page_size,
        total=total,
    ).as_dict()


def queue_detail(actor, reference_code: str) -> dict | None:
    response = _queue_queryset(actor).filter(reference_code=reference_code).first()
    return _project_detail(response) if response is not None else None


def queue_sensitive_detail(actor, reference_code: str) -> dict | None:
    response = _queue_queryset(actor).filter(reference_code=reference_code).first()
    if response is None or not can_view_exit_free_text(actor, response):
        return None
    # The queue selector deliberately loads a metadata-only instance. Read the
    # approved answer field only after the narrower policy has passed.
    response = type(response).objects.select_related(
        "student__user", "form_revision", "form_revision__form_family"
    ).filter(pk=response.pk).first()
    if response is None:
        return None
    return _project_detail(response, answers=response.response_json or {})
