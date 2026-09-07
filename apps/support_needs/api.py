"""Client-facing Student Support Needs API.

Counselor/Head-only surface: no student Support Needs route exists.  Every
route uses the shared operation preparation (no-store, correlation headers,
central rate limits) and, for mutations, the shared idempotency adapter with
the centralized sensitive-write class.  Projections are safe metadata only.
"""

from datetime import date as date_type
from datetime import datetime as datetime_type

from ninja import Router, Schema

from apps.common.api.idempotency import ApiMutationOutcome, run_api_mutation
from apps.common.api.operations import prepare_api_operation
from apps.common.api.pagination import PageQuery, PageSizeQuery, page_request_from_values
from apps.common.api.schemas import PageResultSchema
from apps.common.contracts import ContractValidationError
from apps.common.exceptions import NotFoundError, ValidationError
from apps.support_needs import queries as support_needs_queries
from apps.support_needs.commands import (
    UNSET,
    SupportNeedCreateCommand,
    SupportNeedReasonCommand,
    SupportNeedUpdateCommand,
)
from apps.support_needs.services import (
    archive_support_need,
    create_support_need,
    dispute_support_need,
    mark_support_need_needs_review,
    update_support_need,
    verify_support_need,
)


router = Router(tags=["support-needs"])


class SupportNeedTypeSchema(Schema):
    """Output-only active support-need type projection."""

    key: str
    label: str
    category: str
    is_active: bool


class SupportNeedTypePageSchema(PageResultSchema):
    items: list[SupportNeedTypeSchema]


class SupportNeedProjectionSchema(Schema):
    """Output-only scoped support-need projection."""

    support_need_id: str
    student_profile_id: str
    type_key: str
    type_label: str
    type_category: str
    status: str
    source_type: str
    source_snapshot_label: str | None
    effective_from: date_type | None
    effective_until: date_type | None
    review_due_at: datetime_type | None
    verified_at: datetime_type | None
    disputed_at: datetime_type | None
    archived_at: datetime_type | None
    review_code: str | None = None
    needs_review_reason: str | None = None
    dispute_reason: str | None = None


class SupportNeedPageSchema(PageResultSchema):
    items: list[SupportNeedProjectionSchema]


class SupportNeedMutationResponseSchema(Schema):
    """Bounded first-response/replay superset for support-need mutations."""

    # The idempotent replay projection intentionally contains only these
    # identity/state fields.  The first response may contain the full safe
    # projection below, so the remaining fields must stay optional.
    support_need_id: str
    type_key: str
    status: str
    # Public response IDs intentionally retain the existing string wire
    # format, even though request-side profile IDs are integer-backed.
    student_profile_id: str | None = None
    type_label: str | None = None
    type_category: str | None = None
    source_type: str | None = None
    source_snapshot_label: str | None = None
    effective_from: date_type | None = None
    effective_until: date_type | None = None
    review_due_at: datetime_type | None = None
    verified_at: datetime_type | None = None
    disputed_at: datetime_type | None = None
    archived_at: datetime_type | None = None
    review_code: str | None = None
    needs_review_reason: str | None = None
    dispute_reason: str | None = None


class SupportNeedCreateSchema(Schema):
    student_profile_id: int
    support_need_type_key: str
    source_type: str
    source_snapshot_label: str = ""
    evidence_summary: dict | None = None
    effective_from: date_type | None = None
    effective_until: date_type | None = None
    review_due_at: datetime_type | None = None


class SupportNeedUpdateSchema(Schema):
    effective_from: date_type | None = None
    effective_until: date_type | None = None
    review_due_at: datetime_type | None = None
    source_snapshot_label: str = ""
    evidence_summary: dict | None = None


class ReasonSchema(Schema):
    reason_code: str = ""


def _actor(request):
    return request.auth.user


def _page(page: PageQuery, page_size: PageSizeQuery):
    try:
        return page_request_from_values(page, page_size)
    except ContractValidationError as error:
        raise ValidationError() from error


def _replay(key):
    object_id = getattr(key, "related_object_id", None)
    if not object_id:
        return None
    from apps.support_needs.projections import replay_support_need

    return replay_support_need(object_id)


def _run(request, operation_id, payload, operation):
    prepared = prepare_api_operation(request, operation_id)
    return run_api_mutation(
        request,
        operation_id,
        payload,
        operation,
        _replay,
        prepared_operation=prepared,
    )


def _outcome(record):
    from apps.support_needs.projections import project_support_need

    # The service already reauthorized against the record's current scope,
    # so projecting the mutated instance directly is safe here.
    return ApiMutationOutcome(
        value=project_support_need(record),
        related_object=record,
        safe_response_path=f"/api/v1/support-needs/{record.pk}/",
    )


# Static segments are registered before the detail converter.
@router.get(
    "/types/",
    response=SupportNeedTypePageSchema,
    exclude_unset=True,
    operation_id="support_needs_types",
)
def list_types(request, page: PageQuery, page_size: PageSizeQuery):
    prepare_api_operation(request, "support_needs_types")
    return support_needs_queries.type_catalog(_actor(request), _page(page, page_size))


@router.get(
    "/review-queue/",
    response=SupportNeedPageSchema,
    exclude_unset=True,
    operation_id="support_needs_review_queue",
)
def review_queue(request, page: PageQuery, page_size: PageSizeQuery):
    prepare_api_operation(request, "support_needs_review_queue")
    return support_needs_queries.review_queue_page(_actor(request), _page(page, page_size))


@router.get(
    "/",
    response=SupportNeedPageSchema,
    exclude_unset=True,
    operation_id="support_needs_list",
)
def list_support_needs(
    request,
    status: str | None = None,
    type_key: str | None = None,
    student_profile_id: int | None = None,
    page: PageQuery = 1,
    page_size: PageSizeQuery = 25,
):
    prepare_api_operation(request, "support_needs_list")
    filters = {
        "status": status or "",
        "type_key": type_key or "",
        "student_profile_id": student_profile_id or "",
    }
    return support_needs_queries.scoped_support_need_page(
        _actor(request), _page(page, page_size), filters=filters
    )


@router.get(
    "/{support_need_id}/",
    response=SupportNeedProjectionSchema,
    exclude_unset=True,
    operation_id="support_needs_detail",
)
def support_need_detail(request, support_need_id: int):
    prepare_api_operation(request, "support_needs_detail")
    detail = support_needs_queries.support_need_detail(_actor(request), support_need_id)
    if detail is None:
        raise NotFoundError()
    return detail


@router.post(
    "/",
    response=SupportNeedMutationResponseSchema,
    exclude_unset=True,
    operation_id="support_needs_create",
)
def create_support_need_route(request, payload: SupportNeedCreateSchema):
    actor = _actor(request)
    command = SupportNeedCreateCommand(
        student_profile_id=str(payload.student_profile_id),
        support_need_type_key=payload.support_need_type_key,
        source_type=payload.source_type,
        source_snapshot_label=payload.source_snapshot_label,
        evidence_summary=payload.evidence_summary,
        effective_from=payload.effective_from,
        effective_until=payload.effective_until,
        review_due_at=payload.review_due_at,
    )
    body = {
        "student_profile_id": payload.student_profile_id,
        "support_need_type_key": payload.support_need_type_key,
        "source_type": payload.source_type,
        "source_snapshot_label": payload.source_snapshot_label,
        "effective_from": payload.effective_from,
        "effective_until": payload.effective_until,
        "review_due_at": payload.review_due_at,
    }
    from apps.common.request_dedup import build_command_fingerprint

    if payload.evidence_summary is not None:
        body["evidence_fingerprint"] = build_command_fingerprint(
            {"evidence_summary": payload.evidence_summary}
        )

    def _operation():
        return _outcome(create_support_need(actor, command))

    return _run(request, "support_needs_create", body, _operation)


@router.patch(
    "/{support_need_id}/",
    response=SupportNeedMutationResponseSchema,
    exclude_unset=True,
    operation_id="support_needs_update",
)
def update_support_need_route(request, support_need_id: int, payload: SupportNeedUpdateSchema):
    actor = _actor(request)
    supplied = payload.dict(exclude_unset=True)
    command = SupportNeedUpdateCommand(**supplied)
    body = {
        "support_need_id": support_need_id,
        "effective_from": "" if command.effective_from is UNSET else command.effective_from,
        "effective_until": "" if command.effective_until is UNSET else command.effective_until,
        "review_due_at": "" if command.review_due_at is UNSET else command.review_due_at,
        "source_snapshot_label": (
            "" if command.source_snapshot_label is UNSET else command.source_snapshot_label
        ),
    }
    if command.evidence_summary is UNSET:
        body["evidence_fingerprint"] = ""
    else:
        from apps.common.request_dedup import build_command_fingerprint

        body["evidence_fingerprint"] = build_command_fingerprint(
            {"evidence_summary": command.evidence_summary}
        )

    def _operation():
        return _outcome(update_support_need(actor, support_need_id, command))

    return _run(request, "support_needs_update", body, _operation)


def _reasoned_action(request, actor, support_need_id, reason_code, operation_id, service):
    body = {"support_need_id": support_need_id, "reason_code": reason_code or ""}

    def _operation():
        return _outcome(service(actor, support_need_id, SupportNeedReasonCommand(reason_code)))

    return _run(request, operation_id, body, _operation)


@router.post(
    "/{support_need_id}/verify/",
    response=SupportNeedMutationResponseSchema,
    exclude_unset=True,
    operation_id="support_needs_verify",
)
def verify_support_need_route(request, support_need_id: int, payload: ReasonSchema | None = None):
    return _reasoned_action(
        request,
        _actor(request),
        support_need_id,
        payload.reason_code if payload is not None else "",
        "support_needs_verify",
        verify_support_need,
    )


@router.post(
    "/{support_need_id}/needs-review/",
    response=SupportNeedMutationResponseSchema,
    exclude_unset=True,
    operation_id="support_needs_mark_review",
)
def mark_review_route(request, support_need_id: int, payload: ReasonSchema | None = None):
    return _reasoned_action(
        request,
        _actor(request),
        support_need_id,
        payload.reason_code if payload is not None else "",
        "support_needs_mark_review",
        mark_support_need_needs_review,
    )


@router.post(
    "/{support_need_id}/dispute/",
    response=SupportNeedMutationResponseSchema,
    exclude_unset=True,
    operation_id="support_needs_dispute",
)
def dispute_route(request, support_need_id: int, payload: ReasonSchema | None = None):
    return _reasoned_action(
        request,
        _actor(request),
        support_need_id,
        payload.reason_code if payload is not None else "",
        "support_needs_dispute",
        dispute_support_need,
    )


@router.post(
    "/{support_need_id}/archive/",
    response=SupportNeedMutationResponseSchema,
    exclude_unset=True,
    operation_id="support_needs_archive",
)
def archive_route(request, support_need_id: int, payload: ReasonSchema | None = None):
    return _reasoned_action(
        request,
        _actor(request),
        support_need_id,
        payload.reason_code if payload is not None else "",
        "support_needs_archive",
        archive_support_need,
    )
