"""Client-facing Privacy API.

This router exposes safe privacy projections and privacy-owned administrative
aggregates. DPO appointment administration remains in Governance.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from uuid import UUID

from ninja import Field, Router, Schema

from apps.account_security.api_auth import authenticate_bearer_request
from apps.common.api.idempotency import ApiMutationOutcome, run_api_mutation
from apps.common.api.operations import prepare_api_operation
from apps.common.api.pagination import PageQuery, PageSizeQuery, page_request_from_values
from apps.common.api.schemas import PageResultSchema
from apps.common.contracts import ContractValidationError
from apps.common.exceptions import NotFoundError, PermissionDeniedError, ValidationError

from . import projections, queries, selectors
from .choices import (
    PrivacyAcceptanceDecisionChoices,
    PrivacyIncidentCategoryChoices,
    PrivacyIncidentNotificationDecisionChoices,
    PrivacyIncidentSeverityChoices,
    PrivacyIncidentStatusChoices,
    PrivacyRequestDecisionChoices,
    PrivacyRequestTypeChoices,
)
from .commands import (
    DataSubjectRequestCreateCommand,
    PrivacyIncidentCreateCommand,
    PrivacyIncidentTransitionCommand,
    PrivacyLegalHoldCreateCommand,
    PrivacyLegalHoldReleaseCommand,
    PrivacyNoticeAcceptanceCommand,
    PrivacyRequestAssignmentCommand,
    PrivacyRequestFulfillmentCommand,
    PrivacyRequestTransitionCommand,
    RetentionEvaluationCommand,
)
from .policies import can_view_request, can_view_request_sensitive
from .services import (
    assess_privacy_incident_notification_command,
    assign_data_subject_request_command,
    contain_privacy_incident_command,
    create_data_subject_request_command,
    create_privacy_incident_command,
    evaluate_retention_command,
    fulfill_data_subject_request_command,
    place_legal_hold_command,
    record_notice_acceptance_command,
    release_legal_hold_command,
    transition_data_subject_request_command,
    transition_privacy_incident_command,
    withdraw_data_subject_request_command,
    withdraw_notice_acceptance_command,
)


router = Router(tags=["privacy"])

# Privacy owns its reviewer-authorization, notice-revision, and notice-binding
# aggregates. Their administrative routes stay in v1 but no longer live under
# Governance's policy prefix.
from .governance_api import router as privacy_governance_router  # noqa: E402

router.add_router("", privacy_governance_router)


class PrivacyNoticeSchema(Schema):
    """Output-only projection for the currently published privacy notice."""

    version: str
    effective_at: str | None = None
    body_html: str


class PrivacyAcceptanceProjectionSchema(Schema):
    """Output-only acceptance evidence without subject or session identifiers."""

    id: str
    purpose_workflow: str
    decision: str
    notice_version: str
    decided_at: str


class PrivacyAcceptancePageSchema(PageResultSchema):
    items: list[PrivacyAcceptanceProjectionSchema]


class PrivacyRequestProjectionSchema(Schema):
    """Safe request metadata shared by list, detail, and mutation responses."""

    reference_code: str
    request_type: str
    target_category: str
    status: str
    submitted_at: str | None = None
    identity_verified: bool
    assigned: bool
    fulfilled: bool
    withdrawn_at: str | None = None
    closed_at: str | None = None


class PrivacyRequestSensitiveSchema(Schema):
    """Explicitly authorized sensitive request detail."""

    reference_code: str
    description: str
    decision_notes: str
    decision_reason_code: str


class PrivacyRequestPageSchema(PageResultSchema):
    items: list[PrivacyRequestProjectionSchema]


class PrivacyIncidentSafeEvidenceSchema(Schema):
    """Allowlisted incident evidence; no raw event or record metadata."""

    containment_code: str | None = None
    affected_count: int | None = None
    system_code: str | None = None
    event_count: int | None = None
    authorization_reference: str | None = None
    metadata_only: bool | None = None


class PrivacyIncidentTransitionSchema(Schema):
    from_status: str
    to_status: str
    reason_code: str
    occurred_at: str | None = None
    safe_evidence: PrivacyIncidentSafeEvidenceSchema | None = None


class PrivacyIncidentProjectionSchema(Schema):
    """Incident metadata with optional detail/timeline and technical redaction."""

    incident_code: str
    category: str
    severity: str
    affected_workflow: str
    affected_record_category: str
    status: str
    discovered_at: str | None = None
    containment_code: str
    safe_summary_code: str
    notification_decision: str | None = None
    timeline: list[PrivacyIncidentTransitionSchema] | None = None


class PrivacyIncidentPageSchema(PageResultSchema):
    items: list[PrivacyIncidentProjectionSchema]


class PrivacyLegalHoldSchema(Schema):
    id: str
    record_category: str
    status: str
    reason_code: str
    safe_reference_present: bool
    placed_at: str | None = None
    released_at: str | None = None


class PrivacyLegalHoldPageSchema(PageResultSchema):
    items: list[PrivacyLegalHoldSchema]


class PrivacyRetentionPolicySchema(Schema):
    policy_id: str
    record_category: str
    retention_trigger: str
    retention_period_days: int | None = None
    review_due_at: str | None = None
    legal_basis: str
    owner_role: str
    legal_hold_behavior: str
    disposal_method: str
    evidence_requirement: str
    exception_status: str
    effective_from: str | None = None
    effective_until: str | None = None
    source_reference: str


class PrivacyRetentionPolicyPageSchema(PageResultSchema):
    items: list[PrivacyRetentionPolicySchema]


class PrivacyRetentionEvaluationSchema(Schema):
    id: str
    environment: str
    evaluated_at: str | None = None
    record_category: str
    candidate_count: int
    hold_count: int
    result_code: str
    metadata_only: bool
    policy_id: str


class PrivacyRetentionEvaluationPageSchema(PageResultSchema):
    items: list[PrivacyRetentionEvaluationSchema]


class PrivacyRetentionEvaluationResultSchema(Schema):
    """Explicit result envelope returned by the retention evaluation command."""

    items: list[PrivacyRetentionEvaluationSchema]


class NoticeAcceptanceSchema(Schema):
    purpose_workflow: str
    locale: str = "en"
    decision: str = PrivacyAcceptanceDecisionChoices.ACCEPTED


class RequestCreateSchema(Schema):
    request_type: str
    description: str = ""
    target_category: str = ""
    target_record_reference: str = ""
    staff_assisted: bool = False
    subject_reference: str = ""


class RequestTransitionSchema(Schema):
    reason_code: str = ""
    decision_notes: str = ""
    identity_verified: bool = False


class RequestAssignmentSchema(Schema):
    reviewer_id: int


class RequestFulfillmentSchema(Schema):
    protected_file_id: UUID


class IncidentMetadataSchema(Schema):
    containment_code: str = ""
    affected_count: int | None = None
    system_code: str = ""
    event_count: int | None = None
    authorization_reference: str = ""


class IncidentCreateSchema(Schema):
    category: str
    severity: str
    affected_workflow: str = ""
    affected_record_category: str = ""
    containment_code: str = ""
    metadata: IncidentMetadataSchema | None = None
    notification_decision: str = PrivacyIncidentNotificationDecisionChoices.PENDING
    related_event_references: list[str] = Field(default_factory=list)
    safe_summary_code: str = ""


class IncidentTransitionSchema(Schema):
    reason_code: str = ""
    safe_evidence: IncidentMetadataSchema | None = None


class IncidentNotificationSchema(Schema):
    decision: str
    reason_code: str = ""
    safe_evidence: IncidentMetadataSchema | None = None


class LegalHoldCreateSchema(Schema):
    record_category: str
    reason_code: str
    record_reference: str = ""
    safe_reference: str = ""


class LegalHoldReleaseSchema(Schema):
    reason_code: str = ""


def _actor(request):
    auth = getattr(request, "auth", None)
    if auth is None:
        auth = authenticate_bearer_request(request)
    return getattr(auth, "user", None)


def _page(page: PageQuery, page_size: PageSizeQuery):
    try:
        return page_request_from_values(page, page_size)
    except ContractValidationError as exc:
        raise ValidationError() from exc


def _run(request, operation_id, payload, operation, replay):
    prepared = prepare_api_operation(request, operation_id)
    return run_api_mutation(
        request,
        operation_id,
        payload,
        operation,
        replay,
        prepared_operation=prepared,
    )


def _outcome(value, projector, path):
    return ApiMutationOutcome(value=projector(value), related_object=value, safe_response_path=path)


def _request_replay(request):
    def replay(key):
        from .models import DataSubjectRequest

        row = DataSubjectRequest.objects.filter(pk=key.related_object_id).first()
        if row is None or not can_view_request(_actor(request), row):
            return None
        return projections.request_projection(row)

    return replay


def _incident_replay(request):
    def replay(key):
        from .models import PrivacyIncident

        row = PrivacyIncident.objects.filter(pk=key.related_object_id).first()
        return queries.incident_detail(_actor(request), row.incident_code) if row else None

    return replay


def _hold_replay(request):
    def replay(key):
        return queries.legal_hold_detail(_actor(request), key.related_object_id)

    return replay


def _acceptance_replay(key):
    from .models import PrivacyAcceptanceEvent

    event = PrivacyAcceptanceEvent.objects.select_related("notice_revision").filter(pk=key.related_object_id).first()
    return projections.acceptance_projection(event)


def _safe_metadata(payload: IncidentMetadataSchema | None):
    if payload is None:
        return ()
    values = []
    for key in ("containment_code", "system_code", "authorization_reference"):
        value = getattr(payload, key, "")
        if value:
            values.append((key, value))
    for key in ("affected_count", "event_count"):
        value = getattr(payload, key, None)
        if value is not None:
            values.append((key, value))
    return tuple(values)


def _safe_request_payload(command):
    return {
        "request_type": command.request_type,
        "target_category": command.target_category,
        "record_reference_present": bool(command.target_record_reference),
        "description_present": bool(command.description),
        "staff_assisted": command.staff_assisted,
    }


def _safe_incident_payload(command):
    return {
        "category": command.category,
        "severity": command.severity,
        "affected_workflow": command.affected_workflow,
        "affected_record_category": command.affected_record_category,
        "notification_decision": command.notification_decision,
        "related_event_count": len(command.related_event_references),
    }


@router.get(
    "/notices/{notice_identifier}/",
    auth=None,
    response=PrivacyNoticeSchema,
    exclude_unset=True,
    operation_id="privacy_notice_view",
)
def notice_view(request, notice_identifier: str):
    prepare_api_operation(request, "privacy_notice_view")
    purpose = str(request.GET.get("purpose_workflow", "") or "").strip()
    locale = str(request.GET.get("locale", "en") or "en").strip()
    notice = selectors.current_notice(notice_identifier, purpose, locale=locale)
    if notice is None:
        raise NotFoundError()
    projection = projections.notice_projection(notice)
    if projection is None:
        raise NotFoundError()
    return projection


@router.post(
    "/notices/{notice_identifier}/accept/",
    auth=None,
    response=PrivacyAcceptanceProjectionSchema,
    exclude_unset=True,
    operation_id="privacy_notice_accept",
)
def notice_accept(request, notice_identifier: str, payload: NoticeAcceptanceSchema):
    actor = _actor(request)
    subject_reference = f"user:{actor.pk}" if actor is not None else ""
    token = ""
    if actor is None:
        session = getattr(request, "session", None)
        access_id = session.get("form_collection_verified_access_id") if session is not None else None
        if not access_id:
            raise PermissionDeniedError()
        # Reuse the Form Collection verified-access validator so a revoked,
        # expired, submitted, or session-mismatched invitation cannot be used
        # as a privacy-notice acceptance context.
        from apps.form_collection.models import FormInvitation
        from apps.form_collection.services import get_verified_invitation_for_destination

        invitation = FormInvitation.objects.select_related("collection").filter(pk=access_id).first()
        if invitation is None or invitation.collection is None:
            raise PermissionDeniedError()
        try:
            verified = get_verified_invitation_for_destination(
                session,
                expected_target_form_key=invitation.target_form_key,
                expected_form_type=invitation.collection.form_type,
            )
        except ValidationError as exc:
            raise PermissionDeniedError() from exc
        subject_reference = f"verified-access:{verified.pk}"
        token = str(verified.pk)
    command = PrivacyNoticeAcceptanceCommand(
        notice_identifier=notice_identifier,
        purpose_workflow=payload.purpose_workflow,
        locale=payload.locale,
        decision=payload.decision,
        subject_reference=subject_reference,
        token=token,
    )
    prepare_api_operation(request, "privacy_notice_accept")
    event = record_notice_acceptance_command(
        actor=actor,
        command=command,
        source_route="/api/v1/privacy/notices/accept/",
        request_correlation_id=str(getattr(request, "_compass_request_id", "") or ""),
    )
    return projections.acceptance_projection(event)


@router.post(
    "/notices/{notice_identifier}/withdraw/",
    response=PrivacyAcceptanceProjectionSchema,
    exclude_unset=True,
    operation_id="privacy_notice_withdraw",
)
def notice_withdraw(request, notice_identifier: str, payload: NoticeAcceptanceSchema):
    actor = _actor(request)
    if actor is None:
        raise PermissionDeniedError()
    command = PrivacyNoticeAcceptanceCommand(
        notice_identifier=notice_identifier,
        purpose_workflow=payload.purpose_workflow,
        locale=payload.locale,
        decision=PrivacyAcceptanceDecisionChoices.WITHDRAWN,
        subject_reference=f"user:{actor.pk}",
    )
    return _run(
        request,
        "privacy_notice_withdraw",
        {"notice_identifier": notice_identifier, "purpose_workflow": command.purpose_workflow},
        lambda: _outcome(
            withdraw_notice_acceptance_command(
                actor=actor,
                command=command,
                source_route="/api/v1/privacy/notices/withdraw/",
                request_correlation_id=str(getattr(request, "_compass_request_id", "") or ""),
            ),
            projections.acceptance_projection,
            "/api/v1/privacy/acceptances/",
        ),
        _acceptance_replay,
    )


@router.get(
    "/acceptances/",
    response=PrivacyAcceptancePageSchema,
    exclude_unset=True,
    operation_id="privacy_acceptance_list",
)
def acceptance_list(request, page: PageQuery, page_size: PageSizeQuery):
    prepare_api_operation(request, "privacy_acceptance_list")
    return queries.acceptance_page(_actor(request), _page(page, page_size), purpose_workflow=request.GET.get("purpose_workflow", "")).as_dict()


@router.get(
    "/requests/",
    response=PrivacyRequestPageSchema,
    exclude_unset=True,
    operation_id="privacy_requests_list",
)
def request_list(request, page: PageQuery, page_size: PageSizeQuery):
    prepare_api_operation(request, "privacy_requests_list")
    return queries.request_page(_actor(request), _page(page, page_size)).as_dict()


@router.post(
    "/requests/",
    response=PrivacyRequestProjectionSchema,
    exclude_unset=True,
    operation_id="privacy_request_create",
)
def request_create(request, payload: RequestCreateSchema):
    actor = _actor(request)
    command = DataSubjectRequestCreateCommand(
        request_type=payload.request_type,
        description=payload.description,
        target_category=payload.target_category,
        target_record_reference=payload.target_record_reference,
        staff_assisted=payload.staff_assisted,
        subject_reference=payload.subject_reference,
    )
    return _run(
        request,
        "privacy_request_create",
        _safe_request_payload(command),
        lambda: _outcome(
            create_data_subject_request_command(
                actor=actor,
                command=command,
                source_route="/api/v1/privacy/requests/",
                request_correlation_id=str(getattr(request, "_compass_request_id", "") or ""),
            ),
            projections.request_projection,
            "/api/v1/privacy/requests/",
        ),
        _request_replay(request),
    )


@router.get(
    "/requests/{reference_code}/sensitive/",
    response=PrivacyRequestSensitiveSchema,
    exclude_unset=True,
    operation_id="privacy_request_sensitive_detail",
)
def request_sensitive_detail(request, reference_code: str):
    prepare_api_operation(request, "privacy_request_sensitive_detail")
    value = queries.request_sensitive_detail(_actor(request), reference_code)
    if value is None:
        raise NotFoundError()
    return value


@router.get(
    "/requests/{reference_code}/",
    response=PrivacyRequestProjectionSchema,
    exclude_unset=True,
    operation_id="privacy_request_detail",
)
def request_detail(request, reference_code: str):
    prepare_api_operation(request, "privacy_request_detail")
    value = queries.request_detail(_actor(request), reference_code)
    if value is None:
        raise NotFoundError()
    return value


@router.post(
    "/requests/{reference_code}/withdraw/",
    response=PrivacyRequestProjectionSchema,
    exclude_unset=True,
    operation_id="privacy_request_withdraw",
)
def request_withdraw(request, reference_code: str):
    actor = _actor(request)
    return _run(
        request,
        "privacy_request_withdraw",
        {"reference_code": reference_code},
        lambda: _outcome(
            withdraw_data_subject_request_command(actor=actor, reference_code=reference_code),
            projections.request_projection,
            f"/api/v1/privacy/requests/{reference_code}/",
        ),
        _request_replay(request),
    )


@router.post(
    "/requests/{reference_code}/assign/",
    response=PrivacyRequestProjectionSchema,
    exclude_unset=True,
    operation_id="privacy_request_assign",
)
def request_assign(request, reference_code: str, payload: RequestAssignmentSchema):
    actor = _actor(request)
    command = PrivacyRequestAssignmentCommand(reviewer_id=str(payload.reviewer_id))
    return _run(
        request,
        "privacy_request_assign",
        {"reference_code": reference_code, "reviewer_id": command.reviewer_id},
        lambda: _outcome(
            assign_data_subject_request_command(actor=actor, reference_code=reference_code, command=command),
            projections.request_projection,
            f"/api/v1/privacy/requests/{reference_code}/",
        ),
        _request_replay(request),
    )


def _request_transition(request, reference_code, operation_id, decision, payload):
    actor = _actor(request)
    command = PrivacyRequestTransitionCommand(
        decision=decision,
        reason_code=payload.reason_code,
        decision_notes=payload.decision_notes,
        identity_verified=payload.identity_verified,
    )
    return _run(
        request,
        operation_id,
        {
            "reference_code": reference_code,
            "decision": decision,
            "reason_code": command.reason_code,
            "decision_notes_present": bool(command.decision_notes),
            "identity_verified": command.identity_verified,
        },
        lambda: _outcome(
            transition_data_subject_request_command(
                actor=actor, reference_code=reference_code, command=command
            ),
            projections.request_projection,
            f"/api/v1/privacy/requests/{reference_code}/",
        ),
        _request_replay(request),
    )


@router.post(
    "/requests/{reference_code}/identity-verify/",
    response=PrivacyRequestProjectionSchema,
    exclude_unset=True,
    operation_id="privacy_request_identity_verify",
)
def request_identity_verify(request, reference_code: str, payload: RequestTransitionSchema):
    verified_payload = RequestTransitionSchema(
        reason_code=payload.reason_code,
        decision_notes=payload.decision_notes,
        identity_verified=True,
    )
    return _request_transition(
        request,
        reference_code,
        "privacy_request_identity_verify",
        PrivacyRequestDecisionChoices.APPROVE,
        verified_payload,
    )


@router.post(
    "/requests/{reference_code}/review/",
    response=PrivacyRequestProjectionSchema,
    exclude_unset=True,
    operation_id="privacy_request_review",
)
def request_review(request, reference_code: str, payload: RequestTransitionSchema):
    return _request_transition(request, reference_code, "privacy_request_review", PrivacyRequestDecisionChoices.APPROVE, payload)


@router.post(
    "/requests/{reference_code}/more-information/",
    response=PrivacyRequestProjectionSchema,
    exclude_unset=True,
    operation_id="privacy_request_more_information",
)
def request_more_information(request, reference_code: str, payload: RequestTransitionSchema):
    return _request_transition(request, reference_code, "privacy_request_more_information", PrivacyRequestDecisionChoices.MORE_INFORMATION, payload)


@router.post(
    "/requests/{reference_code}/approve/",
    response=PrivacyRequestProjectionSchema,
    exclude_unset=True,
    operation_id="privacy_request_approve",
)
def request_approve(request, reference_code: str, payload: RequestTransitionSchema):
    return _request_transition(request, reference_code, "privacy_request_approve", PrivacyRequestDecisionChoices.APPROVE, payload)


@router.post(
    "/requests/{reference_code}/partial/",
    response=PrivacyRequestProjectionSchema,
    exclude_unset=True,
    operation_id="privacy_request_partial_fulfill",
)
def request_partial(request, reference_code: str, payload: RequestTransitionSchema):
    return _request_transition(request, reference_code, "privacy_request_partial_fulfill", PrivacyRequestDecisionChoices.PARTIAL, payload)


@router.post(
    "/requests/{reference_code}/deny/",
    response=PrivacyRequestProjectionSchema,
    exclude_unset=True,
    operation_id="privacy_request_deny",
)
def request_deny(request, reference_code: str, payload: RequestTransitionSchema):
    return _request_transition(request, reference_code, "privacy_request_deny", PrivacyRequestDecisionChoices.DENY, payload)


@router.post(
    "/requests/{reference_code}/complete/",
    response=PrivacyRequestProjectionSchema,
    exclude_unset=True,
    operation_id="privacy_request_complete",
)
def request_complete(request, reference_code: str, payload: RequestTransitionSchema):
    return _request_transition(request, reference_code, "privacy_request_complete", PrivacyRequestDecisionChoices.COMPLETE, payload)


@router.post(
    "/requests/{reference_code}/close/",
    response=PrivacyRequestProjectionSchema,
    exclude_unset=True,
    operation_id="privacy_request_close",
)
def request_close(request, reference_code: str, payload: RequestTransitionSchema):
    return _request_transition(request, reference_code, "privacy_request_close", PrivacyRequestDecisionChoices.CLOSE, payload)


@router.post(
    "/requests/{reference_code}/fulfill/",
    response=PrivacyRequestProjectionSchema,
    exclude_unset=True,
    operation_id="privacy_request_fulfill",
)
def request_fulfill(request, reference_code: str, payload: RequestFulfillmentSchema):
    actor = _actor(request)
    command = PrivacyRequestFulfillmentCommand(protected_file_id=str(payload.protected_file_id))
    return _run(
        request,
        "privacy_request_fulfill",
        {"reference_code": reference_code, "protected_file_id": command.protected_file_id},
        lambda: _outcome(
            fulfill_data_subject_request_command(actor=actor, reference_code=reference_code, command=command),
            projections.request_projection,
            f"/api/v1/privacy/requests/{reference_code}/",
        ),
        _request_replay(request),
    )


@router.get(
    "/retention/policies/",
    response=PrivacyRetentionPolicyPageSchema,
    exclude_unset=True,
    operation_id="privacy_retention_policies",
)
def retention_policies(request, page: PageQuery, page_size: PageSizeQuery):
    prepare_api_operation(request, "privacy_retention_policies")
    return queries.retention_policy_page(_actor(request), _page(page, page_size)).as_dict()


@router.get(
    "/retention/evaluations/",
    response=PrivacyRetentionEvaluationPageSchema,
    exclude_unset=True,
    operation_id="privacy_retention_evaluations",
)
def retention_evaluations(request, page: PageQuery, page_size: PageSizeQuery):
    prepare_api_operation(request, "privacy_retention_evaluations")
    return queries.retention_evaluation_page(_actor(request), _page(page, page_size)).as_dict()


def _retention_replay(key):
    from .models import RetentionEvaluation

    first = RetentionEvaluation.objects.filter(pk=key.related_object_id).first()
    if first is None:
        return None
    rows = RetentionEvaluation.objects.filter(
        environment=first.environment,
        evaluated_at=first.evaluated_at,
    ).order_by("record_category")
    return {"items": [projections.retention_evaluation_projection(row) for row in rows]}


@router.post(
    "/retention/evaluate/",
    response=PrivacyRetentionEvaluationResultSchema,
    exclude_unset=True,
    operation_id="privacy_retention_evaluate",
)
def retention_evaluate(request):
    actor = _actor(request)

    def execute():
        rows = evaluate_retention_command(actor=actor, command=RetentionEvaluationCommand())
        value = {"items": [projections.retention_evaluation_projection(row) for row in rows]}
        return ApiMutationOutcome(
            value=value,
            related_object=rows[0] if rows else None,
            related_object_ids=tuple(str(row.pk) for row in rows),
            safe_response_path="/api/v1/privacy/retention/evaluations/",
        )

    return _run(request, "privacy_retention_evaluate", {}, execute, _retention_replay)


@router.get(
    "/legal-holds/",
    response=PrivacyLegalHoldPageSchema,
    exclude_unset=True,
    operation_id="privacy_legal_holds_list",
)
def legal_holds(request, page: PageQuery, page_size: PageSizeQuery):
    prepare_api_operation(request, "privacy_legal_holds_list")
    return queries.legal_hold_page(_actor(request), _page(page, page_size)).as_dict()


@router.get(
    "/legal-holds/{hold_id}/",
    response=PrivacyLegalHoldSchema,
    exclude_unset=True,
    operation_id="privacy_legal_hold_detail",
)
def legal_hold_detail(request, hold_id: UUID):
    prepare_api_operation(request, "privacy_legal_hold_detail")
    value = queries.legal_hold_detail(_actor(request), hold_id)
    if value is None:
        raise NotFoundError()
    return value


@router.post(
    "/legal-holds/",
    response=PrivacyLegalHoldSchema,
    exclude_unset=True,
    operation_id="privacy_legal_hold_create",
)
def legal_hold_create(request, payload: LegalHoldCreateSchema):
    actor = _actor(request)
    command = PrivacyLegalHoldCreateCommand(
        record_category=payload.record_category,
        reason_code=payload.reason_code,
        record_reference=payload.record_reference,
        safe_reference=payload.safe_reference,
    )
    return _run(
        request,
        "privacy_legal_hold_create",
        {"record_category": command.record_category, "reason_code": command.reason_code, "reference_present": bool(command.record_reference)},
        lambda: _outcome(
            place_legal_hold_command(actor=actor, command=command),
            projections.legal_hold_projection,
            "/api/v1/privacy/legal-holds/",
        ),
        _hold_replay(request),
    )


@router.post(
    "/legal-holds/{hold_id}/release/",
    response=PrivacyLegalHoldSchema,
    exclude_unset=True,
    operation_id="privacy_legal_hold_release",
)
def legal_hold_release(request, hold_id: UUID, payload: LegalHoldReleaseSchema):
    actor = _actor(request)
    command = PrivacyLegalHoldReleaseCommand(reason_code=payload.reason_code)
    return _run(
        request,
        "privacy_legal_hold_release",
        {"hold_id": str(hold_id), "reason_code": command.reason_code},
        lambda: _outcome(
            release_legal_hold_command(actor=actor, hold_id=hold_id, command=command),
            projections.legal_hold_projection,
            f"/api/v1/privacy/legal-holds/{hold_id}/",
        ),
        _hold_replay(request),
    )


@router.get(
    "/incidents/",
    response=PrivacyIncidentPageSchema,
    exclude_unset=True,
    operation_id="privacy_incidents_list",
)
def incident_list(request, page: PageQuery, page_size: PageSizeQuery):
    prepare_api_operation(request, "privacy_incidents_list")
    return queries.incident_page(_actor(request), _page(page, page_size)).as_dict()


@router.get(
    "/incidents/{incident_code}/",
    response=PrivacyIncidentProjectionSchema,
    exclude_unset=True,
    operation_id="privacy_incident_detail",
)
def incident_detail(request, incident_code: str):
    prepare_api_operation(request, "privacy_incident_detail")
    value = queries.incident_detail(_actor(request), incident_code)
    if value is None:
        raise NotFoundError()
    return value


@router.post(
    "/incidents/",
    response=PrivacyIncidentProjectionSchema,
    exclude_unset=True,
    operation_id="privacy_incident_create",
)
def incident_create(request, payload: IncidentCreateSchema):
    actor = _actor(request)
    command = PrivacyIncidentCreateCommand(
        category=payload.category,
        severity=payload.severity,
        affected_workflow=payload.affected_workflow,
        affected_record_category=payload.affected_record_category,
        containment_code=payload.containment_code,
        safe_metadata=_safe_metadata(payload.metadata),
        notification_decision=payload.notification_decision,
        related_event_references=tuple(payload.related_event_references),
        safe_summary_code=payload.safe_summary_code,
    )
    return _run(
        request,
        "privacy_incident_create",
        _safe_incident_payload(command),
        lambda: _outcome(
            create_privacy_incident_command(actor=actor, command=command),
            projections.incident_projection,
            "/api/v1/privacy/incidents/",
        ),
        _incident_replay(request),
    )


def _incident_transition(request, incident_code, operation_id, to_status, payload):
    actor = _actor(request)
    command = PrivacyIncidentTransitionCommand(
        to_status=to_status,
        reason_code=payload.reason_code,
        safe_evidence=_safe_metadata(payload.safe_evidence),
    )
    return _run(
        request,
        operation_id,
        {"incident_code": incident_code, "to_status": to_status, "reason_code": command.reason_code},
        lambda: _outcome(
            transition_privacy_incident_command(actor=actor, incident_code=incident_code, command=command),
            projections.incident_projection,
            f"/api/v1/privacy/incidents/{incident_code}/",
        ),
        _incident_replay(request),
    )


@router.post(
    "/incidents/{incident_code}/investigate/",
    response=PrivacyIncidentProjectionSchema,
    exclude_unset=True,
    operation_id="privacy_incident_investigate",
)
def incident_investigate(request, incident_code: str, payload: IncidentTransitionSchema):
    return _incident_transition(request, incident_code, "privacy_incident_investigate", PrivacyIncidentStatusChoices.INVESTIGATING, payload)


@router.post(
    "/incidents/{incident_code}/contain/",
    response=PrivacyIncidentProjectionSchema,
    exclude_unset=True,
    operation_id="privacy_incident_contain",
)
def incident_contain(request, incident_code: str, payload: IncidentTransitionSchema):
    actor = _actor(request)
    command = PrivacyIncidentTransitionCommand(
        to_status=PrivacyIncidentStatusChoices.CONTAINED,
        reason_code=payload.reason_code,
        safe_evidence=_safe_metadata(payload.safe_evidence),
    )
    return _run(
        request,
        "privacy_incident_contain",
        {"incident_code": incident_code, "reason_code": command.reason_code},
        lambda: _outcome(
            contain_privacy_incident_command(actor=actor, incident_code=incident_code, command=command),
            projections.incident_projection,
            f"/api/v1/privacy/incidents/{incident_code}/",
        ),
        _incident_replay(request),
    )


@router.post(
    "/incidents/{incident_code}/notification-assess/",
    response=PrivacyIncidentProjectionSchema,
    exclude_unset=True,
    operation_id="privacy_incident_notification_assess",
)
def incident_notification_assess(request, incident_code: str, payload: IncidentNotificationSchema):
    actor = _actor(request)
    if payload.decision not in PrivacyIncidentNotificationDecisionChoices.values:
        raise ValidationError()
    command = PrivacyIncidentTransitionCommand(
        to_status=PrivacyIncidentStatusChoices.OPEN,
        reason_code=payload.reason_code,
        safe_evidence=_safe_metadata(payload.safe_evidence),
        notification_decision=payload.decision,
    )
    return _run(
        request,
        "privacy_incident_notification_assess",
        {"incident_code": incident_code, "decision": command.notification_decision, "reason_code": command.reason_code},
        lambda: _outcome(
            assess_privacy_incident_notification_command(actor=actor, incident_code=incident_code, command=command),
            projections.incident_projection,
            f"/api/v1/privacy/incidents/{incident_code}/",
        ),
        _incident_replay(request),
    )


@router.post(
    "/incidents/{incident_code}/resolve/",
    response=PrivacyIncidentProjectionSchema,
    exclude_unset=True,
    operation_id="privacy_incident_resolve",
)
def incident_resolve(request, incident_code: str, payload: IncidentTransitionSchema):
    return _incident_transition(request, incident_code, "privacy_incident_resolve", PrivacyIncidentStatusChoices.RESOLVED, payload)


@router.post(
    "/incidents/{incident_code}/dismiss/",
    response=PrivacyIncidentProjectionSchema,
    exclude_unset=True,
    operation_id="privacy_incident_dismiss",
)
def incident_dismiss(request, incident_code: str, payload: IncidentTransitionSchema):
    return _incident_transition(request, incident_code, "privacy_incident_dismiss", PrivacyIncidentStatusChoices.DISMISSED, payload)
