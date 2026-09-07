"""Client-facing Form Collection API.

This router owns collection administration and verified invitation access.  It
does not expose generic form-answer CRUD and never returns invitation
verifiers, token hashes, or identity values.
"""

from __future__ import annotations

from datetime import date, datetime
from uuid import UUID

from ninja import Router, Schema

from apps.account_security.network import get_client_ip_from_headers
from apps.common.api.idempotency import ApiMutationOutcome, run_api_mutation
from apps.common.api.operations import prepare_api_operation
from apps.common.api.pagination import PageQuery, PageSizeQuery, page_request_from_values
from apps.common.api.schemas import PageResultSchema
from apps.common.contracts import ContractValidationError, RequestMetadata
from apps.common.exceptions import NotFoundError, ValidationError
from apps.form_collection import projections, queries
from apps.form_collection.commands import (
    FormCollectionConfigureCommand,
    FormCollectionCreateCommand,
    FormCollectionLifecycleCommand,
    InvitationBatchCommand,
    InvitationIssueCommand,
    InvitationRecipient,
    InvitationRevokeCommand,
    InvitationVerificationCommand,
)
from apps.form_collection.models import FormCollection, FormInvitation, InvitationBatch, UnlinkedFormSubmission
from apps.form_collection.services import (
    archive_collection,
    close_collection,
    configure_collection,
    create_collection,
    create_invitation_batch,
    get_verified_invitation_for_destination,
    issue_form_invitations,
    launch_collection,
    pause_collection,
    revoke_form_invitation,
    selector_session_hash,
    verify_invitation,
)
from apps.orchestration.commands import FormSubmissionMatchCommand
from apps.orchestration.use_cases import (
    link_form_submission_for_composition,
    reject_form_submission_match_for_composition,
)


router = Router(tags=["form-collections"])


class FormCollectionSchema(Schema):
    """Output-only collection projection."""

    id: str
    name: str
    description: str
    audience: str
    status: str
    start_at: datetime
    end_at: datetime
    form_type: str
    # These IDs are intentionally stringified in the existing public wire
    # projection. Request and path schemas remain integer-backed below.
    form_family_id: str | None = None
    form_revision_id: str | None = None
    created_at: datetime
    launched_at: datetime | None = None
    closed_at: datetime | None = None


class FormCollectionPageSchema(PageResultSchema):
    items: list[FormCollectionSchema]


class InvitationBatchSchema(Schema):
    """Output-only invitation batch projection."""

    id: str
    collection_id: str
    name: str
    source_type: str
    status: str
    total_requested: int
    total_issued: int
    total_failed: int
    issued_at: datetime | None = None
    created_at: datetime


class InvitationBatchPageSchema(PageResultSchema):
    items: list[InvitationBatchSchema]


class InvitationMetadataSchema(Schema):
    """Output-only invitation metadata without verifier or identifier hashes."""

    id: str
    selector: str
    collection_id: str
    invitation_batch_id: str | None = None
    target_form_key: str
    intended_recipient_name: str | None = None
    status: str
    expires_at: datetime
    max_uses: int
    used_count: int
    verified_at: datetime | None = None
    submitted_at: datetime | None = None
    linked_student: bool
    created_at: datetime


class InvitationMetadataPageSchema(PageResultSchema):
    items: list[InvitationMetadataSchema]


class VerifiedAccessSchema(Schema):
    """Output-only verified access context without token material."""

    invitation_id: str
    collection_id: str
    target_form_key: str
    form_type: str
    form_revision_id: str | None = None
    recipient_name: str | None = None
    status: str
    expires_at: datetime


class InvitationBatchIssueReceiptSchema(Schema):
    """Persisted batch receipt returned after invitation issuance."""

    batch_id: str
    status: str
    total_requested: int
    total_issued: int
    total_failed: int
    issued_at: datetime | None = None


class ManualMatchSchema(Schema):
    """Output-only redacted unlinked-submission review record."""

    id: str
    source_collection_id: str | None = None
    source_invitation_id: str | None = None
    name_snapshot: str | None = None
    program_snapshot: str | None = None
    student_match_status: str
    matched_at: datetime | None = None
    linked_at: datetime | None = None
    reviewed_at: datetime | None = None


class ManualMatchPageSchema(PageResultSchema):
    items: list[ManualMatchSchema]


class CollectionCreateSchema(Schema):
    name: str
    start_at: datetime
    end_at: datetime
    form_type: str
    form_family_id: int | None = None
    form_revision_id: int | None = None
    description: str = ""
    audience: str = "CUSTOM"


class CollectionConfigureSchema(Schema):
    name: str | None = None
    description: str | None = None
    audience: str | None = None
    start_at: datetime | None = None
    end_at: datetime | None = None
    form_family_id: int | None = None
    form_revision_id: int | None = None
    default_token_expiry_days: int | None = None
    identity_verification_policy: str | None = None
    max_uses_per_token: int | None = None
    allow_draft: bool | None = None
    expected_updated_at: str | None = None


class LifecycleSchema(Schema):
    reason: str = ""
    expected_updated_at: str | None = None


class BatchSchema(Schema):
    name: str
    source_type: str = "MANUAL"
    total_requested: int = 0


class RecipientSchema(Schema):
    email: str | None = None
    control_number: str | None = None
    student_number: str | None = None
    name: str | None = None
    surname: str | None = None
    birthdate: date | None = None


class IssueSchema(Schema):
    recipients: list[RecipientSchema]


class RevokeSchema(Schema):
    reason: str = ""
    expected_updated_at: str | None = None


class VerifySchema(Schema):
    selector: str
    verifier: str
    control_number: str | None = None
    surname: str | None = None
    birthdate: date | None = None
    student_number: str | None = None
    email: str | None = None
    otp: str | None = None


class MatchSchema(Schema):
    student_profile_id: int | None = None
    reason: str = ""
    expected_updated_at: str | None = None


def _actor(request):
    auth = getattr(request, "auth", None)
    return getattr(auth, "user", None)


def _page(page: PageQuery, page_size: PageSizeQuery):
    try:
        return page_request_from_values(page, page_size)
    except ContractValidationError as exc:
        raise ValidationError() from exc


def _request_metadata(request) -> RequestMetadata:
    session = getattr(request, "session", None)
    return RequestMetadata(
        ip_address=get_client_ip_from_headers(getattr(request, "META", {}) or {}),
        user_agent=str((getattr(request, "META", {}) or {}).get("HTTP_USER_AGENT", "") or ""),
        session_key=str(getattr(session, "session_key", "") or ""),
    )


def _replay_for(model, projector):
    def replay(key):
        object_id = getattr(key, "related_object_id", None)
        if not object_id:
            return None
        value = model.objects.filter(pk=object_id).first()
        return projector(value) if value is not None else None

    return replay


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


def _outcome(value, projector, path: str):
    return ApiMutationOutcome(
        value=projector(value),
        related_object=value,
        safe_response_path=path,
    )


def _batch_issue_receipt(batch):
    return {
        "batch_id": str(batch.pk),
        "status": batch.status,
        "total_requested": batch.total_requested,
        "total_issued": batch.total_issued,
        "total_failed": batch.total_failed,
        "issued_at": batch.issued_at.isoformat() if batch.issued_at else None,
    }


@router.get("/", response=FormCollectionPageSchema, exclude_unset=True, operation_id="form_collections_list")
def list_collections(request, page: PageQuery, page_size: PageSizeQuery):
    prepare_api_operation(request, "form_collections_list")
    return queries.collection_page(_actor(request), _page(page, page_size)).as_dict()


@router.post("/", response=FormCollectionSchema, exclude_unset=True, operation_id="form_collections_create")
def create_collection_route(request, payload: CollectionCreateSchema):
    command = FormCollectionCreateCommand(**payload.dict())
    return _run(
        request,
        "form_collections_create",
        {"command": payload.dict()},
        lambda: _outcome(
            create_collection(_actor(request), command),
            projections.collection,
            "/api/v1/form-collections/",
        ),
        _replay_for(FormCollection, projections.collection),
    )


@router.get("/access/current/", auth=None, response=VerifiedAccessSchema, exclude_unset=True, operation_id="form_collection_access_current")
def current_verified_access(request):
    session = getattr(request, "session", None)
    access_id = session.get("form_collection_verified_access_id") if session is not None else None
    if not access_id:
        raise NotFoundError()
    invitation = FormInvitation.objects.select_related("collection").filter(pk=access_id).first()
    if invitation is None:
        raise NotFoundError()
    try:
        verified = get_verified_invitation_for_destination(
            session,
            expected_target_form_key=invitation.target_form_key,
            expected_form_type=invitation.collection.form_type,
        )
    except ValidationError:
        raise NotFoundError()
    return queries.verified_access(verified)


@router.post("/invitations/verify/", auth=None, response=VerifiedAccessSchema, exclude_unset=True, operation_id="form_collection_invitation_verify")
def verify_invitation_route(request, payload: VerifySchema):
    command = InvitationVerificationCommand(**payload.dict())
    prepare_api_operation(request, "form_collection_invitation_verify")
    verified = verify_invitation(None, command, _request_metadata(request))
    if not isinstance(verified, FormInvitation):
        raise ValidationError()
    session = getattr(request, "session", None)
    if session is None:
        raise ValidationError()
    session["form_collection_verified_access_id"] = str(verified.pk)
    session["form_collection_verified_selector_hash"] = selector_session_hash(verified.selector)
    session.save()
    return queries.verified_access(verified)


@router.get("/{uuid:collection_id}/", response=FormCollectionSchema, exclude_unset=True, operation_id="form_collections_detail")
def collection_detail(request, collection_id: UUID):
    collection_id = str(collection_id)
    prepare_api_operation(request, "form_collections_detail")
    value = queries.collection_detail(_actor(request), collection_id)
    if value is None:
        raise NotFoundError()
    return value


@router.patch("/{uuid:collection_id}/", response=FormCollectionSchema, exclude_unset=True, operation_id="form_collections_configure")
def configure_collection_route(request, collection_id: UUID, payload: CollectionConfigureSchema):
    collection_id = str(collection_id)
    command = FormCollectionConfigureCommand(**payload.dict(exclude_unset=True))
    return _run(
        request,
        "form_collections_configure",
        {"collection_id": collection_id, "fields": [key for key in payload.dict(exclude_unset=True) if key != "expected_updated_at"]},
        lambda: _outcome(
            configure_collection(_actor(request), collection_id, command),
            projections.collection,
            f"/api/v1/form-collections/{collection_id}/",
        ),
        _replay_for(FormCollection, projections.collection),
    )


def _lifecycle_route(request, collection_id: UUID | str, operation_id: str, service, payload: LifecycleSchema):
    collection_id = str(collection_id)
    command = FormCollectionLifecycleCommand(**payload.dict(exclude_unset=True))
    from apps.common.request_dedup import build_command_fingerprint

    return _run(
        request,
        operation_id,
        {
            "collection_id": collection_id,
            "reason_fingerprint": build_command_fingerprint({"reason": command.reason}),
            "expected_updated_at": command.expected_updated_at,
        },
        lambda: _outcome(
            service(_actor(request), collection_id, command),
            projections.collection,
            f"/api/v1/form-collections/{collection_id}/",
        ),
        _replay_for(FormCollection, projections.collection),
    )


@router.post("/{uuid:collection_id}/launch/", response=FormCollectionSchema, exclude_unset=True, operation_id="form_collections_launch")
def launch(request, collection_id: UUID, payload: LifecycleSchema | None = None):
    return _lifecycle_route(request, collection_id, "form_collections_launch", launch_collection, payload or LifecycleSchema())


@router.post("/{uuid:collection_id}/pause/", response=FormCollectionSchema, exclude_unset=True, operation_id="form_collections_pause")
def pause(request, collection_id: UUID, payload: LifecycleSchema | None = None):
    return _lifecycle_route(request, collection_id, "form_collections_pause", pause_collection, payload or LifecycleSchema())


@router.post("/{uuid:collection_id}/close/", response=FormCollectionSchema, exclude_unset=True, operation_id="form_collections_close")
def close(request, collection_id: UUID, payload: LifecycleSchema | None = None):
    return _lifecycle_route(request, collection_id, "form_collections_close", close_collection, payload or LifecycleSchema())


@router.post("/{uuid:collection_id}/archive/", response=FormCollectionSchema, exclude_unset=True, operation_id="form_collections_archive")
def archive(request, collection_id: UUID, payload: LifecycleSchema | None = None):
    return _lifecycle_route(request, collection_id, "form_collections_archive", archive_collection, payload or LifecycleSchema())


@router.get("/{uuid:collection_id}/batches/", response=InvitationBatchPageSchema, exclude_unset=True, operation_id="form_collection_batches_list")
def list_batches(request, collection_id: UUID, page: PageQuery, page_size: PageSizeQuery):
    collection_id = str(collection_id)
    prepare_api_operation(request, "form_collection_batches_list")
    return queries.invitation_batch_page(_actor(request), collection_id, _page(page, page_size)).as_dict()


@router.post("/{uuid:collection_id}/batches/", response=InvitationBatchSchema, exclude_unset=True, operation_id="form_collection_batch_create")
def create_batch(request, collection_id: UUID, payload: BatchSchema):
    collection_id = str(collection_id)
    command = InvitationBatchCommand(**payload.dict())
    return _run(
        request,
        "form_collection_batch_create",
        {"collection_id": collection_id, **payload.dict()},
        lambda: _outcome(
            create_invitation_batch(_actor(request), collection_id, command),
            projections.invitation_batch,
            f"/api/v1/form-collections/{collection_id}/batches/",
        ),
        _replay_for(InvitationBatch, projections.invitation_batch),
    )


@router.post("/batches/{batch_id}/issue/", response=InvitationBatchIssueReceiptSchema, exclude_unset=True, operation_id="form_collection_batch_issue")
def issue_batch(request, batch_id: UUID, payload: IssueSchema):
    batch_id = str(batch_id)
    recipients = tuple(InvitationRecipient(**item.dict(exclude_unset=True)) for item in payload.recipients)
    command = InvitationIssueCommand(recipients=recipients)
    from apps.common.request_dedup import build_command_fingerprint

    def operation():
        # The domain service deliberately returns raw verifiers to its
        # controlled delivery boundary.  This API discards them and returns
        # only the persisted batch receipt.
        issue_form_invitations(_actor(request), batch_id, command)
        batch = InvitationBatch.objects.get(pk=batch_id)
        receipt = _batch_issue_receipt(batch)
        return ApiMutationOutcome(
            value=receipt,
            related_object=batch,
            safe_response_path=f"/api/v1/form-collections/batches/{batch.pk}/",
        )

    recipient_fingerprint = build_command_fingerprint(
        {
            "recipients": [
                {
                    "email": item.email,
                    "control_number": item.control_number,
                    "student_number": item.student_number,
                    "name": item.name,
                    "surname": item.surname,
                    "birthdate": item.birthdate,
                }
                for item in recipients
            ]
        }
    )
    fingerprint = {
        "batch_id": batch_id,
        "recipient_count": len(recipients),
        "recipient_fingerprint": recipient_fingerprint,
    }
    return _run(
        request,
        "form_collection_batch_issue",
        fingerprint,
        operation,
        _replay_for(InvitationBatch, _batch_issue_receipt),
    )


@router.get("/{uuid:collection_id}/invitations/", response=InvitationMetadataPageSchema, exclude_unset=True, operation_id="form_collection_invitations_list")
def list_invitations(request, collection_id: UUID, page: PageQuery, page_size: PageSizeQuery):
    collection_id = str(collection_id)
    prepare_api_operation(request, "form_collection_invitations_list")
    return queries.invitation_page(_actor(request), collection_id, _page(page, page_size)).as_dict()


@router.post("/invitations/{invitation_id}/revoke/", response=InvitationMetadataSchema, exclude_unset=True, operation_id="form_collection_invitation_revoke")
def revoke_invitation(request, invitation_id: UUID, payload: RevokeSchema):
    invitation_id = str(invitation_id)
    command = InvitationRevokeCommand(**payload.dict(exclude_unset=True))
    from apps.common.request_dedup import build_command_fingerprint

    return _run(
        request,
        "form_collection_invitation_revoke",
        {
            "invitation_id": invitation_id,
            "reason_fingerprint": build_command_fingerprint({"reason": command.reason}),
            "expected_updated_at": command.expected_updated_at,
        },
        lambda: _outcome(
            revoke_form_invitation(_actor(request), invitation_id, command),
            projections.invitation_metadata,
            f"/api/v1/form-collections/invitations/{invitation_id}/",
        ),
        _replay_for(FormInvitation, projections.invitation_metadata),
    )


@router.get("/manual-matches/", response=ManualMatchPageSchema, exclude_unset=True, operation_id="form_collection_manual_matches_list")
def list_manual_matches(request, page: PageQuery, page_size: PageSizeQuery):
    prepare_api_operation(request, "form_collection_manual_matches_list")
    return queries.manual_match_page(_actor(request), _page(page, page_size)).as_dict()


@router.post("/manual-matches/{record_id}/link/", response=ManualMatchSchema, exclude_unset=True, operation_id="form_collection_manual_match_link")
def link_manual_match(request, record_id: UUID, payload: MatchSchema):
    record_id = str(record_id)
    command = FormSubmissionMatchCommand(record_id=record_id, **payload.dict(exclude_unset=True))
    return _run(
        request,
        "form_collection_manual_match_link",
        {"record_id": record_id, "student_profile_id": command.student_profile_id, "reason": command.reason},
        lambda: _outcome(
            link_form_submission_for_composition(_actor(request), command),
            projections.manual_match,
            f"/api/v1/form-collections/manual-matches/{record_id}/",
        ),
        _replay_for(UnlinkedFormSubmission, projections.manual_match),
    )


@router.post("/manual-matches/{record_id}/reject/", response=ManualMatchSchema, exclude_unset=True, operation_id="form_collection_manual_match_reject")
def reject_manual_match(request, record_id: UUID, payload: MatchSchema | None = None):
    record_id = str(record_id)
    command = FormSubmissionMatchCommand(record_id=record_id, **(payload.dict(exclude_unset=True) if payload else {}))
    return _run(
        request,
        "form_collection_manual_match_reject",
        {"record_id": record_id, "reason": command.reason},
        lambda: _outcome(
            reject_form_submission_match_for_composition(_actor(request), command),
            projections.manual_match,
            f"/api/v1/form-collections/manual-matches/{record_id}/",
        ),
        _replay_for(UnlinkedFormSubmission, projections.manual_match),
    )
