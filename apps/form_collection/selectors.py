"""Scoped ORM selectors for Form Collection reads."""

from django.db.models import QuerySet

from apps.access_control.rules import is_active_nonlegacy_actor
from apps.form_collection.models import (
    CollectionStatus,
    FormCollection,
    FormInvitation,
    InvitationBatch,
    StudentMatchStatus,
    UnlinkedFormSubmission,
)
from apps.form_collection.policies import (
    can_review_manual_match,
    can_view_collection,
    can_view_invitation_metadata,
)


def list_collections_for_actor(actor) -> QuerySet[FormCollection]:
    if not is_active_nonlegacy_actor(actor) or not can_view_collection(actor, None):
        return FormCollection.objects.none()
    return FormCollection.objects.filter(
        status__in=(CollectionStatus.DRAFT, CollectionStatus.ACTIVE, CollectionStatus.PAUSED, CollectionStatus.CLOSED),
    ).select_related("form_family", "form_revision").order_by("-created_at", "-pk")


def get_collection_for_actor(actor, collection_id) -> FormCollection | None:
    if not is_active_nonlegacy_actor(actor):
        return None
    collection = FormCollection.objects.select_related("form_family", "form_revision").filter(pk=collection_id).first()
    if collection is None or not can_view_collection(actor, collection):
        return None
    return collection


def list_invitation_batches_for_actor(actor, collection_id) -> QuerySet[InvitationBatch]:
    collection = get_collection_for_actor(actor, collection_id)
    if collection is None:
        return InvitationBatch.objects.none()
    return InvitationBatch.objects.filter(collection_id=collection.pk).order_by("-created_at", "-pk")


def list_invitation_metadata_for_actor(actor, collection_id) -> QuerySet[FormInvitation]:
    collection = get_collection_for_actor(actor, collection_id)
    if collection is None:
        return FormInvitation.objects.none()
    return FormInvitation.objects.filter(collection_id=collection.pk).select_related("collection").order_by("-created_at", "-pk")


def get_invitation_for_actor(actor, invitation_id) -> FormInvitation | None:
    invitation = FormInvitation.objects.select_related("collection", "invitation_batch").filter(pk=invitation_id).first()
    if invitation is None or not can_view_invitation_metadata(actor, invitation):
        return None
    return invitation


def list_manual_review_queue(actor) -> QuerySet[UnlinkedFormSubmission]:
    if not is_active_nonlegacy_actor(actor) or not can_review_manual_match(actor):
        return UnlinkedFormSubmission.objects.none()
    return UnlinkedFormSubmission.objects.filter(
        student_match_status=StudentMatchStatus.NEEDS_MANUAL_REVIEW,
    ).order_by("-created_at", "-pk")


def get_manual_review_record(actor, record_id) -> UnlinkedFormSubmission | None:
    if not is_active_nonlegacy_actor(actor) or not can_review_manual_match(actor):
        return None
    return UnlinkedFormSubmission.objects.filter(pk=record_id).first()


def resolve_invitation_by_safe_selector_or_hash(*, selector: str | None = None, token_hash: str | None = None) -> FormInvitation | None:
    if selector:
        return FormInvitation.objects.select_related("collection").filter(selector=selector).first()
    if token_hash:
        return FormInvitation.objects.select_related("collection").filter(token_hash=token_hash).first()
    return None


def get_verified_invitation_session_context(form_invitation: FormInvitation) -> dict[str, object]:
    return {
        "token_id": str(form_invitation.id),
        "collection_id": str(form_invitation.collection_id),
        "target_form_key": form_invitation.target_form_key,
        "recipient_name": form_invitation.intended_recipient_name,
        "expires_at": form_invitation.expires_at.isoformat(),
        "status": form_invitation.status,
    }


def get_collection_progress_counts(collection: FormCollection) -> dict[str, int]:
    return {
        "issued": collection.form_invitations.filter(status="ISSUED").count(),
        "opened": collection.form_invitations.filter(status="OPENED").count(),
        "verified": collection.form_invitations.filter(status="VERIFIED").count(),
        "draft_started": collection.form_invitations.filter(status="DRAFT_STARTED").count(),
        "submitted": collection.form_invitations.filter(status="SUBMITTED").count(),
        "linked": collection.form_invitations.filter(status="LINKED_TO_ACCOUNT").count(),
    }
