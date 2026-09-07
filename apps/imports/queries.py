"""Bounded read selectors and model-free onboarding projections."""

from apps.common.contracts import PageRequest, PageResult, page_queryset
from apps.common.exceptions import PermissionDeniedError
from apps.imports.cache import get_cached_onboarding_catalog_metadata
from apps.imports.models import StudentImportBatch, StudentImportRow
from apps.imports.policies import can_review_student_onboarding, can_view_student_onboarding
from apps.imports.projections import (
    batch_projection,
    catalog_projection,
    invitation_projection,
    row_editor_projection,
    row_projection,
)
from apps.notifications.models import EmailDelivery
from apps.student_activation.models import StudentActivationInvitation
from django.db.models import Count, OuterRef, Subquery


def _authorized(actor) -> None:
    if not can_view_student_onboarding(actor):
        raise PermissionDeniedError()


def batch_queryset(actor):
    _authorized(actor)
    return (
        StudentImportBatch.objects.select_related("replacement_of")
        .annotate(_row_count=Count("rows"))
        .order_by("-created_at", "-pk")
    )


def batch_page(actor, page: PageRequest) -> dict:
    return page_queryset(batch_queryset(actor), page, batch_projection)


def batch_detail(actor, batch_id: str):
    _authorized(actor)
    batch = (
        StudentImportBatch.objects.annotate(_row_count=Count("rows"))
        .filter(pk=batch_id)
        .first()
    )
    return batch_projection(batch) if batch else None


def batch_object(batch_id: str):
    """Return one internal batch object for mutation outcome bookkeeping."""
    return StudentImportBatch.objects.filter(pk=batch_id).first()


def row_page(actor, batch_id: str, page: PageRequest, *, editor: bool = False) -> dict:
    if not can_review_student_onboarding(actor):
        raise PermissionDeniedError()
    queryset = (
        StudentImportRow.objects.filter(batch_id=batch_id)
        .select_related("batch")
        .order_by("row_number", "pk")
    )
    return page_queryset(queryset, page, row_editor_projection if editor else row_projection)


def row_detail(actor, batch_id: str, row_id: str, *, editor: bool = False):
    if not can_review_student_onboarding(actor):
        raise PermissionDeniedError()
    row = StudentImportRow.objects.filter(pk=row_id, batch_id=batch_id).select_related("batch").first()
    if row is None:
        return None
    return row_editor_projection(row) if editor else row_projection(row)


def invitation_queryset_for_batch(batch_id: str):
    user_ids = StudentImportRow.objects.filter(
        batch_id=batch_id,
        batch__template_version="student_onboarding-v1",
        provisioned_user_id__isnull=False,
    ).values_list("provisioned_user_id", flat=True)
    delivery_state = (
        EmailDelivery.objects.filter(
            template_key="student_activation",
            related_object_id=OuterRef("pk"),
        )
        .order_by("-created_at", "-id")
        .values("delivery_state")[:1]
    )
    return (
        StudentActivationInvitation.objects.filter(user_id__in=user_ids)
        .annotate(_delivery_state=Subquery(delivery_state))
        .order_by("-created_at", "-pk")
    )


def _onboarding_invitation_queryset():
    user_ids = StudentImportRow.objects.filter(
        batch__template_version="student_onboarding-v1",
        provisioned_user_id__isnull=False,
    ).values_list("provisioned_user_id", flat=True)
    return StudentActivationInvitation.objects.filter(user_id__in=user_ids)


def onboarding_invitation_exists(invitation_id: str) -> bool:
    """Keep imports invitation operations inside the student_onboarding ownership boundary."""
    return _onboarding_invitation_queryset().filter(pk=invitation_id).exists()


def _delivery_state(invitation) -> str:
    delivery = (
        EmailDelivery.objects.filter(
            template_key="student_activation",
            related_object_id=str(invitation.pk),
        )
        .order_by("-created_at", "-id")
        .first()
    )
    return str(delivery.delivery_state or delivery.status) if delivery else ""


def invitation_page(actor, batch_id: str, page: PageRequest) -> dict:
    _authorized(actor)
    queryset = invitation_queryset_for_batch(batch_id)
    return page_queryset(
        queryset,
        page,
        lambda item: invitation_projection(item, delivery_state=getattr(item, "_delivery_state", "") or ""),
    )


def invitation_detail(actor, invitation_id: str):
    _authorized(actor)
    delivery_state = (
        EmailDelivery.objects.filter(
            template_key="student_activation",
            related_object_id=OuterRef("pk"),
        )
        .order_by("-created_at", "-id")
        .values("delivery_state")[:1]
    )
    invitation = (
        _onboarding_invitation_queryset()
        .annotate(_delivery_state=Subquery(delivery_state))
        .filter(pk=invitation_id)
        .first()
    )
    return (
        invitation_projection(invitation, delivery_state=getattr(invitation, "_delivery_state", "") or "")
        if invitation
        else None
    )


def catalog_page(page: PageRequest) -> dict:
    value = catalog_projection(get_cached_onboarding_catalog_metadata())
    placements = value["placements"]
    result = PageResult(
        items=tuple(placements[page.offset : page.offset + page.page_size]),
        page=page.page,
        page_size=page.page_size,
        total=len(placements),
    ).as_dict()
    result["version"] = value["version"]
    result["demo_only"] = value["demo_only"]
    return result
