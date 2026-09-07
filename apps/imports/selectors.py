"""Authorization-aware ORM selectors for student onboarding reads."""

from apps.common.exceptions import PermissionDeniedError
from apps.imports.models import StudentImportBatch, StudentImportRow
from apps.imports.policies import can_review_student_onboarding, can_view_student_onboarding
from apps.student_activation.models import StudentActivationInvitation


def _require_view(actor) -> None:
    if not can_view_student_onboarding(actor):
        raise PermissionDeniedError()


def _require_workspace(actor) -> None:
    if not can_review_student_onboarding(actor):
        raise PermissionDeniedError()


def select_batch(actor, batch_id: str):
    _require_view(actor)
    return StudentImportBatch.objects.filter(pk=batch_id).first()


def select_row(actor, batch_id: str, row_id: str):
    _require_workspace(actor)
    return StudentImportRow.objects.filter(pk=row_id, batch_id=batch_id).select_related("batch").first()


def select_invitation(actor, invitation_id: str):
    _require_view(actor)
    provisioned_users = StudentImportRow.objects.filter(
        batch__template_version="student_onboarding-v1",
        provisioned_user_id__isnull=False,
    ).values_list("provisioned_user_id", flat=True)
    return StudentActivationInvitation.objects.filter(
        pk=invitation_id,
        user_id__in=provisioned_users,
    ).first()
