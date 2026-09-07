"""The only production write boundary for counseling history reasons."""

from apps.counseling.models import (
    CounselingAssignmentHistoryReasonChoices,
    CounselingSessionAssignmentHistory,
    CounselingSessionStatusHistory,
    CounselingStatusHistoryReasonChoices,
    RoutineInterviewStatusHistory,
    RoutineStatusHistoryReasonChoices,
)
from apps.common.exceptions import ValidationError


class CounselingHistoryReasonError(ValidationError):
    def __init__(self):
        super().__init__("counseling_history_reason_invalid")


def _require_member(reason, choices_type):
    if not isinstance(reason, choices_type):
        raise CounselingHistoryReasonError()
    return reason.value


def create_session_status_history(*, session, from_status, to_status, changed_by, reason):
    return CounselingSessionStatusHistory.objects.create(
        session=session,
        from_status=from_status,
        to_status=to_status,
        changed_by=changed_by,
        reason=_require_member(reason, CounselingStatusHistoryReasonChoices),
    )


def create_session_assignment_history(
    *, session, from_counselor, to_counselor, changed_by, reason
):
    return CounselingSessionAssignmentHistory.objects.create(
        session=session,
        from_counselor=from_counselor,
        to_counselor=to_counselor,
        changed_by=changed_by,
        reason=_require_member(reason, CounselingAssignmentHistoryReasonChoices),
    )


def create_routine_status_history(*, record, from_status, to_status, changed_by, reason):
    return RoutineInterviewStatusHistory.objects.create(
        record=record,
        from_status=from_status,
        to_status=to_status,
        changed_by=changed_by,
        reason=_require_member(reason, RoutineStatusHistoryReasonChoices),
    )
