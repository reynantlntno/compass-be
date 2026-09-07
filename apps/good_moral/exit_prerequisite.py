"""Metadata-only Exit Interview prerequisite evaluation for Good Moral."""

from dataclasses import dataclass
from datetime import date
from types import SimpleNamespace

from apps.exit_interviews.models import (
    AssignmentStatus,
    ExitInterviewAssignment,
    ExitInterviewResponse,
    ExitResponseStatus,
)
from apps.governance.selectors import resolve_effective_policy
from apps.good_moral.models import RequestTypeChoices
from apps.good_moral.policy import GOOD_MORAL_POLICY_DEFINITION
from apps.profiles.models import StudentLifecycleChoices
from apps.common.exceptions import ValidationError


NOT_CONFIGURED = "NOT_CONFIGURED"
DISABLED = "DISABLED"
NOT_APPLICABLE = "NOT_APPLICABLE"
NOT_COMPLETED = "NOT_COMPLETED"
SUBMITTED = "SUBMITTED"
NEEDS_CORRECTION = "NEEDS_CORRECTION"
SATISFIED = "SATISFIED"


@dataclass(frozen=True)
class ExitPrerequisiteResult:
    status: str
    policy_state: str
    cohort_year: int | None = None
    response_status: str = ""
    response_reference: str = ""
    blocking_reason: str = ""
    acknowledgment_required: bool = False
    acknowledgment_present: bool = False

    @property
    def is_satisfied(self):
        return self.status in {NOT_APPLICABLE, SATISFIED}


class ExitPrerequisiteError(ValidationError):
    """Raised at an enabled Good Moral boundary when completion is missing."""


def _effective_policy():
    """Return the typed central policy projection used by this evaluator."""

    record = resolve_effective_policy("good_moral.exit_prerequisite")
    if record is None:
        return None
    try:
        config = GOOD_MORAL_POLICY_DEFINITION.normalize_configuration(
            record.configuration_json or {}
        )
    except (ValidationError, ValueError):
        return None
    return SimpleNamespace(
        status="ACTIVE",
        activated_at=record.activated_at,
        enforcement_enabled=bool(config.get("enforcement_enabled", False)),
        effective_graduation_year=config.get("effective_graduation_year"),
        grandfather_existing_requests=bool(config.get("grandfather_existing_requests", False)),
        counselor_acknowledgment_required=bool(config.get("counselor_acknowledgment_required", False)),
        qualifying_exit_statuses=tuple(config.get("qualifying_exit_statuses", ())),
        enforce_on_submission=bool(config.get("enforce_on_submission", False)),
        enforce_on_approval=bool(config.get("enforce_on_approval", False)),
        enforce_on_generation=bool(config.get("enforce_on_generation", False)),
        enforce_on_release=bool(config.get("enforce_on_release", False)),
        reopen_void_behavior=config.get("reopen_void_behavior", "BLOCK_FINAL_BOUNDARY"),
    )


def _year(value):
    if isinstance(value, date):
        return value.year
    text = str(value or "").strip()
    if len(text) == 4 and text.isdigit():
        return int(text)
    return None


def _metadata_year(value):
    if not isinstance(value, dict):
        return None
    return _year(value.get("graduation_year"))


def _cohort_evidence(request, *, lock=False):
    """Return metadata-only cohort evidence; never touches response_json."""
    student = request.student_profile
    years = set()
    request_year = _year(request.applicant_graduation_date)
    if request_year:
        years.add(request_year)

    responses = ExitInterviewResponse.objects.filter(student=student)
    if lock:
        responses = responses.select_for_update()
    responses = responses.only(
        "graduation_year_snapshot",
        "status",
        "reference_code",
        "counselor_acknowledged_at",
    )
    for response in responses:
        response_year = _year(response.graduation_year_snapshot)
        if response_year:
            years.add(response_year)

    assignments = ExitInterviewAssignment.objects.filter(
        student=student,
        status__in=(AssignmentStatus.ASSIGNED, AssignmentStatus.COMPLETED, AssignmentStatus.OVERDUE),
    ).select_related("collection")
    for assignment in assignments:
        assignment_year = _metadata_year(assignment.metadata_json)
        if assignment_year:
            years.add(assignment_year)
        collection_year = _metadata_year(getattr(assignment.collection, "metadata_json", None))
        if collection_year:
            years.add(collection_year)

    return years


def evaluate_exit_prerequisite(request, *, lock=False) -> ExitPrerequisiteResult:
    policy = _effective_policy()
    if policy is None:
        return ExitPrerequisiteResult(status=NOT_CONFIGURED, policy_state=NOT_CONFIGURED)
    if policy.status != "ACTIVE" or not policy.enforcement_enabled:
        return ExitPrerequisiteResult(status=DISABLED, policy_state=DISABLED)
    # The current prerequisite is a graduating-batch requirement, not a
    # universal Good Moral gate. Alumni and already-graduated requests use the
    # graduate certificate variant and are not silently covered by it.
    if (
        request.request_type != RequestTypeChoices.STUDENT
        or request.applicant_lifecycle_status != StudentLifecycleChoices.GRADUATING
    ):
        return ExitPrerequisiteResult(
            status=NOT_APPLICABLE,
            policy_state="ACTIVE",
            cohort_year=_year(request.applicant_graduation_date),
        )
    if not policy.effective_graduation_year:
        return ExitPrerequisiteResult(
            status=NOT_COMPLETED,
            policy_state="ACTIVE",
            blocking_reason="The effective graduation cohort is unresolved.",
        )

    if policy.grandfather_existing_requests and policy.activated_at and request.created_at < policy.activated_at:
        return ExitPrerequisiteResult(
            status=NOT_APPLICABLE,
            policy_state="ACTIVE",
            cohort_year=_year(request.applicant_graduation_date),
        )

    years = _cohort_evidence(request, lock=lock)
    if len(years) > 1:
        return ExitPrerequisiteResult(
            status=NOT_COMPLETED,
            policy_state="ACTIVE",
            blocking_reason="Graduation-linked cohort evidence conflicts.",
        )
    cohort_year = next(iter(years), None)
    if cohort_year is None:
        return ExitPrerequisiteResult(
            status=NOT_COMPLETED,
            policy_state="ACTIVE",
            blocking_reason="Graduation-linked cohort evidence is unavailable.",
        )
    if cohort_year != policy.effective_graduation_year:
        return ExitPrerequisiteResult(
            status=NOT_APPLICABLE,
            policy_state="ACTIVE",
            cohort_year=cohort_year,
        )

    responses = ExitInterviewResponse.objects.filter(student=request.student_profile)
    if lock:
        responses = responses.select_for_update()
    response = (
        responses
        .only("status", "reference_code", "submitted_at", "counselor_acknowledged_at")
        .order_by("-submitted_at", "-updated_at")
        .first()
    )
    if response is None or response.status in (ExitResponseStatus.DRAFT, ExitResponseStatus.VOIDED):
        return ExitPrerequisiteResult(
            status=NOT_COMPLETED,
            policy_state="ACTIVE",
            cohort_year=cohort_year,
            response_status=response.status if response else "",
            response_reference=response.reference_code if response else "",
            acknowledgment_required=policy.counselor_acknowledgment_required,
        )
    if response.status == ExitResponseStatus.REOPENED_FOR_CORRECTION:
        return ExitPrerequisiteResult(
            status=NEEDS_CORRECTION,
            policy_state="ACTIVE",
            cohort_year=cohort_year,
            response_status=response.status,
            response_reference=response.reference_code,
            acknowledgment_required=policy.counselor_acknowledgment_required,
            acknowledgment_present=bool(response.counselor_acknowledged_at),
        )

    qualifying = set(policy.qualifying_exit_statuses or [])
    acknowledgment_present = bool(response.counselor_acknowledged_at)
    if response.status not in qualifying:
        status = SUBMITTED if response.status == ExitResponseStatus.SUBMITTED else NOT_COMPLETED
        return ExitPrerequisiteResult(
            status=status,
            policy_state="ACTIVE",
            cohort_year=cohort_year,
            response_status=response.status,
            response_reference=response.reference_code,
            acknowledgment_required=policy.counselor_acknowledgment_required,
            acknowledgment_present=acknowledgment_present,
        )
    if policy.counselor_acknowledgment_required and not acknowledgment_present:
        return ExitPrerequisiteResult(
            status=SUBMITTED,
            policy_state="ACTIVE",
            cohort_year=cohort_year,
            response_status=response.status,
            response_reference=response.reference_code,
            blocking_reason="Counselor acknowledgment is required.",
            acknowledgment_required=True,
            acknowledgment_present=False,
        )
    return ExitPrerequisiteResult(
        status=SATISFIED,
        policy_state="ACTIVE",
        cohort_year=cohort_year,
        response_status=response.status,
        response_reference=response.reference_code,
        acknowledgment_required=policy.counselor_acknowledgment_required,
        acknowledgment_present=acknowledgment_present,
    )


def enforce_exit_prerequisite(request, *, gate: str):
    """Raise only when an active policy explicitly enables this boundary."""
    policy = _effective_policy()
    if policy is None or not policy.enforcement_enabled:
        return None
    enabled = {
        "submission": policy.enforce_on_submission,
        "approval": policy.enforce_on_approval,
        "generation": policy.enforce_on_generation,
        "release": policy.enforce_on_release,
    }.get(gate, False)
    if not enabled:
        return None
    result = evaluate_exit_prerequisite(request, lock=True)
    if (
        result.status in {NEEDS_CORRECTION, NOT_COMPLETED, SUBMITTED}
        and policy.reopen_void_behavior == "ALLOW_EXISTING_ISSUED"
    ):
        from apps.good_moral.models import GoodMoralStatusChoices
        if request.status in {
            GoodMoralStatusChoices.GENERATED,
            GoodMoralStatusChoices.PRINTED,
            GoodMoralStatusChoices.RELEASED,
        }:
            return result
    if not result.is_satisfied:
        raise ExitPrerequisiteError(
            f"Exit Interview prerequisite is not satisfied ({result.status})."
        )
    return result
