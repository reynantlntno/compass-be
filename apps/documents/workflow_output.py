"""Workflow-owned PDF output adapters.

This module is the narrow bridge between domain-owned records and the shared
Documents renderer.  Callers provide frozen stable-reference commands; model
loading, authorization, lifecycle checks, rendering, storage, and protected
download delegation stay here.  No generic Documents API is exposed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time, timezone as dt_timezone
from typing import Callable

from django.db import transaction
from django.utils import timezone

from apps.access_control.rules import is_active_nonlegacy_actor
from apps.common.exceptions import (
    DependencyFailureError,
    NotFoundError,
    PermissionDeniedError,
    StaleStateError,
    ValidationError,
)
from apps.documents.commands import (
    WorkflowDocumentDownloadCommand,
    WorkflowDocumentGenerateCommand,
    WorkflowDocumentPreviewCommand,
)
from apps.documents.governance import DocumentOutputIntent, get_preview_template_version
from apps.documents.models import (
    DocumentStatusChoices,
    GeneratedDocument,
)
from apps.documents.preview_services import render_family_preview
from apps.documents.services import render_and_store_document
from apps.organizations.selectors import get_active_form_revision
from apps.security.downloads import ProtectedFileDownloadDenied, build_protected_file_download_response


@dataclass(frozen=True, slots=True)
class WorkflowDocumentDefinition:
    stable_key: str
    app_label: str
    model_name: str
    policy_key: str
    loader: Callable[[str, bool], object | None]
    authorized: Callable[[object, object], bool]
    lifecycle_eligible: Callable[[object, object], bool]
    context_builder: Callable[[object, object], dict]
    owner_user: Callable[[object], object | None]
    academic_year: Callable[[object], str]
    form_revision: Callable[[object], object | None]


def _scalar(value):
    if isinstance(value, (date, datetime, time)):
        return value.isoformat()
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _field(label: str, value=None, *, checkbox: bool = False) -> dict:
    return {"label": str(label)[:160], "value": _scalar(value), "checkbox": bool(checkbox), "checked": bool(value) if checkbox else False}


def _section(title: str, fields: list[dict]) -> dict:
    return {"title": str(title)[:120], "fields": tuple(fields)}


def _text_sections(value: dict, *, title: str, allowed_sections: tuple[str, ...]) -> list[dict]:
    """Convert validated form sections into fixed render rows.

    Only named top-level form sections are accepted.  Unknown metadata keys,
    model values, and nested arbitrary objects are discarded; this is not a
    generic JSON serializer.
    """
    sections: list[dict] = []
    for section_key in allowed_sections:
        raw = value.get(section_key) if isinstance(value, dict) else None
        fields: list[dict] = []
        if isinstance(raw, dict):
            for key in sorted(raw)[:80]:
                item = raw[key]
                if isinstance(item, (str, int, float, bool)) or item is None:
                    fields.append(_field(str(key).replace("_", " ").title(), item))
                elif isinstance(item, list):
                    bounded = ", ".join(str(entry)[:160] for entry in item[:20] if isinstance(entry, (str, int, float, bool)))
                    fields.append(_field(str(key).replace("_", " ").title(), bounded))
        elif isinstance(raw, (str, int, float, bool)) or raw is None:
            if raw not in (None, ""):
                fields.append(_field(title, raw))
        if fields:
            sections.append(_section(section_key.replace("_", " ").title(), fields))
    return sections


def _call_context(actor, target) -> dict:
    from apps.call_slips.selectors import get_printable_call_slip_dto

    dto = get_printable_call_slip_dto(actor, target.reference_code)
    if not dto:
        raise PermissionDeniedError()
    fields = [
        _field("Reference code", dto.get("reference_code")),
        _field("Issued date", dto.get("issued_date")),
        _field("Purpose", dto.get("purpose_label")),
        _field("Destination", dto.get("safe_destination")),
        _field("Mode", dto.get("mode_label")),
        _field("Scheduled start", dto.get("scheduled_start_at")),
        _field("Scheduled end", dto.get("scheduled_end_at")),
        _field("Expected duration (minutes)", dto.get("expected_duration_minutes")),
        _field("Instructions", dto.get("student_safe_instructions")),
    ]
    return {"sections": (_section("Call Slip / Interview Permit", fields),), "record_reference": target.reference_code}


def _referral_context(actor, target) -> dict:
    from apps.referrals.selectors import get_referral_sensitive_detail

    detail = get_referral_sensitive_detail(actor, target.reference_code)
    if detail is None:
        raise PermissionDeniedError()
    fields = [
        _field("Reference code", detail.get("reference_code")),
        _field("Status", detail.get("status")),
        _field("Source", detail.get("source_type")),
        _field("Reason category", detail.get("reason_category")),
        _field("Course", detail.get("course_snapshot")),
        _field("Year level", detail.get("year_level_snapshot")),
        _field("Block", detail.get("block_snapshot")),
        _field("Occurred at", detail.get("occurred_at")),
        _field("Source signed on", detail.get("source_signed_on")),
        _field("Reason details", detail.get("reason_text")),
    ]
    return {"sections": (_section("Referral Intake", fields),), "record_reference": target.reference_code}


def _routine_context(actor, target) -> dict:
    from apps.counseling.projections import (
        project_routine_interview_metadata,
        project_routine_interview_sensitive_detail,
        project_student_routine_interview,
    )
    from apps.access_control.rules import is_student

    metadata = (
        project_student_routine_interview(actor, target)
        if is_student(actor)
        else project_routine_interview_metadata(actor, target)
    ) or {}
    sensitive = project_routine_interview_sensitive_detail(actor, target) or {}
    detail_fields = []
    for key, label in (
        ("session_reference_code", "Session reference"), ("status", "Status"),
        ("visit_date", "Visit date"), ("visit_time", "Visit time"),
        ("duration_minutes", "Duration (minutes)"), ("nature_of_visit", "Nature of visit"),
    ):
        detail_fields.append(_field(label, metadata.get(key)))
    response_fields = []
    response_source = sensitive or (metadata if is_student(actor) else {})
    for key, label in (
        ("coping_challenges", "Coping challenges"), ("reason_for_coming", "Reason for coming"),
        ("difficulties_encountered", "Difficulties encountered"),
        ("stress_anxiety_management", "Stress/anxiety management"),
        ("academic_goals", "Academic goals"), ("recommendations", "Recommendations"),
    ):
        if key in response_source:
            response_fields.append(_field(label, response_source.get(key)))
    concern_fields = []
    concern_source = sensitive or metadata
    for key, label in (
        ("concern_academic", "Academic"), ("concern_friends", "Friends"),
        ("concern_classmates", "Classmates"), ("concern_vices", "Vices"),
        ("concern_love_life", "Love life"), ("concern_sleeping_problems", "Sleeping problems"),
        ("concern_family", "Family"), ("concern_financial", "Financial"),
        ("concern_suicidal_thought", "Suicidal thought/tendency"),
        ("concern_dorm_boarding_house", "Dorm/boarding house"),
        ("concern_past_painful_experience", "Past painful experience"),
        ("concern_others", "Others"),
    ):
        if key in concern_source:
            concern_fields.append(_field(label, concern_source.get(key), checkbox=True))
    evaluation_fields = []
    for key, label in (
        ("rating_emotionally", "Emotionally"), ("rating_academically", "Academically"),
        ("rating_physically", "Physically"), ("rating_socially", "Socially"),
        ("rating_spiritually", "Spiritually"), ("rating_financially", "Financially"),
        ("rating_others", "Others"),
    ):
        if key in sensitive or key in metadata:
            evaluation_fields.append(_field(label, (sensitive or metadata).get(key)))
    sections = [_section("Student Information and Visit Details", detail_fields)]
    if response_fields:
        sections.append(_section("Interview Questionnaire", response_fields))
    if concern_fields:
        sections.append(_section("Current Concerns", concern_fields))
    if evaluation_fields:
        sections.append(_section("Counselor Evaluation", evaluation_fields))
    return {"sections": tuple(sections), "record_reference": target.session.reference_code}


def _inventory_context(actor, target) -> dict:
    from apps.access_control.rules import is_student
    from apps.inventory.queries import snapshot_detail

    # Resolve answers through the existing purpose-specific inventory reader.
    # The renderer never receives the model's raw JSON field directly.
    projection = snapshot_detail(actor, str(target.pk)) or {}
    answers = projection.get("answers") if isinstance(projection, dict) else {}
    sections = _text_sections(
        answers if isinstance(answers, dict) else {},
        title="Answer",
        allowed_sections=(
            "personal_data", "family_data", "urgent_support_contact", "siblings", "unique",
            "living_conditions", "health_conditions", "support_context", "educational_background",
            "interest", "membership", "transportation", "perception",
        ),
    )
    if not sections:
        sections = [_section("Individual Inventory", [
            _field("Academic year", target.academic_year),
            _field("Status", target.status),
        ])]
    return {"sections": tuple(sections), "record_reference": str(target.pk), "owner_view": bool(is_student(actor))}


def _exit_context(actor, target) -> dict:
    from apps.exit_interviews.policies import can_view_exit_free_text

    fields = [
        _field("Reference code", target.reference_code),
        _field("Academic year", target.academic_year),
        _field("Program", target.program_snapshot),
        _field("College", target.college_snapshot),
        _field("Graduation year", target.graduation_year_snapshot),
        _field("Status", target.status),
    ]
    if can_view_exit_free_text(actor, target):
        fields.extend([
            _field("Civil status", target.civil_status),
            _field("Program schedule", target.program_schedule),
            _field("Suggestions", target.suggestions),
        ])
    for name, label in (
        ("self_pride_confidence", "Pride/confidence"),
        ("self_balance_academics_recreation", "Balance of academics and recreation"),
        ("self_holistic_wellbeing", "Holistic wellbeing"),
        ("self_career_clarity", "Career clarity"),
        ("dean_availability", "Dean availability"),
        ("faculty_availability", "Faculty availability"),
        ("curriculum_relevance", "Curriculum relevance"),
        ("counselor_availability", "Counselor availability"),
        ("facilities_maintenance", "Facilities maintenance"),
    ):
        fields.append(_field(label, getattr(target, name, None)))
    return {"sections": (_section("Exit Interview", fields),), "record_reference": target.reference_code}


def _gts_context(actor, target) -> dict:
    from apps.graduate_tracer.policies import can_view_gts_free_text

    fields = [
        _field("Reference code", target.reference_code),
        _field("Graduation year", target.graduation_year),
        _field("Program", target.program_snapshot),
        _field("College", target.college_snapshot),
        _field("Status", target.status),
        _field("Employment status", target.employment_status),
        _field("Presently employed", target.presently_employed),
        _field("Employment category", target.present_employment_category),
        _field("Place of work", target.place_of_work),
        _field("First job related", target.first_job_related, checkbox=True),
        _field("First job level", target.first_job_level),
        _field("Current job level", target.current_job_level),
        _field("Initial gross earnings", target.initial_gross_earnings),
        _field("Curriculum relevant", target.curriculum_relevant, checkbox=True),
    ]
    if can_view_gts_free_text(actor, target):
        fields.extend([
            _field("Job relevance summary", target.job_relevance_summary),
            _field("Business line", target.business_line),
            _field("First-job search duration", target.first_job_search_duration),
        ])
    return {"sections": (_section("Graduate Tracer Survey", fields),), "record_reference": target.reference_code}


def _load_call(reference: str, lock: bool):
    from apps.call_slips.models import CallSlip
    qs = CallSlip.objects.select_related("student", "student__student_profile", "assigned_counselor")
    return qs.select_for_update() if lock else qs


def _call_loader(reference: str, lock: bool):
    qs = _load_call(reference, lock)
    try:
        return qs.get(reference_code=reference)
    except CallSlip.DoesNotExist:
        try:
            return qs.get(pk=reference)
        except (CallSlip.DoesNotExist, ValueError, TypeError):
            return None


def _referral_loader(reference: str, lock: bool):
    from apps.referrals.models import Referral
    qs = Referral.objects.select_related("student", "student__student_profile", "assigned_counselor")
    query = qs.select_for_update() if lock else qs
    try:
        return query.get(reference_code=reference)
    except Referral.DoesNotExist:
        try:
            return query.get(pk=reference)
        except (Referral.DoesNotExist, ValueError, TypeError):
            return None


def _routine_loader(reference: str, lock: bool):
    from apps.counseling.models import RoutineInterviewRecord
    qs = RoutineInterviewRecord.objects.select_related("session", "session__student", "session__student__student_profile", "session__assigned_counselor")
    query = qs.select_for_update() if lock else qs
    try:
        return query.get(session__reference_code=reference)
    except RoutineInterviewRecord.DoesNotExist:
        try:
            return query.get(pk=reference)
        except (RoutineInterviewRecord.DoesNotExist, ValueError, TypeError):
            return None


def _inventory_loader(reference: str, lock: bool):
    from apps.inventory.models import StudentInventorySnapshot
    qs = StudentInventorySnapshot.objects.select_related("student_profile", "student_profile__user")
    try:
        return (qs.select_for_update() if lock else qs).get(pk=reference)
    except (StudentInventorySnapshot.DoesNotExist, ValueError, TypeError):
        return None


def _exit_loader(reference: str, lock: bool):
    from apps.exit_interviews.models import ExitInterviewResponse
    qs = ExitInterviewResponse.objects.select_related("student", "student__user", "form_revision", "form_revision__form_family")
    query = qs.select_for_update() if lock else qs
    try:
        return query.get(reference_code=reference)
    except ExitInterviewResponse.DoesNotExist:
        try:
            return query.get(pk=reference)
        except (ExitInterviewResponse.DoesNotExist, ValueError, TypeError):
            return None


def _gts_loader(reference: str, lock: bool):
    from apps.graduate_tracer.models import GraduateTracerResponse
    qs = GraduateTracerResponse.objects.select_related("student", "student__user", "form_revision", "form_revision__form_family")
    query = qs.select_for_update() if lock else qs
    try:
        return query.get(reference_code=reference)
    except GraduateTracerResponse.DoesNotExist:
        try:
            return query.get(pk=reference)
        except (GraduateTracerResponse.DoesNotExist, ValueError, TypeError):
            return None


def _call_authorized(actor, target):
    from apps.call_slips.policies import can_student_view_call_slip, can_view_call_slip_sensitive_detail
    return can_student_view_call_slip(actor, target) or can_view_call_slip_sensitive_detail(actor, target)


def _referral_authorized(actor, target):
    from apps.referrals.policies import can_view_referral_safe_metadata
    return can_view_referral_safe_metadata(actor, target)


def _routine_authorized(actor, target):
    from apps.counseling.policies import can_view_routine_interview_metadata
    return can_view_routine_interview_metadata(actor, target)


def _inventory_authorized(actor, target):
    from apps.inventory.policies import can_view_own_draft, can_view_submitted_inventory
    return can_view_own_draft(actor, target) or can_view_submitted_inventory(actor, target)


def _exit_authorized(actor, target):
    from apps.exit_interviews.policies import can_view_exit_response
    return can_view_exit_response(actor, target)


def _gts_authorized(actor, target):
    from apps.graduate_tracer.policies import can_view_gts_response
    return can_view_gts_response(actor, target)


def _call_eligible(actor, target):
    from apps.call_slips.models import EVER_ISSUED_STATUSES
    return bool(target.issued_at and target.status in EVER_ISSUED_STATUSES)


def _referral_eligible(actor, target):
    from apps.referrals.models import SUBMITTED_OR_LATER_STATUSES
    return target.status in SUBMITTED_OR_LATER_STATUSES


def _routine_eligible(actor, target):
    from apps.access_control.rules import is_student
    from apps.counseling.models import RoutineInterviewStatusChoices
    if is_student(actor):
        return target.status != RoutineInterviewStatusChoices.NOT_STARTED
    return target.status in {
        RoutineInterviewStatusChoices.COMPLETED,
        RoutineInterviewStatusChoices.FINALIZED,
        RoutineInterviewStatusChoices.LOCKED,
    }


def _inventory_eligible(actor, target):
    from apps.access_control.rules import is_student
    from apps.inventory.models import InventoryStatusChoices
    return target.status == InventoryStatusChoices.SUBMITTED or is_student(actor)


def _response_eligible(actor, target):
    return target.status not in {"DRAFT", "NOT_STARTED", "VOIDED"}


def _profile_user(profile):
    return getattr(profile, "user", None)


def _assert_expected_updated_at(target, expected_updated_at: str = "") -> None:
    """Reject a preview or generation request built from an old snapshot."""
    if not expected_updated_at:
        return
    try:
        expected = datetime.fromisoformat(expected_updated_at.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValidationError("expected_updated_at is invalid.") from exc

    current = getattr(target, "updated_at", None)
    if current is None:
        raise StaleStateError()
    if timezone.is_naive(expected):
        expected = timezone.make_aware(expected, dt_timezone.utc)
    if timezone.is_naive(current):
        current = timezone.make_aware(current, dt_timezone.utc)
    if current != expected:
        raise StaleStateError()


def _expected_stable_key(domain: str) -> str:
    try:
        return {
            "call_slips": "call_slip",
            "referrals": "referral_slip",
            "routine_interviews": "routine_interview",
            "inventory": "student_inventory",
            "exit_interviews": "exit_interview",
            "graduate_tracer": "graduate_tracer_survey",
        }[domain]
    except KeyError as exc:
        raise ValidationError("The document workflow is invalid.") from exc


DEFINITIONS = {
    "call_slips": WorkflowDocumentDefinition("call_slips", "call_slips", "CallSlip", "workflow_call_slip_document", _call_loader, _call_authorized, _call_eligible, _call_context, lambda t: t.student, lambda t: str(getattr(t, "created_at", timezone.now()).year), lambda t: get_active_form_revision("call_slip")),
    "referrals": WorkflowDocumentDefinition("referrals", "referrals", "Referral", "workflow_referral_document", _referral_loader, _referral_authorized, _referral_eligible, _referral_context, lambda t: t.student, lambda t: str(getattr(t, "created_at", timezone.now()).year), lambda t: get_active_form_revision("referral_slip")),
    "routine_interviews": WorkflowDocumentDefinition("routine_interviews", "counseling", "RoutineInterviewRecord", "workflow_routine_interview_document", _routine_loader, _routine_authorized, _routine_eligible, _routine_context, lambda t: t.session.student, lambda t: str(getattr(t, "created_at", timezone.now()).year), lambda t: get_active_form_revision("routine_interview")),
    "exit_interviews": WorkflowDocumentDefinition("exit_interviews", "exit_interviews", "ExitInterviewResponse", "workflow_exit_interview_document", _exit_loader, _exit_authorized, _response_eligible, _exit_context, lambda t: _profile_user(t.student), lambda t: str(t.academic_year or timezone.now().year), lambda t: t.form_revision),
    "graduate_tracer": WorkflowDocumentDefinition("graduate_tracer", "graduate_tracer", "GraduateTracerResponse", "workflow_graduate_tracer_document", _gts_loader, _gts_authorized, _response_eligible, _gts_context, lambda t: _profile_user(t.student), lambda t: str(t.graduation_year or timezone.now().year), lambda t: t.form_revision),
}

DEFINITIONS["inventory"] = WorkflowDocumentDefinition(
    "inventory", "inventory", "StudentInventorySnapshot", "workflow_inventory_document",
    _inventory_loader, _inventory_authorized, _inventory_eligible, _inventory_context,
    lambda t: _profile_user(t.student_profile), lambda t: str(t.academic_year or timezone.now().year),
    lambda t: get_active_form_revision("student_inventory"),
)


def _definition(domain: str) -> WorkflowDocumentDefinition:
    try:
        return DEFINITIONS[domain]
    except KeyError as exc:
        raise ValidationError("The document workflow is invalid.") from exc


def _load_authorized(
    actor,
    definition,
    reference: str,
    *,
    lock: bool,
    expected_updated_at: str = "",
):
    if not is_active_nonlegacy_actor(actor):
        raise PermissionDeniedError()
    target = definition.loader(reference, lock)
    if target is None or not definition.authorized(actor, target):
        raise NotFoundError()
    if not definition.lifecycle_eligible(actor, target):
        raise ValidationError("The workflow record is not eligible for document output.")
    _assert_expected_updated_at(target, expected_updated_at)
    return target


def _template_and_revision(definition, target):
    template_version = get_preview_template_version(_expected_stable_key(definition.stable_key))
    if not template_version:
        raise DependencyFailureError("The governed document template is unavailable.")
    # Preview may use the governance draft linked to the preview template;
    # official generation is revalidated by Documents against the active
    # revision before storage.
    revision = definition.form_revision(target) or getattr(template_version, "related_form_revision", None)
    if revision is None:
        raise DependencyFailureError("The governed form revision is unavailable.")
    family = getattr(revision, "form_family", None)
    if getattr(family, "stable_key", "") != _expected_stable_key(definition.stable_key):
        raise DependencyFailureError("The governed form revision does not match the workflow.")
    return template_version, revision


def _owner_tuple(definition, target) -> tuple[str, str, str]:
    object_id = target.pk
    return definition.app_label, definition.model_name, str(object_id)


def _metadata(document) -> dict:
    template_version = getattr(document, "template_version", None)
    template = getattr(template_version, "template", None)
    protected = getattr(document, "protected_file", None)
    return {
        "reference_code": document.reference_code,
        "document_status": document.document_status,
        "template_key": getattr(template, "stable_key", ""),
        "template_version": getattr(template_version, "version_label", ""),
        "output_format": getattr(template_version, "output_format", ""),
        "content_type": getattr(protected, "content_type", "application/pdf") if protected else "application/pdf",
        "generated_at": _scalar(document.generated_at),
        "released_at": _scalar(document.released_at),
    }


def preview_workflow_document(actor, domain: str, command: WorkflowDocumentPreviewCommand):
    if not isinstance(command, WorkflowDocumentPreviewCommand):
        raise ValidationError("Document preview requires a typed command.")
    definition = _definition(domain)
    if command.stable_key != _expected_stable_key(domain):
        raise ValidationError("The document family does not match the workflow.")
    target = _load_authorized(
        actor,
        definition,
        command.target_reference,
        lock=False,
        expected_updated_at=command.expected_updated_at,
    )
    template_version, revision = _template_and_revision(definition, target)
    artifact = render_family_preview(
        stable_key=command.stable_key,
        render_context=definition.context_builder(actor, target),
        form_revision=revision,
    )
    return artifact


@transaction.atomic
def generate_workflow_document(actor, domain: str, command: WorkflowDocumentGenerateCommand):
    if not isinstance(command, WorkflowDocumentGenerateCommand):
        raise ValidationError("Document generation requires a typed command.")
    definition = _definition(domain)
    if command.stable_key != _expected_stable_key(domain):
        raise ValidationError("The document family does not match the workflow.")
    target = _load_authorized(
        actor,
        definition,
        command.target_reference,
        lock=True,
        expected_updated_at=command.expected_updated_at,
    )
    template_version, revision = _template_and_revision(definition, target)
    existing = latest_workflow_document(definition, target)
    if existing:
        return existing
    try:
        return render_and_store_document(
            user=actor,
            template_version=template_version,
            render_context=definition.context_builder(actor, target),
            academic_year=definition.academic_year(target),
            form_revision=revision,
            generated_for_user=definition.owner_user(target),
            owning_app_label=definition.app_label,
            owning_model_name=definition.model_name,
            owning_object_id=str(target.pk),
            access_policy_key=definition.policy_key,
            output_intent=DocumentOutputIntent.OFFICIAL,
        )
    except (PermissionDeniedError, ValidationError, DependencyFailureError):
        raise
    except Exception as exc:
        raise DependencyFailureError("The protected document could not be generated.") from exc


def latest_workflow_document(definition: WorkflowDocumentDefinition, target):
    return (
        GeneratedDocument.objects
        .select_related("template_version", "template_version__template", "protected_file")
        .filter(
            owning_app_label=definition.app_label,
            owning_model_name=definition.model_name,
            owning_object_id=str(target.pk),
            template_version__template__stable_key=_expected_stable_key(definition.stable_key),
            document_status__in=(DocumentStatusChoices.GENERATED, DocumentStatusChoices.RELEASED),
            protected_file__isnull=False,
        )
        .order_by("-generated_at", "-created_at", "-pk")
        .first()
    )


def download_workflow_document(actor, domain: str, command: WorkflowDocumentDownloadCommand):
    if not isinstance(command, WorkflowDocumentDownloadCommand):
        raise ValidationError("Document download requires a typed command.")
    definition = _definition(domain)
    if command.stable_key != _expected_stable_key(domain):
        raise ValidationError("The document family does not match the workflow.")
    target = _load_authorized(actor, definition, command.target_reference, lock=False)
    document = latest_workflow_document(definition, target)
    if not document or not document.protected_file_id:
        raise NotFoundError()
    if not definition.authorized(actor, target):
        raise NotFoundError()
    try:
        return build_protected_file_download_response(actor, document.protected_file_id)
    except ProtectedFileDownloadDenied as exc:
        raise NotFoundError() from exc


def replay_generated_document(actor, domain: str, object_id) -> dict | None:
    """Replay only a safe idempotent generation projection."""
    definition = _definition(domain)
    document = (
        GeneratedDocument.objects
        .select_related("template_version", "template_version__template", "protected_file")
        .filter(pk=object_id)
        .first()
    )
    if document is None:
        return None
    target = definition.loader(str(document.owning_object_id), False)
    if target is None or not definition.authorized(actor, target):
        return None
    return _metadata(document)


def _policy_callback(domain: str, actor, action: str, *, generated_document=None, context=None) -> bool:
    definition = _definition(domain)
    target_id = str((context or {}).get("owning_object_id", ""))
    if generated_document is not None:
        target_id = str(generated_document.owning_object_id or target_id)
    if not target_id:
        return False
    target = definition.loader(target_id, False)
    if target is None:
        return False
    if action == "read_metadata":
        from apps.documents.policies import can_view_generated_document_metadata
        return can_view_generated_document_metadata(actor)
    return bool(definition.authorized(actor, target) and definition.lifecycle_eligible(actor, target))


def register_workflow_document_policies() -> None:
    from apps.documents.policies import register_generated_document_policy
    from apps.security.file_policies import register_file_policy
    from apps.documents.models import GeneratedDocument
    from apps.access_control.authority import has_fixed_capability
    from apps.access_control.capabilities import Capability

    for domain, definition in DEFINITIONS.items():
        register_generated_document_policy(
            definition.policy_key,
            lambda user, action, generated_document=None, context=None, domain=domain: _policy_callback(
                domain, user, action, generated_document=generated_document, context=context,
            ),
        )

        def _file_policy(user, protected_file, action, domain=domain):
            if action in ("read_metadata", "inspect"):
                return bool(has_fixed_capability(user, Capability.PROTECTED_FILES_METADATA_INSPECT))
            try:
                doc = GeneratedDocument.objects.get(protected_file=protected_file)
            except (GeneratedDocument.DoesNotExist, ValueError, TypeError):
                return False
            return _policy_callback(domain, user, "read_content", generated_document=doc, context={})

        register_file_policy(definition.policy_key, _file_policy)
