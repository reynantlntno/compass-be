"""Privacy and records-governance services.

The service layer is intentionally the privacy policy boundary.  Views and
workers receive safe result codes from here; they do not inspect or copy
protected narratives, request bodies, tokens, or provider payloads.
"""

from __future__ import annotations

import hashlib
import hmac
import uuid

from django.conf import settings
from django.core import exceptions as django_exceptions
from apps.common.exceptions import (
    GovernanceError,
    LifecycleConflictError,
    NotFoundError,
    PermissionDeniedError,
    ValidationError,
)
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils import timezone

from apps.access_control.authority import has_fixed_capability
from apps.access_control.capabilities import Capability

from apps.access_control.rules import (
    is_active_nonlegacy_actor,
    is_counselor,
    is_gco_staff,
    is_head_guidance,
    is_it_admin,
    is_student,
)
from apps.audit.services import audit_log
from apps.governance.runtime_config import is_policy_active
from apps.system.readiness_services import environment_name, is_deployment_environment

from .choices import (
    LegalHoldStatusChoices,
    PrivacyAcceptanceDecisionChoices,
    PrivacyActorTypeChoices,
    PrivacyApprovalStateChoices,
    PrivacyIncidentCategoryChoices,
    PrivacyIncidentNotificationDecisionChoices,
    PrivacyIncidentSeverityChoices,
    PrivacyIncidentStatusChoices,
    PrivacyNoticeStatusChoices,
    PrivacyRequestDecisionChoices,
    PrivacyRequestStatusChoices,
    PrivacyRequestTypeChoices,
    ReviewerAuthorizationStatusChoices,
)
from .commands import (
    DataSubjectRequestCreateCommand,
    PrivacyNoticeAcceptanceCommand,
    PrivacyIncidentCreateCommand,
    PrivacyIncidentTransitionCommand,
    PrivacyLegalHoldCreateCommand,
    PrivacyLegalHoldReleaseCommand,
    PrivacyNoticeRevisionApprovalCommand,
    PrivacyNoticeRevisionRetirementCommand,
    PrivacyRequestAssignmentCommand,
    PrivacyRequestFulfillmentCommand,
    PrivacyRequestTransitionCommand,
    RetentionEvaluationCommand,
    PrivacyNoticeRevisionCommand,
    PrivacyWorkflowBindingCommand,
)
from .models import (
    DataSubjectRequest,
    DataSubjectRequestTransition,
    PrivacyAcceptanceEvent,
    PrivacyIncident,
    PrivacyIncidentTransition,
    PrivacyLegalHold,
    PrivacyNoticeRevision,
    PrivacyReviewerAuthorization,
    PrivacyWorkflowBinding,
    RetentionEvaluation,
    SAFE_INCIDENT_METADATA_KEYS,
    SAFE_METADATA_VALUE_RE,
)


def hash_safe_reference(value: str, *, namespace: str = "privacy") -> str:
    """Return a deterministic HMAC reference without persisting the input."""

    if value is None or str(value) == "":
        raise ValidationError("A non-empty reference is required.")
    secret = str(getattr(settings, "AUDIT_HASH_SECRET", settings.SECRET_KEY)).encode("utf-8")
    message = f"{namespace}:{value}".encode("utf-8")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


@transaction.atomic
def create_privacy_reviewer_authorization(
    *,
    actor,
    authorized_user,
    scopes,
    valid_from,
    valid_until,
    source_reference,
):
    """Create reviewer scope through the DPO gate and privacy aggregate."""

    from apps.governance.dpo_services import is_current_dpo

    if not is_policy_active("privacy.reviewer_authorizations"):
        raise PermissionDeniedError("Privacy reviewer authorization is disabled by policy.")
    if not is_current_dpo(actor):
        raise PermissionDeniedError("Only the appointed DPO may authorize privacy reviewers.")
    if not is_active_nonlegacy_actor(authorized_user):
        raise ValidationError("A privacy reviewer must be an active, non-legacy account.")
    row = PrivacyReviewerAuthorization(
        authorized_user=authorized_user,
        scopes=scopes,
        valid_from=valid_from,
        valid_until=valid_until,
        source_reference=source_reference,
        authorized_by=actor,
        status=ReviewerAuthorizationStatusChoices.ACTIVE,
    )
    try:
        row.full_clean()
    except django_exceptions.ValidationError as exc:
        raise ValidationError() from exc
    row.save()
    event = audit_log(
        action_type="PRIVACY_REVIEWER_AUTHORIZED",
        event_category="PRIVACY",
        target_model="privacy.PrivacyReviewerAuthorization",
        target_object_id=str(row.pk),
        actor_user=actor,
        source_app="apps.privacy",
        metadata={"authorized_user_id": authorized_user.pk, "source_reference": source_reference[:120]},
    )
    if event is None:
        raise GovernanceError("Privacy reviewer authorization audit could not be recorded.")
    return row


@transaction.atomic
def create_privacy_reviewer_authorization_command(*, actor, command):
    from apps.accounts.models import User
    from apps.privacy.commands import PrivacyReviewerAuthorizationCommand

    if not isinstance(command, PrivacyReviewerAuthorizationCommand):
        raise ValidationError("A typed reviewer authorization command is required.")
    if not command.scopes or not command.categories or len(command.scopes) > 30 or len(command.categories) > 100:
        raise ValidationError("Reviewer scopes and categories must be explicit and bounded.")
    if any(not str(value).strip() or len(str(value)) > 120 for value in (*command.scopes, *command.categories)):
        raise ValidationError("Reviewer scope values are invalid.")
    if len(command.source_reference.strip()) > 255:
        raise ValidationError("Reviewer authorization evidence is invalid.")
    authorized_user = User.objects.select_for_update().filter(pk=command.authorized_user_id).first()
    if authorized_user is None:
        raise ValidationError("The authorized reviewer does not exist.")
    return create_privacy_reviewer_authorization(
        actor=actor,
        authorized_user=authorized_user,
        scopes={"scopes": list(command.scopes), "categories": list(command.categories)},
        valid_from=command.valid_from,
        valid_until=command.valid_until,
        source_reference=command.source_reference,
    )


@transaction.atomic
def revoke_privacy_reviewer_authorization(*, actor, authorization, reason_code="REVOKED_BY_DPO"):
    """Revoke reviewer scope with append-only privacy audit evidence."""

    from apps.governance.dpo_services import is_current_dpo

    if not is_policy_active("privacy.reviewer_authorizations"):
        raise PermissionDeniedError("Privacy reviewer authorization is disabled by policy.")
    if not is_current_dpo(actor):
        raise PermissionDeniedError("Only the appointed DPO may revoke reviewer authorization.")
    current = PrivacyReviewerAuthorization.objects.select_for_update().get(pk=authorization.pk)
    if current.status == ReviewerAuthorizationStatusChoices.REVOKED:
        return current
    current.status = ReviewerAuthorizationStatusChoices.REVOKED
    current.revoked_by = actor
    current.revoked_at = timezone.now()
    current.save(update_fields=["status", "revoked_by", "revoked_at", "updated_at"])
    event = audit_log(
        action_type="PRIVACY_REVIEWER_AUTHORIZATION_REVOKED",
        event_category="PRIVACY",
        target_model="privacy.PrivacyReviewerAuthorization",
        target_object_id=str(current.pk),
        actor_user=actor,
        source_app="apps.privacy",
        metadata={"reason_code": str(reason_code)[:80]},
    )
    if event is None:
        raise GovernanceError("Privacy reviewer revocation audit could not be recorded.")
    return current


@transaction.atomic
def revoke_privacy_reviewer_authorization_by_id(*, actor, authorization_id, reason_code="REVOKED_BY_DPO"):
    authorization = PrivacyReviewerAuthorization.objects.select_for_update().filter(pk=authorization_id).first()
    if authorization is None:
        raise NotFoundError()
    return revoke_privacy_reviewer_authorization(
        actor=actor,
        authorization=authorization,
        reason_code=reason_code,
    )


def _actor_type(actor) -> str:
    if not actor or not getattr(actor, "is_authenticated", False):
        return PrivacyActorTypeChoices.ANONYMOUS
    if is_head_guidance(actor):
        return PrivacyActorTypeChoices.HEAD_GUIDANCE
    if is_student(actor):
        return PrivacyActorTypeChoices.STUDENT
    if is_counselor(actor):
        return PrivacyActorTypeChoices.COUNSELOR
    if is_gco_staff(actor):
        return PrivacyActorTypeChoices.GCO_STAFF
    if is_it_admin(actor):
        return PrivacyActorTypeChoices.IT_ADMIN
    return PrivacyActorTypeChoices.SYSTEM


def resolve_current_notice(notice_identifier: str, purpose_workflow: str, *, locale: str = "en"):
    """Resolve exactly one published notice, or return ``None`` fail-closed."""

    if not is_policy_active("privacy.notices"):
        return None

    binding = PrivacyWorkflowBinding.objects.filter(
        purpose_workflow=purpose_workflow,
    ).first()
    if (
        binding is None
        or binding.status != PrivacyNoticeStatusChoices.PUBLISHED
        or not binding.notice_revision_id
    ):
        return None
    now = timezone.now()
    rows = list(
        PrivacyNoticeRevision.objects.filter(
            notice_identifier=notice_identifier,
            purpose_workflow=purpose_workflow,
            locale=locale,
            status=PrivacyNoticeStatusChoices.PUBLISHED,
            approval_state=PrivacyApprovalStateChoices.APPROVED,
        ).filter(Q(effective_at__isnull=True) | Q(effective_at__lte=now)).order_by("-effective_at", "-created_at")[:2]
    )
    if len(rows) != 1:
        return None
    if binding.notice_revision_id != rows[0].pk:
        return None
    return rows[0]


def record_acceptance(
    *,
    notice_revision,
    purpose_workflow: str,
    subject_reference: str,
    actor=None,
    decision: str = PrivacyAcceptanceDecisionChoices.ACCEPTED,
    source_route: str,
    request_correlation_id: str = "",
    session_reference: str = "",
    actor_type: str | None = None,
    subject_reference_hash: str = "",
):
    """Append exact-version evidence using HMAC-only subject/session data."""

    if decision not in PrivacyAcceptanceDecisionChoices.values:
        raise ValidationError("Unsupported privacy acceptance decision.")
    if notice_revision.purpose_workflow != purpose_workflow:
        raise ValidationError("Notice purpose does not match the workflow.")
    if (
        notice_revision.status != PrivacyNoticeStatusChoices.PUBLISHED
        or notice_revision.approval_state != PrivacyApprovalStateChoices.APPROVED
    ):
        raise ValidationError("This privacy notice is not available for new acceptance.")
    binding = PrivacyWorkflowBinding.objects.filter(
        purpose_workflow=purpose_workflow,
        status=PrivacyNoticeStatusChoices.PUBLISHED,
        notice_revision_id=notice_revision.pk,
    ).first()
    if binding is None:
        raise ValidationError("The workflow has no active notice binding.")
    event = PrivacyAcceptanceEvent.objects.create(
        notice_revision=notice_revision,
        purpose_workflow=purpose_workflow,
        subject_reference_hash=subject_reference_hash or hash_safe_reference(subject_reference, namespace=f"subject:{purpose_workflow}"),
        subject_user=actor if getattr(actor, "is_authenticated", False) else None,
        actor_type=actor_type or _actor_type(actor),
        decision=decision,
        source_route=(source_route or "")[:255],
        request_correlation_id=(request_correlation_id or "")[:100],
        token_session_hash=(
            hash_safe_reference(session_reference, namespace=f"session:{purpose_workflow}")
            if session_reference
            else ""
        ),
    )
    audit_log(
        action_type="PRIVACY_ACCEPTANCE_RECORDED",
        event_category="PRIVACY_GOVERNANCE",
        target_model="PrivacyAcceptanceEvent",
        target_object_id=str(event.pk),
        actor_user=actor if getattr(actor, "is_authenticated", False) else None,
        source_app="privacy",
        source_view=source_route,
        request_id=request_correlation_id,
        metadata={
            "purpose_workflow": purpose_workflow,
            "decision": decision,
            "notice_version": notice_revision.version,
        },
    )
    return event


def record_verified_token_acceptance(
    *,
    notice_revision,
    purpose_workflow: str,
    token: str,
    subject_reference: str,
    source_route: str,
    request_correlation_id: str = "",
    actor=None,
):
    """Adapter for a verified token; the raw token exists only for hashing."""

    if not token:
        raise ValidationError("A verified token is required.")
    return record_acceptance(
        notice_revision=notice_revision,
        purpose_workflow=purpose_workflow,
        subject_reference=subject_reference,
        actor=actor,
        source_route=source_route,
        request_correlation_id=request_correlation_id,
        session_reference=token,
        actor_type=PrivacyActorTypeChoices.VERIFIED_TOKEN,
    )


@transaction.atomic
def record_notice_acceptance_command(*, actor, command: PrivacyNoticeAcceptanceCommand, source_route: str, request_correlation_id: str = ""):
    """Resolve and record one notice decision without accepting ORM inputs."""

    if not isinstance(command, PrivacyNoticeAcceptanceCommand):
        raise ValidationError()
    if not isinstance(command.notice_identifier, str) or not command.notice_identifier or len(command.notice_identifier) > 120:
        raise ValidationError()
    if not isinstance(command.purpose_workflow, str) or not command.purpose_workflow or len(command.purpose_workflow) > 100:
        raise ValidationError()
    if command.decision not in PrivacyAcceptanceDecisionChoices.values:
        raise ValidationError()
    if command.token and command.decision != PrivacyAcceptanceDecisionChoices.ACCEPTED:
        raise ValidationError()
    resolved = resolve_current_notice(
        command.notice_identifier,
        command.purpose_workflow,
        locale=command.locale or "en",
    )
    if resolved is None:
        raise NotFoundError()
    notice = PrivacyNoticeRevision.objects.select_for_update().filter(pk=resolved.pk).first()
    if notice is None:
        raise NotFoundError()
    if command.token:
        return record_verified_token_acceptance(
            notice_revision=notice,
            purpose_workflow=command.purpose_workflow,
            token=command.token,
            subject_reference=command.subject_reference,
            source_route=source_route,
            request_correlation_id=request_correlation_id,
            actor=actor,
        )
    if not command.subject_reference:
        raise ValidationError()
    return record_acceptance(
        notice_revision=notice,
        purpose_workflow=command.purpose_workflow,
        subject_reference=command.subject_reference,
        actor=actor,
        decision=command.decision,
        source_route=source_route,
        request_correlation_id=request_correlation_id,
        session_reference=command.session_reference,
    )


@transaction.atomic
def withdraw_notice_acceptance_command(*, actor, command: PrivacyNoticeAcceptanceCommand, source_route: str, request_correlation_id: str = ""):
    """Append a withdrawal for the active actor or verified subject."""

    if not isinstance(command, PrivacyNoticeAcceptanceCommand):
        raise ValidationError()
    if not command.subject_reference:
        raise ValidationError()
    subject_hash = hash_safe_reference(
        command.subject_reference,
        namespace=f"subject:{command.purpose_workflow}",
    )
    previous = PrivacyAcceptanceEvent.objects.select_for_update().filter(
        purpose_workflow=command.purpose_workflow,
        subject_reference_hash=subject_hash,
        decision=PrivacyAcceptanceDecisionChoices.ACCEPTED,
    ).order_by("-decided_at", "-created_at").first()
    if previous is None:
        raise NotFoundError()
    if actor is not None and getattr(actor, "is_authenticated", False) and previous.subject_user_id != actor.pk:
        raise PermissionDeniedError()
    return withdraw_acceptance(
        previous_event=previous,
        source_route=source_route,
        actor=actor,
        request_correlation_id=request_correlation_id,
    )


@transaction.atomic
def create_privacy_notice_revision_command(*, actor, command: PrivacyNoticeRevisionCommand):
    """Create one immutable notice revision through the DPO governance plane."""

    from apps.governance.dpo_services import is_current_dpo

    if not isinstance(command, PrivacyNoticeRevisionCommand) or not is_current_dpo(actor):
        raise PermissionDeniedError()
    if not all(isinstance(value, str) for value in (
        command.notice_identifier,
        command.version,
        command.body_markdown,
        command.source_reference,
        command.locale,
        command.purpose_workflow,
        command.supersedes_id,
    )):
        raise ValidationError()
    if not command.notice_identifier or len(command.notice_identifier) > 120:
        raise ValidationError()
    if not command.version or len(command.version) > 40 or not command.purpose_workflow:
        raise ValidationError()
    if len(command.body_markdown.encode("utf-8")) > 64 * 1024:
        raise ValidationError()
    if len(command.source_reference) > 500 or len(command.locale) > 20:
        raise ValidationError()
    supersedes = None
    if command.supersedes_id:
        try:
            supersedes_id = int(command.supersedes_id)
        except (ValueError, TypeError) as exc:
            raise ValidationError() from exc
        if supersedes_id <= 0:
            raise ValidationError()
        supersedes = PrivacyNoticeRevision.objects.filter(pk=supersedes_id).first()
        if supersedes is None:
            raise NotFoundError()
    revision = PrivacyNoticeRevision(
        notice_identifier=command.notice_identifier,
        version=command.version,
        body_markdown=command.body_markdown,
        source_reference=command.source_reference,
        effective_at=command.effective_at,
        locale=command.locale,
        purpose_workflow=command.purpose_workflow,
        supersedes=supersedes,
        created_by=actor,
        status=PrivacyNoticeStatusChoices.PROPOSED,
        approval_state=PrivacyApprovalStateChoices.PENDING,
    )
    try:
        revision.save()
    except django_exceptions.ValidationError as exc:
        raise ValidationError() from exc
    except IntegrityError as exc:
        raise LifecycleConflictError("A notice revision with the same identity already exists.") from exc
    audit_log(
        action_type="PRIVACY_NOTICE_REVISION_CREATED",
        event_category="PRIVACY_GOVERNANCE",
        target_model="privacy.PrivacyNoticeRevision",
        target_object_id=str(revision.pk),
        actor_user=actor,
        source_app="privacy",
        metadata={"notice_identifier": revision.notice_identifier, "version": revision.version},
    )
    return revision


@transaction.atomic
def approve_privacy_notice_revision_command(*, actor, revision_id, command: PrivacyNoticeRevisionApprovalCommand):
    """Approve immutable notice content before it can be published."""

    from apps.governance.dpo_services import is_current_dpo

    if not isinstance(command, PrivacyNoticeRevisionApprovalCommand) or not is_current_dpo(actor):
        raise PermissionDeniedError()
    if not isinstance(command.approval_reference, str) or not command.approval_reference or len(command.approval_reference) > 255:
        raise ValidationError()
    revision = PrivacyNoticeRevision.objects.select_for_update().filter(pk=revision_id).first()
    if revision is None:
        raise NotFoundError()
    if revision.status == PrivacyNoticeStatusChoices.RETIRED:
        raise LifecycleConflictError()
    if revision.approval_state == PrivacyApprovalStateChoices.APPROVED:
        return revision
    revision.approval_state = PrivacyApprovalStateChoices.APPROVED
    revision.approved_by = actor
    revision.approved_at = timezone.now()
    revision.approval_reference = command.approval_reference[:255]
    try:
        revision.save(update_fields=["approval_state", "approved_by", "approved_at", "approval_reference", "updated_at"])
    except django_exceptions.ValidationError as exc:
        raise ValidationError() from exc
    event = audit_log(
        action_type="PRIVACY_NOTICE_REVISION_APPROVED",
        event_category="PRIVACY_GOVERNANCE",
        target_model="privacy.PrivacyNoticeRevision",
        target_object_id=str(revision.pk),
        actor_user=actor,
        source_app="privacy",
        metadata={"notice_identifier": revision.notice_identifier, "version": revision.version},
    )
    if event is None:
        raise GovernanceError("Privacy notice approval audit could not be recorded.")
    return revision


@transaction.atomic
def retire_privacy_notice_revision_command(*, actor, revision_id, command: PrivacyNoticeRevisionRetirementCommand):
    """Retire a notice revision after its workflow binding is changed."""

    from apps.governance.dpo_services import is_current_dpo

    if not isinstance(command, PrivacyNoticeRevisionRetirementCommand) or not is_current_dpo(actor):
        raise PermissionDeniedError()
    if not isinstance(command.reason_code, str) or not command.reason_code or len(command.reason_code) > 80:
        raise ValidationError()
    revision = PrivacyNoticeRevision.objects.select_for_update().filter(pk=revision_id).first()
    if revision is None:
        raise NotFoundError()
    if PrivacyWorkflowBinding.objects.filter(
        notice_revision_id=revision.pk,
        status=PrivacyNoticeStatusChoices.PUBLISHED,
    ).exists():
        raise LifecycleConflictError()
    if revision.status == PrivacyNoticeStatusChoices.RETIRED:
        return revision
    revision.status = PrivacyNoticeStatusChoices.RETIRED
    try:
        revision.save(update_fields=["status", "updated_at"])
    except django_exceptions.ValidationError as exc:
        raise ValidationError() from exc
    event = audit_log(
        action_type="PRIVACY_NOTICE_REVISION_RETIRED",
        event_category="PRIVACY_GOVERNANCE",
        target_model="privacy.PrivacyNoticeRevision",
        target_object_id=str(revision.pk),
        actor_user=actor,
        source_app="privacy",
        metadata={"reason_code": command.reason_code[:80]},
    )
    if event is None:
        raise GovernanceError("Privacy notice retirement audit could not be recorded.")
    return revision


@transaction.atomic
def bind_privacy_notice_command(*, actor, command: PrivacyWorkflowBindingCommand):
    """Bind a workflow to an immutable notice revision through Governance."""

    from apps.governance.dpo_services import is_current_dpo

    if not isinstance(command, PrivacyWorkflowBindingCommand) or not is_current_dpo(actor):
        raise PermissionDeniedError()
    if not command.purpose_workflow or len(command.purpose_workflow) > 100:
        raise ValidationError()
    if not isinstance(command.required, bool) or command.status not in PrivacyNoticeStatusChoices.values:
        raise ValidationError()
    if len(command.source_reference) > 500 or len(command.block_reason) > 255:
        raise ValidationError()
    revision = None
    if command.notice_revision_id:
        revision = PrivacyNoticeRevision.objects.select_for_update().filter(pk=command.notice_revision_id).first()
        if revision is None:
            raise NotFoundError()
        if revision.purpose_workflow != command.purpose_workflow:
            raise ValidationError()
    if command.status == PrivacyNoticeStatusChoices.PUBLISHED and revision is None:
        raise ValidationError()
    if command.status == PrivacyNoticeStatusChoices.PUBLISHED:
        if revision.approval_state != PrivacyApprovalStateChoices.APPROVED:
            raise ValidationError("Only an approved notice revision may be published.")
        if revision.status != PrivacyNoticeStatusChoices.PUBLISHED:
            revision.status = PrivacyNoticeStatusChoices.PUBLISHED
            revision.save(update_fields=["status", "updated_at"])
    if command.status == PrivacyNoticeStatusChoices.BLOCKED and not command.block_reason:
        raise ValidationError()
    binding = PrivacyWorkflowBinding.objects.select_for_update().filter(
        purpose_workflow=command.purpose_workflow
    ).first()
    if binding is None:
        binding = PrivacyWorkflowBinding(purpose_workflow=command.purpose_workflow)
    binding.notice_revision=revision
    binding.status=command.status
    binding.required=bool(command.required)
    binding.source_reference=command.source_reference[:500]
    binding.block_reason=command.block_reason[:255]
    try:
        binding.full_clean()
        binding.save()
    except django_exceptions.ValidationError as exc:
        raise ValidationError() from exc
    except IntegrityError as exc:
        raise LifecycleConflictError("The workflow notice binding changed concurrently.") from exc
    audit_log(
        action_type="PRIVACY_WORKFLOW_BINDING_UPDATED",
        event_category="PRIVACY_GOVERNANCE",
        target_model="privacy.PrivacyWorkflowBinding",
        target_object_id=str(binding.pk),
        actor_user=actor,
        source_app="privacy",
        metadata={"purpose_workflow": binding.purpose_workflow, "status": binding.status},
    )
    return binding


def withdraw_acceptance(*, previous_event, source_route: str, actor=None, request_correlation_id: str = ""):
    """Record withdrawal without changing the original acceptance row."""

    return record_acceptance(
        notice_revision=previous_event.notice_revision,
        purpose_workflow=previous_event.purpose_workflow,
        subject_reference=previous_event.subject_reference_hash,
        actor=actor,
        decision=PrivacyAcceptanceDecisionChoices.WITHDRAWN,
        source_route=source_route,
        request_correlation_id=request_correlation_id,
        subject_reference_hash=previous_event.subject_reference_hash,
    )


def recording_consent_is_available() -> bool:
    """New recording consent is blocked until a published approved policy exists."""

    notice = resolve_current_notice("ecounseling-recording", "ecounseling_recording")
    rule = resolve_retention_policy("ecounseling_recordings")
    return bool(
        notice
        and notice.approval_state == PrivacyApprovalStateChoices.APPROVED
        and rule
    )


def resolve_retention_policy(record_category: str, *, at=None):
    """Resolve one exact target-scoped retention policy through Governance."""

    from apps.governance.selectors import resolve_effective_policy

    category = str(record_category or "").strip()
    if not category or len(category) > 120:
        return None
    return resolve_effective_policy(
        "privacy.retention",
        target_type="privacy.RetentionRule",
        target_reference=category,
        at=at,
    )


def recording_retention_days(*, at=None) -> int:
    """Return the exact Governance retention period for recordings.

    Recording enablement remains independently fail-closed.  This helper only
    reads the target-scoped privacy retention policy and deliberately returns
    zero when the policy is absent, malformed, review-date-only, or outside
    the supported positive range.
    """

    policy = resolve_retention_policy("ecounseling_recordings", at=at)
    if policy is None:
        return 0
    raw_days = (policy.configuration_json or {}).get("retention_period_days")
    if isinstance(raw_days, bool) or not isinstance(raw_days, int) or not 1 <= raw_days <= 36500:
        return 0
    return raw_days


def has_reviewer_scope(actor, scope: str, *, target_category: str = "") -> bool:
    """Return whether an actor may perform one governed privacy action."""

    if not is_active_nonlegacy_actor(actor):
        return False
    from apps.governance.dpo_services import is_current_dpo

    if is_current_dpo(actor):
        return bool(scope)
    if not (is_counselor(actor) or is_gco_staff(actor) or is_it_admin(actor)):
        return False
    for scopes, allowed_categories in _active_reviewer_scopes(actor):
        if scope not in scopes and "*" not in scopes:
            continue
        if not target_category or ("*" not in allowed_categories and target_category not in allowed_categories):
            continue
        return True
    return False


def reviewer_allowed_categories(actor, scope: str) -> set[str] | None:
    """Return category scope, or ``None`` for an explicit unrestricted grant."""

    from apps.governance.dpo_services import is_current_dpo

    if is_current_dpo(actor):
        return None
    categories: set[str] = set()
    unrestricted = False
    for scopes, scoped_categories in _active_reviewer_scopes(actor):
        if scope not in scopes and "*" not in scopes:
            continue
        if "*" in scoped_categories:
            unrestricted = True
        elif scoped_categories:
            categories.update(scoped_categories)
    return None if unrestricted else categories


def _active_reviewer_scopes(actor):
    """Yield normalized action/category scopes for valid reviewer grants."""

    if not is_active_nonlegacy_actor(actor):
        return
    if not (is_counselor(actor) or is_gco_staff(actor) or is_it_admin(actor)):
        return
    now = timezone.now()
    rows = PrivacyReviewerAuthorization.objects.filter(
        authorized_user=actor,
        status=ReviewerAuthorizationStatusChoices.ACTIVE,
        revoked_at__isnull=True,
        valid_from__lte=now,
    ).filter(Q(valid_until__isnull=True) | Q(valid_until__gte=now))
    for row in rows:
        raw_scopes = row.scopes
        if isinstance(raw_scopes, list):
            scopes = raw_scopes
            allowed_categories = []
        elif isinstance(raw_scopes, dict):
            scopes = raw_scopes.get("scopes", [])
            allowed_categories = raw_scopes.get("categories", [])
        else:
            continue
        if not isinstance(scopes, (list, tuple, set)) or not isinstance(allowed_categories, (list, tuple, set)):
            continue
        yield (
            {str(item) for item in scopes},
            {str(item)[:120] for item in allowed_categories},
        )


def privacy_requests_visible_to(actor):
    """Metadata-only request queryset respecting reviewer category scope."""

    categories = reviewer_allowed_categories(actor, "request_review")
    if categories is None:
        return DataSubjectRequest.objects.all()
    if not categories:
        return DataSubjectRequest.objects.none()
    return DataSubjectRequest.objects.filter(target_category__in=categories)


def privacy_incidents_visible_to(actor):
    if has_fixed_capability(actor, Capability.PRIVACY_INCIDENTS_TECHNICAL_OPERATE):
        return PrivacyIncident.objects.all()
    categories = reviewer_allowed_categories(actor, "incident_record")
    if categories is None:
        return PrivacyIncident.objects.all()
    if not categories:
        return PrivacyIncident.objects.none()
    return PrivacyIncident.objects.filter(affected_record_category__in=categories)


def can_view_request(actor, request: DataSubjectRequest) -> bool:
    if request is None or not is_active_nonlegacy_actor(actor):
        return False
    if is_student(actor):
        return request.subject_reference_hash == hash_safe_reference(f"user:{actor.pk}", namespace="subject:privacy_request")
    return has_reviewer_scope(actor, "request_review", target_category=request.target_category)


REQUEST_TRANSITIONS = {
    PrivacyRequestStatusChoices.SUBMITTED: {
        PrivacyRequestDecisionChoices.APPROVE: PrivacyRequestStatusChoices.IDENTITY_VERIFICATION_REQUIRED,
        PrivacyRequestDecisionChoices.WITHDRAW: PrivacyRequestStatusChoices.WITHDRAWN,
    },
    PrivacyRequestStatusChoices.IDENTITY_VERIFICATION_REQUIRED: {
        PrivacyRequestDecisionChoices.APPROVE: PrivacyRequestStatusChoices.UNDER_REVIEW,
        PrivacyRequestDecisionChoices.WITHDRAW: PrivacyRequestStatusChoices.WITHDRAWN,
    },
    PrivacyRequestStatusChoices.UNDER_REVIEW: {
        PrivacyRequestDecisionChoices.APPROVE: PrivacyRequestStatusChoices.APPROVED,
        PrivacyRequestDecisionChoices.PARTIAL: PrivacyRequestStatusChoices.PARTIALLY_FULFILLED,
        PrivacyRequestDecisionChoices.DENY: PrivacyRequestStatusChoices.DENIED,
        PrivacyRequestDecisionChoices.MORE_INFORMATION: PrivacyRequestStatusChoices.MORE_INFORMATION_REQUIRED,
        PrivacyRequestDecisionChoices.COMPLETE: PrivacyRequestStatusChoices.COMPLETED,
        PrivacyRequestDecisionChoices.WITHDRAW: PrivacyRequestStatusChoices.WITHDRAWN,
    },
    PrivacyRequestStatusChoices.MORE_INFORMATION_REQUIRED: {
        PrivacyRequestDecisionChoices.APPROVE: PrivacyRequestStatusChoices.UNDER_REVIEW,
        PrivacyRequestDecisionChoices.WITHDRAW: PrivacyRequestStatusChoices.WITHDRAWN,
    },
    PrivacyRequestStatusChoices.APPROVED: {
        PrivacyRequestDecisionChoices.COMPLETE: PrivacyRequestStatusChoices.COMPLETED,
        PrivacyRequestDecisionChoices.PARTIAL: PrivacyRequestStatusChoices.PARTIALLY_FULFILLED,
    },
    PrivacyRequestStatusChoices.PARTIALLY_FULFILLED: {
        PrivacyRequestDecisionChoices.COMPLETE: PrivacyRequestStatusChoices.COMPLETED,
    },
    PrivacyRequestStatusChoices.DENIED: {PrivacyRequestDecisionChoices.CLOSE: PrivacyRequestStatusChoices.CLOSED},
    PrivacyRequestStatusChoices.COMPLETED: {PrivacyRequestDecisionChoices.CLOSE: PrivacyRequestStatusChoices.CLOSED},
    PrivacyRequestStatusChoices.WITHDRAWN: {PrivacyRequestDecisionChoices.CLOSE: PrivacyRequestStatusChoices.CLOSED},
}


@transaction.atomic
def create_data_subject_request(
    *,
    actor,
    request_type: str,
    description: str = "",
    target_category: str = "",
    target_record_reference: str = "",
    staff_assisted: bool = False,
    subject_reference: str = "",
    source_route: str = "",
    request_correlation_id: str = "",
):
    if request_type not in PrivacyRequestTypeChoices.values:
        raise ValidationError("Unsupported privacy request type.")
    if staff_assisted:
        if not has_reviewer_scope(actor, "request_intake", target_category=target_category):
            raise PermissionDeniedError("Staff-assisted intake requires an authorized reviewer.")
    elif not (is_active_nonlegacy_actor(actor) and is_student(actor)):
        raise PermissionDeniedError("Only an authenticated student may self-submit a request.")
    if not staff_assisted:
        expected_subject = f"user:{actor.pk}"
        if subject_reference and subject_reference != expected_subject:
            raise PermissionDeniedError("A student may submit only their own privacy request.")
        subject = expected_subject
    else:
        subject = subject_reference or f"user:{actor.pk}"
    request = DataSubjectRequest.objects.create(
        reference_code=f"PRV-{uuid.uuid4().hex[:12].upper()}",
        requester=actor if getattr(actor, "is_authenticated", False) else None,
        subject_reference_hash=hash_safe_reference(subject, namespace="subject:privacy_request"),
        request_type=request_type,
        target_category=(target_category or "")[:120],
        target_record_reference_hash=(
            hash_safe_reference(target_record_reference, namespace="record:privacy_request")
            if target_record_reference
            else ""
        ),
        description_encrypted=description or None,
        source_route=(source_route or "")[:255],
        request_correlation_id=(request_correlation_id or "")[:100],
        staff_assisted=bool(staff_assisted),
    )
    DataSubjectRequestTransition.objects.create(
        request=request,
        from_status="",
        to_status=PrivacyRequestStatusChoices.SUBMITTED,
        actor_user=actor if getattr(actor, "is_authenticated", False) else None,
        reason_code="submitted",
        decision_evidence={"staff_assisted": bool(staff_assisted)},
    )
    audit_log(
        action_type="PRIVACY_REQUEST_SUBMITTED",
        event_category="PRIVACY_GOVERNANCE",
        target_model="DataSubjectRequest",
        target_object_id=str(request.pk),
        actor_user=actor if getattr(actor, "is_authenticated", False) else None,
        reference_code=request.reference_code,
        source_app="privacy",
        source_view=source_route,
        request_id=request_correlation_id,
        metadata={"request_type": request_type, "target_category": target_category, "staff_assisted": bool(staff_assisted)},
    )
    return request


@transaction.atomic
def transition_data_subject_request(
    *,
    actor,
    request: DataSubjectRequest,
    decision: str,
    reason_code: str,
    decision_notes: str = "",
    identity_verified: bool = False,
):
    if not has_reviewer_scope(actor, "request_decision", target_category=request.target_category):
        raise PermissionDeniedError("An authorized privacy reviewer is required.")
    next_status = REQUEST_TRANSITIONS.get(request.status, {}).get(decision)
    if not next_status:
        raise LifecycleConflictError("This privacy request transition is not permitted.")
    if (
        request.status == PrivacyRequestStatusChoices.IDENTITY_VERIFICATION_REQUIRED
        and decision == PrivacyRequestDecisionChoices.APPROVE
        and not identity_verified
    ):
        raise ValidationError("Identity verification evidence is required before review.")
    now = timezone.now()
    previous = request.status
    request.status = next_status
    request.reviewed_by = actor
    request.reviewed_at = now
    request.decision_reason_code = (reason_code or "")[:80]
    if decision_notes:
        request.decision_notes_encrypted = decision_notes
    if identity_verified:
        request.identity_verified_at = now
    if next_status in {PrivacyRequestStatusChoices.COMPLETED, PrivacyRequestStatusChoices.PARTIALLY_FULFILLED}:
        request.fulfilled_at = now
    if next_status == PrivacyRequestStatusChoices.WITHDRAWN:
        request.withdrawn_at = now
    if next_status == PrivacyRequestStatusChoices.CLOSED:
        request.closed_at = now
    request.save()
    DataSubjectRequestTransition.objects.create(
        request=request,
        from_status=previous,
        to_status=next_status,
        actor_user=actor,
        reason_code=(reason_code or "")[:80],
        decision_evidence={"identity_verified": bool(identity_verified)},
    )
    audit_log(
        action_type="PRIVACY_REQUEST_TRANSITION",
        event_category="PRIVACY_GOVERNANCE",
        target_model="DataSubjectRequest",
        target_object_id=str(request.pk),
        actor_user=actor,
        reference_code=request.reference_code,
        source_app="privacy",
        metadata={"from_status": previous, "to_status": next_status, "reason_code": reason_code},
    )
    return request


@transaction.atomic
def withdraw_data_subject_request(*, actor, request: DataSubjectRequest):
    if not (is_active_nonlegacy_actor(actor) and is_student(actor)) or request.subject_reference_hash != hash_safe_reference(
        f"user:{actor.pk}", namespace="subject:privacy_request"
    ):
        raise PermissionDeniedError("You may withdraw only your own privacy request.")
    if request.status in {
        PrivacyRequestStatusChoices.COMPLETED,
        PrivacyRequestStatusChoices.CLOSED,
        PrivacyRequestStatusChoices.WITHDRAWN,
    }:
        raise LifecycleConflictError("This privacy request cannot be withdrawn in its current state.")
    previous = request.status
    request.status = PrivacyRequestStatusChoices.WITHDRAWN
    request.withdrawn_at = timezone.now()
    request.save(update_fields=["status", "withdrawn_at", "updated_at"])
    DataSubjectRequestTransition.objects.create(
        request=request,
        from_status=previous,
        to_status=PrivacyRequestStatusChoices.WITHDRAWN,
        actor_user=actor,
        reason_code="subject_withdrawal",
        decision_evidence={},
    )
    return request


def attach_protected_fulfillment(*, actor, request: DataSubjectRequest, protected_file):
    if not has_reviewer_scope(actor, "request_fulfillment", target_category=request.target_category):
        raise PermissionDeniedError("An authorized reviewer is required for fulfillment.")
    if request.status not in {
        PrivacyRequestStatusChoices.APPROVED,
        PrivacyRequestStatusChoices.PARTIALLY_FULFILLED,
    }:
        raise LifecycleConflictError("Fulfillment requires an approved request state.")
    if not protected_file or not getattr(protected_file, "pk", None):
        raise ValidationError("A protected artifact is required.")
    # The privacy request never grants file access by itself. Reuse the
    # underlying ProtectedFile policy before associating a fulfillment.
    from apps.security.file_policies import verify_file_access
    from apps.security.exceptions import PolicyValidationError
    try:
        verify_file_access(actor, protected_file, action="read_metadata")
    except PolicyValidationError as exc:
        raise PermissionDeniedError("The underlying protected-record policy denied this artifact.") from exc
    request.protected_fulfillment_file = protected_file
    request.save(update_fields=["protected_fulfillment_file", "updated_at"])
    return request


SAFE_INCIDENT_CODES = frozenset({
    "ACCESS_REVOKED", "TOKEN_ROTATED", "EXPORT_DISABLED", "RESTORE_ISOLATED", "DISCLOSURE_RECALLED",
    "SOURCE_QUARANTINED", "RETENTION_REVIEW_OPENED", "NO_EXTERNAL_NOTIFICATION", "NOTIFICATION_ASSESSED",
})


def _safe_incident_metadata(metadata: dict | None):
    metadata = metadata or {}
    if not isinstance(metadata, dict):
        raise ValidationError("Incident metadata must be an allowlisted object.")
    unknown = set(metadata) - SAFE_INCIDENT_METADATA_KEYS
    if unknown:
        raise ValidationError("Incident metadata contains an unsupported field.")
    safe = {}
    for key, value in metadata.items():
        if key in {"affected_count", "event_count"}:
            if not isinstance(value, int) or value < 0:
                raise ValidationError("Incident counts must be non-negative integers.")
            safe[key] = value
        else:
            if not isinstance(value, str) or not SAFE_METADATA_VALUE_RE.fullmatch(value):
                raise ValidationError("Incident metadata values must be allowlisted codes.")
            safe[key] = str(value)[:80]
    return safe


@transaction.atomic
def create_privacy_incident(
    *,
    actor,
    category: str,
    severity: str,
    affected_workflow: str = "",
    affected_record_category: str = "",
    containment_code: str = "",
    action_metadata: dict | None = None,
    notification_decision: str = PrivacyIncidentNotificationDecisionChoices.PENDING,
    related_event_ids: list | None = None,
    safe_summary_code: str = "",
):
    if not is_policy_active("privacy.incidents"):
        raise PermissionDeniedError("Privacy incident recording is disabled by policy.")
    if category not in PrivacyIncidentCategoryChoices.values or severity not in PrivacyIncidentSeverityChoices.values:
        raise ValidationError("Unsupported incident category or severity.")
    if notification_decision not in PrivacyIncidentNotificationDecisionChoices.values:
        raise ValidationError("Unsupported notification decision.")
    incident_record_scope = has_reviewer_scope(
        actor,
        "incident_record",
        target_category=affected_record_category,
    )
    incident_decision_scope = has_reviewer_scope(
        actor,
        "incident_decision",
        target_category=affected_record_category,
    )
    active_it_admin = has_fixed_capability(actor, Capability.PRIVACY_INCIDENTS_TECHNICAL_OPERATE)
    if not (active_it_admin or incident_record_scope):
        raise PermissionDeniedError("Only IT Admin or an authorized privacy reviewer may record incidents.")
    if (
        notification_decision != PrivacyIncidentNotificationDecisionChoices.PENDING
        and not incident_decision_scope
    ):
        raise PermissionDeniedError("An authorized privacy reviewer is required for notification decisions.")
    safe_metadata = _safe_incident_metadata(action_metadata)
    if containment_code and containment_code not in SAFE_INCIDENT_CODES:
        raise ValidationError("Containment code is not allowlisted.")
    incident = PrivacyIncident.objects.create(
        incident_code=f"INC-{uuid.uuid4().hex[:12].upper()}",
        category=category,
        severity=severity,
        affected_workflow=(affected_workflow or "")[:100],
        affected_record_category=(affected_record_category or "")[:120],
        reporter=actor,
        containment_code=(containment_code or "")[:80],
        action_metadata=safe_metadata,
        notification_decision=notification_decision,
        related_event_ids=[hash_safe_reference(str(value), namespace="incident-event") for value in (related_event_ids or [])][:20],
        safe_summary_code=(safe_summary_code or "")[:80],
    )
    PrivacyIncidentTransition.objects.create(
        incident=incident,
        from_status="",
        to_status=PrivacyIncidentStatusChoices.OPEN,
        actor_user=actor,
        reason_code="recorded",
        safe_evidence={"metadata_only": True},
    )
    return incident


@transaction.atomic
def transition_privacy_incident(*, actor, incident: PrivacyIncident, to_status: str, reason_code: str, safe_evidence: dict | None = None):
    if to_status not in PrivacyIncidentStatusChoices.values:
        raise ValidationError("Unsupported incident status.")
    active_it_admin = has_fixed_capability(actor, Capability.PRIVACY_INCIDENTS_TECHNICAL_OPERATE)
    incident_decision_scope = has_reviewer_scope(
        actor,
        "incident_decision",
        target_category=incident.affected_record_category,
    )
    if active_it_admin and not incident_decision_scope:
        if not active_it_admin or to_status != PrivacyIncidentStatusChoices.CONTAINED:
            raise PermissionDeniedError("IT Admin may record technical containment only.")
    elif not incident_decision_scope:
        raise PermissionDeniedError("An authorized privacy reviewer is required for incident decisions.")
    allowed = {
        PrivacyIncidentStatusChoices.OPEN: {PrivacyIncidentStatusChoices.INVESTIGATING, PrivacyIncidentStatusChoices.CONTAINED, PrivacyIncidentStatusChoices.DISMISSED},
        PrivacyIncidentStatusChoices.INVESTIGATING: {PrivacyIncidentStatusChoices.CONTAINED, PrivacyIncidentStatusChoices.RESOLVED, PrivacyIncidentStatusChoices.DISMISSED},
        PrivacyIncidentStatusChoices.CONTAINED: {PrivacyIncidentStatusChoices.RESOLVED, PrivacyIncidentStatusChoices.INVESTIGATING},
        PrivacyIncidentStatusChoices.RESOLVED: set(),
        PrivacyIncidentStatusChoices.DISMISSED: set(),
    }
    if to_status not in allowed.get(incident.status, set()):
        raise LifecycleConflictError("This privacy incident transition is not permitted.")
    evidence = _safe_incident_metadata(safe_evidence)
    previous = incident.status
    incident.status = to_status
    if to_status == PrivacyIncidentStatusChoices.RESOLVED:
        incident.resolved_at = timezone.now()
    incident.save(update_fields=["status", "resolved_at", "updated_at"])
    PrivacyIncidentTransition.objects.create(
        incident=incident,
        from_status=previous,
        to_status=to_status,
        actor_user=actor,
        reason_code=(reason_code or "")[:80],
        safe_evidence=evidence,
    )
    return incident


def contain_privacy_incident(*, actor, incident: PrivacyIncident, reason_code: str, safe_evidence: dict | None = None):
    """Record the technical containment step through the same policy gate."""

    if not is_policy_active("privacy.incident_containment"):
        raise PermissionDeniedError("Privacy incident containment is disabled by policy.")

    return transition_privacy_incident(
        actor=actor,
        incident=incident,
        to_status=PrivacyIncidentStatusChoices.CONTAINED,
        reason_code=reason_code,
        safe_evidence=safe_evidence,
    )


@transaction.atomic
def assess_privacy_incident_notification_command(*, actor, incident_code: str, command: PrivacyIncidentTransitionCommand):
    """Record a DPO notification decision without changing incident status."""

    if not isinstance(command, PrivacyIncidentTransitionCommand):
        raise ValidationError()
    if command.notification_decision not in PrivacyIncidentNotificationDecisionChoices.values:
        raise ValidationError()
    incident = PrivacyIncident.objects.select_for_update().filter(incident_code=incident_code).first()
    if incident is None:
        raise NotFoundError()
    if not has_reviewer_scope(
        actor, "incident_decision", target_category=incident.affected_record_category
    ):
        raise PermissionDeniedError()
    incident.notification_decision = command.notification_decision
    incident.save(update_fields=["notification_decision", "updated_at"])
    audit_log(
        action_type="PRIVACY_INCIDENT_NOTIFICATION_ASSESSED",
        event_category="PRIVACY",
        target_model="privacy.PrivacyIncident",
        target_object_id=str(incident.pk),
        actor_user=actor,
        source_app="privacy",
        reference_code=incident.incident_code,
        metadata={"decision": command.notification_decision, "metadata_only": True},
    )
    return incident


def has_active_legal_hold(record_category: str, record_reference: str = "") -> bool:
    reference_hash = hash_safe_reference(record_reference, namespace=f"record:{record_category}") if record_reference else ""
    query = PrivacyLegalHold.objects.filter(record_category=record_category, status=LegalHoldStatusChoices.ACTIVE)
    if reference_hash:
        query = query.filter(Q(record_reference_hash="") | Q(record_reference_hash=reference_hash))
    return query.exists()


@transaction.atomic
def place_legal_hold(*, actor, record_category: str, reason_code: str, record_reference: str = "", safe_reference: str = ""):
    if not has_reviewer_scope(actor, "legal_hold", target_category=record_category):
        raise PermissionDeniedError("An authorized reviewer is required for a legal hold.")
    return PrivacyLegalHold.objects.create(
        record_category=record_category,
        record_reference_hash=hash_safe_reference(record_reference, namespace=f"record:{record_category}") if record_reference else "",
        reason_code=(reason_code or "")[:80],
        placed_by=actor,
        safe_reference=(
            hash_safe_reference(safe_reference, namespace=f"hold-safe:{record_category}")
            if safe_reference
            else ""
        ),
    )


@transaction.atomic
def release_legal_hold(*, actor, hold: PrivacyLegalHold, reason_code: str):
    if not has_reviewer_scope(actor, "legal_hold", target_category=hold.record_category):
        raise PermissionDeniedError("An authorized reviewer is required to release a legal hold.")
    if hold.status != LegalHoldStatusChoices.ACTIVE:
        raise LifecycleConflictError("This legal hold is already released.")
    hold.status = LegalHoldStatusChoices.RELEASED
    hold.released_by = actor
    hold.released_at = timezone.now()
    hold.reason_code = (reason_code or hold.reason_code)[:80]
    hold.save(update_fields=["status", "released_by", "released_at", "reason_code", "updated_at"])
    return hold


def can_dispose_record_category(record_category: str, *, record_reference: str = "", explicit_confirmation: bool = False) -> bool:
    """Conservative disposal gate; deployment never enables disposal by default."""

    if not explicit_confirmation or is_deployment_environment():
        return False
    rule = resolve_retention_policy(record_category)
    return bool(rule and not has_active_legal_hold(record_category, record_reference))


def evaluate_retention_rules(*, environment: str | None = None, now=None):
    """Store aggregate, content-blind dry-run evidence for every configured rule."""

    environment = (environment or environment_name()).strip().lower()
    now = now or timezone.now()
    rows = []
    from apps.governance.selectors import effective_policy_snapshots

    for policy in effective_policy_snapshots(
        "privacy.retention",
        target_type="privacy.RetentionRule",
        at=now,
    ):
        category = policy.target_reference
        holds = PrivacyLegalHold.objects.filter(record_category=category, status=LegalHoldStatusChoices.ACTIVE).count()
        result = "LEGAL_HOLD" if holds else "NO_CANDIDATES"
        rows.append(RetentionEvaluation.objects.create(
            environment=environment,
            evaluated_at=now,
            record_category=category,
            candidate_count=0,
            hold_count=holds,
            result_code=result,
            safe_metadata={
                "policy_id": str(policy.pk),
                "policy_source_reference": policy.source_reference[:120],
                "metadata_only": True,
            },
        ))
    return rows


def _load_request_for_update(reference_code: str):
    request = (
        DataSubjectRequest.objects.select_for_update()
        .filter(reference_code=str(reference_code or "").strip())
        .first()
    )
    if request is None:
        raise NotFoundError()
    return request


@transaction.atomic
def create_data_subject_request_command(*, actor, command: DataSubjectRequestCreateCommand, source_route: str, request_correlation_id: str = ""):
    if not isinstance(command, DataSubjectRequestCreateCommand):
        raise ValidationError()
    if len(command.description) > 16_384 or len(command.target_category) > 120 or len(command.target_record_reference) > 255:
        raise ValidationError()
    return create_data_subject_request(
        actor=actor,
        request_type=command.request_type,
        description=command.description,
        target_category=command.target_category,
        target_record_reference=command.target_record_reference,
        staff_assisted=command.staff_assisted,
        subject_reference=command.subject_reference,
        source_route=source_route,
        request_correlation_id=request_correlation_id,
    )


@transaction.atomic
def transition_data_subject_request_command(*, actor, reference_code: str, command: PrivacyRequestTransitionCommand):
    request = _load_request_for_update(reference_code)
    if not isinstance(command, PrivacyRequestTransitionCommand):
        raise ValidationError()
    if len(command.reason_code) > 80 or len(command.decision_notes) > 16_384:
        raise ValidationError()
    return transition_data_subject_request(
        actor=actor,
        request=request,
        decision=command.decision,
        reason_code=command.reason_code,
        decision_notes=command.decision_notes,
        identity_verified=command.identity_verified,
    )


@transaction.atomic
def withdraw_data_subject_request_command(*, actor, reference_code: str):
    request = _load_request_for_update(reference_code)
    return withdraw_data_subject_request(actor=actor, request=request)


@transaction.atomic
def assign_data_subject_request_command(*, actor, reference_code: str, command: PrivacyRequestAssignmentCommand):
    request = _load_request_for_update(reference_code)
    from .policies import can_assign_request

    if not isinstance(command, PrivacyRequestAssignmentCommand) or not can_assign_request(
        actor, target_category=request.target_category
    ):
        raise PermissionDeniedError()
    from apps.accounts.models import User

    reviewer = User.objects.filter(pk=command.reviewer_id, is_active=True, is_superuser=False).first()
    if reviewer is None:
        raise NotFoundError()
    if not has_reviewer_scope(reviewer, "request_review", target_category=request.target_category):
        raise ValidationError()
    request.assigned_reviewer = reviewer
    request.save(update_fields=["assigned_reviewer", "updated_at"])
    audit_log(
        action_type="PRIVACY_REQUEST_ASSIGNED",
        event_category="PRIVACY_GOVERNANCE",
        target_model="privacy.DataSubjectRequest",
        target_object_id=str(request.pk),
        actor_user=actor,
        reference_code=request.reference_code,
        source_app="privacy",
        metadata={"target_category": request.target_category, "assigned": True},
    )
    return request


@transaction.atomic
def fulfill_data_subject_request_command(*, actor, reference_code: str, command: PrivacyRequestFulfillmentCommand):
    request = _load_request_for_update(reference_code)
    if not isinstance(command, PrivacyRequestFulfillmentCommand):
        raise ValidationError()
    from apps.security.models import ProtectedFile

    protected_file = ProtectedFile.objects.select_for_update().filter(pk=command.protected_file_id).first()
    if protected_file is None:
        raise NotFoundError()
    return attach_protected_fulfillment(actor=actor, request=request, protected_file=protected_file)


@transaction.atomic
def create_privacy_incident_command(*, actor, command: PrivacyIncidentCreateCommand):
    if not isinstance(command, PrivacyIncidentCreateCommand):
        raise ValidationError()
    if len(command.safe_metadata) > 8 or len(command.related_event_references) > 20:
        raise ValidationError()
    return create_privacy_incident(
        actor=actor,
        category=command.category,
        severity=command.severity,
        affected_workflow=command.affected_workflow,
        affected_record_category=command.affected_record_category,
        containment_code=command.containment_code,
        action_metadata=command.metadata_dict(),
        notification_decision=command.notification_decision,
        related_event_ids=command.related_event_references,
        safe_summary_code=command.safe_summary_code,
    )


@transaction.atomic
def transition_privacy_incident_command(*, actor, incident_code: str, command: PrivacyIncidentTransitionCommand):
    if not isinstance(command, PrivacyIncidentTransitionCommand):
        raise ValidationError()
    incident = PrivacyIncident.objects.select_for_update().filter(incident_code=incident_code).first()
    if incident is None:
        raise NotFoundError()
    return transition_privacy_incident(
        actor=actor,
        incident=incident,
        to_status=command.to_status,
        reason_code=command.reason_code,
        safe_evidence=command.evidence_dict(),
    )


@transaction.atomic
def contain_privacy_incident_command(*, actor, incident_code: str, command: PrivacyIncidentTransitionCommand):
    if not isinstance(command, PrivacyIncidentTransitionCommand):
        raise ValidationError()
    incident = PrivacyIncident.objects.select_for_update().filter(incident_code=incident_code).first()
    if incident is None:
        raise NotFoundError()
    return contain_privacy_incident(
        actor=actor,
        incident=incident,
        reason_code=command.reason_code,
        safe_evidence=command.evidence_dict(),
    )


@transaction.atomic
def place_legal_hold_command(*, actor, command: PrivacyLegalHoldCreateCommand):
    if not isinstance(command, PrivacyLegalHoldCreateCommand):
        raise ValidationError()
    if len(command.record_category) > 120 or len(command.reason_code) > 80:
        raise ValidationError()
    return place_legal_hold(
        actor=actor,
        record_category=command.record_category,
        reason_code=command.reason_code,
        record_reference=command.record_reference,
        safe_reference=command.safe_reference,
    )


@transaction.atomic
def release_legal_hold_command(*, actor, hold_id: str, command: PrivacyLegalHoldReleaseCommand):
    if not isinstance(command, PrivacyLegalHoldReleaseCommand):
        raise ValidationError()
    hold = PrivacyLegalHold.objects.select_for_update().filter(pk=hold_id).first()
    if hold is None:
        raise NotFoundError()
    return release_legal_hold(actor=actor, hold=hold, reason_code=command.reason_code)


def evaluate_retention_command(*, actor, command: RetentionEvaluationCommand):
    if not isinstance(command, RetentionEvaluationCommand):
        raise ValidationError()
    from apps.governance.dpo_services import is_current_dpo

    if not is_active_nonlegacy_actor(actor) or not is_current_dpo(actor):
        raise PermissionDeniedError()
    return evaluate_retention_rules(environment=command.environment or None)


def privacy_credential_readiness(asset, *, now=None) -> dict:
    """Return safe readiness metadata for the privacy credential."""

    now = now or timezone.now()
    expired = bool(getattr(asset, "effective_until", None) and asset.effective_until < now.date())
    exact_name = getattr(asset, "credential_reference", "") == "DPO/DPS Registered"
    fields_ready = all(
        getattr(asset, field, "")
        for field in ("credential_holder", "credential_issuer", "credential_verified_at", "credential_source_reference")
    )
    return {
        "label": "DPO/DPS Registered",
        "ready": bool(exact_name and fields_ready and not expired),
        "reason_code": "READY" if exact_name and fields_ready and not expired else "PENDING_VERIFICATION",
        "exact_name": exact_name,
        "expired": expired,
        "fields_ready": fields_ready,
    }
