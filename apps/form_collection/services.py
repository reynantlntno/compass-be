# Project: COMPASS
# File: apps/form_collection/services.py
# Module: apps.form_collection
# Purpose: Service layer implementing collection lifecycle, token issuance, verification, and record linking
# Domain boundary and service policy.

from datetime import timedelta
import logging

from apps.common.exceptions import GovernanceError, PermissionDeniedError, RateLimitError, StaleStateError, ValidationError
from apps.common.contracts import RequestMetadata
from apps.common.verified_access import VerifiedFormAccessPrincipal
from django.db import transaction
from django.utils import timezone

from apps.account_security.tokens import hash_identifier, compare_tokens
from apps.account_security.abuse_controls import (
    AbuseAction,
    record_failure as record_abuse_failure,
    record_success as record_abuse_success,
)
from apps.audit.services import audit_log
from apps.orchestration.commands import FormRevisionUsageCommand
from apps.orchestration.use_cases import mark_form_revision_used_for_composition
from apps.profiles.models import StudentProfile, StudentLifecycleChoices
from apps.form_collection.models import (
    FormCollection,
    InvitationBatch,
    FormInvitation,
    FormInvitationAttempt,
    UnlinkedFormSubmission,
    CollectionStatus,
    InvitationBatchStatus,
    FormInvitationStatus,
    StudentMatchStatus,
    FormInvitationAttemptStatus,
    FormInvitationFailureReason,
    FormType
)
from apps.form_collection.commands import (
    FormCollectionConfigureCommand,
    FormCollectionCreateCommand,
    FormCollectionLifecycleCommand,
    InvitationBatchCommand,
    InvitationIssueCommand,
    InvitationRevokeCommand,
    InvitationVerificationCommand,
    ManualMatchDecisionCommand,
    UnlinkedSubmissionCommand,
    InvitationRecipient,
)
from apps.form_collection.tokens import (
    generate_selector_and_verifier,
    hash_verifier,
    normalize_email,
    normalize_identifier,
    normalize_surname,
    normalize_birthdate
)
from apps.form_collection.policies import (
    can_create_collection,
    can_configure_collection,
    can_launch_collection,
    can_issue_invitation_batch,
    can_revoke_form_invitation,
    can_link_unlinked_submission,
    can_review_manual_match,
    can_change_student_lifecycle
)
from apps.form_collection.rate_limits import is_rate_limited
from apps.common.policy import PolicyChangeRequest
from apps.governance.policy_lifecycle import ensure_active_policy_for_target, replace_active_policy_for_target
from apps.governance.selectors import resolve_effective_policy

logger = logging.getLogger(__name__)


def _collection_controls(collection):
    """Read invitation controls from the target-scoped Policy Center record."""

    policy = resolve_effective_policy(
        "form_collection.invitation_controls",
        target=collection,
    )
    if policy is None:
        raise GovernanceError("Form Collection invitation policy is not configured.")
    config = policy.configuration_json or {}
    try:
        expiry_days = int(config["default_token_expiry_days"])
        max_uses = int(config["max_uses_per_token"])
    except (TypeError, ValueError):
        raise ValidationError("Form Collection invitation policy is invalid.")
    if not 1 <= expiry_days <= 366 or not 1 <= max_uses <= 100:
        raise ValidationError("Form Collection invitation policy is outside the safe bounds.")
    identity_policy = config.get("identity_verification_policy")
    allow_draft = bool(config.get("allow_draft"))
    return expiry_days, identity_policy, max_uses, allow_draft


def _hash_optional(value: str | None) -> str | None:
    return hash_identifier(str(value)) if value else None


def selector_session_hash(selector: str) -> str:
    """Hash a selector for session binding without exposing the selector itself."""
    return hash_identifier(f"selector:{selector}")


def _attempt_identifier_hash(policy: str, verification_data: dict | None = None, selector: str | None = None) -> str | None:
    """Build a privacy-safe verifier scope for rate limits and attempt evidence."""
    if selector:
        return hash_identifier(f"selector:{selector}")
    data = verification_data or {}
    if policy == "CONTROL_SURNAME_BIRTHDATE":
        control_number = data.get("control_number")
        return hash_identifier(f"control:{normalize_identifier(control_number)}") if control_number else None
    if policy == "CONTROL_EMAIL_OTP":
        control_number = data.get("control_number")
        return hash_identifier(f"control:{normalize_identifier(control_number)}") if control_number else None
    if policy == "STUDENT_EMAIL":
        student_number = data.get("student_number")
        email = data.get("email")
        if student_number or email:
            return hash_identifier(f"student-email:{normalize_identifier(student_number)}:{normalize_email(email)}")
    if policy == "EMAIL_OTP":
        email = data.get("email")
        return hash_identifier(f"email:{normalize_email(email)}") if email else None
    return None


def get_verified_invitation_for_destination(
    session,
    *,
    expected_target_form_key: str,
    expected_form_type: str,
) -> FormInvitation:
    """Return the verified token for a survey destination or fail closed."""
    access_id = session.get("form_collection_verified_access_id")
    if not access_id:
        raise ValidationError("Verified form access is required.")

    try:
        token = FormInvitation.objects.select_related("collection", "linked_student", "unlinked_submission").get(pk=access_id)
    except FormInvitation.DoesNotExist:
        raise ValidationError("Verified form access is invalid.")

    session_selector_hash = session.get("form_collection_verified_selector_hash")
    if session_selector_hash and session_selector_hash != selector_session_hash(token.selector):
        raise ValidationError("Verified form access is invalid.")

    collection = token.collection
    if not collection:
        raise ValidationError("Verified form access is invalid.")
    if token.target_form_key != expected_target_form_key:
        raise ValidationError("Verified form access is invalid.")
    if collection.form_type != expected_form_type:
        raise ValidationError("Verified form access is invalid.")
    if collection.status != CollectionStatus.ACTIVE:
        raise ValidationError("Verified form access is not available.")
    if token.status in (FormInvitationStatus.REVOKED, FormInvitationStatus.EXPIRED, FormInvitationStatus.SUBMITTED):
        raise ValidationError("Verified form access is not available.")
    if timezone.now() > token.expires_at:
        raise ValidationError("Verified form access is not available.")
    if token.used_count >= token.max_uses:
        raise ValidationError("Verified form access is not available.")
    if token.status not in (FormInvitationStatus.VERIFIED, FormInvitationStatus.DRAFT_STARTED):
        raise ValidationError("Verified form access is not available.")

    return token


def get_verified_invitation_for_principal(
    principal: VerifiedFormAccessPrincipal,
    *,
    expected_target_form_key: str,
) -> FormInvitation:
    """Reload and validate a request-local verified-access principal.

    This is intentionally separate from session parsing.  The API edge
    validates the session and creates the principal; this domain boundary
    still reloads the invitation and rechecks lifecycle, expiry, usage, and
    target containment before any response mutation.
    """
    if not isinstance(principal, VerifiedFormAccessPrincipal):
        raise ValidationError("Verified form access is required.")
    if principal.target_form_key != expected_target_form_key:
        raise ValidationError("Verified form access is invalid.")
    token = (
        FormInvitation.objects
        .select_related("collection", "linked_student", "unlinked_submission")
        .filter(pk=principal.invitation_id)
        .first()
    )
    if token is None or not principal.matches_invitation(token):
        raise ValidationError("Verified form access is invalid.")
    if token.collection.form_type != expected_target_form_key:
        raise ValidationError("Verified form access is invalid.")
    if token.collection.status != CollectionStatus.ACTIVE:
        raise ValidationError("Verified form access is not available.")
    if token.status not in (FormInvitationStatus.VERIFIED, FormInvitationStatus.DRAFT_STARTED):
        raise ValidationError("Verified form access is not available.")
    if timezone.now() > token.expires_at or token.used_count >= token.max_uses:
        raise ValidationError("Verified form access is not available.")
    if principal.form_revision_id and str(token.collection.form_revision_id) != principal.form_revision_id:
        raise ValidationError("Verified form access is invalid.")
    if principal.student_profile_id != (str(token.linked_student_id) if token.linked_student_id else None):
        raise ValidationError("Verified form access is invalid.")
    if principal.unlinked_submission_id != (
        str(token.unlinked_submission_id) if token.unlinked_submission_id else None
    ):
        raise ValidationError("Verified form access is invalid.")
    return token


def _record_verification_attempt(
    *,
    form_invitation=None,
    collection=None,
    status,
    failure_reason=None,
    ip_address: str = None,
    user_agent: str = None,
    session_id: str = None,
    identifier_hash: str = None,
):
    attempt = FormInvitationAttempt.objects.create(
        form_invitation=form_invitation,
        collection=collection,
        action_scope="VERIFY",
        identifier_hash=identifier_hash,
        ip_hash=_hash_optional(ip_address),
        user_agent_hash=_hash_optional(user_agent),
        session_hash=_hash_optional(session_id),
        status=status,
        failure_reason=failure_reason,
    )
    token_scope = getattr(form_invitation, "selector", None) or identifier_hash
    if status == FormInvitationAttemptStatus.SUCCESS:
        record_abuse_success(
            AbuseAction.TOKEN_VERIFY,
            subject=identifier_hash,
            ip=ip_address,
            session=session_id,
            token=token_scope,
        )
    else:
        record_abuse_failure(
            AbuseAction.TOKEN_VERIFY,
            subject=identifier_hash,
            ip=ip_address,
            session=session_id,
            token=token_scope,
            reason_code=str(failure_reason or status),
        )
    return attempt


def _record_failed_attempt(token, reason, ip_address=None, user_agent=None, session_id=None, identifier_hash=None):
    return _record_verification_attempt(
        form_invitation=token,
        collection=token.collection if token else None,
        status=FormInvitationAttemptStatus.FAILED,
        failure_reason=reason,
        ip_address=ip_address,
        user_agent=user_agent,
        session_id=session_id,
        identifier_hash=identifier_hash,
    )


@transaction.atomic
def _create_collection_legacy(
    user,
    name: str,
    start_at,
    end_at,
    form_family=None,
    form_revision=None,
    form_type: str = "individual_inventory",
    default_token_expiry_days: int = 30,
    identity_verification_policy: str = "NONE",
    max_uses_per_token: int = 1,
    allow_draft: bool = True,
    description: str = "",
    audience: str = "CUSTOM",
    metadata_json: dict = None
) -> FormCollection:
    """Create a new collection in DRAFT status."""
    if not can_create_collection(user):
        raise PermissionDeniedError("You do not have permission to create collections.")
    if form_type == FormType.CSM_FEEDBACK:
        raise ValidationError(
            "CSM is created only from a completed service in COMPASS."
        )

    if start_at >= end_at:
        raise ValidationError("Start time must be before end time.")

    collection = FormCollection.objects.create(
        name=name,
        description=description,
        audience=audience,
        status=CollectionStatus.DRAFT,
        start_at=start_at,
        end_at=end_at,
        form_family=form_family,
        form_revision=form_revision,
        form_type=form_type,
        created_by=user,
        metadata_json=metadata_json or {}
    )
    ensure_active_policy_for_target(
        user,
        PolicyChangeRequest(
            key="form_collection.invitation_controls",
            configuration={
                "default_token_expiry_days": default_token_expiry_days,
                "identity_verification_policy": identity_verification_policy,
                "max_uses_per_token": max_uses_per_token,
                "allow_draft": allow_draft,
            },
            target_type="form_collection.FormCollection",
            target_reference=str(collection.pk),
            source_reference=f"FORM_COLLECTION:{collection.pk}:INITIAL_CONTROLS",
        ),
    )

    audit_log(
        action_type="CREATE",
        event_category="FORM_COLLECTION",
        target_model="form_collection.FormCollection",
        target_object_id=str(collection.id),
        actor_user=user,
        metadata={"name": name, "form_type": form_type}
    )
    return collection


def _configure_collection_legacy(user, collection: FormCollection, command: FormCollectionConfigureCommand) -> FormCollection:
    """Configure a draft collection's parameters."""
    if not isinstance(command, FormCollectionConfigureCommand):
        raise ValidationError("Form Collection configuration requires a typed command.")
    if not can_configure_collection(user, collection):
        raise PermissionDeniedError("You do not have permission to configure this collection.")

    if collection.status != CollectionStatus.DRAFT:
        raise ValidationError("Only draft collections can be configured.")

    policy_field_names = {
        "default_token_expiry_days",
        "identity_verification_policy",
        "max_uses_per_token",
        "allow_draft",
    }
    fields = {}
    for field_name in ("name", "description", "audience", "start_at", "end_at"):
        if command.has(field_name):
            fields[field_name] = getattr(command, field_name)
    from apps.organizations.models import FormFamily, FormRevision
    if command.has("form_family_id"):
        fields["form_family"] = FormFamily.objects.filter(pk=command.form_family_id).first()
        if fields["form_family"] is None:
            raise ValidationError("The form family was not found.")
    if command.has("form_revision_id"):
        fields["form_revision"] = FormRevision.objects.filter(pk=command.form_revision_id).first()
        if fields["form_revision"] is None:
            raise ValidationError("The form revision was not found.")
    policy_fields = {
        field_name: getattr(command, field_name)
        for field_name in policy_field_names
        if command.has(field_name)
    }
    configured_field_names = list(fields) + list(policy_fields)
    for field, value in fields.items():
        setattr(collection, field, value)
    
    if collection.start_at >= collection.end_at:
        raise ValidationError("Start time must be before end time.")

    collection.save()

    if policy_fields:
        current_policy = resolve_effective_policy(
            "form_collection.invitation_controls",
            target=collection,
        )
        if current_policy is None:
            raise GovernanceError("Form Collection invitation policy is not configured.")
        config = dict(current_policy.configuration_json or {})
        config.update(policy_fields)
        replace_active_policy_for_target(
            user,
            PolicyChangeRequest(
                key="form_collection.invitation_controls",
                configuration={
                    "default_token_expiry_days": int(config["default_token_expiry_days"]),
                    "identity_verification_policy": str(config["identity_verification_policy"]),
                    "max_uses_per_token": int(config["max_uses_per_token"]),
                    "allow_draft": bool(config["allow_draft"]),
                },
                target_type="form_collection.FormCollection",
                target_reference=str(collection.pk),
                source_reference=f"FORM_COLLECTION:{collection.pk}:CONTROLS_UPDATED",
            ),
        )

    audit_log(
        action_type="UPDATE",
        event_category="FORM_COLLECTION",
        target_model="form_collection.FormCollection",
        target_object_id=str(collection.id),
        actor_user=user,
        metadata={"configured_fields": configured_field_names}
    )
    return collection


def _launch_collection_legacy(user, collection: FormCollection) -> FormCollection:
    """Launch a collection, activating it for tokenized form submissions."""
    if not can_launch_collection(user, collection):
        raise PermissionDeniedError("You do not have permission to launch this collection.")
    if collection.form_type == FormType.CSM_FEEDBACK:
        raise ValidationError(
            "Generic CSM collections cannot be launched. Use a completed service invitation."
        )

    if collection.status not in (CollectionStatus.DRAFT, CollectionStatus.PAUSED):
        raise ValidationError("Collection must be in Draft or Paused status to launch.")

    # Validate presence of form revision for revision-governed collections
    if collection.form_type in (FormType.INDIVIDUAL_INVENTORY, FormType.EXIT_INTERVIEW, FormType.GRADUATE_TRACER, FormType.CSM_FEEDBACK):
        if not collection.form_revision:
            raise ValidationError("Collection must have a form revision selected before launching.")
        if collection.form_revision.status != "ACTIVE":
            raise ValidationError("Selected form revision must be active.")

        try:
            mark_form_revision_used_for_composition(
                user,
                FormRevisionUsageCommand(str(collection.form_revision_id)),
            )
        except GovernanceError as exc:
            raise ValidationError(str(exc)) from exc

    collection.status = CollectionStatus.ACTIVE
    collection.launched_by = user
    collection.launched_at = timezone.now()
    collection.save()

    audit_log(
        action_type="STATUS_CHANGE",
        event_category="FORM_COLLECTION",
        target_model="form_collection.FormCollection",
        target_object_id=str(collection.id),
        actor_user=user,
        metadata={"status": "ACTIVE"}
    )
    return collection


def _pause_collection_legacy(user, collection: FormCollection) -> FormCollection:
    """Pause a launched collection."""
    if not can_configure_collection(user, collection):
        raise PermissionDeniedError("You do not have permission to pause this collection.")

    if collection.status != CollectionStatus.ACTIVE:
        raise ValidationError("Only active collections can be paused.")

    collection.status = CollectionStatus.PAUSED
    collection.save()

    audit_log(
        action_type="STATUS_CHANGE",
        event_category="FORM_COLLECTION",
        target_model="form_collection.FormCollection",
        target_object_id=str(collection.id),
        actor_user=user,
        metadata={"status": "PAUSED"}
    )
    return collection


def _close_collection_legacy(user, collection: FormCollection) -> FormCollection:
    """Permanently close a collection."""
    if not can_configure_collection(user, collection):
        raise PermissionDeniedError("You do not have permission to close this collection.")

    collection.status = CollectionStatus.CLOSED
    collection.closed_by = user
    collection.closed_at = timezone.now()
    collection.save()

    audit_log(
        action_type="STATUS_CHANGE",
        event_category="FORM_COLLECTION",
        target_model="form_collection.FormCollection",
        target_object_id=str(collection.id),
        actor_user=user,
        metadata={"status": "CLOSED"}
    )
    return collection


def _archive_collection_legacy(user, collection: FormCollection) -> FormCollection:
    """Archive a closed collection."""
    if not can_configure_collection(user, collection):
        raise PermissionDeniedError("You do not have permission to archive this collection.")

    collection.status = CollectionStatus.ARCHIVED
    collection.save()

    audit_log(
        action_type="STATUS_CHANGE",
        event_category="FORM_COLLECTION",
        target_model="form_collection.FormCollection",
        target_object_id=str(collection.id),
        actor_user=user,
        metadata={"status": "ARCHIVED"}
    )
    return collection


@transaction.atomic
def _create_invitation_batch_legacy(user, collection: FormCollection, command: InvitationBatchCommand) -> InvitationBatch:
    """Create a new token invitation_batch in DRAFT status."""
    if not isinstance(command, InvitationBatchCommand):
        raise ValidationError("Invitation batches require an InvitationBatchCommand.")
    if not can_issue_invitation_batch(user, collection):
        raise PermissionDeniedError("You do not have permission to issue token invitation_batches.")

    invitation_batch = InvitationBatch.objects.create(
        collection=collection,
        invitation_batch_name=command.name,
        source_type=command.source_type,
        total_requested=command.total_requested,
        status=InvitationBatchStatus.DRAFT,
        created_by=user,
        metadata_json={}
    )

    audit_log(
        action_type="CREATE",
        event_category="TOKEN_BATCH",
        target_model="form_collection.InvitationBatch",
        target_object_id=str(invitation_batch.id),
        actor_user=user,
        metadata={"invitation_batch_name": command.name}
    )
    return invitation_batch


@transaction.atomic
def _issue_form_invitations_legacy(user, invitation_batch: InvitationBatch, recipients: list[InvitationRecipient]) -> list[dict]:
    """Issue form_invitations to list of recipients. Returns raw verifier links/data once."""
    if not isinstance(recipients, list) or not all(isinstance(item, InvitationRecipient) for item in recipients):
        raise ValidationError("Form invitations require validated InvitationRecipient commands.")
    if not can_issue_invitation_batch(user, invitation_batch.collection):
        raise PermissionDeniedError("You do not have permission to issue form_invitations.")

    # Locked read on invitation_batch to prevent race conditions
    invitation_batch = InvitationBatch.objects.select_for_update().get(pk=invitation_batch.id)
    if invitation_batch.collection.form_type == FormType.CSM_FEEDBACK:
        raise ValidationError(
            "Generic CSM form_invitations cannot be issued. Use a completed service invitation."
        )

    if invitation_batch.collection.status != CollectionStatus.ACTIVE:
        raise ValidationError("Collection must be active to issue form_invitations.")

    now = timezone.now()
    if now < invitation_batch.collection.start_at or now > invitation_batch.collection.end_at:
        raise ValidationError("Collection is outside its active date range.")

    invitation_batch.status = InvitationBatchStatus.VALIDATING
    invitation_batch.save()

    issued_tokens = []
    total_issued = 0
    total_failed = 0

    for idx, recipient in enumerate(recipients):
        email = recipient.email
        control_num = recipient.control_number
        student_num = recipient.student_number
        name = recipient.name
        surname = recipient.surname
        birthdate = recipient.birthdate

        try:
            selector, verifier = generate_selector_and_verifier()
            token_hash = hash_verifier(verifier)

            intended_email_hash = hash_identifier(normalize_email(email)) if email else None
            control_number_hash = hash_identifier(normalize_identifier(control_num)) if control_num else None
            student_number_hash = hash_identifier(normalize_identifier(student_num)) if student_num else None

            # Safe secondary verification metadata hashing
            meta_hashes = {}
            if surname:
                meta_hashes["surname_hash"] = hash_identifier(normalize_surname(surname))
            if birthdate:
                meta_hashes["birthdate_hash"] = hash_identifier(normalize_birthdate(birthdate))

            expiry_days, _identity_policy, max_uses, _allow_draft = _collection_controls(invitation_batch.collection)
            token = FormInvitation.objects.create(
                token_hash=token_hash,
                selector=selector,
                collection=invitation_batch.collection,
                invitation_batch=invitation_batch,
                target_form_key=invitation_batch.collection.form_type,
                intended_recipient_name=name,
                intended_email_hash=intended_email_hash,
                control_number_hash=control_number_hash,
                student_number_hash=student_number_hash,
                expires_at=now + timedelta(days=expiry_days),
                max_uses=max_uses,
                status=FormInvitationStatus.ISSUED,
                created_by=user,
                metadata_json=meta_hashes
            )

            issued_tokens.append({
                "selector": selector,
                "raw_token": verifier,
                "recipient_name": name,
                "email": email,
                "control_number": control_num,
                "student_number": student_num
            })
            total_issued += 1
        except Exception:
            logger.warning(
                "Token issuance failed for invitation_batch %s at recipient index %s.",
                invitation_batch.id,
                idx,
            )
            total_failed += 1

    invitation_batch.total_requested = len(recipients)
    invitation_batch.total_issued = total_issued
    invitation_batch.total_failed = total_failed
    invitation_batch.status = InvitationBatchStatus.ISSUED if total_failed == 0 else InvitationBatchStatus.PARTIALLY_ISSUED
    invitation_batch.issued_by = user
    invitation_batch.issued_at = now
    invitation_batch.save()

    audit_log(
        action_type="STATUS_CHANGE",
        event_category="TOKEN_BATCH",
        target_model="form_collection.InvitationBatch",
        target_object_id=str(invitation_batch.id),
        actor_user=user,
        metadata={"total_issued": total_issued, "total_failed": total_failed}
    )
    return issued_tokens


@transaction.atomic
def _record_invitation_opened_legacy(
    selector: str,
    verifier: str,
    ip_address: str = None,
    user_agent: str = None,
    session_id: str = None
) -> tuple[bool, str | FormInvitation]:
    """Validate the raw verifier at the initial boundary and record token opening."""
    selector_identifier_hash = _attempt_identifier_hash("", selector=selector)
    if is_rate_limited(ip_address, session_id, identifier_hash=selector_identifier_hash):
        _record_verification_attempt(
            status=FormInvitationAttemptStatus.RATE_LIMITED,
            failure_reason=FormInvitationFailureReason.INVALID_VERIFIER,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            identifier_hash=selector_identifier_hash,
        )
        return False, "rate_limited"

    try:
        token = FormInvitation.objects.select_for_update().get(selector=selector)
    except FormInvitation.DoesNotExist:
        _record_verification_attempt(
            status=FormInvitationAttemptStatus.FAILED,
            failure_reason=FormInvitationFailureReason.INVALID_TOKEN,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            identifier_hash=selector_identifier_hash,
        )
        return False, "invalid_token"

    if is_rate_limited(ip_address, session_id, form_invitation=token, identifier_hash=selector_identifier_hash):
        _record_verification_attempt(
            form_invitation=token,
            collection=token.collection,
            status=FormInvitationAttemptStatus.RATE_LIMITED,
            failure_reason=FormInvitationFailureReason.INVALID_VERIFIER,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            identifier_hash=selector_identifier_hash,
        )
        return False, "rate_limited"

    now = timezone.now()
    if token.status == FormInvitationStatus.REVOKED:
        _record_verification_attempt(
            form_invitation=token,
            collection=token.collection,
            status=FormInvitationAttemptStatus.REVOKED,
            failure_reason=FormInvitationFailureReason.REVOKED,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            identifier_hash=selector_identifier_hash,
        )
        return False, "revoked"
    if token.status == FormInvitationStatus.EXPIRED or now > token.expires_at:
        if token.status != FormInvitationStatus.EXPIRED:
            token.status = FormInvitationStatus.EXPIRED
            token.save(update_fields=["status", "updated_at"])
        _record_verification_attempt(
            form_invitation=token,
            collection=token.collection,
            status=FormInvitationAttemptStatus.EXPIRED,
            failure_reason=FormInvitationFailureReason.EXPIRED,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            identifier_hash=selector_identifier_hash,
        )
        return False, "expired"
    if token.collection.status != CollectionStatus.ACTIVE:
        _record_failed_attempt(token, FormInvitationFailureReason.COLLECTION_INACTIVE, ip_address, user_agent, session_id, selector_identifier_hash)
        return False, "collection_inactive"
    if token.used_count >= token.max_uses:
        _record_failed_attempt(token, FormInvitationFailureReason.MAX_USES, ip_address, user_agent, session_id, selector_identifier_hash)
        return False, "max_uses_exceeded"
    if not verifier or not compare_tokens(token.token_hash, hash_verifier(verifier)):
        _record_failed_attempt(token, FormInvitationFailureReason.INVALID_TOKEN, ip_address, user_agent, session_id, selector_identifier_hash)
        return False, "invalid_token"

    if token.status == FormInvitationStatus.ISSUED:
        token.status = FormInvitationStatus.OPENED
        token.first_opened_at = timezone.now()
    token.last_opened_at = timezone.now()
    token.save()

    audit_log(
        action_type="TOKEN_OPEN",
        event_category="SECURITY",
        target_model="form_collection.FormInvitation",
        target_object_id=str(token.id),
        ip_address=ip_address,
        user_agent=user_agent,
        metadata={"status": token.status}
    )
    return True, token


@transaction.atomic
def _verify_form_invitation_legacy(
    selector: str,
    verifier: str | None = None,
    ip_address: str = None,
    user_agent: str = None,
    session_id: str = None,
    verification_data: dict = None,
    require_verifier: bool = True,
) -> tuple[bool, str | FormInvitation]:
    """Verify raw token and identity verification parameters. Returns (is_valid, token/error_reason)."""
    selector_identifier_hash = _attempt_identifier_hash("", selector=selector)
    if is_rate_limited(ip_address, session_id, identifier_hash=selector_identifier_hash):
        _record_verification_attempt(
            collection=None,
            identifier_hash=selector_identifier_hash,
            status=FormInvitationAttemptStatus.RATE_LIMITED,
            failure_reason=FormInvitationFailureReason.INVALID_VERIFIER,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
        )
        return False, "rate_limited"

    # 2. Selector lookup
    try:
        token = FormInvitation.objects.select_for_update().get(selector=selector)
    except FormInvitation.DoesNotExist:
        _record_verification_attempt(
            collection=None,
            identifier_hash=selector_identifier_hash,
            status=FormInvitationAttemptStatus.FAILED,
            failure_reason=FormInvitationFailureReason.INVALID_TOKEN,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
        )
        return False, "invalid_token"

    _expiry_days, policy, _max_uses, _allow_draft = _collection_controls(token.collection)
    v_data = verification_data or {}
    verifier_identifier_hash = _attempt_identifier_hash(policy, v_data) or selector_identifier_hash
    if is_rate_limited(ip_address, session_id, form_invitation=token, identifier_hash=verifier_identifier_hash):
        _record_verification_attempt(
            form_invitation=token,
            collection=token.collection,
            status=FormInvitationAttemptStatus.RATE_LIMITED,
            failure_reason=FormInvitationFailureReason.INVALID_VERIFIER,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            identifier_hash=verifier_identifier_hash,
        )
        return False, "rate_limited"

    # 3. Expiry and Revocation check
    now = timezone.now()
    if token.status == FormInvitationStatus.REVOKED:
        _record_verification_attempt(
            form_invitation=token,
            collection=token.collection,
            identifier_hash=verifier_identifier_hash,
            status=FormInvitationAttemptStatus.REVOKED,
            failure_reason=FormInvitationFailureReason.REVOKED,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
        )
        return False, "revoked"

    if token.status == FormInvitationStatus.EXPIRED or now > token.expires_at:
        if token.status != FormInvitationStatus.EXPIRED:
            token.status = FormInvitationStatus.EXPIRED
            token.save()
        _record_verification_attempt(
            form_invitation=token,
            collection=token.collection,
            identifier_hash=verifier_identifier_hash,
            status=FormInvitationAttemptStatus.EXPIRED,
            failure_reason=FormInvitationFailureReason.EXPIRED,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
        )
        return False, "expired"

    # 4. Collection status check
    if token.collection.status != CollectionStatus.ACTIVE:
        _record_verification_attempt(
            form_invitation=token,
            collection=token.collection,
            identifier_hash=verifier_identifier_hash,
            status=FormInvitationAttemptStatus.FAILED,
            failure_reason=FormInvitationFailureReason.COLLECTION_INACTIVE,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
        )
        return False, "collection_inactive"

    # 5. Max uses check
    if token.used_count >= token.max_uses:
        _record_verification_attempt(
            form_invitation=token,
            collection=token.collection,
            identifier_hash=verifier_identifier_hash,
            status=FormInvitationAttemptStatus.FAILED,
            failure_reason=FormInvitationFailureReason.MAX_USES,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
        )
        return False, "max_uses_exceeded"

    # 6. Verify token verifier hash
    if require_verifier and (not verifier or not compare_tokens(token.token_hash, hash_verifier(verifier))):
        _record_verification_attempt(
            form_invitation=token,
            collection=token.collection,
            identifier_hash=verifier_identifier_hash,
            status=FormInvitationAttemptStatus.FAILED,
            failure_reason=FormInvitationFailureReason.INVALID_TOKEN,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
        )
        return False, "invalid_token"

    # 7. Identity Verification Policies check
    if policy == "CONTROL_SURNAME_BIRTHDATE":
        control_num = v_data.get("control_number")
        surname = v_data.get("surname")
        birthdate = v_data.get("birthdate")

        if not control_num or not surname or not birthdate:
            _record_failed_attempt(token, FormInvitationFailureReason.INVALID_VERIFIER, ip_address, user_agent, session_id, verifier_identifier_hash)
            return False, "invalid_verifier"

        c_hash = hash_identifier(normalize_identifier(control_num))
        s_hash = hash_identifier(normalize_surname(surname))
        b_hash = hash_identifier(normalize_birthdate(birthdate))

        expected_surname_hash = token.metadata_json.get("surname_hash")
        expected_birthdate_hash = token.metadata_json.get("birthdate_hash")

        # Fallback to matching with linked profiles if profile exists
        if token.control_number_hash != c_hash:
            _record_failed_attempt(token, FormInvitationFailureReason.INVALID_VERIFIER, ip_address, user_agent, session_id, verifier_identifier_hash)
            return False, "invalid_verifier"

        # Check metadata hashes
        if expected_surname_hash and expected_surname_hash != s_hash:
            _record_failed_attempt(token, FormInvitationFailureReason.INVALID_VERIFIER, ip_address, user_agent, session_id, verifier_identifier_hash)
            return False, "invalid_verifier"
        if expected_birthdate_hash and expected_birthdate_hash != b_hash:
            _record_failed_attempt(token, FormInvitationFailureReason.INVALID_VERIFIER, ip_address, user_agent, session_id, verifier_identifier_hash)
            return False, "invalid_verifier"

    elif policy == "CONTROL_EMAIL_OTP":
        control_num = v_data.get("control_number")
        otp = v_data.get("otp")
        if not control_num or not otp:
            _record_failed_attempt(token, FormInvitationFailureReason.INVALID_VERIFIER, ip_address, user_agent, session_id, verifier_identifier_hash)
            return False, "invalid_verifier"

        c_hash = hash_identifier(normalize_identifier(control_num))
        if token.control_number_hash != c_hash:
            _record_failed_attempt(token, FormInvitationFailureReason.INVALID_VERIFIER, ip_address, user_agent, session_id, verifier_identifier_hash)
            return False, "invalid_verifier"

        # OTP Verification
        stored_otp = token.metadata_json.get("verification_otp")
        otp_expiry = token.metadata_json.get("otp_expires_at")
        if not stored_otp or not otp_expiry:
            _record_failed_attempt(token, FormInvitationFailureReason.INVALID_VERIFIER, ip_address, user_agent, session_id, verifier_identifier_hash)
            return False, "invalid_verifier"
        
        # Parse timestamp
        expiry_dt = timezone.datetime.fromisoformat(otp_expiry) if isinstance(otp_expiry, str) else otp_expiry
        if timezone.now() > expiry_dt or not compare_tokens(stored_otp, hash_identifier(normalize_identifier(otp))):
            _record_failed_attempt(token, FormInvitationFailureReason.INVALID_VERIFIER, ip_address, user_agent, session_id, verifier_identifier_hash)
            return False, "invalid_verifier"

    elif policy == "STUDENT_EMAIL":
        student_num = v_data.get("student_number")
        email = v_data.get("email")
        if not student_num or not email:
            _record_failed_attempt(token, FormInvitationFailureReason.INVALID_VERIFIER, ip_address, user_agent, session_id, verifier_identifier_hash)
            return False, "invalid_verifier"

        s_hash = hash_identifier(normalize_identifier(student_num))
        e_hash = hash_identifier(normalize_email(email))

        if token.student_number_hash != s_hash or token.intended_email_hash != e_hash:
            _record_failed_attempt(token, FormInvitationFailureReason.INVALID_VERIFIER, ip_address, user_agent, session_id, verifier_identifier_hash)
            return False, "invalid_verifier"

    elif policy == "EMAIL_OTP":
        email = v_data.get("email")
        otp = v_data.get("otp")
        if not email or not otp:
            _record_failed_attempt(token, FormInvitationFailureReason.INVALID_VERIFIER, ip_address, user_agent, session_id, verifier_identifier_hash)
            return False, "invalid_verifier"

        e_hash = hash_identifier(normalize_email(email))
        if token.intended_email_hash != e_hash:
            _record_failed_attempt(token, FormInvitationFailureReason.INVALID_VERIFIER, ip_address, user_agent, session_id, verifier_identifier_hash)
            return False, "invalid_verifier"

        stored_otp = token.metadata_json.get("verification_otp")
        otp_expiry = token.metadata_json.get("otp_expires_at")
        if not stored_otp or not otp_expiry:
            _record_failed_attempt(token, FormInvitationFailureReason.INVALID_VERIFIER, ip_address, user_agent, session_id, verifier_identifier_hash)
            return False, "invalid_verifier"

        expiry_dt = timezone.datetime.fromisoformat(otp_expiry) if isinstance(otp_expiry, str) else otp_expiry
        if timezone.now() > expiry_dt or not compare_tokens(stored_otp, hash_identifier(normalize_identifier(otp))):
            _record_failed_attempt(token, FormInvitationFailureReason.INVALID_VERIFIER, ip_address, user_agent, session_id, verifier_identifier_hash)
            return False, "invalid_verifier"

    # Identity verification passes!
    if token.status in (FormInvitationStatus.ISSUED, FormInvitationStatus.OPENED):
        token.status = FormInvitationStatus.VERIFIED
        token.verified_at = timezone.now()
    token.save()

    _record_verification_attempt(
        form_invitation=token,
        collection=token.collection,
        identifier_hash=verifier_identifier_hash,
        status=FormInvitationAttemptStatus.SUCCESS,
        ip_address=ip_address,
        user_agent=user_agent,
        session_id=session_id,
    )

    audit_log(
        action_type="TOKEN_VERIFY",
        event_category="SECURITY",
        target_model="form_collection.FormInvitation",
        target_object_id=str(token.id),
        ip_address=ip_address,
        user_agent=user_agent,
        metadata={"status": token.status}
    )
    return True, token


def _start_form_invitation_draft_legacy(form_invitation: FormInvitation) -> FormInvitation:
    """Hook called when form draft saving begins."""
    token = FormInvitation.objects.get(pk=form_invitation.pk)
    if token.collection.status != CollectionStatus.ACTIVE:
        raise ValidationError("Collection is inactive.")
    if token.status in (FormInvitationStatus.REVOKED, FormInvitationStatus.EXPIRED):
        raise ValidationError("Token is expired or revoked.")
    if token.used_count >= token.max_uses:
        raise ValidationError("Token max uses exceeded.")

    if token.status in (FormInvitationStatus.ISSUED, FormInvitationStatus.VERIFIED, FormInvitationStatus.OPENED):
        token.status = FormInvitationStatus.DRAFT_STARTED
        token.save()

    audit_log(
        action_type="FORM_DRAFT_START",
        event_category="FORM",
        target_model="form_collection.FormInvitation",
        target_object_id=str(token.id),
        metadata={"status": token.status}
    )
    return token


@transaction.atomic
def _mark_form_invitation_submitted_legacy(form_invitation: FormInvitation) -> FormInvitation:
    """Hook called when the form is submitted."""
    token = FormInvitation.objects.select_for_update().get(pk=form_invitation.pk)
    if token.collection.status != CollectionStatus.ACTIVE:
        raise ValidationError("Collection is inactive.")
    if token.status in (FormInvitationStatus.REVOKED, FormInvitationStatus.EXPIRED):
        raise ValidationError("Token is expired or revoked.")
    if token.used_count >= token.max_uses:
        raise ValidationError("Token has already been fully used.")

    token.used_count += 1
    if token.used_count >= token.max_uses:
        token.status = FormInvitationStatus.SUBMITTED
    token.submitted_at = timezone.now()
    token.save()

    audit_log(
        action_type="FORM_SUBMIT",
        event_category="FORM",
        target_model="form_collection.FormInvitation",
        target_object_id=str(token.id),
        metadata={"status": token.status, "used_count": token.used_count}
    )
    return token


@transaction.atomic
def _revoke_form_invitation_legacy(user, token: FormInvitation, reason: str = "") -> FormInvitation:
    """Revoke form access token."""
    if not can_revoke_form_invitation(user, token):
        raise PermissionDeniedError("You do not have permission to revoke form_invitations.")

    token = FormInvitation.objects.select_for_update().get(pk=token.pk)
    token.status = FormInvitationStatus.REVOKED
    token.revoked_by = user
    token.revoked_at = timezone.now()
    token.revoke_reason = reason
    token.save()

    audit_log(
        action_type="REVOKE",
        event_category="SECURITY",
        target_model="form_collection.FormInvitation",
        target_object_id=str(token.id),
        actor_user=user,
        metadata={"status": token.status}
    )
    return token


@transaction.atomic
def _create_unlinked_submission_legacy(
    collection: FormCollection,
    token: FormInvitation,
    control_number: str,
    student_number: str = None,
    email: str = None,
    name: str = None,
    program: str = None,
    metadata_json: dict = None
) -> UnlinkedFormSubmission:
    """Create a unlinked student record from a form submission prior to official account setup."""
    c_hash = hash_identifier(normalize_identifier(control_number)) if control_number else None
    s_hash = hash_identifier(normalize_identifier(student_number)) if student_number else None
    e_hash = hash_identifier(normalize_email(email)) if email else None

    record = UnlinkedFormSubmission.objects.create(
        control_number_hash=c_hash,
        student_number_hash=s_hash,
        email_hash=e_hash,
        name_snapshot=name,
        program_snapshot=program,
        submitted_inventory=True,
        student_match_status=StudentMatchStatus.UNMATCHED,
        source_collection=collection,
        source_invitation=token,
        metadata_json=metadata_json or {}
    )

    # Perform matching
    record = _match_unlinked_submission_legacy(record, raw_control_number=control_number, raw_student_number=student_number, raw_email=email)

    audit_log(
        action_type="CREATE",
        event_category="UNLINKED_FORM_SUBMISSION",
        target_model="form_collection.UnlinkedFormSubmission",
        target_object_id=str(record.id),
        metadata={"student_match_status": record.student_match_status}
    )
    return record


@transaction.atomic
def _match_unlinked_submission_legacy(
    record: UnlinkedFormSubmission,
    raw_control_number: str = None,
    raw_student_number: str = None,
    raw_email: str = None
) -> UnlinkedFormSubmission:
    """Find matching official StudentProfile based on priority check: Control number, then student number, then email."""
    record = UnlinkedFormSubmission.objects.select_for_update().get(pk=record.id)
    if record.student_match_status == StudentMatchStatus.LINKED:
        return record

    candidates = set()

    # Priority 1: Control number match
    if raw_control_number:
        norm_c = normalize_identifier(raw_control_number)
        c_matches = StudentProfile.objects.filter(control_number=norm_c)
        for c in c_matches:
            candidates.add(c)

    # Priority 2: Student number match
    if raw_student_number:
        norm_s = normalize_identifier(raw_student_number)
        s_matches = StudentProfile.objects.filter(student_number=norm_s)
        for s in s_matches:
            candidates.add(s)

    email_verified = bool(record.metadata_json.get("email_verified"))

    # Verified email can support review candidates, but raw submitted email alone
    # never silently links a unlinked record.
    if raw_email and email_verified and (raw_control_number or raw_student_number):
        norm_e = normalize_email(raw_email)
        email_matches = StudentProfile.objects.filter(user__email=norm_e)
        for em in email_matches:
            candidates.add(em)

    if len(candidates) >= 1:
        # Any likely existing profile requires authorized manual review before linking.
        record.student_match_status = StudentMatchStatus.NEEDS_MANUAL_REVIEW
        record.linked_student = None
        record.matched_at = timezone.now()
    else:
        # Unmatched
        record.student_match_status = StudentMatchStatus.UNMATCHED
        record.linked_student = None
        record.matched_at = None

    record.save()
    return record


@transaction.atomic
def _link_unlinked_submission_legacy(user, record: UnlinkedFormSubmission, student_profile: StudentProfile) -> UnlinkedFormSubmission:
    """Explicitly link a unlinked record to a verified StudentProfile."""
    if not can_link_unlinked_submission(user):
        raise PermissionDeniedError("You do not have permission to link unlinked records.")

    record = UnlinkedFormSubmission.objects.select_for_update().get(pk=record.id)
    if record.student_match_status == StudentMatchStatus.LINKED:
        raise ValidationError("This unlinked record is already linked.")

    record.linked_student = student_profile
    record.student_match_status = StudentMatchStatus.LINKED
    record.linked_at = timezone.now()
    record.reviewed_by = user
    record.reviewed_at = timezone.now()
    record.save()

    # Link source token if exists
    if record.source_invitation:
        token = FormInvitation.objects.select_for_update().get(pk=record.source_invitation.pk)
        token.linked_student = student_profile
        token.status = FormInvitationStatus.LINKED_TO_ACCOUNT
        token.save()
        if token.collection.form_type == FormType.GRADUATE_TRACER:
            from apps.graduate_tracer.notification_services import enqueue_gts_reminder

            enqueue_gts_reminder(token)
        elif token.collection.form_type == FormType.EXIT_INTERVIEW:
            from apps.exit_interviews.notification_services import enqueue_notification_event

            enqueue_notification_event(
                "exit_interview.reminder",
                {
                    "assignment_id": "",
                    "response_id": "",
                    "access_id": str(token.pk),
                    "action": "reminder",
                    "status": "Available",
                },
                related_object=token,
                event_key=f"exit_interview:token_reminder:{token.pk}",
            )
        else:
            from apps.form_collection.notification_services import enqueue_collection_linked_event

            enqueue_collection_linked_event(token)

    audit_log(
        action_type="LINK_ACCOUNT",
        event_category="UNLINKED_FORM_SUBMISSION",
        target_model="form_collection.UnlinkedFormSubmission",
        target_object_id=str(record.id),
        actor_user=user,
        metadata={"linked_student_id": str(student_profile.id)}
    )
    return record


@transaction.atomic
def _reject_unlinked_match_legacy(user, record: UnlinkedFormSubmission) -> UnlinkedFormSubmission:
    """Manually reject a unlinked matching link request."""
    if not can_review_manual_match(user):
        raise PermissionDeniedError("You do not have permission to reject unlinked matches.")

    record = UnlinkedFormSubmission.objects.select_for_update().get(pk=record.id)
    if record.student_match_status == StudentMatchStatus.LINKED:
        raise ValidationError("Cannot reject an already linked record.")

    record.student_match_status = StudentMatchStatus.REJECTED
    record.reviewed_by = user
    record.reviewed_at = timezone.now()
    record.save()

    audit_log(
        action_type="REJECT_MATCH",
        event_category="UNLINKED_FORM_SUBMISSION",
        target_model="form_collection.UnlinkedFormSubmission",
        target_object_id=str(record.id),
        actor_user=user
    )
    return record


@transaction.atomic
def _transition_student_lifecycle_legacy(user, student_profile: StudentProfile, new_status: str) -> StudentProfile:
    """Transition a student lifecycle status (e.g. from graduating/graduated to alumni)."""
    if not can_change_student_lifecycle(user):
        raise PermissionDeniedError("You do not have permission to change student lifecycle statuses.")

    old_status = student_profile.lifecycle_status
    if old_status == new_status:
        return student_profile

    # Re-validate choices
    if new_status not in StudentLifecycleChoices.values:
        raise ValidationError(f"Invalid lifecycle status choices: {new_status}")

    student_profile.lifecycle_status = new_status
    student_profile.save()

    audit_log(
        action_type="STATUS_CHANGE",
        event_category="STUDENT_LIFECYCLE",
        target_model="profiles.StudentProfile",
        target_object_id=str(student_profile.id),
        actor_user=user,
        metadata={"old_status": old_status, "new_status": new_status}
    )
    return student_profile


# ---------------------------------------------------------------------------
# Canonical stable-ID service boundary
# ---------------------------------------------------------------------------


def _check_expected_updated_at(value, expected: str | None) -> None:
    if expected and value.updated_at.isoformat() != expected:
        raise StaleStateError()


def _collection_by_id(collection_id):
    collection = FormCollection.objects.select_for_update().select_related("form_family", "form_revision").filter(pk=collection_id).first()
    if collection is None:
        raise ValidationError("The Form Collection was not found.")
    return collection


@transaction.atomic
def create_collection(actor, command: FormCollectionCreateCommand) -> FormCollection:
    if not isinstance(command, FormCollectionCreateCommand):
        raise ValidationError("Form Collection creation requires a typed command.")
    from apps.organizations.models import FormFamily, FormRevision

    form_family = FormFamily.objects.filter(pk=command.form_family_id).first() if command.form_family_id else None
    form_revision = FormRevision.objects.filter(pk=command.form_revision_id).first() if command.form_revision_id else None
    if command.form_family_id and form_family is None:
        raise ValidationError("The form family was not found.")
    if command.form_revision_id and form_revision is None:
        raise ValidationError("The form revision was not found.")
    return _create_collection_legacy(
        actor,
        name=command.name,
        start_at=command.start_at,
        end_at=command.end_at,
        form_family=form_family,
        form_revision=form_revision,
        form_type=command.form_type,
        description=command.description,
        audience=command.audience,
    )


@transaction.atomic
def configure_collection(actor, collection_id, command: FormCollectionConfigureCommand) -> FormCollection:
    if not isinstance(command, FormCollectionConfigureCommand):
        raise ValidationError("Form Collection configuration requires a typed command.")
    collection = _collection_by_id(collection_id)
    _check_expected_updated_at(collection, command.expected_updated_at)
    return _configure_collection_legacy(actor, collection, command)


def _lifecycle_collection(actor, collection_id, command, transition):
    if not isinstance(command, FormCollectionLifecycleCommand):
        raise ValidationError("Collection lifecycle operations require a typed command.")
    collection = _collection_by_id(collection_id)
    _check_expected_updated_at(collection, command.expected_updated_at)
    return transition(actor, collection)


def launch_collection(actor, collection_id, command: FormCollectionLifecycleCommand | None = None):
    return _lifecycle_collection(actor, collection_id, command or FormCollectionLifecycleCommand(), _launch_collection_legacy)


def pause_collection(actor, collection_id, command: FormCollectionLifecycleCommand | None = None):
    return _lifecycle_collection(actor, collection_id, command or FormCollectionLifecycleCommand(), _pause_collection_legacy)


def close_collection(actor, collection_id, command: FormCollectionLifecycleCommand | None = None):
    return _lifecycle_collection(actor, collection_id, command or FormCollectionLifecycleCommand(), _close_collection_legacy)


def archive_collection(actor, collection_id, command: FormCollectionLifecycleCommand | None = None):
    return _lifecycle_collection(actor, collection_id, command or FormCollectionLifecycleCommand(), _archive_collection_legacy)


@transaction.atomic
def create_invitation_batch(actor, collection_id, command: InvitationBatchCommand) -> InvitationBatch:
    if not isinstance(command, InvitationBatchCommand):
        raise ValidationError("Invitation batches require a typed command.")
    collection = _collection_by_id(collection_id)
    return _create_invitation_batch_legacy(actor, collection, command)


@transaction.atomic
def issue_form_invitations(actor, invitation_batch_id, command: InvitationIssueCommand) -> list[dict]:
    if not isinstance(command, InvitationIssueCommand):
        raise ValidationError("Invitation issuance requires a typed command.")
    batch = InvitationBatch.objects.select_for_update().select_related("collection").filter(pk=invitation_batch_id).first()
    if batch is None:
        raise ValidationError("The invitation batch was not found.")
    return _issue_form_invitations_legacy(actor, batch, list(command.recipients))


def verify_invitation(actor, command: InvitationVerificationCommand, request_metadata: RequestMetadata):
    if not isinstance(command, InvitationVerificationCommand):
        raise ValidationError("Invitation verification requires a typed command.")
    if not isinstance(request_metadata, RequestMetadata):
        raise ValidationError("Request metadata is required for invitation verification.")
    valid, result = _verify_form_invitation_legacy(
        selector=command.selector,
        verifier=command.verifier,
        ip_address=request_metadata.ip_address,
        user_agent=request_metadata.user_agent,
        session_id=request_metadata.session_key,
        verification_data=command.as_verification_data(),
    )
    if not valid:
        if result == "rate_limited":
            raise RateLimitError(retry_after=60)
        raise ValidationError("The invitation could not be verified.")
    return result


def start_invitation_draft(invitation_id):
    invitation = FormInvitation.objects.select_for_update().filter(pk=invitation_id).first()
    if invitation is None:
        raise ValidationError("The invitation was not found.")
    return _start_form_invitation_draft_legacy(invitation)


@transaction.atomic
def consume_invitation(invitation_id):
    invitation = FormInvitation.objects.select_for_update().filter(pk=invitation_id).first()
    if invitation is None:
        raise ValidationError("The invitation was not found.")
    return _mark_form_invitation_submitted_legacy(invitation)


@transaction.atomic
def revoke_form_invitation(actor, invitation_id, command: InvitationRevokeCommand) -> FormInvitation:
    if not isinstance(command, InvitationRevokeCommand):
        raise ValidationError("Invitation revocation requires a typed command.")
    token = FormInvitation.objects.select_for_update().filter(pk=invitation_id).first()
    if token is None:
        raise ValidationError("The invitation was not found.")
    _check_expected_updated_at(token, command.expected_updated_at)
    return _revoke_form_invitation_legacy(actor, token, command.reason)


@transaction.atomic
def link_unlinked_submission(actor, record_id, command: ManualMatchDecisionCommand):
    if not isinstance(command, ManualMatchDecisionCommand) or not command.student_profile_id:
        raise ValidationError("Linking requires a target student profile.")
    record = UnlinkedFormSubmission.objects.select_for_update().filter(pk=record_id).first()
    if record is None:
        raise ValidationError("The unlinked submission was not found.")
    _check_expected_updated_at(record, command.expected_updated_at)
    student_profile = StudentProfile.objects.filter(pk=command.student_profile_id).first()
    if student_profile is None:
        raise ValidationError("The student profile was not found.")
    return _link_unlinked_submission_legacy(actor, record, student_profile)


@transaction.atomic
def reject_unlinked_match(actor, record_id, command: ManualMatchDecisionCommand | None = None):
    command = command or ManualMatchDecisionCommand()
    if not isinstance(command, ManualMatchDecisionCommand):
        raise ValidationError("Match rejection requires a typed command.")
    record = UnlinkedFormSubmission.objects.select_for_update().filter(pk=record_id).first()
    if record is None:
        raise ValidationError("The unlinked submission was not found.")
    _check_expected_updated_at(record, command.expected_updated_at)
    return _reject_unlinked_match_legacy(actor, record)
