# Project: COMPASS
# File: apps/good_moral/policies.py
# Module: apps.good_moral
# Purpose: Access policies for Good Moral requests and generated documents
# Domain boundary and service policy.

import logging
from django.db.models import Q
from apps.access_control.rules import (
    is_active_nonlegacy_actor,
    is_student,
    is_counselor,
    is_gco_staff,
    is_it_admin,
    owns_student_profile,
    owns_user,
)
from apps.access_control.authority import has_capability, has_fixed_capability
from apps.access_control.capabilities import Capability
from apps.access_control.scopes import (
    build_geographic_scope_q,
    build_workflow_authority_scope_q,
    counselor_has_live_coverage_for_student,
    get_active_workflow_authority_grants,
    get_live_counselor_coverages,
    workflow_authority_authorizes_record,
)

logger = logging.getLogger(__name__)


GOOD_MORAL_OPERATION_CAPABILITIES = (
    Capability.GOOD_MORAL_RECEIPT_ENCODE,
    Capability.GOOD_MORAL_RECEIPT_VERIFY,
    Capability.GOOD_MORAL_CANCEL,
    Capability.GOOD_MORAL_DOCUMENT_GENERATE,
    Capability.GOOD_MORAL_PRINT,
    Capability.GOOD_MORAL_REGISTRAR_SEAL_CONFIRM,
    Capability.GOOD_MORAL_RELEASE,
)
GOOD_MORAL_DOCUMENT_CAPABILITIES = (
    Capability.GOOD_MORAL_DOCUMENT_GENERATE,
    Capability.GOOD_MORAL_PRINT,
    Capability.GOOD_MORAL_RELEASE,
)


def _is_active_authenticated(user) -> bool:
    return is_active_nonlegacy_actor(user)


def _is_assigned_reviewer(user, request) -> bool:
    return bool(
        _is_active_authenticated(user)
        and request
        and request.assigned_reviewer_id
        and request.assigned_reviewer_id == user.pk
    )


def _is_head_authority(user) -> bool:
    return bool(
        _is_active_authenticated(user)
        and has_fixed_capability(user, Capability.GOOD_MORAL_REVIEW)
    )


def _is_assigned_counselor_in_scope(user, request) -> bool:
    return bool(
        _is_assigned_reviewer(user, request)
        and is_counselor(user)
        and counselor_has_live_coverage_for_student(user, request.student_profile)
    )


def _counselor_can_process_student(user, student_profile) -> bool:
    """Return whether a counselor has scoped Good Moral work for a student."""
    if not (_is_active_authenticated(user) and is_counselor(user) and student_profile):
        return False
    return bool(
        counselor_has_live_coverage_for_student(user, student_profile)
        or has_capability(user, Capability.GOOD_MORAL_REVIEW, target=student_profile)
    )


def _counselor_can_process_request(user, request) -> bool:
    """Require target scope and reject requests assigned to another counselor."""
    if not (_counselor_can_process_student(user, getattr(request, "student_profile", None))):
        return False
    assigned_id = getattr(request, "assigned_reviewer_id", None)
    if assigned_id and assigned_id != getattr(user, "pk", None):
        return False
    return bool(
        _is_assigned_counselor_in_scope(user, request)
        or _workflow_authority_authorizes_request(user, request, Capability.GOOD_MORAL_REVIEW)
        or counselor_has_live_coverage_for_student(user, request.student_profile)
    )


def _is_document_operator(user, request) -> bool:
    return any(_workflow_authority_authorizes_request(user, request, capability)
               for capability in GOOD_MORAL_DOCUMENT_CAPABILITIES)


def _workflow_authority_authorizes_request(user, request, capability) -> bool:
    return bool(
        request
        and has_capability(user, capability, target=request.student_profile)
        and (
            _is_head_authority(user)
            or workflow_authority_authorizes_record(
                user,
                capability=capability,
                student_profile=request.student_profile,
                assigned_counselor=request.assigned_reviewer,
            )
        )
    )


def _staff_scope_q(user):
    from apps.good_moral.models import GoodMoralStatusChoices

    status_q = Q(status__in=(
        GoodMoralStatusChoices.SUBMITTED,
        GoodMoralStatusChoices.FOR_PAYMENT,
        GoodMoralStatusChoices.PAYMENT_ENCODED,
        GoodMoralStatusChoices.APPROVED_FOR_GENERATION,
        GoodMoralStatusChoices.GENERATED,
        GoodMoralStatusChoices.PRINTED,
        GoodMoralStatusChoices.RELEASED,
        GoodMoralStatusChoices.FAILED,
    ))
    scope_q = Q(pk__in=[])
    for capability in GOOD_MORAL_OPERATION_CAPABILITIES:
        scope_q |= build_workflow_authority_scope_q(
            user,
            capability=capability,
            field_map={
                "campus": "student_profile__campus",
                "college": "student_profile__college",
                "department": "student_profile__department",
                "program": "student_profile__program",
            },
            counselor_field="assigned_reviewer",
        )
    return status_q & scope_q


def _counselor_scope_q(user):
    from apps.good_moral.models import GoodMoralStatusChoices

    coverage_q = build_geographic_scope_q(
        get_live_counselor_coverages(user),
        {
            "campus": "student_profile__campus",
            "college": "student_profile__college",
            "department": "student_profile__department",
            "program": "student_profile__program",
        },
    )
    grant_q = build_workflow_authority_scope_q(
        user,
        capability=Capability.GOOD_MORAL_REVIEW,
        field_map={
            "campus": "student_profile__campus",
            "college": "student_profile__college",
            "department": "student_profile__department",
            "program": "student_profile__program",
        },
        counselor_field="assigned_reviewer",
    )
    confirmation_grant_q = build_workflow_authority_scope_q(
        user,
        capability=Capability.GOOD_MORAL_REGISTRAR_SEAL_CONFIRM,
        field_map={
            "campus": "student_profile__campus",
            "college": "student_profile__college",
            "department": "student_profile__department",
            "program": "student_profile__program",
        },
        counselor_field="assigned_reviewer",
    )
    return (
        (
            Q(assigned_reviewer=user) & coverage_q
        ) | grant_q | confirmation_grant_q
    ) & Q(
        status__in=(
            GoodMoralStatusChoices.PAYMENT_ENCODED,
            GoodMoralStatusChoices.FOR_RECORD_CHECKING,
            GoodMoralStatusChoices.PENDING_MANUAL_OSSD_VERIFICATION,
            GoodMoralStatusChoices.ON_HOLD_FOR_REVIEW,
            GoodMoralStatusChoices.FOR_APPROVAL,
            GoodMoralStatusChoices.APPROVED_FOR_GENERATION,
            GoodMoralStatusChoices.FAILED,
            GoodMoralStatusChoices.RELEASED,
        ),
    )


def _head_guidance_scope_q():
    from apps.good_moral.models import GoodMoralStatusChoices

    return ~Q(status=GoodMoralStatusChoices.DRAFT)


def visible_request_filter_for(user):
    """Return an object/status-scoped Q for requests visible to the actor."""
    if not _is_active_authenticated(user) or is_it_admin(user):
        return Q(pk__in=[])
    if is_student(user):
        return Q(requester_user=user)
    if _is_head_authority(user):
        return _head_guidance_scope_q()
    if is_counselor(user):
        return _counselor_scope_q(user)
    if is_gco_staff(user):
        return _staff_scope_q(user)
    return Q(pk__in=[])


def can_view_review_queue(user) -> bool:
    if not _is_active_authenticated(user) or is_it_admin(user):
        return False
    if _is_head_authority(user):
        return True
    if is_counselor(user):
        return get_active_workflow_authority_grants(
            user, capability=Capability.GOOD_MORAL_REVIEW
        ).exists() or get_live_counselor_coverages(user).exists()
    if is_gco_staff(user):
        return any(get_active_workflow_authority_grants(user, capability=capability).exists()
                   for capability in GOOD_MORAL_OPERATION_CAPABILITIES)
    return False


def can_create_request(user, student_profile, *, requester_user=None) -> bool:
    """Authorize creation against the concrete student target.

    Student creation is exact owner self-service.  Counselor creation is
    coverage/grant scoped; GCO creation requires the explicit document
    operation grant.  Role membership alone never authorizes creation.
    """
    if not _is_active_authenticated(user):
        return False
    if is_it_admin(user) or student_profile is None:
        return False
    if is_student(user):
        return owns_student_profile(user, student_profile) and (
            requester_user is None or owns_user(user, getattr(requester_user, "pk", None))
        )
    if is_counselor(user):
        return _counselor_can_process_student(user, student_profile)
    if is_gco_staff(user):
        return has_capability(
            user, Capability.GOOD_MORAL_DOCUMENT_GENERATE, target=student_profile
        )
    return False


def can_view_request(user, request) -> bool:
    """Object/status scoped request detail visibility."""
    if not _is_active_authenticated(user) or not request:
        return False
    if is_it_admin(user):
        return False  # Technical metadata only, no request content
    if is_student(user):
        return owns_user(user, request.requester_user_id)
    if _is_head_authority(user):
        from apps.good_moral.models import GoodMoralStatusChoices

        return request.status != GoodMoralStatusChoices.DRAFT
    if is_counselor(user):
        from apps.good_moral.models import GoodMoralStatusChoices

        return (
            (
                _is_assigned_counselor_in_scope(user, request)
                or _workflow_authority_authorizes_request(
                    user, request, Capability.GOOD_MORAL_REVIEW
                )
                or _workflow_authority_authorizes_request(
                    user, request, Capability.GOOD_MORAL_REGISTRAR_SEAL_CONFIRM
                )
            )
            and request.status != GoodMoralStatusChoices.DRAFT
        )
    if is_gco_staff(user):
        return (
            any(
                _workflow_authority_authorizes_request(user, request, capability)
                for capability in GOOD_MORAL_OPERATION_CAPABILITIES
            )
            and request.status != "DRAFT"
        )
    return False


def can_submit_request(user, request) -> bool:
    """Submit a draft owned by the student or prepared by guidance personnel."""
    if not _is_active_authenticated(user) or is_it_admin(user) or not request:
        return False
    from apps.good_moral.models import GoodMoralStatusChoices

    if request.status != GoodMoralStatusChoices.DRAFT:
        return False
    if is_student(user):
        return owns_user(user, request.requester_user_id)
    return (
        (is_counselor(user) and _counselor_can_process_request(user, request))
        or _workflow_authority_authorizes_request(user, request, Capability.GOOD_MORAL_DOCUMENT_GENERATE)
    )


def can_update_draft(user, request) -> bool:
    """Allow only the owner or the same scoped operational actor to edit a draft."""
    if not _is_active_authenticated(user) or not request:
        return False
    from apps.good_moral.models import GoodMoralStatusChoices

    if request.status != GoodMoralStatusChoices.DRAFT:
        return False
    if is_student(user):
        return owns_user(user, request.requester_user_id)
    if is_counselor(user):
        return _counselor_can_process_request(user, request)
    if is_gco_staff(user):
        return _workflow_authority_authorizes_request(
            user, request, Capability.GOOD_MORAL_DOCUMENT_GENERATE
        )
    return False


def can_cancel_request(user, request) -> bool:
    """Student self-cancellation or explicitly granted operational cancellation."""
    if not _is_active_authenticated(user) or request is None:
        return False
    from apps.good_moral.models import GoodMoralStatusChoices
    if is_student(user):
        if not owns_user(user, request.requester_user_id):
            return False
        return request.status in (
            GoodMoralStatusChoices.DRAFT,
            GoodMoralStatusChoices.SUBMITTED,
            GoodMoralStatusChoices.FOR_PAYMENT,
        )
    return _workflow_authority_authorizes_request(user, request, Capability.GOOD_MORAL_CANCEL)


def _has_verified_receipt(request) -> bool:
    from apps.good_moral.models import ReceiptStatusChoices

    return bool(request and request.receipt_status == ReceiptStatusChoices.VERIFIED)


def can_encode_receipt_metadata(user, request) -> bool:
    """Authorize entering receipt details; this does not verify payment."""
    if not _is_active_authenticated(user) or not request:
        return False
    from apps.good_moral.models import GoodMoralStatusChoices

    if request.status not in (
        GoodMoralStatusChoices.SUBMITTED,
        GoodMoralStatusChoices.FOR_PAYMENT,
        GoodMoralStatusChoices.PAYMENT_ENCODED,
    ):
        return False
    return (
        _is_head_authority(user)
        or _workflow_authority_authorizes_request(user, request, Capability.GOOD_MORAL_RECEIPT_ENCODE)
    )


def can_verify_receipt_metadata(user, request) -> bool:
    """Authorize GCO-side verification of Cashier-provided receipt data."""
    if not _is_active_authenticated(user) or not request:
        return False
    from apps.good_moral.models import GoodMoralStatusChoices, ReceiptStatusChoices

    if request.receipt_status != ReceiptStatusChoices.ENCODED:
        return False
    if request.status not in (
        GoodMoralStatusChoices.PAYMENT_ENCODED,
        GoodMoralStatusChoices.FOR_RECORD_CHECKING,
    ):
        return False
    return (
        _is_head_authority(user)
        or _workflow_authority_authorizes_request(user, request, Capability.GOOD_MORAL_RECEIPT_VERIFY)
    )


def can_start_review(user, request) -> bool:
    """Only scoped counselor/head can start review."""
    if not _is_active_authenticated(user):
        return False
    from apps.good_moral.models import GoodMoralStatusChoices

    if not _has_verified_receipt(request) or request.status not in (
        GoodMoralStatusChoices.PAYMENT_ENCODED,
        GoodMoralStatusChoices.FOR_RECORD_CHECKING,
        GoodMoralStatusChoices.PENDING_MANUAL_OSSD_VERIFICATION,
        GoodMoralStatusChoices.ON_HOLD_FOR_REVIEW,
    ):
        return False
    return _is_head_authority(user) or _is_assigned_counselor_in_scope(user, request) or _workflow_authority_authorizes_request(
        user, request, Capability.GOOD_MORAL_REVIEW,
    )


def can_assign_reviewer(user, request, reviewer) -> bool:
    """Allow Head Guidance to make an explicit, scoped reviewer assignment."""
    if not _is_head_authority(user) or not request or not reviewer:
        return False
    from apps.good_moral.models import GoodMoralStatusChoices

    if not _has_verified_receipt(request) or request.status not in (
        GoodMoralStatusChoices.PAYMENT_ENCODED,
        GoodMoralStatusChoices.FOR_RECORD_CHECKING,
        GoodMoralStatusChoices.PENDING_MANUAL_OSSD_VERIFICATION,
        GoodMoralStatusChoices.ON_HOLD_FOR_REVIEW,
    ):
        return False
    if not _is_active_authenticated(reviewer) or not is_counselor(reviewer):
        return False
    if has_fixed_capability(reviewer, Capability.GOOD_MORAL_REVIEW):
        return True
    return counselor_has_live_coverage_for_student(reviewer, request.student_profile)


def can_hold_request(user, request) -> bool:
    """Only scoped assigned counselor/head can hold request."""
    if not _is_active_authenticated(user):
        return False
    from apps.good_moral.models import GoodMoralStatusChoices

    if not _has_verified_receipt(request) or request.status not in (
        GoodMoralStatusChoices.FOR_RECORD_CHECKING,
        GoodMoralStatusChoices.PENDING_MANUAL_OSSD_VERIFICATION,
        GoodMoralStatusChoices.ON_HOLD_FOR_REVIEW,
        GoodMoralStatusChoices.FOR_APPROVAL,
    ):
        return False
    return _is_head_authority(user) or _is_assigned_counselor_in_scope(user, request) or _workflow_authority_authorizes_request(
        user, request, Capability.GOOD_MORAL_REVIEW,
    )


def can_approve_request(user, request) -> bool:
    """Only the institutional Head/signatory approves the request."""
    if not _is_active_authenticated(user):
        return False
    from apps.good_moral.models import GoodMoralStatusChoices

    if not _has_verified_receipt(request) or request.status not in (
        GoodMoralStatusChoices.FOR_RECORD_CHECKING,
        GoodMoralStatusChoices.ON_HOLD_FOR_REVIEW,
        GoodMoralStatusChoices.FOR_APPROVAL,
    ):
        return False
    return _is_head_authority(user) or _workflow_authority_authorizes_request(
        user, request, Capability.GOOD_MORAL_APPROVE,
    )


def can_reject_request(user, request) -> bool:
    """Only scoped assigned counselor/head can reject request."""
    if not _is_active_authenticated(user):
        return False
    from apps.good_moral.models import GoodMoralStatusChoices

    if not _has_verified_receipt(request) or request.status in (
        GoodMoralStatusChoices.DRAFT,
        GoodMoralStatusChoices.RELEASED,
        GoodMoralStatusChoices.VOIDED,
        GoodMoralStatusChoices.ARCHIVED,
        GoodMoralStatusChoices.CANCELLED,
        GoodMoralStatusChoices.REJECTED,
    ):
        return False
    return _is_head_authority(user) or _is_assigned_counselor_in_scope(user, request) or _workflow_authority_authorizes_request(
        user, request, Capability.GOOD_MORAL_REJECT,
    )


def can_generate_request_document(user, request) -> bool:
    """Only an assigned document operator generates the official certificate."""
    if not _is_active_authenticated(user):
        return False
    from apps.good_moral.models import GoodMoralStatusChoices

    if not _has_verified_receipt(request) or request.status not in (
        GoodMoralStatusChoices.APPROVED_FOR_GENERATION,
        GoodMoralStatusChoices.FAILED,
    ):
        return False
    return _workflow_authority_authorizes_request(user, request, Capability.GOOD_MORAL_DOCUMENT_GENERATE)


def can_mark_printed(user, request) -> bool:
    """Only an assigned document operator marks a certificate printed."""
    if not _is_active_authenticated(user):
        return False
    from apps.good_moral.models import GoodMoralStatusChoices

    if not _has_verified_receipt(request) or request.status not in (GoodMoralStatusChoices.GENERATED, GoodMoralStatusChoices.PRINTED):
        return False
    return _workflow_authority_authorizes_request(user, request, Capability.GOOD_MORAL_PRINT)


def can_confirm_dry_seal(user, request) -> bool:
    """Authorize recording an external Registrar dry-seal confirmation.

    This records provenance for an event that happened outside COMPASS. It
    never means that the actor applied, owns, or represents the Registrar.
    """
    if not _is_active_authenticated(user) or not request:
        return False
    from apps.good_moral.models import GoodMoralStatusChoices, DrySealStatusChoices

    if (
        request.status != GoodMoralStatusChoices.RELEASED
        or request.dry_seal_status != DrySealStatusChoices.PENDING
        or not request.student_profile
    ):
        return False
    if is_student(user):
        return owns_user(user, request.requester_user_id)
    if not (is_counselor(user) or is_gco_staff(user)):
        return False
    if not has_capability(
        user,
        Capability.GOOD_MORAL_REGISTRAR_SEAL_CONFIRM,
        target=request.student_profile,
    ):
        return False
    if _is_head_authority(user):
        return True
    return workflow_authority_authorizes_record(
        user,
        capability=Capability.GOOD_MORAL_REGISTRAR_SEAL_CONFIRM,
        student_profile=request.student_profile,
        assigned_counselor=request.assigned_reviewer,
    )


def can_release_request(user, request) -> bool:
    """Only an assigned document operator releases the certificate."""
    if not _is_active_authenticated(user):
        return False
    from apps.good_moral.models import GoodMoralStatusChoices

    if (
        not _has_verified_receipt(request)
        or request.status != GoodMoralStatusChoices.PRINTED
        or not request.generated_document_id
    ):
        return False
    return _workflow_authority_authorizes_request(user, request, Capability.GOOD_MORAL_RELEASE)


def can_void_request(user, request) -> bool:
    """Only Head Guidance can void eligible generated/released requests."""
    if not _is_active_authenticated(user):
        return False
    from apps.good_moral.models import GoodMoralStatusChoices

    return (_is_head_authority(user) or _workflow_authority_authorizes_request(user, request, Capability.GOOD_MORAL_VOID)) and request.status in (
        GoodMoralStatusChoices.GENERATED,
        GoodMoralStatusChoices.PRINTED,
        GoodMoralStatusChoices.RELEASED,
    )


def can_supersede_request(user, request) -> bool:
    """Only Head Guidance can replace an existing generated certificate."""
    return bool(request and request.generated_document_id and can_void_request(user, request))


def can_archive_request(user, request) -> bool:
    """Only Head Guidance can archive terminal requests."""
    if not _is_active_authenticated(user):
        return False
    from apps.good_moral.models import GoodMoralStatusChoices

    return (_is_head_authority(user) or _workflow_authority_authorizes_request(user, request, Capability.GOOD_MORAL_ARCHIVE)) and request.status in (
        GoodMoralStatusChoices.REJECTED,
        GoodMoralStatusChoices.CANCELLED,
        GoodMoralStatusChoices.VOIDED,
        GoodMoralStatusChoices.RELEASED,
    )


def can_read_generated_certificate_content(user, request, generated_document) -> bool:
    """Exact Good Moral certificate content policy.

    Head Guidance and assigned document operators may access content during
    the operational print/release preparation states. Requester
    access is limited to the released certificate. IT Admin, regular
    counselors, and public/anonymous users are denied before release.
    """
    if not _is_active_authenticated(user) or is_it_admin(user):
        return False
    if not request or not generated_document:
        return False
    if request.generated_document_id != generated_document.pk:
        return False
    from apps.documents.models import DocumentStatusChoices
    from apps.good_moral.models import GoodMoralStatusChoices

    if (
        generated_document.document_status == DocumentStatusChoices.GENERATED
        and request.status in (
            GoodMoralStatusChoices.GENERATED,
            GoodMoralStatusChoices.PRINTED,
        )
    ):
        return _is_head_authority(user) or _is_document_operator(user, request)

    return (
        is_student(user)
        and owns_user(user, request.requester_user_id)
        and request.status == GoodMoralStatusChoices.RELEASED
        and generated_document.document_status == DocumentStatusChoices.RELEASED
    )


# ---------------------------------------------------------------------------
# Generated Document policy callback for apps.documents
# ---------------------------------------------------------------------------

def good_moral_document_policy(user, action: str, *, generated_document=None, context=None) -> bool:
    """Policy callback for GeneratedDocument access registered with apps.documents.

    Delegates to request-scoped logical guards.
    """
    if not user or not getattr(user, "is_active", False):
        if not context or not context.get("system_context"):
            return False

    if is_it_admin(user):
        return False  # IT Admin has no content access

    # Action: generate
    if action == "generate":
        ctx = context or {}
        if ctx.get("owning_app_label") != "good_moral" or ctx.get("owning_model_name") != "GoodMoralRequest":
            return False
        request_id = ctx.get("owning_object_id")
        if not request_id:
            return False
        try:
            from apps.good_moral.models import GoodMoralRequest, GoodMoralStatusChoices
            request_obj = GoodMoralRequest.objects.get(pk=request_id)
        except (GoodMoralRequest.DoesNotExist, ValueError, TypeError):
            return False

        if request_obj.status not in (
            GoodMoralStatusChoices.APPROVED_FOR_GENERATION,
            GoodMoralStatusChoices.GENERATING,
        ):
            return False

        if ctx.get("system_context"):
            return True
        return can_generate_request_document(user, request_obj)

    # Action: read_content, release, void, archive
    if not generated_document:
        return False

    try:
        from apps.good_moral.models import GoodMoralRequest, GoodMoralStatusChoices
        request_obj = GoodMoralRequest.objects.get(generated_document=generated_document)
    except (GoodMoralRequest.DoesNotExist, ValueError, TypeError):
        return False

    if action == "read_content":
        return can_read_generated_certificate_content(user, request_obj, generated_document)

    elif action == "release":
        return can_release_request(user, request_obj)

    elif action == "void":
        return can_void_request(user, request_obj)

    elif action == "archive":
        return can_archive_request(user, request_obj)

    return False


def register_policies():
    """Register callback policy with documents app."""
    from apps.documents.policies import (
        generated_document_file_policy,
        register_generated_document_policy,
    )
    from apps.security.file_policies import register_file_policy

    register_generated_document_policy("good_moral_request", good_moral_document_policy)
    register_file_policy("good_moral_request", generated_document_file_policy)
