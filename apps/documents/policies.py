# Project: COMPASS
# File: apps/documents/policies.py
# Module: apps.documents
# Purpose: Access policies for document templates and generated documents
# Domain boundary and service policy.
# Notes:
#   Role alone must not grant generated-document content access.
#   IT Admin gets metadata-only by default.
#   Head Guidance has business authority for template lifecycle.
#   Student access to own released documents is future workflow behavior.
#   Anonymous/public denied.
#   Policy ambiguity fails closed.

from apps.access_control.authority import has_capability, has_fixed_capability
from apps.access_control.capabilities import Capability
from apps.access_control.rules import is_it_admin
from apps.governance.runtime_config import is_policy_active

GENERATED_DOCUMENT_DEFAULT_POLICY_KEY = "generated_document"
_GENERATED_DOCUMENT_POLICY_REGISTRY = {}


def _template_governance_active() -> bool:
    return is_policy_active("documents.templates")


class GeneratedDocumentPolicyRegistrationError(ValueError):
    """Raised when a generated-document workflow policy registration is invalid."""


def register_generated_document_policy(policy_key: str, callback_fn):
    """Register an explicit workflow/object policy for generated-document actions.

    The callback signature is:
    callback_fn(user, action: str, *, generated_document=None, context=None) -> bool
    """
    if not policy_key or not callable(callback_fn):
        raise GeneratedDocumentPolicyRegistrationError(
            "Invalid generated-document policy registration."
        )
    _GENERATED_DOCUMENT_POLICY_REGISTRY[policy_key] = callback_fn


def unregister_generated_document_policy(policy_key: str):
    """Unregister a generated-document workflow policy."""
    _GENERATED_DOCUMENT_POLICY_REGISTRY.pop(policy_key, None)


def _policy_allows(user, action: str, *, policy_key: str, generated_document=None, context=None) -> bool:
    """Delegate to a registered workflow/object policy, failing closed."""
    callback_fn = _GENERATED_DOCUMENT_POLICY_REGISTRY.get(policy_key or "")
    if not callback_fn:
        return False
    try:
        return bool(
            callback_fn(
                user,
                action,
                generated_document=generated_document,
                context=context or {},
            )
        )
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Template lifecycle policies
# ---------------------------------------------------------------------------

def can_create_template_draft(user) -> bool:
    """Only Head Guidance may author template governance drafts."""
    if not user or not user.is_authenticated:
        return False
    return bool(_template_governance_active() and has_capability(user, Capability.DOCUMENT_TEMPLATES_MANAGE))


def can_activate_template(user) -> bool:
    """Only Head Guidance can activate template versions."""
    if not user or not user.is_authenticated:
        return False
    return bool(_template_governance_active() and has_capability(user, Capability.DOCUMENT_TEMPLATES_MANAGE))


def can_retire_template(user) -> bool:
    """Only Head Guidance can retire template versions."""
    if not user or not user.is_authenticated:
        return False
    return bool(_template_governance_active() and has_capability(user, Capability.DOCUMENT_TEMPLATES_MANAGE))


def can_archive_template(user) -> bool:
    """Only Head Guidance can archive template versions."""
    if not user or not user.is_authenticated:
        return False
    return bool(_template_governance_active() and has_capability(user, Capability.DOCUMENT_TEMPLATES_MANAGE))


def can_view_template_metadata(user) -> bool:
    """Template governance metadata is a Head-owned business surface."""
    if not user or not user.is_authenticated:
        return False
    return bool(_template_governance_active() and has_capability(user, Capability.DOCUMENT_TEMPLATES_MANAGE))


# ---------------------------------------------------------------------------
# Generated document policies
# ---------------------------------------------------------------------------

def can_view_generated_document_metadata(user) -> bool:
    """Head Guidance and IT Admin can view generated document metadata.

    IT Admin gets metadata-only; no content access.
    """
    if not user or not user.is_authenticated:
        return False
    return bool(
        has_capability(user, Capability.DOCUMENT_TEMPLATES_MANAGE)
        or has_fixed_capability(user, Capability.DOCUMENTS_TECHNICAL_METADATA_VIEW)
    )


def can_access_generated_document_content(user, generated_document) -> bool:
    """Object-level content access for generated documents.

    Role alone must not grant content access.
    Head Guidance, counselors, staff, and students require an explicit
    workflow/object policy before content access is allowed.
    IT Admin: metadata-only, no content access.
    Students: no access in this foundation; future workflow behavior.
    Anonymous/public: denied.
    System renderer jobs need explicit narrow context.
    """
    if not user or not user.is_authenticated:
        return False

    # IT Admin: metadata-only, never content
    if is_it_admin(user):
        return False

    if not generated_document:
        return False

    from apps.documents.models import DocumentStatusChoices
    if generated_document.document_status not in (
        DocumentStatusChoices.GENERATED,
        DocumentStatusChoices.RELEASED,
    ):
        return False
    return _policy_allows(
        user,
        "read_content",
        policy_key=generated_document.access_policy_key,
        generated_document=generated_document,
    )


def can_generate_document(
    user,
    *,
    access_policy_key: str = "",
    context: dict | None = None,
    system_context=False,
) -> bool:
    """Document generation is service-driven, not role-granted.

    Default-deny. Future workflows must register explicit exact policies.
    """
    if not user or not user.is_authenticated:
        if not system_context:
            return False
    policy_context = {**(context or {}), "system_context": bool(system_context)}
    return _policy_allows(
        user,
        "generate",
        policy_key=access_policy_key,
        context=policy_context,
    )


def can_release_generated_document(user, generated_document=None) -> bool:
    """Release is workflow-driven and default-denied in this foundation."""
    if not user or not user.is_authenticated:
        return False
    if not generated_document:
        return False
    return _policy_allows(
        user,
        "release",
        policy_key=generated_document.access_policy_key,
        generated_document=generated_document,
    )


def can_void_generated_document(user, generated_document=None) -> bool:
    """Void is workflow-driven and default-denied in this foundation."""
    if not user or not user.is_authenticated:
        return False
    if not generated_document:
        return False
    return _policy_allows(
        user,
        "void",
        policy_key=generated_document.access_policy_key,
        generated_document=generated_document,
    )


def can_archive_generated_document(user, generated_document=None) -> bool:
    """Archive is workflow-driven and default-denied in this foundation."""
    if not user or not user.is_authenticated:
        return False
    if not generated_document:
        return False
    return _policy_allows(
        user,
        "archive",
        policy_key=generated_document.access_policy_key,
        generated_document=generated_document,
    )


# ---------------------------------------------------------------------------
# Protected file policy callback for generated documents
# ---------------------------------------------------------------------------

def generated_document_file_policy(user, protected_file, action: str) -> bool:
    """Policy callback registered with apps.security for generated document files.

    Delegates to document-level access checks. Role alone does not grant access.
    """
    if not user or not user.is_authenticated:
        return False

    from apps.documents.models import GeneratedDocument
    try:
        doc = GeneratedDocument.objects.get(protected_file=protected_file)
    except (GeneratedDocument.DoesNotExist, ValueError, TypeError):
        return False

    # Metadata inspection is safe only after resolving the owning document.
    if action in ("read_metadata", "inspect"):
        return can_view_generated_document_metadata(user)

    return can_access_generated_document_content(user, doc)
