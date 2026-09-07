# Project: COMPASS
# File: apps/documents/services.py
# Module: apps.documents
# Purpose: Service-layer actions for document template lifecycle and generation
# Domain boundary and service policy.
# Notes:
#   Services own all lifecycle transitions, rendering, and storage.
#   Audit events use allowlisted metadata only.
#   No document contents, student names/numbers, counseling/referral narratives,
#   protected object keys, signed URLs, raw HTML, or secrets in audit metadata.

import hashlib
import logging

from django.db import transaction
from django.utils import timezone

from apps.audit.services import audit_log
from apps.documents.models import (
    DocumentStatusChoices,
    DocumentTemplate,
    DocumentTemplateVersion,
    GeneratedDocument,
    OutputFormatChoices,
    RendererBackendChoices,
    TemplateStatusChoices,
)
from apps.documents.policies import (
    can_activate_template,
    can_archive_generated_document,
    can_archive_template,
    can_create_template_draft,
    can_generate_document,
    can_release_generated_document,
    can_retire_template,
    can_void_generated_document,
)
from apps.documents.renderers import (
    RendererError,
    RendererUnavailableError,
    ensure_template_exists,
    get_renderer,
    validate_stylesheet_path_safety,
)
from apps.documents.template_context import (
    build_brand_asset_snapshot,
    build_generation_context_snapshot,
    build_renderer_snapshot,
    build_template_version_snapshot,
    allowed_fields_from_schema,
    find_disallowed_render_context_keys,
    find_forbidden_render_context_keys,
    required_fields_from_schema,
    validate_render_context,
)
from apps.documents.governance import (
    DOCUMENT_FAMILY_REGISTRY,
    DocumentOutputIntent,
    DocumentReadiness,
    build_document_branding_context,
    build_document_control_context,
    resolve_document_readiness,
    select_approved_print_header_asset,
)
from apps.documents.shells import DocumentShellKey, SHELL_DEFINITIONS, resolve_document_shell
from apps.documents.reference_codes import generate_document_reference_code
from apps.organizations.selectors import (
    build_form_revision_snapshot,
    get_active_form_revision,
    build_institution_profile_snapshot,
    build_office_profile_snapshot,
    get_current_institution_profile,
    get_current_office_profile,
)
from apps.organizations.models import GovernanceStatusChoices
from apps.common.exceptions import DependencyFailureError, ErrorCode, NotFoundError, PermissionDeniedError, ValidationError

logger = logging.getLogger(__name__)

_SOURCE_APP = "apps.documents"


class DocumentServiceError(ValidationError):
    """Raised when a document service action fails."""


class DocumentPolicyError(PermissionDeniedError):
    """Raised when an explicit generated-document policy denies an action."""


class DocumentRenderContextError(ValidationError):
    """Raised when a render context violates the safe schema boundary."""


class DocumentDependencyError(DocumentServiceError, DependencyFailureError):
    """Raised when rendering or protected storage is temporarily unavailable."""

    code = ErrorCode.DEPENDENCY_FAILURE
    public_message = DependencyFailureError.public_message


# ---------------------------------------------------------------------------
# Audit helpers (allowlisted metadata only)
# ---------------------------------------------------------------------------

def _template_audit_meta(template):
    return {
        "model": "DocumentTemplate",
        "object_id": template.pk,
        "stable_key": template.stable_key,
        "status": template.status,
        "document_kind": template.document_kind,
    }


def _version_audit_meta(version):
    return {
        "model": "DocumentTemplateVersion",
        "object_id": version.pk,
        "template_key": version.template.stable_key,
        "version_label": version.version_label,
        "status": version.status,
        "renderer_backend": version.renderer_backend,
        "output_format": version.output_format,
        "is_used": version.is_used,
    }


def _generated_doc_audit_meta(doc):
    return {
        "model": "GeneratedDocument",
        "reference_code": doc.reference_code,
        "document_status": doc.document_status,
        "template_key": doc.template_version.template.stable_key,
        "version_label": doc.template_version.version_label,
    }


def _require_active_template_state(version):
    if version.template.status != TemplateStatusChoices.ACTIVE:
        raise DocumentServiceError("Template must be active before template versions can be used.")
    if version.status != TemplateStatusChoices.ACTIVE:
        raise DocumentServiceError("Only active template versions can be used.")


def _require_current_identity():
    institution = get_current_institution_profile()
    if not institution:
        raise DocumentServiceError("Active institution profile is required.")
    office = get_current_office_profile(institution)
    if not office:
        raise DocumentServiceError("Active office profile is required.")
    return institution, office


def _resolve_required_form_revision(version, supplied_form_revision=None):
    template_family = version.template.related_form_family
    version_revision = version.related_form_revision

    if template_family and not version_revision:
        raise DocumentServiceError("A template linked to a form family requires a form revision.")
    if version_revision and template_family and version_revision.form_family_id != template_family.pk:
        raise DocumentServiceError("Template version form revision does not match the template form family.")
    if supplied_form_revision and version_revision and supplied_form_revision.pk != version_revision.pk:
        raise DocumentServiceError("Supplied form revision does not match the template version.")

    form_revision = version_revision or supplied_form_revision
    if not form_revision:
        return None
    if form_revision.status != GovernanceStatusChoices.ACTIVE:
        raise DocumentServiceError("Form revision must be active before document generation.")
    active_revision = get_active_form_revision(form_revision.form_family.stable_key)
    if not active_revision or active_revision.pk != form_revision.pk:
        raise DocumentServiceError("Form revision is missing, ambiguous, or not the active revision.")
    return form_revision


def _validate_version_paths(version):
    ensure_template_exists(version.template_path)
    validate_stylesheet_path_safety(version.stylesheet_path)


def _page_number_footer_enabled(version) -> bool:
    """Read only the bounded print option stored with the governed template."""
    schema = version.required_context_schema_json or {}
    options = schema.get("print_options", {}) if isinstance(schema, dict) else {}
    shell = resolve_document_shell(version)
    if version.template.stable_key in DOCUMENT_FAMILY_REGISTRY and (
        shell is None or not shell.show_page_number
    ):
        return False
    return (
        isinstance(options, dict)
        and options.get("page_number_footer") is True
        and options.get("page_number_footer_mode", "renderer") == "renderer"
    )


def _controlled_page_identity_label(version) -> str:
    """Build a bounded repeating PDF header only from governed snapshots."""
    if not _page_number_footer_enabled(version):
        return ""
    schema = version.required_context_schema_json or {}
    options = schema.get("print_options", {}) if isinstance(schema, dict) else {}
    if isinstance(options, dict) and options.get("page_identity_header") is False:
        return ""
    institution = version.institution_profile_snapshot or {}
    office = version.office_profile_snapshot or {}
    form_revision = version.form_revision_snapshot or {}
    parts = [
        institution.get("legal_name"),
        office.get("document_header_name") or office.get("office_name"),
        form_revision.get("official_form_code"),
    ]
    return " | ".join(
        str(value).strip()[:120]
        for value in parts
        if isinstance(value, str) and value.strip()
    )[:300]


def _prepare_render_context(*, template_version, render_context, institution, office,
                            form_revision, server_context=None):
    caller_context = dict(render_context or {})
    forbidden = find_forbidden_render_context_keys(caller_context)
    if forbidden:
        raise DocumentRenderContextError("Render context contains forbidden keys.")

    schema = template_version.required_context_schema_json or {}
    allowed_fields = allowed_fields_from_schema(schema)
    disallowed = find_disallowed_render_context_keys(caller_context, allowed_fields)
    if disallowed:
        raise DocumentRenderContextError("Render context contains keys outside the template schema.")

    safe_context = {
        **caller_context,
        "institution": build_institution_profile_snapshot(institution),
        "office": build_office_profile_snapshot(office),
        "form_revision": build_form_revision_snapshot(form_revision),
    }
    # Server-owned control metadata is appended only after caller validation so
    # a template consumer cannot spoof readiness, source mapping, or branding.
    if server_context:
        safe_context.update(server_context)
    required_fields = required_fields_from_schema(schema)
    missing = validate_render_context(safe_context, required_fields)
    if missing:
        raise DocumentRenderContextError("Render context is missing required fields.")
    return safe_context


def _audit_generation_failure(*, doc, reference_code, user, action_type, error_type):
    audit_log(
        action_type=action_type,
        event_category="WORKFLOW",
        severity="ERROR",
        target_model="GeneratedDocument",
        target_object_id=str(doc.pk) if doc else "unknown",
        reference_code=reference_code,
        actor_user=user,
        source_app=_SOURCE_APP,
        metadata={
            **(_generated_doc_audit_meta(doc) if doc else {}),
            "error_type": error_type,
        },
    )


# ---------------------------------------------------------------------------
# DocumentTemplate services
# ---------------------------------------------------------------------------

def create_template_draft(*, user, command):
    """Create a draft document template."""
    from apps.documents.commands import DocumentTemplateDraftCommand

    if not isinstance(command, DocumentTemplateDraftCommand):
        raise ValidationError("Template creation requires a typed command.")
    if not can_create_template_draft(user):
        raise DocumentPolicyError("Permission denied: cannot create template draft.")
    template = DocumentTemplate.objects.create(
        status=TemplateStatusChoices.DRAFT,
        stable_key=command.stable_key,
        display_name=command.display_name,
        document_kind=command.document_kind,
        default_output_format=command.default_output_format,
        retention_classification=command.retention_classification,
        access_policy_key=command.access_policy_key,
        description=command.description,
        source_notes=command.source_notes,
        related_form_family_id=command.related_form_family_id,
        owner_office_id=command.owner_office_id,
    )
    audit_log(
        action_type="DOCUMENT_TEMPLATE_CREATED",
        event_category="GOVERNANCE",
        target_model="DocumentTemplate",
        target_object_id=str(template.pk),
        actor_user=user,
        source_app=_SOURCE_APP,
        metadata=_template_audit_meta(template),
    )
    return template


def _activate_template(*, user, template):
    """Activate a draft document template."""
    if not can_activate_template(user):
        raise DocumentPolicyError("Permission denied: cannot activate template.")
    if template.status != TemplateStatusChoices.DRAFT:
        raise DocumentServiceError("Only draft templates can be activated.")
    old_status = template.status
    template.status = TemplateStatusChoices.ACTIVE
    template.save()
    audit_log(
        action_type="DOCUMENT_TEMPLATE_ACTIVATED",
        event_category="GOVERNANCE",
        target_model="DocumentTemplate",
        target_object_id=str(template.pk),
        actor_user=user,
        source_app=_SOURCE_APP,
        metadata={**_template_audit_meta(template), "status_from": old_status},
    )
    return template


def _retire_template(*, user, template):
    """Retire an active document template."""
    if not can_retire_template(user):
        raise DocumentPolicyError("Permission denied: cannot retire template.")
    if template.status != TemplateStatusChoices.ACTIVE:
        raise DocumentServiceError("Only active templates can be retired.")
    old_status = template.status
    template.status = TemplateStatusChoices.RETIRED
    template.save()
    audit_log(
        action_type="DOCUMENT_TEMPLATE_RETIRED",
        event_category="GOVERNANCE",
        target_model="DocumentTemplate",
        target_object_id=str(template.pk),
        actor_user=user,
        source_app=_SOURCE_APP,
        metadata={**_template_audit_meta(template), "status_from": old_status},
    )
    return template


def _archive_template(*, user, template):
    """Archive a retired document template."""
    if not can_archive_template(user):
        raise DocumentPolicyError("Permission denied: cannot archive template.")
    if template.status != TemplateStatusChoices.RETIRED:
        raise DocumentServiceError("Only retired templates can be archived.")
    old_status = template.status
    template.status = TemplateStatusChoices.ARCHIVED
    template.save()
    audit_log(
        action_type="DOCUMENT_TEMPLATE_ARCHIVED",
        event_category="GOVERNANCE",
        target_model="DocumentTemplate",
        target_object_id=str(template.pk),
        actor_user=user,
        source_app=_SOURCE_APP,
        metadata={**_template_audit_meta(template), "status_from": old_status},
    )
    return template


# ---------------------------------------------------------------------------
# DocumentTemplateVersion services
# ---------------------------------------------------------------------------

def create_version_draft(*, user, command):
    """Create a draft document template version."""
    from apps.documents.commands import DocumentTemplateVersionDraftCommand

    if not isinstance(command, DocumentTemplateVersionDraftCommand):
        raise ValidationError("Template version creation requires a typed command.")
    if not can_create_template_draft(user):
        raise DocumentPolicyError("Permission denied: cannot create version draft.")
    try:
        template = DocumentTemplate.objects.get(pk=command.template_id)
    except (DocumentTemplate.DoesNotExist, ValueError, TypeError) as exc:
        raise ValidationError("The template target was not found.") from exc
    version = DocumentTemplateVersion.objects.create(
        template=template,
        status=TemplateStatusChoices.DRAFT,
        version_label=command.version_label,
        template_path=command.template_path,
        stylesheet_path=command.stylesheet_path,
        related_form_revision_id=command.related_form_revision_id,
        internal_template_version=command.internal_template_version,
        renderer_backend=command.renderer_backend,
        output_format=command.output_format,
        page_size=command.page_size,
        page_orientation=command.page_orientation,
        page_margins_json=dict(command.page_margins),
        required_context_schema_json=dict(command.required_context_schema),
        source_notes=command.source_notes,
    )
    audit_log(
        action_type="DOCUMENT_TEMPLATE_VERSION_CREATED",
        event_category="GOVERNANCE",
        target_model="DocumentTemplateVersion",
        target_object_id=str(version.pk),
        actor_user=user,
        source_app=_SOURCE_APP,
        metadata=_version_audit_meta(version),
    )
    return version


@transaction.atomic
def _activate_version(*, user, version):
    """Activate a draft document template version.

    Snapshots institution, office, brand, and form revision metadata.
    Rejects activation when another active version exists for the same template.
    """
    version = DocumentTemplateVersion.objects.select_for_update().get(pk=version.pk)
    if not can_activate_template(user):
        raise DocumentPolicyError("Permission denied: cannot activate version.")
    if version.template.status != TemplateStatusChoices.ACTIVE:
        raise DocumentServiceError("Template must be active before activating a version.")
    if version.status != TemplateStatusChoices.DRAFT:
        raise DocumentServiceError("Only draft versions can be activated.")
    _validate_version_paths(version)
    form_revision = _resolve_required_form_revision(version)

    # Reject if another active version exists
    if DocumentTemplateVersion.objects.select_for_update().filter(
        template=version.template,
        status=TemplateStatusChoices.ACTIVE,
    ).exclude(pk=version.pk).exists():
        raise DocumentServiceError(
            "Cannot activate version while another active version exists for this template."
        )

    now = timezone.now()
    old_status = version.status

    # Snapshot required governance metadata at activation time.
    institution, office = _require_current_identity()

    version.institution_profile_snapshot = build_institution_profile_snapshot(institution)
    version.office_profile_snapshot = build_office_profile_snapshot(office)

    # Snapshot form revision if related
    if form_revision:
        version.form_revision_snapshot = build_form_revision_snapshot(form_revision)

    version.status = TemplateStatusChoices.ACTIVE
    version.approved_at = now
    version.approved_by = user
    version.save()

    audit_log(
        action_type="DOCUMENT_TEMPLATE_VERSION_ACTIVATED",
        event_category="GOVERNANCE",
        target_model="DocumentTemplateVersion",
        target_object_id=str(version.pk),
        actor_user=user,
        source_app=_SOURCE_APP,
        metadata={**_version_audit_meta(version), "status_from": old_status},
    )
    return version


@transaction.atomic
def _retire_version(*, user, version):
    """Retire an active document template version."""
    if not can_retire_template(user):
        raise DocumentPolicyError("Permission denied: cannot retire version.")
    if version.status != TemplateStatusChoices.ACTIVE:
        raise DocumentServiceError("Only active versions can be retired.")
    old_status = version.status
    version.status = TemplateStatusChoices.RETIRED
    version.retired_at = timezone.now()
    version.retired_by = user
    version.save()
    audit_log(
        action_type="DOCUMENT_TEMPLATE_VERSION_RETIRED",
        event_category="GOVERNANCE",
        target_model="DocumentTemplateVersion",
        target_object_id=str(version.pk),
        actor_user=user,
        source_app=_SOURCE_APP,
        metadata={**_version_audit_meta(version), "status_from": old_status},
    )
    return version


@transaction.atomic
def _archive_version(*, user, version):
    """Archive a retired document template version."""
    if not can_archive_template(user):
        raise DocumentPolicyError("Permission denied: cannot archive version.")
    if version.status != TemplateStatusChoices.RETIRED:
        raise DocumentServiceError("Only retired versions can be archived.")
    old_status = version.status
    version.status = TemplateStatusChoices.ARCHIVED
    version.save()
    audit_log(
        action_type="DOCUMENT_TEMPLATE_VERSION_ARCHIVED",
        event_category="GOVERNANCE",
        target_model="DocumentTemplateVersion",
        target_object_id=str(version.pk),
        actor_user=user,
        source_app=_SOURCE_APP,
        metadata={**_version_audit_meta(version), "status_from": old_status},
    )
    return version


@transaction.atomic
def _clone_version_to_draft(*, user, source_version):
    """Clone an active/retired version into a new draft for editing."""
    if not can_create_template_draft(user):
        raise DocumentPolicyError("Permission denied: cannot clone version.")
    if source_version.status not in (TemplateStatusChoices.ACTIVE, TemplateStatusChoices.RETIRED):
        raise DocumentServiceError("Only active or retired versions can be cloned.")

    # Derive unique internal_template_version
    base = source_version.internal_template_version
    existing_count = DocumentTemplateVersion.objects.filter(
        template=source_version.template,
        version_label=source_version.version_label,
    ).count()
    clone_version = f"{base}-draft-{existing_count + 1}"

    clone = DocumentTemplateVersion.objects.create(
        template=source_version.template,
        version_label=source_version.version_label,
        related_form_revision=source_version.related_form_revision,
        internal_template_version=clone_version,
        template_path=source_version.template_path,
        stylesheet_path=source_version.stylesheet_path,
        renderer_backend=source_version.renderer_backend,
        output_format=source_version.output_format,
        page_size=source_version.page_size,
        page_orientation=source_version.page_orientation,
        page_margins_json=source_version.page_margins_json,
        required_context_schema_json=source_version.required_context_schema_json,
        template_checksum=source_version.template_checksum,
        source_notes=f"Cloned from version {source_version.pk}.",
        status=TemplateStatusChoices.DRAFT,
    )
    audit_log(
        action_type="DOCUMENT_TEMPLATE_VERSION_CLONED",
        event_category="GOVERNANCE",
        target_model="DocumentTemplateVersion",
        target_object_id=str(clone.pk),
        actor_user=user,
        source_app=_SOURCE_APP,
        metadata={
            **_version_audit_meta(clone),
            "cloned_from": source_version.pk,
        },
    )
    return clone


@transaction.atomic
def _mark_version_used(*, version, user=None, system_context=False):
    """Mark a template version as used by a generated document.

    Once used, meaning-bearing fields become immutable.
    """
    if version.status != TemplateStatusChoices.ACTIVE:
        raise DocumentServiceError("Only active versions can be marked as used.")
    if not version.is_used:
        version.is_used = True
        version.first_used_at = timezone.now()
        version.save(update_fields=["is_used", "first_used_at", "updated_at"])
    return version


def _load_template_for_boundary(template_id, *, lock=False):
    queryset = DocumentTemplate.objects.select_related("related_form_family")
    if lock:
        queryset = queryset.select_for_update()
    try:
        return queryset.get(pk=template_id)
    except (DocumentTemplate.DoesNotExist, ValueError, TypeError) as exc:
        raise NotFoundError() from exc


def _load_template_version_for_boundary(version_id, *, lock=False):
    queryset = DocumentTemplateVersion.objects.select_related(
        "template",
        "related_form_revision",
        "related_form_revision__form_family",
    )
    if lock:
        queryset = queryset.select_for_update()
    try:
        return queryset.get(pk=version_id)
    except (DocumentTemplateVersion.DoesNotExist, ValueError, TypeError) as exc:
        raise NotFoundError() from exc


def _check_expected_status(current_status, expected_status):
    if expected_status is not None and current_status != expected_status:
        raise DocumentServiceError("The document resource changed before this action.")


def activate_template(*, user, command):
    from apps.documents.commands import DocumentTemplateLifecycleCommand

    if not isinstance(command, DocumentTemplateLifecycleCommand):
        raise ValidationError("Template activation requires a typed command.")
    with transaction.atomic():
        template = _load_template_for_boundary(command.template_id, lock=True)
        _check_expected_status(template.status, command.expected_status)
        return _activate_template(user=user, template=template)


def retire_template(*, user, command):
    from apps.documents.commands import DocumentTemplateLifecycleCommand

    if not isinstance(command, DocumentTemplateLifecycleCommand):
        raise ValidationError("Template retirement requires a typed command.")
    with transaction.atomic():
        template = _load_template_for_boundary(command.template_id, lock=True)
        _check_expected_status(template.status, command.expected_status)
        return _retire_template(user=user, template=template)


def archive_template(*, user, command):
    from apps.documents.commands import DocumentTemplateLifecycleCommand

    if not isinstance(command, DocumentTemplateLifecycleCommand):
        raise ValidationError("Template archival requires a typed command.")
    with transaction.atomic():
        template = _load_template_for_boundary(command.template_id, lock=True)
        _check_expected_status(template.status, command.expected_status)
        return _archive_template(user=user, template=template)


def activate_version(*, user, command):
    from apps.documents.commands import DocumentTemplateVersionLifecycleCommand

    if not isinstance(command, DocumentTemplateVersionLifecycleCommand):
        raise ValidationError("Template version activation requires a typed command.")
    with transaction.atomic():
        version = _load_template_version_for_boundary(command.version_id, lock=True)
        _check_expected_status(version.status, command.expected_status)
        return _activate_version(user=user, version=version)


def retire_version(*, user, command):
    from apps.documents.commands import DocumentTemplateVersionLifecycleCommand

    if not isinstance(command, DocumentTemplateVersionLifecycleCommand):
        raise ValidationError("Template version retirement requires a typed command.")
    with transaction.atomic():
        version = _load_template_version_for_boundary(command.version_id, lock=True)
        _check_expected_status(version.status, command.expected_status)
        return _retire_version(user=user, version=version)


def archive_version(*, user, command):
    from apps.documents.commands import DocumentTemplateVersionLifecycleCommand

    if not isinstance(command, DocumentTemplateVersionLifecycleCommand):
        raise ValidationError("Template version archival requires a typed command.")
    with transaction.atomic():
        version = _load_template_version_for_boundary(command.version_id, lock=True)
        _check_expected_status(version.status, command.expected_status)
        return _archive_version(user=user, version=version)


def clone_version_to_draft(*, user, command):
    from apps.documents.commands import DocumentTemplateCloneCommand

    if not isinstance(command, DocumentTemplateCloneCommand):
        raise ValidationError("Template version cloning requires a typed command.")
    with transaction.atomic():
        source_version = _load_template_version_for_boundary(command.source_version_id, lock=True)
        return _clone_version_to_draft(user=user, source_version=source_version)


# ---------------------------------------------------------------------------
# Render services
# ---------------------------------------------------------------------------

def render_html(*, template_version, context: dict) -> str:
    """Render a document template version to HTML.

    Uses the template version's configured template_path and renderer_backend.
    """
    renderer = get_renderer(template_version.renderer_backend)
    return renderer.render_to_html(template_version.template_path, context)


def _pdf_page_settings(template_version, *, page_number=None, page_total=None):
    """Build the only renderer settings accepted for a governed PDF page."""
    return {
        "page_size": template_version.page_size,
        "page_orientation": template_version.page_orientation,
        "margins": template_version.page_margins_json,
        "stylesheet_path": template_version.stylesheet_path,
        "page_number_footer": _page_number_footer_enabled(template_version),
        "header_label": _controlled_page_identity_label(template_version),
        "footer_page_number": page_number,
        "footer_page_total": page_total,
    }


def _governance_context(*, template_version, form_revision, intent):
    """Return server-owned document.readiness context, preserving generic test templates."""
    stable_key = template_version.template.stable_key
    if stable_key not in DOCUMENT_FAMILY_REGISTRY:
        return {}, None, None
    control, readiness = build_document_control_context(
        stable_key=stable_key,
        template_version=template_version,
        form_revision=form_revision,
        intent=intent,
    )
    institution = get_current_institution_profile()
    office = get_current_office_profile(institution)
    asset = select_approved_print_header_asset(institution=institution, office=office) if institution and office else None
    shell = resolve_document_shell(template_version) or SHELL_DEFINITIONS[DocumentShellKey.COMPACT_FORM]
    render_branding, _brand_metadata = build_document_branding_context(
        shell=shell,
        institution=institution,
        office=office,
    )
    primary = render_branding.get("primary") or {}
    return {
        "document_control": control,
        "print_brand": {
            **render_branding,
            # Compatibility keys keep older governed templates renderable;
            # their values remain transient and are never persisted.
            "logo_data_uri": primary.get("data_uri", ""),
            "logo_alt": primary.get("alt_text", ""),
        },
    }, readiness, asset


def _resolve_preview_form_revision(version, supplied_form_revision=None):
    """Resolve a preview's relation without requiring unfinished metadata active."""
    template_family = version.template.related_form_family
    version_revision = version.related_form_revision
    if template_family and not version_revision:
        return supplied_form_revision
    if supplied_form_revision and version_revision and supplied_form_revision.pk != version_revision.pk:
        raise DocumentServiceError("Supplied form revision does not match the template version.")
    return version_revision or supplied_form_revision


def render_document_preview(*, template_version, render_context: dict, form_revision=None,
                            output_intent: DocumentOutputIntent = DocumentOutputIntent.PREVIEW):
    """Render an authorized document preview without creating a document row.

    Preview rendering uses the same active-template, identity, form-revision,
    path, context-schema, renderer, and PDF availability gates as official
    generation. It deliberately stops before protected storage and audit
    records for a generated output.
    """
    governed = template_version.template.stable_key in DOCUMENT_FAMILY_REGISTRY
    if not governed or output_intent == DocumentOutputIntent.OFFICIAL:
        _require_active_template_state(template_version)
    _validate_version_paths(template_version)
    institution, office = _require_current_identity()
    if (not governed or output_intent == DocumentOutputIntent.OFFICIAL) and (
        not template_version.institution_profile_snapshot or not template_version.office_profile_snapshot
    ):
        raise DocumentServiceError("Active template version must include identity snapshots.")
    form_revision = (
        _resolve_preview_form_revision(template_version, form_revision)
        if governed and output_intent == DocumentOutputIntent.PREVIEW
        else _resolve_required_form_revision(template_version, form_revision)
    )
    if (not governed or output_intent == DocumentOutputIntent.OFFICIAL) and form_revision and not template_version.form_revision_snapshot:
        raise DocumentServiceError("Active template version must include a form revision snapshot.")
    server_context, readiness, _asset = _governance_context(
        template_version=template_version, form_revision=form_revision, intent=output_intent
    )
    if template_version.template.stable_key == "public_service_guide":
        # Document-template readiness is necessary but not sufficient for this
        # public projection: the guide itself must have an in-window published
        # revision with every office-owned field confirmed.
        guide = render_context.get("public_service_guide") if isinstance(render_context, dict) else None
        guide_ready = bool(
            isinstance(guide, dict)
            and guide.get("has_approved_revision")
            and isinstance(guide.get("readiness"), dict)
            and guide["readiness"].get("official")
        )
        if not guide_ready:
            server_context = dict(server_context or {})
            document_control = dict(server_context.get("document_control") or {})
            document_control.update({
                "readiness": "PENDING_APPROVAL",
                "label": "PREVIEW — PENDING APPROVAL",
                "official": False,
            })
            server_context["document_control"] = document_control
    if output_intent == DocumentOutputIntent.OFFICIAL and readiness and not readiness.is_official:
        raise DocumentServiceError(
            "Official output is pending approval: " + ", ".join(readiness.reasons)
        )
    safe_render_context = _prepare_render_context(
        template_version=template_version,
        render_context=render_context,
        institution=institution,
        office=office,
        form_revision=form_revision,
        server_context=server_context,
    )

    renderer = get_renderer(template_version.renderer_backend)
    html_content = renderer.render_to_html(template_version.template_path, safe_render_context)
    if template_version.output_format == OutputFormatChoices.PDF:
        if template_version.renderer_backend != RendererBackendChoices.PLAYWRIGHT_PDF:
            raise RendererUnavailableError("PDF output requires the Playwright PDF renderer.")
        if not renderer.is_pdf_available():
            raise RendererUnavailableError("PDF renderer is unavailable.")
        content = renderer.render_to_pdf(
            html_content,
            _pdf_page_settings(template_version),
        )
        return content, "application/pdf"

    return html_content.encode("utf-8"), "text/html"


# ---------------------------------------------------------------------------
# Generated document services
# ---------------------------------------------------------------------------

def render_and_store_document(
    *,
    user,
    template_version,
    render_context: dict,
    academic_year: str,
    form_revision=None,
    generated_for_user=None,
    owning_app_label="",
    owning_model_name="",
    owning_object_id="",
    access_policy_key="generated_document",
    system_context=False,
    output_intent: DocumentOutputIntent = DocumentOutputIntent.OFFICIAL,
):
    """Render a document and store the output as a GeneratedDocument.

    This is the primary generation entry point. It:
    1. Validates permissions
    2. Renders HTML
    3. Optionally renders PDF
    4. Stores through apps.security.ProtectedFile
    5. Creates GeneratedDocument metadata
    6. Marks the template version as used
    7. Audits the generation
    """
    policy_context = {
        "template_version_id": template_version.pk,
        "template_key": template_version.template.stable_key,
        "owning_app_label": owning_app_label,
        "owning_model_name": owning_model_name,
        "owning_object_id": owning_object_id,
        "generated_for_user_id": generated_for_user.pk if generated_for_user else None,
    }
    if not can_generate_document(
        user,
        access_policy_key=access_policy_key,
        context=policy_context,
        system_context=system_context,
    ):
        raise DocumentPolicyError("Permission denied: cannot generate document.")

    governed = template_version.template.stable_key in DOCUMENT_FAMILY_REGISTRY
    if not governed or output_intent == DocumentOutputIntent.OFFICIAL:
        _require_active_template_state(template_version)
    _validate_version_paths(template_version)
    institution, office = _require_current_identity()
    if (not governed or output_intent == DocumentOutputIntent.OFFICIAL) and (
        not template_version.institution_profile_snapshot or not template_version.office_profile_snapshot
    ):
        raise DocumentServiceError("Active template version must include identity snapshots.")
    form_revision = (
        _resolve_preview_form_revision(template_version, form_revision)
        if governed and output_intent == DocumentOutputIntent.PREVIEW
        else _resolve_required_form_revision(template_version, form_revision)
    )
    if (not governed or output_intent == DocumentOutputIntent.OFFICIAL) and form_revision and not template_version.form_revision_snapshot:
        raise DocumentServiceError("Active template version must include a form revision snapshot.")
    server_context, readiness, asset = _governance_context(
        template_version=template_version, form_revision=form_revision, intent=output_intent
    )
    if template_version.template.stable_key == "public_service_guide" and output_intent == DocumentOutputIntent.OFFICIAL:
        guide = render_context.get("public_service_guide") if isinstance(render_context, dict) else None
        if not (
            isinstance(guide, dict)
            and guide.get("has_approved_revision")
            and isinstance(guide.get("readiness"), dict)
            and guide["readiness"].get("official")
        ):
            raise DocumentServiceError("Official public service guide output is pending guide approval.")
    if output_intent == DocumentOutputIntent.OFFICIAL and readiness and not readiness.is_official:
        raise DocumentServiceError(
            "Official output is pending approval: " + ", ".join(readiness.reasons)
        )
    safe_render_context = _prepare_render_context(
        template_version=template_version,
        render_context=render_context,
        institution=institution,
        office=office,
        form_revision=form_revision,
        server_context=server_context,
    )
    # Generate reference code
    reference_code = generate_document_reference_code(academic_year)

    # Get renderer
    renderer = get_renderer(template_version.renderer_backend)

    # Create metadata before render/store so failures leave an explicit record.
    doc = GeneratedDocument.objects.create(
        reference_code=reference_code,
        template_version=template_version,
        form_revision=form_revision,
        generated_for_user=generated_for_user,
        owning_app_label=owning_app_label,
        owning_model_name=owning_model_name,
        owning_object_id=owning_object_id,
        document_status=DocumentStatusChoices.DRAFT,
        generated_by=user,
        generated_at=timezone.now(),
        access_policy_key=access_policy_key,
        template_version_snapshot=build_template_version_snapshot(template_version),
        institution_profile_snapshot=build_institution_profile_snapshot(institution),
        office_profile_snapshot=build_office_profile_snapshot(office),
        form_revision_snapshot=build_form_revision_snapshot(form_revision),
        renderer_snapshot=build_renderer_snapshot(renderer),
        generation_context_snapshot_json=build_generation_context_snapshot(
            template_version=template_version,
            renderer=renderer,
            institution_profile=institution,
            office_profile=office,
            brand_asset=asset,
            form_revision=form_revision,
            document_control=(server_context or {}).get("document_control", {}),
            owner_tuple={
                "app_label": owning_app_label,
                "model_name": owning_model_name,
                "object_id": owning_object_id,
            } if owning_app_label else {},
        ),
    )

    try:
        if template_version.output_format == OutputFormatChoices.PDF:
            if template_version.renderer_backend != RendererBackendChoices.PLAYWRIGHT_PDF:
                raise RendererUnavailableError("PDF output requires the Playwright PDF renderer.")
            if not renderer.is_pdf_available():
                raise RendererUnavailableError("PDF renderer is unavailable.")
            html_content = renderer.render_to_html(
                template_version.template_path, safe_render_context
            )
            content = renderer.render_to_pdf(
                html_content,
                _pdf_page_settings(template_version),
            )
            content_type = "application/pdf"
        else:
            html_content = renderer.render_to_html(
                template_version.template_path, safe_render_context
            )
            content = html_content.encode("utf-8")
            content_type = "text/html"
    except Exception as exc:
        doc.document_status = DocumentStatusChoices.FAILED
        doc.save(update_fields=["document_status", "updated_at"])
        _audit_generation_failure(
            doc=doc,
            reference_code=reference_code,
            user=user,
            action_type="GENERATED_DOCUMENT_RENDERER_ERROR",
            error_type=type(exc).__name__,
        )
        raise DocumentDependencyError() from exc

    content_hash = hashlib.sha256(content).hexdigest()
    doc.content_hash = content_hash
    doc.save(update_fields=["content_hash", "updated_at"])

    # Store through apps.security. This happens after metadata creation and
    # outside a surrounding document DB transaction; failures mark the document
    # FAILED instead of reporting a successful generation.
    from apps.documents.storage import store_generated_document_file

    try:
        protected_file = store_generated_document_file(
            user=user,
            content=content,
            content_type=content_type,
            generated_document=doc,
        )
        doc.protected_file = protected_file
        doc.document_status = DocumentStatusChoices.GENERATED
        doc.save(update_fields=["protected_file", "document_status", "updated_at"])

        audit_log(
            action_type="GENERATED_DOCUMENT_PROTECTED_FILE_LINKED",
            event_category="WORKFLOW",
            target_model="GeneratedDocument",
            target_object_id=str(doc.pk),
            reference_code=reference_code,
            actor_user=user,
            source_app=_SOURCE_APP,
            metadata={
                **_generated_doc_audit_meta(doc),
                "classification": protected_file.classification,
                "purpose": protected_file.purpose,
            },
        )
    except Exception as exc:
        doc.document_status = DocumentStatusChoices.FAILED
        doc.save(update_fields=["document_status", "updated_at"])
        _audit_generation_failure(
            doc=doc,
            reference_code=reference_code,
            user=user,
            action_type="GENERATED_DOCUMENT_STORAGE_FAILED",
            error_type="storage_failed",
        )
        raise DocumentDependencyError() from exc

    # Preview storage is never an official use of a draft template.  Existing
    # official generation retains the immutable-used transition.
    if output_intent == DocumentOutputIntent.OFFICIAL:
        _mark_version_used(version=template_version, user=user, system_context=system_context)

    audit_log(
        action_type="GENERATED_DOCUMENT_RENDERED",
        event_category="WORKFLOW",
        target_model="GeneratedDocument",
        target_object_id=str(doc.pk),
        reference_code=reference_code,
        actor_user=user,
        source_app=_SOURCE_APP,
        metadata=_generated_doc_audit_meta(doc),
    )
    return doc


# ---------------------------------------------------------------------------
# Generated document lifecycle services (metadata transitions only)
# ---------------------------------------------------------------------------

@transaction.atomic
def _release_generated_document(*, user, document):
    """Release a generated document. Metadata transition only."""
    if not can_release_generated_document(user, document):
        raise DocumentPolicyError("Permission denied: cannot release document.")
    if document.document_status != DocumentStatusChoices.GENERATED:
        raise DocumentServiceError("Only generated documents can be released.")
    old_status = document.document_status
    document.document_status = DocumentStatusChoices.RELEASED
    document.released_by = user
    document.released_at = timezone.now()
    document.save(update_fields=[
        "document_status", "released_by", "released_at", "updated_at",
    ])
    audit_log(
        action_type="GENERATED_DOCUMENT_RELEASED",
        event_category="WORKFLOW",
        target_model="GeneratedDocument",
        target_object_id=str(document.pk),
        reference_code=document.reference_code,
        actor_user=user,
        source_app=_SOURCE_APP,
        metadata={**_generated_doc_audit_meta(document), "status_from": old_status},
    )
    return document


@transaction.atomic
def _void_generated_document(*, user, document, reason_code=""):
    """Void a generated document. Metadata transition only."""
    if not can_void_generated_document(user, document):
        raise DocumentPolicyError("Permission denied: cannot void document.")
    if document.document_status not in (
        DocumentStatusChoices.GENERATED,
        DocumentStatusChoices.RELEASED,
    ):
        raise DocumentServiceError("Only generated or released documents can be voided.")
    old_status = document.document_status
    document.document_status = DocumentStatusChoices.VOIDED
    document.voided_by = user
    document.voided_at = timezone.now()
    document.void_reason_code = reason_code
    document.save(update_fields=[
        "document_status", "voided_by", "voided_at", "void_reason_code", "updated_at",
    ])
    audit_log(
        action_type="GENERATED_DOCUMENT_VOIDED",
        event_category="WORKFLOW",
        target_model="GeneratedDocument",
        target_object_id=str(document.pk),
        reference_code=document.reference_code,
        actor_user=user,
        source_app=_SOURCE_APP,
        metadata={
            **_generated_doc_audit_meta(document),
            "status_from": old_status,
            "void_reason_code": reason_code,
        },
    )
    return document


@transaction.atomic
def _archive_generated_document(*, user, document):
    """Archive a voided generated document. Metadata transition only."""
    if not can_archive_generated_document(user, document):
        raise DocumentPolicyError("Permission denied: cannot archive document.")
    if document.document_status != DocumentStatusChoices.VOIDED:
        raise DocumentServiceError("Only voided documents can be archived.")
    old_status = document.document_status
    document.document_status = DocumentStatusChoices.ARCHIVED
    document.save(update_fields=["document_status", "updated_at"])
    audit_log(
        action_type="GENERATED_DOCUMENT_ARCHIVED",
        event_category="WORKFLOW",
        target_model="GeneratedDocument",
        target_object_id=str(document.pk),
        reference_code=document.reference_code,
        actor_user=user,
        source_app=_SOURCE_APP,
        metadata={**_generated_doc_audit_meta(document), "status_from": old_status},
    )
    return document


def _load_generated_document_for_boundary(document_id, *, lock=False):
    queryset = GeneratedDocument.objects.select_related(
        "template_version",
        "template_version__template",
        "protected_file",
    )
    if lock:
        queryset = queryset.select_for_update()
    try:
        return queryset.get(pk=document_id)
    except (GeneratedDocument.DoesNotExist, ValueError, TypeError) as exc:
        raise NotFoundError() from exc


def release_generated_document(*, user, command):
    """Release a generated document through a stable-ID command."""
    from apps.documents.commands import GeneratedDocumentLifecycleCommand

    if not isinstance(command, GeneratedDocumentLifecycleCommand):
        raise ValidationError("Document release requires a typed command.")
    with transaction.atomic():
        document = _load_generated_document_for_boundary(command.document_id, lock=True)
        return _release_generated_document(user=user, document=document)


def void_generated_document(*, user, command):
    """Void a generated document through a stable-ID command."""
    from apps.documents.commands import GeneratedDocumentLifecycleCommand

    if not isinstance(command, GeneratedDocumentLifecycleCommand):
        raise ValidationError("Document voiding requires a typed command.")
    with transaction.atomic():
        document = _load_generated_document_for_boundary(command.document_id, lock=True)
        return _void_generated_document(
            user=user,
            document=document,
            reason_code=command.reason_code,
        )


def archive_generated_document(*, user, command):
    """Archive a generated document through a stable-ID command."""
    from apps.documents.commands import GeneratedDocumentLifecycleCommand

    if not isinstance(command, GeneratedDocumentLifecycleCommand):
        raise ValidationError("Document archival requires a typed command.")
    with transaction.atomic():
        document = _load_generated_document_for_boundary(command.document_id, lock=True)
        return _archive_generated_document(user=user, document=document)


# ---------------------------------------------------------------------------
# Audit hooks for open/download/access denied
# ---------------------------------------------------------------------------

def audit_document_opened(*, user, document):
    """Audit that a generated document was opened."""
    audit_log(
        action_type="GENERATED_DOCUMENT_OPENED",
        event_category="DATA_ACCESS",
        target_model="GeneratedDocument",
        target_object_id=str(document.pk),
        reference_code=document.reference_code,
        actor_user=user,
        source_app=_SOURCE_APP,
        metadata=_generated_doc_audit_meta(document),
    )


def audit_document_downloaded(*, user, document):
    """Audit that a generated document was downloaded."""
    audit_log(
        action_type="GENERATED_DOCUMENT_DOWNLOADED",
        event_category="DATA_ACCESS",
        target_model="GeneratedDocument",
        target_object_id=str(document.pk),
        reference_code=document.reference_code,
        actor_user=user,
        source_app=_SOURCE_APP,
        metadata=_generated_doc_audit_meta(document),
    )


def audit_document_access_denied(*, user, document=None, reference_code=None):
    """Audit that access to a generated document was denied."""
    audit_log(
        action_type="GENERATED_DOCUMENT_ACCESS_DENIED",
        event_category="SECURITY",
        severity="WARNING",
        target_model="GeneratedDocument",
        target_object_id=str(document.pk) if document else "unknown",
        reference_code=reference_code or (document.reference_code if document else None),
        actor_user=user,
        source_app=_SOURCE_APP,
        metadata={
            "reason": "access_denied",
        },
    )
