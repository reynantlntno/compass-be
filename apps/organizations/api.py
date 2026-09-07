"""Public institutional configuration and Head Guidance governance API."""

from __future__ import annotations

from datetime import date, datetime
from pathlib import PurePosixPath
from uuid import UUID, uuid4

from django.core.files.storage import default_storage
from django.utils.dateparse import parse_date, parse_datetime
from ninja import Field, Router, Schema

from apps.common.api.idempotency import ApiMutationOutcome, run_api_mutation
from apps.common.api.operations import prepare_api_operation
from apps.common.api.pagination import PageQuery, PageSizeQuery, page_request_from_values
from apps.common.api.response_docs import binary_response_openapi
from apps.common.api.schemas import PageResultSchema
from apps.common.contracts import ContractValidationError
from apps.common.exceptions import NotFoundError, PermissionDeniedError, ValidationError
from apps.organizations import queries
from apps.organizations.asset_delivery import (
    issue_public_brand_asset_delivery,
    public_brand_asset_ttl_seconds,
    verify_public_brand_asset_delivery,
)
from apps.organizations.response_adapters import public_brand_asset_response
from apps.organizations.selectors import get_public_brand_asset
from apps.organizations.commands import (
    AcademicTermDraftCommand,
    AssetUploadReceipt,
    BrandAssetDraftCommand,
    FormFamilyDraftCommand,
    FormFieldSpec,
    FormOption,
    FormRevisionDraftCommand,
    FormRevisionSourceCommand,
    InstitutionProfileDraftCommand,
    LifecycleCommand,
    OfficeProfileDraftCommand,
    PublicLinkDraftCommand,
    RolloverPreviewCommand,
    RollbackCommand,
)
from apps.organizations.governance_services import (
    activate_academic_term,
    activate_form_revision,
    approve_academic_term,
    approve_form_revision,
    archive_academic_term,
    archive_form_revision,
    attach_form_revision_source,
    build_term_rollover_preview,
    close_academic_term,
    create_academic_term_draft,
    create_form_revision_draft,
    form_revision_activation_preflight,
    rollback_academic_term,
    submit_academic_term_for_approval,
    submit_form_revision_for_approval,
    update_academic_term_draft,
    update_form_revision_draft,
    retire_form_revision,
    clone_form_revision,
)
from apps.organizations.projections import (
    academic_term_projection,
    brand_asset_projection,
    form_family_projection,
    form_revision_projection,
    institution_profile_projection,
    office_profile_projection,
    public_link_projection,
)
from apps.organizations.services import (
    activate_brand_asset,
    activate_form_family,
    activate_institution_profile,
    activate_office_profile,
    activate_public_link,
    archive_brand_asset,
    archive_form_family,
    archive_institution_profile,
    archive_office_profile,
    archive_public_link,
    create_brand_asset_draft,
    create_form_family,
    create_institution_profile_draft,
    create_office_profile_draft,
    create_public_link_draft,
    retire_brand_asset,
    retire_form_family,
    retire_institution_profile,
    retire_office_profile,
    retire_public_link,
    update_brand_asset_draft,
    update_form_family_draft,
    update_institution_profile_draft,
    update_office_profile_draft,
    update_public_link_draft,
)


router = Router(tags=["organizations"])


class InstitutionProfileProjectionSchema(Schema):
    id: str
    legal_name: str
    short_name: str
    address: str
    main_campus: str
    primary_brand_color: str
    secondary_brand_color: str
    accent_brand_color: str
    version_label: str
    status: str
    effective_from: date | None = None
    effective_until: date | None = None
    former_name: str
    former_short_name: str
    source_note: str
    activated_at: datetime | None = None
    retired_at: datetime | None = None


class InstitutionProfilePageSchema(PageResultSchema):
    items: list[InstitutionProfileProjectionSchema]


class OfficeProfileProjectionSchema(Schema):
    id: str
    institution_id: str | None = None
    office_name: str
    office_short_name: str
    document_header_name: str
    office_address: str
    office_hours: str
    contact_email: str
    contact_number: str
    version_label: str
    status: str
    effective_from: date | None = None
    effective_until: date | None = None
    legacy_office_name: str
    default_signatory_name: str
    default_signatory_title: str
    footer_note: str
    source_note: str
    activated_at: datetime | None = None
    retired_at: datetime | None = None


class OfficeProfilePageSchema(PageResultSchema):
    items: list[OfficeProfileProjectionSchema]


class BrandAssetProjectionSchema(Schema):
    id: str
    institution_id: str | None = None
    office_id: str | None = None
    asset_type: str
    semantic_role: str
    owner_type: str
    placement: str
    display_order: int
    alt_text: str
    usage_context: str
    background_variant: str
    version_label: str
    status: str
    content_type: str
    image_width: int | None = None
    image_height: int | None = None
    effective_from: date | None = None
    effective_until: date | None = None
    approved_at: datetime | None = None


class BrandAssetPageSchema(PageResultSchema):
    items: list[BrandAssetProjectionSchema]


class PublicLinkProjectionSchema(Schema):
    id: str
    owner_type: str
    institution_id: str | None = None
    office_id: str | None = None
    link_type: str
    label: str
    url: str
    placement: str
    display_order: int
    status: str
    effective_from: date | None = None
    effective_until: date | None = None


class PublicLinkPageSchema(PageResultSchema):
    items: list[PublicLinkProjectionSchema]


class AcademicTermProjectionSchema(Schema):
    id: str
    academic_year: str
    semester: str
    start_date: date
    end_date: date
    status: str
    is_current: bool
    configuration_identifier: str
    approved_at: datetime | None = None
    activated_at: datetime | None = None
    closed_at: datetime | None = None


class AcademicTermPageSchema(PageResultSchema):
    items: list[AcademicTermProjectionSchema]


class FormFamilyProjectionSchema(Schema):
    id: str
    stable_key: str
    display_name: str
    description: str
    owner_office_id: str | None = None
    status: str
    current_active_revision_id: str | None = None


class FormFamilyPageSchema(PageResultSchema):
    items: list[FormFamilyProjectionSchema]


class FormRevisionActivationPreflightSchema(Schema):
    ready: bool
    blockers: list[str]
    status: str
    safe_template: bool


class FormRevisionProjectionSchema(Schema):
    id: str
    form_family_id: str
    form_family_key: str
    official_form_code: str
    official_revision: str
    display_title: str
    status: str
    effective_from: date | None = None
    effective_until: date | None = None
    is_used: bool
    internal_schema_version: str
    internal_template_version: str
    institution_profile_id: str | None = None
    office_profile_id: str | None = None
    source_label: str
    approved_at: datetime | None = None
    submitted_at: datetime | None = None
    activated_at: datetime | None = None
    retired_at: datetime | None = None
    activation_preflight: FormRevisionActivationPreflightSchema | None = None


class FormRevisionPageSchema(PageResultSchema):
    items: list[FormRevisionProjectionSchema]


class DocumentTemplateProjectionSchema(Schema):
    id: str
    stable_key: str
    display_name: str
    document_kind: str
    status: str
    default_output_format: str
    retention_classification: str


class DocumentTemplatePageSchema(PageResultSchema):
    items: list[DocumentTemplateProjectionSchema]


class AcademicTermRolloverProviderSchema(Schema):
    key: str
    status: str
    count: int
    reason_code: str | None = None


class AcademicTermRolloverRollbackSchema(Schema):
    status: str
    condition: str
    reference: str


class AcademicTermRolloverPreviewSchema(Schema):
    academic_year: str
    semester: str
    prior_term: str
    providers: list[AcademicTermRolloverProviderSchema]
    rollback: AcademicTermRolloverRollbackSchema


class FormOptionSchema(Schema):
    value: str
    label: str


class FormFieldSchema(Schema):
    key: str
    name: str = ""
    type: str = "text"
    label: str = ""
    required: bool = False
    options: list[FormOptionSchema] = Field(default_factory=list)
    max_length: int | None = None


class FormSchemaSummary(Schema):
    fields: list[FormFieldSchema] = Field(default_factory=list)


class InstitutionSchema(Schema):
    legal_name: str
    short_name: str
    former_name: str = ""
    former_short_name: str = ""
    address: str = ""
    main_campus: str = ""
    primary_brand_color: str = ""
    secondary_brand_color: str = ""
    accent_brand_color: str = ""
    version_label: str = ""
    effective_from: date | None = None
    effective_until: date | None = None
    source_note: str = ""
    expected_updated_at: str | None = None


class OfficeSchema(Schema):
    office_name: str
    office_short_name: str
    institution_id: int | None = None
    legacy_office_name: str = ""
    document_header_name: str = ""
    office_address: str = ""
    contact_email: str = ""
    contact_number: str = ""
    office_hours: str = ""
    default_signatory_name: str = ""
    default_signatory_title: str = ""
    footer_note: str = ""
    version_label: str = ""
    effective_from: date | None = None
    effective_until: date | None = None
    source_note: str = ""
    expected_updated_at: str | None = None


class BrandAssetSchema(Schema):
    institution_id: int | None = None
    office_id: int | None = None
    asset_type: str
    semantic_role: str
    owner_type: str
    placement: str = ""
    display_order: int = 0
    alt_text: str
    usage_context: str = ""
    background_variant: str = "TRANSPARENT"
    version_label: str = ""
    source_note: str = ""
    effective_from: date | None = None
    effective_until: date | None = None
    expected_updated_at: str | None = None


class PublicLinkSchema(Schema):
    owner_type: str
    link_type: str
    label: str
    url: str
    placement: str
    institution_id: int | None = None
    office_id: int | None = None
    display_order: int = 0
    effective_from: date | None = None
    effective_until: date | None = None
    source_note: str = ""
    expected_updated_at: str | None = None


class TermSchema(Schema):
    academic_year: str
    semester: str
    start_date: date
    end_date: date
    configuration_identifier: str
    source_reference: str = ""
    source_note: str = ""
    expected_updated_at: str | None = None


class FamilySchema(Schema):
    stable_key: str
    display_name: str
    description: str = ""
    owner_office_id: int | None = None
    source_notes: str = ""
    expected_updated_at: str | None = None


class RevisionSchema(Schema):
    form_family_id: int
    official_form_code: str
    official_revision: str
    internal_schema_version: str
    internal_template_version: str
    display_title: str
    institution_profile_id: int | None = None
    office_profile_id: int | None = None
    source_document_reference: str = ""
    source_label: str = ""
    schema_summary: FormSchemaSummary | None = None
    printable_template_path: str = ""
    source_notes: str = ""
    effective_from: date | None = None
    effective_until: date | None = None
    expected_updated_at: str | None = None


class LifecycleSchema(Schema):
    expected_status: str | None = None
    expected_updated_at: str | None = None
    reason_code: str = ""


class SourceSchema(Schema):
    source_label: str = ""
    upload_receipt_id: UUID
    expected_updated_at: str | None = None


class RolloverSchema(Schema):
    prior_term_id: int | None = None


class RollbackSchema(Schema):
    prior_term_id: int
    expected_updated_at: str | None = None
    reason_code: str = "TERM_ROLLBACK"


class PublicInstitutionIdentitySchema(Schema):
    display_name: str | None = None
    former_name: str | None = None
    campus: str | None = None
    address: str | None = None


class PublicOfficeIdentitySchema(Schema):
    display_name: str | None = None
    location: str | None = None
    office_hours: str | None = None
    email: str | None = None
    phone: str | None = None


class PublicLinkItemSchema(Schema):
    label: str
    url: str
    owner_type: str
    owner_label: str
    link_type: str
    placement: str
    display_order: int


class PublicLinksSchema(Schema):
    institution_links: list[PublicLinkItemSchema] = Field(default_factory=list)
    office_links: list[PublicLinkItemSchema] = Field(default_factory=list)
    compass_links: list[PublicLinkItemSchema] = Field(default_factory=list)


class PublicIdentitySchema(Schema):
    institution: PublicInstitutionIdentitySchema
    office: PublicOfficeIdentitySchema
    public_links: PublicLinksSchema


class PublicBrandingAssetMetadataSchema(Schema):
    id: str
    delivery_path: str
    delivery_mode: str
    alt_text: str
    asset_type: str
    placement: str
    display_order: int
    width: int
    height: int
    content_type: str
    effective_from: str | None = None
    effective_until: str | None = None


class PublicBrandingSchema(Schema):
    header_identity: list[PublicBrandingAssetMetadataSchema] = Field(default_factory=list)
    footer_identity: list[PublicBrandingAssetMetadataSchema] = Field(default_factory=list)
    footer_identity_row: list[PublicBrandingAssetMetadataSchema] = Field(default_factory=list)
    footer_certifications: list[PublicBrandingAssetMetadataSchema] = Field(default_factory=list)
    footer_recognitions: list[PublicBrandingAssetMetadataSchema] = Field(default_factory=list)
    footer_privacy_credentials: list[PublicBrandingAssetMetadataSchema] = Field(default_factory=list)
    publication_marks: list[PublicBrandingAssetMetadataSchema] = Field(default_factory=list)


class PublicBrandAssetDeliverySchema(Schema):
    asset_id: str
    url: str
    expires_at: str
    ttl_seconds: int
    content_type: str
    cache_control: str


class PublicAcademicTermSchema(Schema):
    id: str | None = None
    academic_year: str | None = None
    semester: str | None = None
    start_date: str | None = None
    end_date: str | None = None
    status: str | None = None
    is_current: bool | None = None


class PublicFormOptionSchema(Schema):
    value: str | None = None
    label: str | None = None


class PublicFormFieldSchema(Schema):
    key: str | None = None
    name: str | None = None
    type: str | None = None
    label: str | None = None
    required: bool | None = None
    options: list[PublicFormOptionSchema] = Field(default_factory=list)
    max_length: int | None = None


class PublicFormRevisionSchema(Schema):
    id: str | None = None
    form_family_id: str | None = None
    form_family_key: str | None = None
    official_form_code: str | None = None
    official_revision: str | None = None
    display_title: str | None = None
    status: str | None = None
    effective_from: str | None = None
    effective_until: str | None = None
    form_schema: list[PublicFormFieldSchema] | None = Field(default=None, alias="schema")


class PublicDocumentTemplateSchema(Schema):
    id: str
    stable_key: str
    display_name: str
    document_kind: str
    default_output_format: str
    status: str


class PublicDocumentTemplateVersionSchema(Schema):
    id: str
    template_stable_key: str
    version_label: str
    output_format: str
    status: str


class PublicDocumentTemplatesSchema(Schema):
    templates: list[PublicDocumentTemplateSchema] = Field(default_factory=list)
    versions: list[PublicDocumentTemplateVersionSchema] = Field(default_factory=list)


def _actor(request):
    return getattr(getattr(request, "auth", None), "user", None)


def _page(page: PageQuery, page_size: PageSizeQuery):
    try:
        return page_request_from_values(page, page_size)
    except ContractValidationError as exc:
        raise ValidationError() from exc


def _timestamp(value):
    if not value:
        return None
    parsed = parse_datetime(str(value))
    if parsed is None:
        raise ValidationError()
    return parsed


def _life(target_id, payload: LifecycleSchema):
    return LifecycleCommand(
        target_id=str(target_id),
        expected_status=payload.expected_status,
        expected_updated_at=_timestamp(payload.expected_updated_at),
        reason_code=payload.reason_code,
    )


def _run(request, operation_id, payload, operation, replay, *, prepared=None):
    prepared = prepared or prepare_api_operation(request, operation_id)
    return run_api_mutation(
        request, operation_id, payload, operation, replay,
        prepared_operation=prepared,
    )


def _outcome(value, model, path):
    return ApiMutationOutcome(value=value, related_object=model, safe_response_path=path)


def _public_page(value):
    return value


def _store_asset_upload(request):
    upload = (getattr(request, "FILES", {}) or {}).get("file")
    if upload is None:
        raise ValidationError(field_errors={"file": ["An image file is required."]})
    size = int(getattr(upload, "size", 0) or 0)
    content_type = str(getattr(upload, "content_type", "") or "")
    if size <= 0 or size > 5 * 1024 * 1024 or content_type not in {"image/png", "image/jpeg", "image/webp"}:
        raise ValidationError(field_errors={"file": ["The image file is invalid or exceeds the permitted size."]})
    original = str(getattr(upload, "name", "asset") or "asset").strip().replace("\\", "/")
    original = PurePosixPath(original).name[:255]
    storage_name = default_storage.save(f"organizations/brand_assets/pending/{uuid4().hex}-{original}", upload)
    return AssetUploadReceipt(storage_name=storage_name, content_type=content_type, size_bytes=size, original_filename=original)


def _expected_data(payload):
    data = payload.dict()
    data["expected_updated_at"] = _timestamp(payload.expected_updated_at)
    return data


def _institution_command(payload: InstitutionSchema):
    data = payload.dict()
    data["expected_updated_at"] = _timestamp(payload.expected_updated_at)
    return InstitutionProfileDraftCommand(**data)


def _office_command(payload: OfficeSchema):
    data = payload.dict()
    data["expected_updated_at"] = _timestamp(payload.expected_updated_at)
    return OfficeProfileDraftCommand(**data)


def _revision_command(payload: RevisionSchema):
    data = payload.dict(exclude={"schema_summary"})
    summary = payload.schema_summary
    data["schema_summary"] = tuple(
        FormFieldSpec(
            key=field.key,
            name=field.name,
            type=field.type,
            label=field.label,
            required=field.required,
            options=tuple(FormOption(value=item.value, label=item.label) for item in field.options),
            max_length=field.max_length,
        )
        for field in (summary.fields if summary else [])
    )
    data["expected_updated_at"] = _timestamp(payload.expected_updated_at)
    return FormRevisionDraftCommand(**data)


# ---------------------------------------------------------------------------
# Public safe reads
# ---------------------------------------------------------------------------

@router.get(
    "/public/identity/",
    response=PublicIdentitySchema,
    auth=None,
    exclude_unset=True,
    operation_id="organizations_public_identity",
)
def public_identity(request):
    return _public_page(queries.public_identity())


@router.get(
    "/public/branding/",
    response=PublicBrandingSchema,
    auth=None,
    operation_id="organizations_public_branding",
)
def public_branding(request):
    return _public_page(queries.public_branding())


@router.get(
    "/public/branding/assets/{asset_id}/",
    response=PublicBrandAssetDeliverySchema,
    auth=None,
    operation_id="organizations_public_branding_asset",
)
def public_branding_asset(request, asset_id: int):
    """Issue a short-lived signed URL for one approved public image."""
    prepare_api_operation(request, "organizations_public_branding_asset")
    asset = get_public_brand_asset(asset_id)
    if asset is None:
        raise NotFoundError()
    return issue_public_brand_asset_delivery(asset).as_safe_json()


@router.get(
    "/public/branding/assets/{asset_id}/content/",
    response=None,
    auth=None,
    openapi_extra=binary_response_openapi(
        "image/png",
        "image/jpeg",
        "image/webp",
        description="Approved public branding image",
    ),
    operation_id="organizations_public_branding_asset_content",
)
def public_branding_asset_content(request, asset_id: int, token: str = ""):
    """Serve approved image bytes only through a valid short-lived signature."""
    prepare_api_operation(request, "organizations_public_branding_asset_content")
    if not verify_public_brand_asset_delivery(asset_id=asset_id, token=token):
        raise NotFoundError()
    asset = get_public_brand_asset(asset_id)
    if asset is None:
        raise NotFoundError()
    try:
        stream = asset.file.open("rb")
    except Exception:
        raise NotFoundError()

    ttl_seconds = public_brand_asset_ttl_seconds()
    content_type = str(asset.content_type_hint or "").lower()
    extension = {
        "image/png": "png",
        "image/jpeg": "jpg",
        "image/webp": "webp",
    }.get(content_type, "bin")
    return public_brand_asset_response(
        stream=stream,
        asset_id=asset.pk,
        content_type=content_type,
        extension=extension,
        ttl_seconds=ttl_seconds,
    )


@router.get(
    "/public/links/",
    response=PublicLinksSchema,
    auth=None,
    operation_id="organizations_public_links",
)
def public_links(request):
    return _public_page(queries.public_links())


@router.get(
    "/public/academic-term/",
    response=PublicAcademicTermSchema,
    auth=None,
    exclude_unset=True,
    operation_id="organizations_public_academic_term",
)
def public_academic_term(request):
    return _public_page(queries.public_academic_term())


@router.get(
    "/public/forms/{stable_key}/",
    response=PublicFormRevisionSchema,
    auth=None,
    by_alias=True,
    exclude_unset=True,
    operation_id="organizations_public_form_revision",
)
def public_form_revision(request, stable_key: str):
    # An active revision is optional public metadata.  An empty snapshot is a
    # valid fail-closed response and is serialized as ``{}`` by
    # ``exclude_unset=True``; callers do not need a synthetic error envelope
    # just because the office has not published this form yet.
    return queries.public_form_revision(stable_key)


@router.get(
    "/public/document-templates/",
    response=PublicDocumentTemplatesSchema,
    auth=None,
    operation_id="organizations_public_document_templates",
)
def public_document_templates(request):
    return queries.public_document_templates()


# ---------------------------------------------------------------------------
# Governance reads
# ---------------------------------------------------------------------------

@router.get("/governance/institution-profiles/", response=InstitutionProfilePageSchema, operation_id="organizations_institution_profiles_list")
def institution_profiles(request, page: PageQuery, page_size: PageSizeQuery):
    return queries.institution_profile_page(_actor(request), _page(page, page_size))


@router.get("/governance/institution-profiles/{profile_id}/", response=InstitutionProfileProjectionSchema, exclude_unset=True, operation_id="organizations_institution_profile_detail")
def institution_profile(request, profile_id: int):
    value = queries.institution_profile_detail(_actor(request), profile_id)
    if value is None:
        raise NotFoundError()
    return value


@router.get("/governance/offices/", response=OfficeProfilePageSchema, operation_id="organizations_offices_list")
def offices(request, page: PageQuery, page_size: PageSizeQuery):
    return queries.office_profile_page(_actor(request), _page(page, page_size))


@router.get("/governance/offices/{office_id}/", response=OfficeProfileProjectionSchema, exclude_unset=True, operation_id="organizations_office_detail")
def office(request, office_id: int):
    value = queries.office_profile_detail(_actor(request), office_id)
    if value is None:
        raise NotFoundError()
    return value


@router.get("/governance/brand-assets/", response=BrandAssetPageSchema, operation_id="organizations_brand_assets_list")
def brand_assets(request, page: PageQuery, page_size: PageSizeQuery):
    return queries.brand_asset_page(_actor(request), _page(page, page_size))


@router.get("/governance/brand-assets/{asset_id}/", response=BrandAssetProjectionSchema, exclude_unset=True, operation_id="organizations_brand_asset_detail")
def brand_asset(request, asset_id: int):
    value = queries.brand_asset_detail(_actor(request), asset_id)
    if value is None:
        raise NotFoundError()
    return value


@router.get("/governance/public-links/", response=PublicLinkPageSchema, operation_id="organizations_public_links_list")
def public_link_list(request, page: PageQuery, page_size: PageSizeQuery):
    return queries.public_link_page(_actor(request), _page(page, page_size))


@router.get("/governance/public-links/{link_id}/", response=PublicLinkProjectionSchema, exclude_unset=True, operation_id="organizations_public_link_detail")
def public_link_detail(request, link_id: int):
    value = queries.public_link_detail(_actor(request), link_id)
    if value is None:
        raise NotFoundError()
    return value


@router.get("/governance/academic-terms/", response=AcademicTermPageSchema, operation_id="organizations_academic_terms_list")
def academic_terms(request, page: PageQuery, page_size: PageSizeQuery):
    return queries.academic_term_page(_actor(request), _page(page, page_size))


@router.get("/governance/academic-terms/{term_id}/", response=AcademicTermProjectionSchema, exclude_unset=True, operation_id="organizations_academic_term_detail")
def academic_term(request, term_id: int):
    value = queries.academic_term_detail(_actor(request), term_id)
    if value is None:
        raise NotFoundError()
    return value


@router.get("/governance/form-families/", response=FormFamilyPageSchema, operation_id="organizations_form_families_list")
def form_families(request, page: PageQuery, page_size: PageSizeQuery):
    return queries.form_family_page(_actor(request), _page(page, page_size))


@router.get("/governance/form-families/{family_id}/", response=FormFamilyProjectionSchema, exclude_unset=True, operation_id="organizations_form_family_detail")
def form_family(request, family_id: int):
    value = queries.form_family_detail(_actor(request), family_id)
    if value is None:
        raise NotFoundError()
    return value


@router.get("/governance/form-revisions/", response=FormRevisionPageSchema, operation_id="organizations_form_revisions_list")
def form_revisions(request, page: PageQuery, page_size: PageSizeQuery):
    return queries.form_revision_page(_actor(request), _page(page, page_size))


@router.get("/governance/form-revisions/{revision_id}/", response=FormRevisionProjectionSchema, exclude_unset=True, operation_id="organizations_form_revision_detail")
def form_revision(request, revision_id: int):
    value = queries.form_revision_detail(_actor(request), revision_id)
    if value is None:
        raise NotFoundError()
    return value


@router.get("/governance/document-templates/", response=DocumentTemplatePageSchema, operation_id="organizations_document_templates_list")
def document_templates(request, page: PageQuery, page_size: PageSizeQuery):
    return queries.document_template_page(_actor(request), _page(page, page_size))


@router.get("/governance/document-templates/{template_id}/", response=DocumentTemplateProjectionSchema, exclude_unset=True, operation_id="organizations_document_template_detail")
def document_template(request, template_id: int):
    value = queries.document_template_detail(_actor(request), template_id)
    if value is None:
        raise NotFoundError()
    return value


@router.get("/governance/academic-terms/{term_id}/rollover-preview/", response=AcademicTermRolloverPreviewSchema, exclude_unset=True, operation_id="organizations_academic_term_rollover_preview")
def academic_term_rollover_preview(request, term_id: int):
    payload = RolloverSchema(prior_term_id=request.GET.get("prior_term_id"))
    return build_term_rollover_preview(
        _actor(request),
        RolloverPreviewCommand(term_id=str(term_id), prior_term_id=payload.prior_term_id),
    )


@router.get("/governance/form-revisions/{revision_id}/activation-preflight/", response=FormRevisionActivationPreflightSchema, exclude_unset=True, operation_id="organizations_form_revision_activation_preflight")
def form_revision_preflight(request, revision_id: int):
    return form_revision_activation_preflight(_actor(request), LifecycleCommand(target_id=str(revision_id)))


# ---------------------------------------------------------------------------
# Typed governance mutations
# ---------------------------------------------------------------------------

@router.post("/governance/institution-profiles/", response=InstitutionProfileProjectionSchema, exclude_unset=True, operation_id="organizations_institution_profile_create")
def institution_profile_create(request, payload: InstitutionSchema):
    command = _institution_command(payload)
    return _mutation_response(request, "organizations_institution_profile_create", payload.dict(), lambda: create_institution_profile_draft(_actor(request), command), institution_profile_projection, lambda key: queries.institution_profile_detail(_actor(request), key.related_object_id))


def _mutation_response(request, operation_id, payload, operation, projector, replay, *, prepared=None):
    def action():
        value = operation()
        return ApiMutationOutcome(value=projector(value), related_object=value, safe_response_path="/api/v1/organizations/")
    return _run(request, operation_id, payload, action, replay, prepared=prepared)


@router.post("/governance/institution-profiles/{profile_id}/update/", response=InstitutionProfileProjectionSchema, exclude_unset=True, operation_id="organizations_institution_profile_update")
def institution_profile_update(request, profile_id: int, payload: InstitutionSchema):
    command = _institution_command(payload)
    return _mutation_response(request, "organizations_institution_profile_update", {"id": profile_id, **payload.dict()}, lambda: update_institution_profile_draft(_actor(request), profile_id, command), institution_profile_projection, lambda key: queries.institution_profile_detail(_actor(request), key.related_object_id))


@router.post("/governance/institution-profiles/{profile_id}/activate/", response=InstitutionProfileProjectionSchema, exclude_unset=True, operation_id="organizations_institution_profile_activate")
def institution_profile_activate(request, profile_id: int, payload: LifecycleSchema):
    return _mutation_response(request, "organizations_institution_profile_activate", {"id": profile_id, **payload.dict()}, lambda: activate_institution_profile(_actor(request), _life(profile_id, payload)), institution_profile_projection, lambda key: queries.institution_profile_detail(_actor(request), key.related_object_id))


@router.post("/governance/institution-profiles/{profile_id}/retire/", response=InstitutionProfileProjectionSchema, exclude_unset=True, operation_id="organizations_institution_profile_retire")
def institution_profile_retire(request, profile_id: int, payload: LifecycleSchema):
    return _mutation_response(request, "organizations_institution_profile_retire", {"id": profile_id, **payload.dict()}, lambda: retire_institution_profile(_actor(request), _life(profile_id, payload)), institution_profile_projection, lambda key: queries.institution_profile_detail(_actor(request), key.related_object_id))


@router.post("/governance/institution-profiles/{profile_id}/archive/", response=InstitutionProfileProjectionSchema, exclude_unset=True, operation_id="organizations_institution_profile_archive")
def institution_profile_archive(request, profile_id: int, payload: LifecycleSchema):
    return _mutation_response(request, "organizations_institution_profile_archive", {"id": profile_id, **payload.dict()}, lambda: archive_institution_profile(_actor(request), _life(profile_id, payload)), institution_profile_projection, lambda key: queries.institution_profile_detail(_actor(request), key.related_object_id))


@router.post("/governance/offices/", response=OfficeProfileProjectionSchema, exclude_unset=True, operation_id="organizations_office_create")
def office_create(request, payload: OfficeSchema):
    command = _office_command(payload)
    return _mutation_response(request, "organizations_office_create", payload.dict(), lambda: create_office_profile_draft(_actor(request), command), office_profile_projection, lambda key: queries.office_profile_detail(_actor(request), key.related_object_id))


@router.post("/governance/offices/{office_id}/update/", response=OfficeProfileProjectionSchema, exclude_unset=True, operation_id="organizations_office_update")
def office_update(request, office_id: int, payload: OfficeSchema):
    command = _office_command(payload)
    return _mutation_response(request, "organizations_office_update", {"id": office_id, **payload.dict()}, lambda: update_office_profile_draft(_actor(request), office_id, command), office_profile_projection, lambda key: queries.office_profile_detail(_actor(request), key.related_object_id))


@router.post("/governance/offices/{office_id}/activate/", response=OfficeProfileProjectionSchema, exclude_unset=True, operation_id="organizations_office_activate")
def office_activate(request, office_id: int, payload: LifecycleSchema):
    return _mutation_response(request, "organizations_office_activate", {"id": office_id, **payload.dict()}, lambda: activate_office_profile(_actor(request), _life(office_id, payload)), office_profile_projection, lambda key: queries.office_profile_detail(_actor(request), key.related_object_id))


@router.post("/governance/offices/{office_id}/retire/", response=OfficeProfileProjectionSchema, exclude_unset=True, operation_id="organizations_office_retire")
def office_retire(request, office_id: int, payload: LifecycleSchema):
    return _mutation_response(request, "organizations_office_retire", {"id": office_id, **payload.dict()}, lambda: retire_office_profile(_actor(request), _life(office_id, payload)), office_profile_projection, lambda key: queries.office_profile_detail(_actor(request), key.related_object_id))


@router.post("/governance/offices/{office_id}/archive/", response=OfficeProfileProjectionSchema, exclude_unset=True, operation_id="organizations_office_archive")
def office_archive(request, office_id: int, payload: LifecycleSchema):
    return _mutation_response(request, "organizations_office_archive", {"id": office_id, **payload.dict()}, lambda: archive_office_profile(_actor(request), _life(office_id, payload)), office_profile_projection, lambda key: queries.office_profile_detail(_actor(request), key.related_object_id))


@router.post("/governance/brand-assets/", response=BrandAssetProjectionSchema, exclude_unset=True, operation_id="organizations_brand_asset_create")
def brand_asset_create(request, payload: BrandAssetSchema):
    operation_id = "organizations_brand_asset_create"
    prepared = prepare_api_operation(request, operation_id)
    safe_payload = {**payload.dict(), "upload": True}

    def operation():
        receipt = _store_asset_upload(request)
        try:
            data = payload.dict()
            data["upload_receipt"] = receipt
            data["expected_updated_at"] = _timestamp(payload.expected_updated_at)
            return create_brand_asset_draft(_actor(request), BrandAssetDraftCommand(**data))
        except Exception:
            try:
                default_storage.delete(receipt.storage_name)
            except Exception:
                pass
            raise

    return _mutation_response(
        request,
        operation_id,
        safe_payload,
        operation,
        brand_asset_projection,
        lambda key: queries.brand_asset_detail(_actor(request), key.related_object_id),
        prepared=prepared,
    )


@router.post("/governance/brand-assets/{asset_id}/update/", response=BrandAssetProjectionSchema, exclude_unset=True, operation_id="organizations_brand_asset_update")
def brand_asset_update(request, asset_id: int, payload: BrandAssetSchema):
    operation_id = "organizations_brand_asset_update"
    prepared = prepare_api_operation(request, operation_id)
    has_upload = bool((getattr(request, "FILES", {}) or {}).get("file"))
    safe_payload = {"id": asset_id, **payload.dict(), "upload": has_upload}

    def operation():
        receipt = _store_asset_upload(request) if has_upload else None
        try:
            data = payload.dict()
            data["upload_receipt"] = receipt
            data["expected_updated_at"] = _timestamp(payload.expected_updated_at)
            return update_brand_asset_draft(_actor(request), asset_id, BrandAssetDraftCommand(**data))
        except Exception:
            if receipt:
                try:
                    default_storage.delete(receipt.storage_name)
                except Exception:
                    pass
            raise

    return _mutation_response(
        request,
        operation_id,
        safe_payload,
        operation,
        brand_asset_projection,
        lambda key: queries.brand_asset_detail(_actor(request), key.related_object_id),
        prepared=prepared,
    )


@router.post("/governance/brand-assets/{asset_id}/activate/", response=BrandAssetProjectionSchema, exclude_unset=True, operation_id="organizations_brand_asset_activate")
def brand_asset_activate(request, asset_id: int, payload: LifecycleSchema):
    return _mutation_response(request, "organizations_brand_asset_activate", {"id": asset_id, **payload.dict()}, lambda: activate_brand_asset(_actor(request), _life(asset_id, payload)), brand_asset_projection, lambda key: queries.brand_asset_detail(_actor(request), key.related_object_id))


@router.post("/governance/brand-assets/{asset_id}/retire/", response=BrandAssetProjectionSchema, exclude_unset=True, operation_id="organizations_brand_asset_retire")
def brand_asset_retire(request, asset_id: int, payload: LifecycleSchema):
    return _mutation_response(request, "organizations_brand_asset_retire", {"id": asset_id, **payload.dict()}, lambda: retire_brand_asset(_actor(request), _life(asset_id, payload)), brand_asset_projection, lambda key: queries.brand_asset_detail(_actor(request), key.related_object_id))


@router.post("/governance/brand-assets/{asset_id}/archive/", response=BrandAssetProjectionSchema, exclude_unset=True, operation_id="organizations_brand_asset_archive")
def brand_asset_archive(request, asset_id: int, payload: LifecycleSchema):
    return _mutation_response(request, "organizations_brand_asset_archive", {"id": asset_id, **payload.dict()}, lambda: archive_brand_asset(_actor(request), _life(asset_id, payload)), brand_asset_projection, lambda key: queries.brand_asset_detail(_actor(request), key.related_object_id))


@router.post("/governance/public-links/", response=PublicLinkProjectionSchema, exclude_unset=True, operation_id="organizations_public_link_create")
def public_link_create(request, payload: PublicLinkSchema):
    command = PublicLinkDraftCommand(**_expected_data(payload))
    return _mutation_response(request, "organizations_public_link_create", payload.dict(), lambda: create_public_link_draft(_actor(request), command), public_link_projection, lambda key: queries.public_link_detail(_actor(request), key.related_object_id))


@router.post("/governance/public-links/{link_id}/update/", response=PublicLinkProjectionSchema, exclude_unset=True, operation_id="organizations_public_link_update")
def public_link_update(request, link_id: int, payload: PublicLinkSchema):
    command = PublicLinkDraftCommand(**_expected_data(payload))
    return _mutation_response(request, "organizations_public_link_update", {"id": link_id, **payload.dict()}, lambda: update_public_link_draft(_actor(request), link_id, command), public_link_projection, lambda key: queries.public_link_detail(_actor(request), key.related_object_id))


@router.post("/governance/public-links/{link_id}/activate/", response=PublicLinkProjectionSchema, exclude_unset=True, operation_id="organizations_public_link_activate")
def public_link_activate(request, link_id: int, payload: LifecycleSchema):
    return _mutation_response(request, "organizations_public_link_activate", {"id": link_id, **payload.dict()}, lambda: activate_public_link(_actor(request), _life(link_id, payload)), public_link_projection, lambda key: queries.public_link_detail(_actor(request), key.related_object_id))


@router.post("/governance/public-links/{link_id}/retire/", response=PublicLinkProjectionSchema, exclude_unset=True, operation_id="organizations_public_link_retire")
def public_link_retire(request, link_id: int, payload: LifecycleSchema):
    return _mutation_response(request, "organizations_public_link_retire", {"id": link_id, **payload.dict()}, lambda: retire_public_link(_actor(request), _life(link_id, payload)), public_link_projection, lambda key: queries.public_link_detail(_actor(request), key.related_object_id))


@router.post("/governance/public-links/{link_id}/archive/", response=PublicLinkProjectionSchema, exclude_unset=True, operation_id="organizations_public_link_archive")
def public_link_archive(request, link_id: int, payload: LifecycleSchema):
    return _mutation_response(request, "organizations_public_link_archive", {"id": link_id, **payload.dict()}, lambda: archive_public_link(_actor(request), _life(link_id, payload)), public_link_projection, lambda key: queries.public_link_detail(_actor(request), key.related_object_id))


@router.post("/governance/academic-terms/", response=AcademicTermProjectionSchema, exclude_unset=True, operation_id="organizations_academic_term_create")
def academic_term_create(request, payload: TermSchema):
    command = AcademicTermDraftCommand(**_expected_data(payload))
    return _mutation_response(request, "organizations_academic_term_create", payload.dict(), lambda: create_academic_term_draft(_actor(request), command), academic_term_projection, lambda key: queries.academic_term_detail(_actor(request), key.related_object_id))


@router.post("/governance/academic-terms/{term_id}/update/", response=AcademicTermProjectionSchema, exclude_unset=True, operation_id="organizations_academic_term_update")
def academic_term_update(request, term_id: int, payload: TermSchema):
    command = AcademicTermDraftCommand(**_expected_data(payload))
    return _mutation_response(request, "organizations_academic_term_update", {"id": term_id, **payload.dict()}, lambda: update_academic_term_draft(_actor(request), term_id, command), academic_term_projection, lambda key: queries.academic_term_detail(_actor(request), key.related_object_id))


def _term_lifecycle(request, operation_id, term_id, payload, service):
    return _mutation_response(request, operation_id, {"id": term_id, **payload.dict()}, lambda: service(_actor(request), _life(term_id, payload)), academic_term_projection, lambda key: queries.academic_term_detail(_actor(request), key.related_object_id))


@router.post("/governance/academic-terms/{term_id}/submit/", response=AcademicTermProjectionSchema, exclude_unset=True, operation_id="organizations_academic_term_submit")
def academic_term_submit(request, term_id: int, payload: LifecycleSchema):
    return _term_lifecycle(request, "organizations_academic_term_submit", term_id, payload, submit_academic_term_for_approval)


@router.post("/governance/academic-terms/{term_id}/approve/", response=AcademicTermProjectionSchema, exclude_unset=True, operation_id="organizations_academic_term_approve")
def academic_term_approve(request, term_id: int, payload: LifecycleSchema):
    return _term_lifecycle(request, "organizations_academic_term_approve", term_id, payload, approve_academic_term)


@router.post("/governance/academic-terms/{term_id}/activate/", response=AcademicTermProjectionSchema, exclude_unset=True, operation_id="organizations_academic_term_activate")
def academic_term_activate(request, term_id: int, payload: LifecycleSchema):
    return _term_lifecycle(request, "organizations_academic_term_activate", term_id, payload, activate_academic_term)


@router.post("/governance/academic-terms/{term_id}/close/", response=AcademicTermProjectionSchema, exclude_unset=True, operation_id="organizations_academic_term_close")
def academic_term_close(request, term_id: int, payload: LifecycleSchema):
    return _term_lifecycle(request, "organizations_academic_term_close", term_id, payload, close_academic_term)


@router.post("/governance/academic-terms/{term_id}/archive/", response=AcademicTermProjectionSchema, exclude_unset=True, operation_id="organizations_academic_term_archive")
def academic_term_archive(request, term_id: int, payload: LifecycleSchema):
    return _term_lifecycle(request, "organizations_academic_term_archive", term_id, payload, archive_academic_term)


@router.post("/governance/academic-terms/{term_id}/rollback/", response=AcademicTermProjectionSchema, exclude_unset=True, operation_id="organizations_academic_term_rollback")
def academic_term_rollback(request, term_id: int, payload: RollbackSchema):
    command = RollbackCommand(term_id=str(term_id), prior_term_id=str(payload.prior_term_id), expected_updated_at=_timestamp(payload.expected_updated_at), reason_code=payload.reason_code)
    return _mutation_response(request, "organizations_academic_term_rollback", {"id": term_id, "prior_term_id": payload.prior_term_id, "reason_code": payload.reason_code}, lambda: rollback_academic_term(_actor(request), command), academic_term_projection, lambda key: queries.academic_term_detail(_actor(request), key.related_object_id))


@router.post("/governance/form-families/", response=FormFamilyProjectionSchema, exclude_unset=True, operation_id="organizations_form_family_create")
def form_family_create(request, payload: FamilySchema):
    command = FormFamilyDraftCommand(**_expected_data(payload))
    return _mutation_response(request, "organizations_form_family_create", payload.dict(), lambda: create_form_family(_actor(request), command), form_family_projection, lambda key: queries.form_family_detail(_actor(request), key.related_object_id))


@router.post("/governance/form-families/{family_id}/update/", response=FormFamilyProjectionSchema, exclude_unset=True, operation_id="organizations_form_family_update")
def form_family_update(request, family_id: int, payload: FamilySchema):
    command = FormFamilyDraftCommand(**_expected_data(payload))
    return _mutation_response(request, "organizations_form_family_update", {"id": family_id, **payload.dict()}, lambda: update_form_family_draft(_actor(request), family_id, command), form_family_projection, lambda key: queries.form_family_detail(_actor(request), key.related_object_id))


@router.post("/governance/form-families/{family_id}/activate/", response=FormFamilyProjectionSchema, exclude_unset=True, operation_id="organizations_form_family_activate")
def form_family_activate(request, family_id: int, payload: LifecycleSchema):
    return _mutation_response(request, "organizations_form_family_activate", {"id": family_id, **payload.dict()}, lambda: activate_form_family(_actor(request), _life(family_id, payload)), form_family_projection, lambda key: queries.form_family_detail(_actor(request), key.related_object_id))


@router.post("/governance/form-families/{family_id}/retire/", response=FormFamilyProjectionSchema, exclude_unset=True, operation_id="organizations_form_family_retire")
def form_family_retire(request, family_id: int, payload: LifecycleSchema):
    return _mutation_response(request, "organizations_form_family_retire", {"id": family_id, **payload.dict()}, lambda: retire_form_family(_actor(request), _life(family_id, payload)), form_family_projection, lambda key: queries.form_family_detail(_actor(request), key.related_object_id))


@router.post("/governance/form-families/{family_id}/archive/", response=FormFamilyProjectionSchema, exclude_unset=True, operation_id="organizations_form_family_archive")
def form_family_archive(request, family_id: int, payload: LifecycleSchema):
    return _mutation_response(request, "organizations_form_family_archive", {"id": family_id, **payload.dict()}, lambda: archive_form_family(_actor(request), _life(family_id, payload)), form_family_projection, lambda key: queries.form_family_detail(_actor(request), key.related_object_id))


@router.post("/governance/form-revisions/", response=FormRevisionProjectionSchema, exclude_unset=True, operation_id="organizations_form_revision_create")
def form_revision_create(request, payload: RevisionSchema):
    command = _revision_command(payload)
    return _mutation_response(request, "organizations_form_revision_create", payload.dict(), lambda: create_form_revision_draft(_actor(request), command), form_revision_projection, lambda key: queries.form_revision_detail(_actor(request), key.related_object_id))


@router.post("/governance/form-revisions/{revision_id}/update/", response=FormRevisionProjectionSchema, exclude_unset=True, operation_id="organizations_form_revision_update")
def form_revision_update(request, revision_id: int, payload: RevisionSchema):
    command = _revision_command(payload)
    return _mutation_response(request, "organizations_form_revision_update", {"id": revision_id, **payload.dict()}, lambda: update_form_revision_draft(_actor(request), revision_id, command), form_revision_projection, lambda key: queries.form_revision_detail(_actor(request), key.related_object_id))


@router.post("/governance/form-revisions/{revision_id}/attach-source/", response=FormRevisionProjectionSchema, exclude_unset=True, operation_id="organizations_form_revision_attach_source")
def form_revision_attach_source(request, revision_id: int, payload: SourceSchema):
    command = FormRevisionSourceCommand(
        revision_id=str(revision_id),
        source_label=payload.source_label,
        upload_receipt_id=str(payload.upload_receipt_id),
        expected_updated_at=_timestamp(payload.expected_updated_at),
    )
    return _mutation_response(request, "organizations_form_revision_attach_source", {"id": revision_id, "upload_receipt": True, "source_label": payload.source_label}, lambda: attach_form_revision_source(_actor(request), command), form_revision_projection, lambda key: queries.form_revision_detail(_actor(request), key.related_object_id))


def _revision_lifecycle(request, operation_id, revision_id, payload, service):
    return _mutation_response(request, operation_id, {"id": revision_id, **payload.dict()}, lambda: service(_actor(request), _life(revision_id, payload)), form_revision_projection, lambda key: queries.form_revision_detail(_actor(request), key.related_object_id))


@router.post("/governance/form-revisions/{revision_id}/submit/", response=FormRevisionProjectionSchema, exclude_unset=True, operation_id="organizations_form_revision_submit")
def form_revision_submit(request, revision_id: int, payload: LifecycleSchema):
    return _revision_lifecycle(request, "organizations_form_revision_submit", revision_id, payload, submit_form_revision_for_approval)


@router.post("/governance/form-revisions/{revision_id}/approve/", response=FormRevisionProjectionSchema, exclude_unset=True, operation_id="organizations_form_revision_approve")
def form_revision_approve(request, revision_id: int, payload: LifecycleSchema):
    return _revision_lifecycle(request, "organizations_form_revision_approve", revision_id, payload, approve_form_revision)


@router.post("/governance/form-revisions/{revision_id}/activate/", response=FormRevisionProjectionSchema, exclude_unset=True, operation_id="organizations_form_revision_activate")
def form_revision_activate(request, revision_id: int, payload: LifecycleSchema):
    return _revision_lifecycle(request, "organizations_form_revision_activate", revision_id, payload, activate_form_revision)


@router.post("/governance/form-revisions/{revision_id}/retire/", response=FormRevisionProjectionSchema, exclude_unset=True, operation_id="organizations_form_revision_retire")
def form_revision_retire(request, revision_id: int, payload: LifecycleSchema):
    return _revision_lifecycle(request, "organizations_form_revision_retire", revision_id, payload, retire_form_revision)


@router.post("/governance/form-revisions/{revision_id}/archive/", response=FormRevisionProjectionSchema, exclude_unset=True, operation_id="organizations_form_revision_archive")
def form_revision_archive(request, revision_id: int, payload: LifecycleSchema):
    return _revision_lifecycle(request, "organizations_form_revision_archive", revision_id, payload, archive_form_revision)


@router.post("/governance/form-revisions/{revision_id}/clone/", response=FormRevisionProjectionSchema, exclude_unset=True, operation_id="organizations_form_revision_clone")
def form_revision_clone(request, revision_id: int, payload: LifecycleSchema):
    return _mutation_response(request, "organizations_form_revision_clone", {"id": revision_id, **payload.dict()}, lambda: clone_form_revision(_actor(request), _life(revision_id, payload)), form_revision_projection, lambda key: queries.form_revision_detail(_actor(request), key.related_object_id))
