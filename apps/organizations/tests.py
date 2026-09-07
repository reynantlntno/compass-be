"""Focused contracts for the institutional configuration vertical."""

from datetime import date
import base64
import hashlib
import importlib
import json
import tempfile
from types import SimpleNamespace
from unittest import mock

from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.exceptions import FieldDoesNotExist
from django.test import Client, SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from apps.accounts.models import RoleChoices, User
from apps.common.exceptions import PermissionDeniedError, StaleStateError, ValidationError
from apps.organizations.api import (
    AcademicTermPageSchema,
    AcademicTermProjectionSchema,
    AcademicTermRolloverPreviewSchema,
    BrandAssetPageSchema,
    BrandAssetProjectionSchema,
    DocumentTemplatePageSchema,
    DocumentTemplateProjectionSchema,
    FormFamilyPageSchema,
    FormFamilyProjectionSchema,
    FormRevisionActivationPreflightSchema,
    FormRevisionPageSchema,
    FormRevisionProjectionSchema,
    InstitutionProfilePageSchema,
    InstitutionProfileProjectionSchema,
    OfficeProfilePageSchema,
    OfficeProfileProjectionSchema,
    PublicLinkPageSchema,
    PublicLinkProjectionSchema,
)
from apps.organizations import queries, selectors
from apps.organizations.commands import (
    AssetUploadReceipt,
    InstitutionProfileDraftCommand,
    LifecycleCommand,
)
from apps.organizations.models import (
    AssetStatusChoices,
    AssetTypeChoices,
    BrandAsset,
    BrandAssetOwnerChoices,
    BrandAssetPlacementChoices,
    BrandAssetRoleChoices,
    GovernanceStatusChoices,
    InstitutionProfile,
    OfficeProfile,
    AcademicTerm,
    FormFamily,
    FormRevision,
    PublicLinkOwnerChoices,
    PublicLinkPlacementChoices,
)
from apps.organizations.projections import (
    academic_term_projection,
    brand_asset_projection,
    document_template_projection,
    form_family_projection,
    form_revision_projection,
    institution_profile_projection,
    office_profile_projection,
    public_link_projection,
)
from apps.organizations.services import (
    activate_institution_profile,
    create_institution_profile_draft,
)
from apps.profiles.models import CounselorProfile
from apps.account_security.api_tokens import issue_token_pair


class OrganizationCommandTests(SimpleTestCase):
    def test_commands_are_frozen_and_reject_models_or_raw_files(self):
        command = InstitutionProfileDraftCommand(legal_name="Example University", short_name="EU")
        with self.assertRaises((AttributeError, TypeError)):
            command.legal_name = "Changed"
        with self.assertRaises(TypeError):
            InstitutionProfileDraftCommand(
                legal_name="Example University",
                short_name="EU",
                public_links={"value": object()},
            )
        with self.assertRaises(ValidationError):
            AssetUploadReceipt(
                storage_name=object(),
                content_type="image/png",
                size_bytes=10,
                original_filename="logo.png",
            )


class OrganizationProjectionTests(SimpleTestCase):
    def test_projection_allowlist_does_not_cross_file_or_credential_fields(self):
        class FakeAsset:
            pk = 1
            institution_id = None
            office_id = None
            asset_type = "LOGO_FULL"
            semantic_role = "IDENTITY"
            owner_type = "COMPASS"
            placement = "HEADER_IDENTITY"
            alt_text = "Logo"
            usage_context = "PUBLIC_HEADER"
            background_variant = "TRANSPARENT"
            version_label = "v1"
            status = "ACTIVE"
            content_type_hint = "image/png"
            file_size_bytes = 10
            image_width = 10
            image_height = 10
            effective_from = None
            effective_until = None
            approved_at = None
            original_filename = "secret.png"
            source_note = "secret source"
            credential_reference = "credential"
            file = object()

        result = brand_asset_projection(FakeAsset())
        self.assertNotIn("file", result)
        self.assertNotIn("original_filename", result)
        self.assertNotIn("source_note", result)
        self.assertNotIn("credential_reference", result)

    def test_configuration_owners_no_longer_expose_duplicate_legacy_fields(self):
        removed_fields = {
            InstitutionProfile: ("logo_image", "seal_image", "public_links", "effective_date"),
            OfficeProfile: ("header_logo", "public_links"),
            AcademicTerm: ("is_current",),
            FormFamily: ("future_owning_app",),
        }
        for model, field_names in removed_fields.items():
            for field_name in field_names:
                with self.subTest(model=model.__name__, field=field_name):
                    with self.assertRaises(FieldDoesNotExist):
                        model._meta.get_field(field_name)

    def test_current_term_projection_is_derived_from_status(self):
        term = SimpleNamespace(
            pk=1,
            academic_year="2025-2026",
            semester="First",
            start_date=None,
            end_date=None,
            status="ACTIVE",
            configuration_identifier="term.current",
            approved_at=None,
            activated_at=None,
            closed_at=None,
        )
        self.assertTrue(academic_term_projection(term)["is_current"])
        term.status = "CLOSED"
        self.assertFalse(academic_term_projection(term)["is_current"])

    def test_form_family_projection_omits_planning_owner(self):
        family = SimpleNamespace(
            pk=1,
            stable_key="call_slip",
            display_name="Call Slip",
            description="",
            owner_office_id=None,
            status="ACTIVE",
            current_active_revision_id=None,
            future_owning_app="should-never-be-read",
        )
        self.assertNotIn("future_owning_app", form_family_projection(family))

    def test_public_branding_keeps_asset_groups_separate_from_links(self):
        snapshot = {
            "header_identity": [{
                "id": "asset-1",
                "delivery_path": "/api/v1/organizations/public/branding/assets/asset-1/",
            }],
            "institution_links": [{"label": "Institution site"}],
            "office_links": [{"label": "Office site"}],
        }
        with mock.patch.object(queries, "get_public_branding_snapshot", return_value=snapshot):
            result = queries.public_branding()

        expected_groups = {
            "header_identity",
            "footer_identity",
            "footer_identity_row",
            "footer_certifications",
            "footer_recognitions",
            "footer_privacy_credentials",
            "publication_marks",
        }
        self.assertEqual(set(result), expected_groups)
        self.assertEqual(result["header_identity"][0]["id"], "asset-1")
        self.assertNotIn("institution_links", result)
        self.assertNotIn("office_links", result)

    def test_public_branding_sorts_footer_identity_by_safe_metadata(self):
        asset = SimpleNamespace(
            placement=BrandAssetPlacementChoices.FOOTER_IDENTITY,
            usage_context="PUBLIC_FOOTER",
        )
        projected = {"id": "asset-1", "display_order": 1}
        candidates = mock.Mock()
        candidates.select_related.return_value = candidates
        candidates.order_by.return_value = [asset]

        with (
            mock.patch.object(selectors, "_select_authoritative_institution", return_value=None),
            mock.patch.object(selectors, "_select_authoritative_office", return_value=None),
            mock.patch.object(selectors.BrandAsset.objects, "filter", return_value=candidates),
            mock.patch.object(selectors, "_asset_is_effective", return_value=True),
            mock.patch.object(selectors, "_owner_scope_allows_asset", return_value=True),
            mock.patch.object(selectors, "_normalized_usage_context", return_value="LEGACY_FIELD") as legacy_usage,
            mock.patch.object(selectors, "_public_brand_asset_dto", return_value=projected),
        ):
            result = selectors.get_public_brand_assets()

        self.assertEqual(result["footer_identity_row"], [projected])
        legacy_usage.assert_not_called()

    def test_public_branding_omits_ambiguous_privacy_credentials(self):
        assets = [
            SimpleNamespace(placement=BrandAssetPlacementChoices.FOOTER_PRIVACY_CREDENTIALS),
            SimpleNamespace(placement=BrandAssetPlacementChoices.FOOTER_PRIVACY_CREDENTIALS),
        ]
        candidates = mock.Mock()
        candidates.select_related.return_value = candidates
        candidates.order_by.return_value = assets

        with (
            mock.patch.object(selectors, "_select_authoritative_institution", return_value=None),
            mock.patch.object(selectors, "_select_authoritative_office", return_value=None),
            mock.patch.object(selectors.BrandAsset.objects, "filter", return_value=candidates),
            mock.patch.object(selectors, "_asset_is_effective", return_value=True),
            mock.patch.object(selectors, "_owner_scope_allows_asset", return_value=True),
            mock.patch.object(
                selectors,
                "_public_brand_asset_dto",
                side_effect=[
                    {"id": "seal-1", "placement": BrandAssetPlacementChoices.FOOTER_PRIVACY_CREDENTIALS},
                    {"id": "seal-2", "placement": BrandAssetPlacementChoices.FOOTER_PRIVACY_CREDENTIALS},
                ],
            ),
        ):
            result = selectors.get_public_brand_assets()

        self.assertEqual(result["footer_privacy_credentials"], [])

    def test_public_links_only_project_footer_placement(self):
        header = SimpleNamespace(
            placement=PublicLinkPlacementChoices.HEADER,
            owner_type=PublicLinkOwnerChoices.OFFICE,
        )
        footer = SimpleNamespace(
            placement=PublicLinkPlacementChoices.FOOTER,
            owner_type=PublicLinkOwnerChoices.OFFICE,
        )
        candidates = mock.Mock()
        candidates.select_related.return_value = candidates
        candidates.order_by.return_value = [header, footer]
        dto = {
            "label": "Office page",
            "url": "https://example.test/office",
            "owner_type": PublicLinkOwnerChoices.OFFICE,
            "owner_label": "GCO",
            "link_type": "OTHER",
            "placement": PublicLinkPlacementChoices.FOOTER,
            "display_order": 1,
        }

        with (
            mock.patch.object(selectors, "_select_authoritative_institution", return_value=None),
            mock.patch.object(selectors, "_select_authoritative_office", return_value=None),
            mock.patch.object(selectors.PublicLink.objects, "filter", return_value=candidates),
            mock.patch.object(selectors, "_public_link_dto", return_value=dto) as public_link_dto,
        ):
            result = selectors._build_public_links()

        self.assertEqual(result["office_links"], [dto])
        public_link_dto.assert_called_once_with(
            footer,
            institution=None,
            office=None,
        )


class OrganizationResponseContractTests(SimpleTestCase):
    def test_governance_projections_fit_resource_specific_output_schemas(self):
        today = date(2026, 8, 31)
        now = timezone.now()
        institution = SimpleNamespace(
            pk="institution-1",
            legal_name="Example University",
            short_name="EU",
            former_name="Former University",
            former_short_name="FU",
            address="Main campus",
            main_campus="North Campus",
            primary_brand_color="#112233",
            secondary_brand_color="#445566",
            accent_brand_color="#778899",
            version_label="2026.1",
            status="DRAFT",
            effective_from=today,
            effective_until=None,
            source_note="Approved institutional source",
            activated_at=None,
            retired_at=None,
        )
        office = SimpleNamespace(
            pk="office-1",
            institution_id="institution-1",
            office_name="Guidance Office",
            office_short_name="GCO",
            legacy_office_name="Counseling Office",
            document_header_name="Guidance and Counseling Office",
            office_address="Student Services Building",
            contact_email="guidance@example.test",
            contact_number="09170000000",
            office_hours="08:00-17:00",
            default_signatory_name="Head Guidance",
            default_signatory_title="Head Guidance Counselor",
            footer_note="Office footer",
            version_label="2026.1",
            status="ACTIVE",
            effective_from=today,
            effective_until=None,
            source_note="Office source",
            activated_at=now,
            retired_at=None,
        )
        asset = SimpleNamespace(
            pk="asset-1",
            institution_id="institution-1",
            office_id="office-1",
            asset_type="LOGO_FULL",
            semantic_role="IDENTITY",
            owner_type="INSTITUTION",
            placement="HEADER_IDENTITY",
            display_order=1,
            alt_text="Example University logo",
            usage_context="PUBLIC_HEADER",
            background_variant="TRANSPARENT",
            version_label="2026.1",
            status="ACTIVE",
            content_type_hint="image/png",
            image_width=320,
            image_height=80,
            effective_from=today,
            effective_until=None,
            approved_at=now,
            original_filename="private-logo.png",
            credential_reference="private-credential",
            source_note="private source",
            file=object(),
        )
        link = SimpleNamespace(
            pk="link-1",
            owner_type="INSTITUTION",
            institution_id="institution-1",
            office_id=None,
            link_type="WEBSITE",
            label="Institution website",
            url="https://example.test",
            placement="FOOTER",
            display_order=1,
            status="ACTIVE",
            effective_from=today,
            effective_until=None,
        )
        term = SimpleNamespace(
            pk="term-1",
            academic_year="2026-2027",
            semester="First Semester",
            start_date=today,
            end_date=date(2027, 1, 31),
            status="ACTIVE",
            configuration_identifier="academic-term-2026-2027",
            approved_at=now,
            activated_at=now,
            closed_at=None,
        )
        family = SimpleNamespace(
            pk="family-1",
            stable_key="call-slip",
            display_name="Call Slip",
            description="Student appointment call slip",
            owner_office_id="office-1",
            status="ACTIVE",
            current_active_revision_id="revision-1",
        )
        revision = SimpleNamespace(
            pk="revision-1",
            form_family=SimpleNamespace(stable_key="call-slip"),
            form_family_id="family-1",
            official_form_code="CALL-SLIP",
            official_revision="2026.1",
            internal_schema_version="schema-2026.1",
            internal_template_version="template-2026.1",
            display_title="Call Slip",
            institution_profile_id="institution-1",
            office_profile_id="office-1",
            source_label="Approved source",
            effective_from=today,
            effective_until=None,
            status="ACTIVE",
            is_used=False,
            approved_at=now,
            submitted_at=now,
            activated_at=now,
            retired_at=None,
            source_document_reference="private/source.docx",
            source_notes="private notes",
            printable_template_path="private/template.docx",
            source_checksum="private-checksum",
            activation_preflight=None,
        )
        template = SimpleNamespace(
            pk="template-1",
            stable_key="call-slip-document",
            display_name="Call Slip Document",
            document_kind="CALL_SLIP",
            status="ACTIVE",
            default_output_format="PDF",
            retention_classification="OPERATIONAL",
        )

        values = (
            (institution_profile_projection(institution), InstitutionProfileProjectionSchema, InstitutionProfilePageSchema),
            (office_profile_projection(office), OfficeProfileProjectionSchema, OfficeProfilePageSchema),
            (brand_asset_projection(asset), BrandAssetProjectionSchema, BrandAssetPageSchema),
            (public_link_projection(link), PublicLinkProjectionSchema, PublicLinkPageSchema),
            (academic_term_projection(term), AcademicTermProjectionSchema, AcademicTermPageSchema),
            (form_family_projection(family), FormFamilyProjectionSchema, FormFamilyPageSchema),
            (form_revision_projection(revision), FormRevisionProjectionSchema, FormRevisionPageSchema),
            (document_template_projection(template), DocumentTemplateProjectionSchema, DocumentTemplatePageSchema),
        )
        forbidden = {
            "expected_updated_at",
            "reason_code",
            "source_document_reference",
            "source_notes",
            "printable_template_path",
            "source_checksum",
            "original_filename",
            "credential_reference",
            "file",
            "approved_by_id",
            "activated_by_id",
            "retired_by_id",
            "uploaded_by_id",
        }
        for projection, output_schema, page_schema in values:
            with self.subTest(schema=output_schema.__name__):
                self.assertTrue(forbidden.isdisjoint(projection))
                validated = output_schema(**projection)
                self.assertEqual(validated.id, projection["id"])
                page = page_schema(items=[projection], page=1, page_size=25, total=1)
                self.assertEqual(page.items[0].id, projection["id"])

    def test_rollover_and_activation_preflight_are_bounded_nested_outputs(self):
        rollover = AcademicTermRolloverPreviewSchema(
            academic_year="2026-2027",
            semester="First Semester",
            prior_term="2025-2026",
            providers=[
                {"key": "inventory", "status": "READY", "count": 4},
                {"key": "lifecycle_rules", "status": "READY", "count": 0, "reason_code": "METADATA_ONLY_PROVIDER"},
            ],
            rollback={
                "status": "PENDING_REVIEW",
                "condition": "No dependent records may exist.",
                "reference": "academic_term.rollback.runbook",
            },
        )
        self.assertEqual(rollover.providers[1].reason_code, "METADATA_ONLY_PROVIDER")
        self.assertNotIn("prior_term_id", rollover.dict())

        preflight = FormRevisionActivationPreflightSchema(
            ready=False,
            blockers=["DOCUMENT_TEMPLATE_NOT_READY"],
            status="BLOCKED",
            safe_template=False,
        )
        self.assertEqual(preflight.blockers, ["DOCUMENT_TEMPLATE_NOT_READY"])
        revision = FormRevisionProjectionSchema(
            **{
                "id": "revision-1",
                "form_family_id": "family-1",
                "form_family_key": "call-slip",
                "official_form_code": "CALL-SLIP",
                "official_revision": "2026.1",
                "display_title": "Call Slip",
                "status": "APPROVED",
                "effective_from": "2026-08-31",
                "effective_until": None,
                "is_used": False,
                "internal_schema_version": "schema-2026.1",
                "internal_template_version": "template-2026.1",
                "institution_profile_id": "institution-1",
                "office_profile_id": "office-1",
                "source_label": "Approved source",
                "approved_at": "2026-08-31T10:00:00+00:00",
                "submitted_at": None,
                "activated_at": None,
                "retired_at": None,
                "activation_preflight": preflight,
            }
        )
        self.assertFalse(revision.activation_preflight.ready)


class OrganizationApiContractTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.head = User.objects.create_user(
            email="organization-api-head@example.test",
            password="correct-horse-battery-staple",
            first_name="Head",
            last_name="Guidance",
            role=RoleChoices.COUNSELOR,
            is_active=True,
        )
        CounselorProfile.objects.create(user=self.head, is_head_guidance=True)
        self.token = issue_token_pair(self.head, assurance_verified=True).access_token

    def test_institution_mutation_returns_typed_projection_and_replays_identically(self):
        payload = {
            "legal_name": "Example University",
            "short_name": "EU",
            "effective_from": "2026-08-31",
        }
        headers = {
            "HTTP_AUTHORIZATION": f"Bearer {self.token}",
            "HTTP_IDEMPOTENCY_KEY": "organizations-api-institution-1",
        }
        response = self.client.post(
            "/api/v1/organizations/governance/institution-profiles/",
            data=json.dumps(payload),
            content_type="application/json",
            **headers,
        )
        self.assertEqual(response.status_code, 200, response.content)
        result = response.json()
        validated = InstitutionProfileProjectionSchema(**result)
        self.assertEqual(validated.status, "DRAFT")
        self.assertNotIn("expected_updated_at", result)
        self.assertNotIn("reason_code", result)
        self.assertNotIn("approved_by_id", result)

        replay = self.client.post(
            "/api/v1/organizations/governance/institution-profiles/",
            data=json.dumps(payload),
            content_type="application/json",
            **headers,
        )
        self.assertEqual(replay.status_code, 200, replay.content)
        self.assertEqual(replay.json(), result)


class OrganizationNormalizationMigrationTests(SimpleTestCase):
    @staticmethod
    def _historical_apps(*, institution_rows=(), office_rows=(), term_rows=(), family_rows=()):
        class Manager:
            def __init__(self, rows):
                self.rows = rows

            def values(self, *field_names):
                return self

            def iterator(self):
                return iter(self.rows)

        class HistoricalModel:
            def __init__(self, rows):
                self.objects = Manager(rows)

        models = {
            "InstitutionProfile": HistoricalModel(institution_rows),
            "OfficeProfile": HistoricalModel(office_rows),
            "AcademicTerm": HistoricalModel(term_rows),
            "FormFamily": HistoricalModel(family_rows),
        }

        class HistoricalApps:
            def get_model(self, app_label, model_name):
                self.asserted_app_label = app_label
                return models[model_name]

        return HistoricalApps()

    def test_preflight_rejects_nonempty_legacy_values(self):
        migration = importlib.import_module(
            "apps.organizations.migrations.0004_normalize_configuration_fields"
        )
        apps = self._historical_apps(
            institution_rows=[
                {
                    "pk": 7,
                    "logo_image": "organizations/logos/old.png",
                    "seal_image": "",
                    "public_links": [],
                    "effective_date": None,
                }
            ],
            term_rows=[{"pk": 1, "status": "ACTIVE", "is_current": True}],
        )
        with self.assertRaisesRegex(RuntimeError, r"InstitutionProfile\(pk=7\).logo_image"):
            migration.preflight_legacy_configuration_fields(apps, None)

    def test_preflight_accepts_empty_legacy_values_and_consistent_term_status(self):
        migration = importlib.import_module(
            "apps.organizations.migrations.0004_normalize_configuration_fields"
        )
        apps = self._historical_apps(
            institution_rows=[
                {
                    "pk": 7,
                    "logo_image": "",
                    "seal_image": None,
                    "public_links": [],
                    "effective_date": None,
                }
            ],
            office_rows=[{"pk": 8, "header_logo": "", "public_links": []}],
            term_rows=[
                {"pk": 1, "status": "ACTIVE", "is_current": True},
                {"pk": 2, "status": "CLOSED", "is_current": False},
            ],
            family_rows=[{"pk": 9, "future_owning_app": ""}],
        )
        migration.preflight_legacy_configuration_fields(apps, None)


class OrganizationServiceTests(TestCase):
    def setUp(self):
        self.head = User.objects.create_user(
            email="organization-head@example.test",
            password="correct-horse-battery-staple",
            first_name="Head",
            last_name="Guidance",
            role=RoleChoices.COUNSELOR,
            is_active=True,
        )
        CounselorProfile.objects.create(user=self.head, is_head_guidance=True)

    def test_stable_id_service_reloads_and_activates(self):
        profile = create_institution_profile_draft(
            self.head,
            InstitutionProfileDraftCommand(
                legal_name="Example University",
                short_name="EU",
                effective_from=date.today(),
            ),
        )
        self.assertEqual(profile.status, GovernanceStatusChoices.DRAFT)
        activated = activate_institution_profile(
            self.head,
            LifecycleCommand(target_id=str(profile.pk)),
        )
        self.assertEqual(activated.status, GovernanceStatusChoices.ACTIVE)
        self.assertEqual(
            InstitutionProfile.objects.get(pk=profile.pk).status,
            GovernanceStatusChoices.ACTIVE,
        )

    def test_draft_update_rejects_stale_expected_timestamp(self):
        profile = create_institution_profile_draft(
            self.head,
            InstitutionProfileDraftCommand(
                legal_name="Example University",
                short_name="EU",
                effective_from=date.today(),
            ),
        )
        expected = profile.updated_at
        profile.legal_name = "Changed by another workspace"
        profile.save(update_fields=["legal_name", "updated_at"])
        with self.assertRaises(StaleStateError):
            from apps.organizations.services import update_institution_profile_draft

            update_institution_profile_draft(
                self.head,
                str(profile.pk),
                InstitutionProfileDraftCommand(
                    legal_name="Stale update",
                    short_name="EU",
                    expected_updated_at=expected,
                ),
            )

    def test_non_head_cannot_use_governance_mutation(self):
        actor = User.objects.create_user(
            email="organization-counselor@example.test",
            password="correct-horse-battery-staple",
            first_name="Regular",
            last_name="Counselor",
            role=RoleChoices.COUNSELOR,
            is_active=True,
        )
        with self.assertRaises(PermissionDeniedError):
            create_institution_profile_draft(
                actor,
                InstitutionProfileDraftCommand(legal_name="Example University", short_name="EU"),
            )

    def test_public_route_is_anonymous_and_safe(self):
        response = Client().get("/api/v1/organizations/public/identity/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("institution", response.json())
        self.assertIn("X-Request-ID", response.headers)

    def test_public_route_does_not_expose_a_draft_profile(self):
        InstitutionProfile.objects.create(
            legal_name="Draft University",
            short_name="DRAFT",
            status=GovernanceStatusChoices.DRAFT,
            effective_from=date.today(),
        )
        response = Client().get("/api/v1/organizations/public/identity/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["institution"], {})

    def test_public_identity_does_not_fallback_to_global_office(self):
        cache.clear()
        institution = InstitutionProfile.objects.create(
            legal_name="Active University",
            short_name="AU",
            status=GovernanceStatusChoices.ACTIVE,
            effective_from=date.today(),
        )
        global_office = OfficeProfile.objects.create(
            institution=None,
            office_name="Global Guidance Office",
            office_short_name="GGO",
            status=GovernanceStatusChoices.ACTIVE,
            effective_from=date.today(),
        )

        self.assertIsNotNone(institution)
        self.assertIsNotNone(global_office)
        self.assertIsNone(selectors.get_current_office_profile(institution=institution))
        self.assertIsNone(selectors.get_current_office_profile())

        response = Client().get("/api/v1/organizations/public/identity/")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["institution"]["display_name"], "Active University")
        self.assertEqual(payload["office"], {})

    def test_empty_term_and_form_snapshots_are_valid_anonymous_objects(self):
        with (
            mock.patch.object(queries, "get_public_academic_term_snapshot", return_value={}),
            mock.patch.object(queries, "get_public_form_revision_snapshot", return_value={}),
        ):
            term_response = Client().get("/api/v1/organizations/public/academic-term/")
            form_response = Client().get("/api/v1/organizations/public/forms/call-slip/")

        self.assertEqual(term_response.status_code, 200)
        self.assertEqual(term_response.json(), {})
        self.assertEqual(form_response.status_code, 200)
        self.assertEqual(form_response.json(), {})

    def test_active_public_form_revision_uses_wire_schema_alias(self):
        cache.clear()
        family = FormFamily.objects.create(
            stable_key="public-test-form",
            display_name="Public test form",
            status=GovernanceStatusChoices.ACTIVE,
        )
        revision = FormRevision.objects.create(
            form_family=family,
            status="ACTIVE",
            approved_by=self.head,
            approved_at=timezone.now(),
            schema_summary_json={
                "fields": [{
                    "key": "reference",
                    "label": "Reference",
                    "type": "text",
                    "required": True,
                }],
            },
        )
        family.current_active_revision = revision
        family.save(update_fields=["current_active_revision", "updated_at"])

        response = Client().get("/api/v1/organizations/public/forms/public-test-form/")

        self.assertEqual(response.status_code, 200, response.content)
        payload = response.json()
        self.assertEqual(payload["form_family_key"], "public-test-form")
        self.assertEqual(payload["schema"][0]["key"], "reference")
        self.assertNotIn("form_schema", payload)
        self.assertNotIn("is_used", payload)


class OrganizationAssetDeliveryTests(TestCase):
    _PNG_1X1 = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
        "YAAAAAYAAjCB0C8AAAAASUVORK5CYII="
    )

    def test_public_asset_issues_signed_url_and_cdn_cacheable_content(self):
        with tempfile.TemporaryDirectory() as media_root, override_settings(MEDIA_ROOT=media_root):
            institution = InstitutionProfile.objects.create(
                legal_name="Example University",
                short_name="EU",
                status=GovernanceStatusChoices.ACTIVE,
                effective_from=date.today(),
            )
            approver = User.objects.create_user(
                email="brand-approver@example.test",
                password="correct-horse-battery-staple",
                role=RoleChoices.COUNSELOR,
                is_active=True,
            )
            digest = hashlib.sha256(self._PNG_1X1).hexdigest()
            asset = BrandAsset(
                institution=institution,
                asset_type=AssetTypeChoices.LOGO_FULL,
                semantic_role=BrandAssetRoleChoices.IDENTITY,
                owner_type=BrandAssetOwnerChoices.INSTITUTION,
                placement=BrandAssetPlacementChoices.HEADER_IDENTITY,
                usage_context="PUBLIC_HEADER",
                alt_text="Example University identity",
                status=AssetStatusChoices.ACTIVE,
                effective_from=date.today(),
                approved_by=approver,
                approved_at=timezone.now(),
                content_type_hint="image/png",
                file_size_bytes=len(self._PNG_1X1),
                image_width=1,
                image_height=1,
                source_note=f"Approved repository asset; SHA-256: {digest}",
                original_filename="private-original-logo.png",
            )
            asset.file.save(
                "managed-logo.png",
                SimpleUploadedFile("managed-logo.png", self._PNG_1X1, content_type="image/png"),
                save=False,
            )
            asset.save()

            issue = Client().get(f"/api/v1/organizations/public/branding/assets/{asset.pk}/")
            self.assertEqual(issue.status_code, 200)
            self.assertEqual(issue.headers["Cache-Control"], "no-store")
            self.assertEqual(issue.headers["X-Robots-Tag"], "noindex, nofollow, noarchive")
            payload = issue.json()
            self.assertEqual(payload["asset_id"], str(asset.pk))
            self.assertEqual(payload["content_type"], "image/png")
            self.assertNotIn("private-original-logo.png", payload["url"])
            self.assertIn("token=", payload["url"])

            content = Client().get(payload["url"])
            self.assertEqual(content.status_code, 200)
            self.assertEqual(content.headers["Content-Type"], "image/png")
            self.assertTrue(content.headers["Cache-Control"].startswith("public,"))
            self.assertEqual(content.headers["X-Robots-Tag"], "noindex, nofollow, noarchive")
            self.assertEqual(content.headers["X-Content-Type-Options"], "nosniff")
            self.assertNotIn("private-original-logo.png", content.headers["Content-Disposition"])
            self.assertEqual(b"".join(content.streaming_content), self._PNG_1X1)

    def test_public_asset_rejects_unapproved_asset_before_signing(self):
        institution = InstitutionProfile.objects.create(
            legal_name="Example University",
            short_name="EU",
            status=GovernanceStatusChoices.ACTIVE,
            effective_from=date.today(),
        )
        asset = BrandAsset.objects.create(
            institution=institution,
            asset_type=AssetTypeChoices.LOGO_FULL,
            semantic_role=BrandAssetRoleChoices.IDENTITY,
            owner_type=BrandAssetOwnerChoices.INSTITUTION,
            placement=BrandAssetPlacementChoices.HEADER_IDENTITY,
            usage_context="PUBLIC_HEADER",
            alt_text="Unapproved",
            status=AssetStatusChoices.PROVISIONAL,
            effective_from=date.today(),
        )
        response = Client().get(f"/api/v1/organizations/public/branding/assets/{asset.pk}/")
        self.assertEqual(response.status_code, 404)
