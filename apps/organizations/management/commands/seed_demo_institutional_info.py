from datetime import date
import hashlib
from pathlib import Path

from django.conf import settings
from django.core.files import File
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from apps.content.models import (
    Announcement,
    AudienceChoices,
    ContentStatus,
    ContentPage,
    Resource,
    ResourceCategory,
    ResourceType,
)
from apps.content.services import seed_demo_content
from apps.content.commands import ContentSeedCommand
from apps.content.cache import invalidate_public_content_after_commit
from apps.organizations.models import (
    AssetStatusChoices,
    AssetTypeChoices,
    BackgroundVariantChoices,
    BrandAsset,
    BrandAssetOwnerChoices,
    BrandAssetPlacementChoices,
    BrandAssetRoleChoices,
    GovernanceStatusChoices,
    InstitutionProfile,
    OfficeProfile,
    PublicLink,
    PublicLinkOwnerChoices,
    PublicLinkPlacementChoices,
    PublicLinkTypeChoices,
)


class Command(BaseCommand):
    help = "Seed demo institution, office, brand, announcements, and resources."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            default=False,
            help="Preview records that would be created or reused without writing.",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        mode = "DRY-RUN" if dry_run else "LIVE"

        summary = {
            "institution": "skipped",
            "office": "skipped",
            "brand_assets": 0,
            "public_links": 0,
            "about_page": 0,
            "announcements": 0,
            "resources": 0,
        }

        if dry_run:
            self.stdout.write("[DRY-RUN] Would seed demo UCN/GCO institutional profile, public brand asset, About page, announcements, and resources.")
            self.stdout.write(self.style.SUCCESS(f"[{mode}] Summary: {summary}"))
            return

        with transaction.atomic():
            institution, created = InstitutionProfile.objects.update_or_create(
                short_name="UCN",
                defaults={
                    "legal_name": "University of Camarines Norte",
                    "former_name": "Camarines Norte State College",
                    "former_short_name": "CNSC",
                    "address": "Daet, Camarines Norte",
                    "main_campus": "Main Campus, Daet",
                    "primary_brand_color": "#7a1712",
                    "secondary_brand_color": "#d6a536",
                    "transition_note": "Demo profile based on the UCN transition established by Republic Act No. 11399.",
                    "status": GovernanceStatusChoices.ACTIVE,
                    "version_label": "demo-ucn-2026",
                    "effective_from": timezone.localdate(),
                    "source_note": "Demo seed for local COMPASS branding; replace with client-approved profile before deployment.",
                },
            )
            summary["institution"] = "created" if created else "updated"

            office, created = OfficeProfile.objects.update_or_create(
                institution=institution,
                office_short_name="GCO",
                defaults={
                    "office_name": "Guidance and Counseling Office",
                    "legacy_office_name": "Guidance, Testing and Admission Office",
                    "document_header_name": "Guidance and Counseling Office",
                    "office_address": "UCN Main Campus, Daet, Camarines Norte",
                    "office_hours": "Monday to Friday, 8:00 AM to 5:00 PM",
                    "status": GovernanceStatusChoices.ACTIVE,
                    "version_label": "demo-gco-2026",
                    "effective_from": timezone.localdate(),
                    "source_note": "Demo seed for local COMPASS branding; verify contact channels with the office before deployment.",
                },
            )
            summary["office"] = "created" if created else "updated"

            summary["brand_assets"] = self._seed_brand_assets(institution)
            summary["public_links"] = self._seed_public_links(institution)
            summary["about_page"] = self._seed_about_page()
            summary["announcements"] = self._seed_announcements()
            summary["resources"] = self._seed_resources()
            self._retire_superseded_demo_records(institution)

        # The retirement helper uses bulk updates, so model signals cannot
        # observe those rows individually. Rotate the public-content cache
        # only after the whole seed transaction has committed.
        invalidate_public_content_after_commit()

        self.stdout.write(self.style.SUCCESS(f"[{mode}] Summary: {summary}"))

    def _seed_brand_assets(self, institution):
        # The public-facing lockup supplied for the current COMPASS build is
        # the UCN mark alongside the former CNSC mark.  Keep the source name
        # explicit so a missing/replaced asset fails closed instead of silently
        # falling back to an older logo.
        ucn_transition_logo = Path(settings.BASE_DIR) / "static" / "images" / "ucn_cnsc_logo.png"
        seeds = [
            {
                "source": ucn_transition_logo,
                "target": "demo/ucn-cnsc-logo-header.png",
                "asset_type": AssetTypeChoices.PUBLIC_PAGE_LOGO,
                "usage_context": "PUBLIC_HEADER",
                "alt_text": "University of Camarines Norte logo",
                "content_type": "image/png",
                "semantic_role": BrandAssetRoleChoices.IDENTITY,
                "owner_type": BrandAssetOwnerChoices.INSTITUTION,
                "placement": BrandAssetPlacementChoices.HEADER_IDENTITY,
                "display_order": 0,
                "image_width": 149,
                "image_height": 87,
                "provenance_note": "Client-selected UCN/CNSC transition lockup for the COMPASS public header.",
            },
            {
                "source": ucn_transition_logo,
                "target": "demo/ucn-cnsc-logo-footer.png",
                "asset_type": AssetTypeChoices.PUBLIC_PAGE_LOGO,
                "usage_context": "PUBLIC_FOOTER_IDENTITY_ROW",
                "alt_text": "University of Camarines Norte logo",
                "content_type": "image/png",
                "semantic_role": BrandAssetRoleChoices.IDENTITY,
                "owner_type": BrandAssetOwnerChoices.INSTITUTION,
                "placement": BrandAssetPlacementChoices.FOOTER_IDENTITY_ROW,
                "display_order": 10,
                "image_width": 149,
                "image_height": 87,
                "provenance_note": "Client-selected UCN/CNSC transition lockup for the COMPASS public footer.",
            },
            {
                "source": Path(settings.BASE_DIR) / "static" / "images" / "Bagong_Pilipinas_logo.png",
                "target": "demo/bagong-pilipinas.png",
                "asset_type": AssetTypeChoices.PUBLIC_PAGE_LOGO,
                "usage_context": "PUBLIC_FOOTER_IDENTITY_ROW",
                "alt_text": "Bagong Pilipinas collection mark",
                "content_type": "image/png",
                "semantic_role": BrandAssetRoleChoices.CAMPAIGN,
                "owner_type": BrandAssetOwnerChoices.INSTITUTION,
                "placement": BrandAssetPlacementChoices.FOOTER_IDENTITY_ROW,
                "display_order": 20,
                "image_width": 960,
                "image_height": 894,
            },
            {
                "source": Path(settings.BASE_DIR) / "static" / "images" / "cnsc-iso-9001.jpg",
                "target": "demo/cnsc-iso-9001.jpg",
                "asset_type": AssetTypeChoices.PUBLIC_PAGE_LOGO,
                "usage_context": "PUBLIC_FOOTER_IDENTITY_ROW",
                "alt_text": "UCN institutional ISO 9001:2015 certification mark",
                "content_type": "image/jpeg",
                "semantic_role": BrandAssetRoleChoices.CERTIFICATION,
                "owner_type": BrandAssetOwnerChoices.INSTITUTION,
                "placement": BrandAssetPlacementChoices.FOOTER_IDENTITY_ROW,
                "display_order": 30,
                "image_width": 582,
                "image_height": 220,
                "effective_from": date(2024, 12, 18),
                "effective_until": date(2027, 12, 17),
                "verification_url": "https://cnsc.edu.ph/UCN/wp-content/uploads/2024/12/01-100-1834850_Camarines-Norte-State-College_EN.pdf",
                "credential_reference": "ISO 9001:2015; TÜV Rheinland certificate 01 100 1834850/04",
            },
            {
                "source": Path(settings.BASE_DIR) / "static" / "images" / "WURI_Logo.png",
                "target": "demo/wuri.png",
                "asset_type": AssetTypeChoices.PUBLIC_PAGE_LOGO,
                "usage_context": "PUBLIC_FOOTER_IDENTITY_ROW",
                "alt_text": "World University Rankings for Innovation recognition mark",
                "content_type": "image/png",
                "semantic_role": BrandAssetRoleChoices.RECOGNITION,
                "owner_type": BrandAssetOwnerChoices.INSTITUTION,
                "placement": BrandAssetPlacementChoices.FOOTER_IDENTITY_ROW,
                "display_order": 40,
                "image_width": 2851,
                "image_height": 729,
            },
            {
                "source": Path(settings.BASE_DIR) / "static" / "images" / "data-privacy_page-00021.png",
                "target": "demo/dpo-dps-registered.png",
                "asset_type": AssetTypeChoices.SEAL,
                "usage_context": "PUBLIC_FOOTER_PRIVACY_CREDENTIAL",
                "alt_text": "National Privacy Commission DPO/DPS Registered seal, valid through 30 September 2026",
                "content_type": "image/png",
                "semantic_role": BrandAssetRoleChoices.PRIVACY_CREDENTIAL,
                "owner_type": BrandAssetOwnerChoices.INSTITUTION,
                "placement": BrandAssetPlacementChoices.FOOTER_PRIVACY_CREDENTIALS,
                "display_order": 10,
                "image_width": 514,
                "image_height": 485,
                "effective_from": date(2026, 1, 1),
                "effective_until": date(2026, 9, 30),
                "credential_reference": "DPO/DPS Registered",
                "provenance_note": (
                    "Local transparent-canvas normalization applied to the supplied seal; verify against the approved original before deployment. "
                    "DPO/DPS Registered is a privacy registration credential for its named holder; "
                    "it does not certify COMPASS or establish blanket legal compliance."
                ),
            },
        ]
        # Document surfaces intentionally use separate governed records even
        # when they reuse the same committed image.  They remain provisional;
        # this local reconciliation command never manufactures approval.
        seeds.extend([
            {
                "source": ucn_transition_logo,
                "target": "demo/ucn-cnsc-document-header.png",
                "asset_type": AssetTypeChoices.DOCUMENT_HEADER_LOGO,
                "usage_context": "DOCUMENT_PRINT_HEADER",
                "alt_text": "University of Camarines Norte institutional identity",
                "content_type": "image/png",
                "semantic_role": BrandAssetRoleChoices.IDENTITY,
                "owner_type": BrandAssetOwnerChoices.INSTITUTION,
                "placement": BrandAssetPlacementChoices.HEADER_IDENTITY,
                "display_order": 0,
                "image_width": 149,
                "image_height": 87,
                "version_label": "demo-document-shell-2026",
                "provenance_note": "Committed UCN/CNSC identity mark reserved for governed document shells; Head Guidance approval required.",
            },
            {
                "source": Path(settings.BASE_DIR) / "static" / "images" / "Bagong_Pilipinas_logo.png",
                "target": "demo/bagong-pilipinas-document-header.png",
                "asset_type": AssetTypeChoices.PUBLIC_PAGE_LOGO,
                "usage_context": "DOCUMENT_PRINT_HEADER_SECONDARY",
                "alt_text": "Bagong Pilipinas collection mark",
                "content_type": "image/png",
                "semantic_role": BrandAssetRoleChoices.CAMPAIGN,
                "owner_type": BrandAssetOwnerChoices.INSTITUTION,
                "placement": BrandAssetPlacementChoices.HEADER_IDENTITY,
                "display_order": 0,
                "image_width": 960,
                "image_height": 894,
                "version_label": "demo-document-shell-2026",
                "provenance_note": "Committed institutional campaign mark reserved for governed document shells; Head Guidance approval required.",
            },
            {
                "source": ucn_transition_logo,
                "target": "demo/ucn-cnsc-document-footer.png",
                "asset_type": AssetTypeChoices.PUBLIC_PAGE_LOGO,
                "usage_context": "DOCUMENT_PRINT_FOOTER_IDENTITY",
                "alt_text": "University of Camarines Norte institutional identity",
                "content_type": "image/png",
                "semantic_role": BrandAssetRoleChoices.IDENTITY,
                "owner_type": BrandAssetOwnerChoices.INSTITUTION,
                "placement": BrandAssetPlacementChoices.FOOTER_IDENTITY_ROW,
                "display_order": 10,
                "image_width": 149,
                "image_height": 87,
                "version_label": "demo-document-shell-2026",
                "provenance_note": "Committed UCN/CNSC identity mark reserved for governed formal-document footers; Head Guidance approval required.",
            },
            {
                "source": Path(settings.BASE_DIR) / "static" / "images" / "Bagong_Pilipinas_logo.png",
                "target": "demo/bagong-pilipinas-document-footer.png",
                "asset_type": AssetTypeChoices.PUBLIC_PAGE_LOGO,
                "usage_context": "DOCUMENT_PRINT_FOOTER_CAMPAIGN",
                "alt_text": "Bagong Pilipinas collection mark",
                "content_type": "image/png",
                "semantic_role": BrandAssetRoleChoices.CAMPAIGN,
                "owner_type": BrandAssetOwnerChoices.INSTITUTION,
                "placement": BrandAssetPlacementChoices.FOOTER_IDENTITY_ROW,
                "display_order": 20,
                "image_width": 960,
                "image_height": 894,
                "version_label": "demo-document-shell-2026",
                "provenance_note": "Committed institutional campaign mark reserved for governed formal-document footers; Head Guidance approval required.",
            },
            {
                "source": Path(settings.BASE_DIR) / "static" / "images" / "cnsc-iso-9001.jpg",
                "target": "demo/cnsc-iso-9001-document-footer.jpg",
                "asset_type": AssetTypeChoices.PUBLIC_PAGE_LOGO,
                "usage_context": "DOCUMENT_PRINT_FOOTER_CERTIFICATION",
                "alt_text": "UCN institutional ISO 9001:2015 certification mark",
                "content_type": "image/jpeg",
                "semantic_role": BrandAssetRoleChoices.CERTIFICATION,
                "owner_type": BrandAssetOwnerChoices.INSTITUTION,
                "placement": BrandAssetPlacementChoices.FOOTER_IDENTITY_ROW,
                "display_order": 30,
                "image_width": 582,
                "image_height": 220,
                "effective_from": date(2024, 12, 18),
                "effective_until": date(2027, 12, 17),
                "version_label": "demo-document-shell-2026",
                "verification_url": "https://cnsc.edu.ph/UCN/wp-content/uploads/2024/12/01-100-1834850_Camarines-Norte-State-College_EN.pdf",
                "credential_reference": "ISO 9001:2015; TÜV Rheinland certificate 01 100 1834850/04",
                "provenance_note": "Committed certification mark reserved for governed formal-document footers; Head Guidance approval required.",
            },
            {
                "source": Path(settings.BASE_DIR) / "static" / "images" / "WURI_Logo.png",
                "target": "demo/wuri-document-footer.png",
                "asset_type": AssetTypeChoices.PUBLIC_PAGE_LOGO,
                "usage_context": "DOCUMENT_PRINT_FOOTER_RECOGNITION",
                "alt_text": "World University Rankings for Innovation recognition mark",
                "content_type": "image/png",
                "semantic_role": BrandAssetRoleChoices.RECOGNITION,
                "owner_type": BrandAssetOwnerChoices.INSTITUTION,
                "placement": BrandAssetPlacementChoices.FOOTER_IDENTITY_ROW,
                "display_order": 40,
                "image_width": 2851,
                "image_height": 729,
                "version_label": "demo-document-shell-2026",
                "provenance_note": "Committed recognition mark reserved for governed formal-document footers; Head Guidance approval required.",
            },
        ])
        count = 0
        for seed in seeds:
            source = seed["source"]
            if not source.exists():
                continue

            asset = BrandAsset.objects.filter(
                institution=institution,
                usage_context=seed["usage_context"],
                original_filename=source.name,
            ).order_by("pk").first()
            signature_changed = False
            if asset is None:
                asset = BrandAsset(
                    institution=institution,
                    asset_type=seed["asset_type"],
                    usage_context=seed["usage_context"],
                )
                count += 1
            else:
                existing_signature = (
                    asset.asset_type,
                    asset.original_filename,
                    asset.content_type_hint,
                    asset.image_width,
                    asset.image_height,
                    asset.verification_url,
                    asset.credential_reference,
                    asset.placement,
                    asset.semantic_role,
                    asset.owner_type,
                )
                seed_signature = (
                    seed["asset_type"],
                    source.name,
                    seed["content_type"],
                    seed["image_width"],
                    seed["image_height"],
                    seed.get("verification_url", ""),
                    seed.get("credential_reference", ""),
                    seed["placement"],
                    seed["semantic_role"],
                    seed["owner_type"],
                )
                if existing_signature != seed_signature:
                    signature_changed = True
                    # Approval is bound to the exact governed asset
                    # signature.  Never carry approval across a seeded
                    # replacement or semantic reassignment.
                    asset.approved_at = None
                    asset.approved_by = None
                    asset.status = AssetStatusChoices.PROVISIONAL

            asset.alt_text = seed["alt_text"]
            asset.institution = institution
            asset.office = None
            asset.asset_type = seed["asset_type"]
            asset.semantic_role = seed["semantic_role"]
            asset.owner_type = seed["owner_type"]
            asset.placement = seed["placement"]
            asset.display_order = seed["display_order"]
            asset.background_variant = BackgroundVariantChoices.TRANSPARENT
            # Preserve a genuine approval on an unchanged asset. New or
            # changed assets remain unlinked until Head Guidance reviews
            # the replacement.
            if asset.pk is None or signature_changed:
                asset.status = AssetStatusChoices.PROVISIONAL
            asset.version_label = seed.get("version_label", "demo-public-brand-2026")
            source_size = source.stat().st_size
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            asset.source_note = (
                f"Demo seed from static/images/{source.name}; SHA-256: {digest}; "
                f"size: {source_size} bytes; dimensions: {seed['image_width']}x{seed['image_height']}; "
                "source reviewed 2026-08-12; unlinked local development projection only; "
                f"{seed.get('provenance_note', 'Replace with an approved governed brand asset before deployment.')}"
            )
            asset.content_type_hint = seed["content_type"]
            asset.original_filename = source.name
            asset.file_size_bytes = source_size
            asset.image_width = seed["image_width"]
            asset.image_height = seed["image_height"]
            asset.effective_from = seed.get("effective_from")
            asset.effective_until = seed.get("effective_until")
            asset.verification_url = seed.get("verification_url", "")
            asset.credential_reference = seed.get("credential_reference", "")

            with source.open("rb") as handle:
                asset.file.save(seed["target"], File(handle), save=False)
            asset.save()
        return count

    def _seed_public_links(self, institution):
        """Seed only verified institution-owned demo destinations.

        These rows are active for the local demo projection, but intentionally
        have no approver.  Production selectors require real approval metadata.
        """
        seeds = [
            {
                "label": "Official UCN website",
                "url": "https://ucn.edu.ph/UCN/",
                "link_type": PublicLinkTypeChoices.WEBSITE,
            },
            {
                "label": "About UCN",
                "url": "https://ucn.edu.ph/UCN/main-home-page-copy/about-ucn/",
                "link_type": PublicLinkTypeChoices.WEBSITE,
            },
            {
                "label": "UCN Data Privacy Notice",
                "url": "https://ucn.edu.ph/UCN/data-privacy-notice/",
                "link_type": PublicLinkTypeChoices.POLICY,
            },
            {
                "label": "UCN SIAS",
                "url": "https://eservices.ucn.edu.ph/",
                "link_type": PublicLinkTypeChoices.SERVICE,
            },
            {
                "label": "UCN official Facebook page",
                "url": "https://www.facebook.com/UCNofficial",
                "link_type": PublicLinkTypeChoices.OTHER,
            },
        ]
        count = 0
        source_note = (
            "Demo seed from official UCN public navigation; destination supplied for privacy.credential_readiness; "
            "local development projection only; verify ownership and approval before deployment."
        )
        for display_order, seed in enumerate(seeds):
            link = PublicLink.objects.filter(
                owner_type=PublicLinkOwnerChoices.INSTITUTION,
                institution=institution,
                office__isnull=True,
                label=seed["label"],
            ).order_by("pk").first()
            if link is None:
                link = PublicLink(
                    owner_type=PublicLinkOwnerChoices.INSTITUTION,
                    institution=institution,
                    label=seed["label"],
                    status=GovernanceStatusChoices.ACTIVE,
                )
                count += 1
            elif link.url.rstrip("/") != seed["url"].rstrip("/"):
                # A public-link approval is destination-bound.  Changing the
                # URL must return the row to the local demo-only projection.
                link.approved_at = None
                link.approved_by = None
                link.status = GovernanceStatusChoices.DRAFT

            link.office = None
            link.link_type = seed["link_type"]
            link.url = seed["url"]
            link.placement = PublicLinkPlacementChoices.FOOTER
            link.display_order = display_order
            link.effective_from = timezone.localdate()
            link.effective_until = None
            link.source_note = source_note
            # Do not manufacture approval metadata for the demo seed.  A
            # genuine approval is preserved only when the governed signature
            # and destination remain unchanged.
            link.save()
        return count

    def _seed_about_page(self):
        _, created = seed_demo_content(
            ContentPage,
            ContentSeedCommand(
                page_key="about",
                title="About COMPASS",
                summary="A private, student-centered space for Guidance and Counseling services at the University of Camarines Norte.",
                body_markdown="## A place to start\n\nCOMPASS is the digital service space of the Guidance and Counseling Office. It helps students, counselors, and authorized staff keep the next step visible—from requesting an appointment to completing required guidance forms.\n\nYou can read the public service guide without signing in. Sign in when you need to view a personal status, submit a request, or continue a form. Some invitations, such as Graduate Tracer or Exit Interview forms, may use a controlled link instead of a regular student account.\n\n## What you can do here\n\n- learn what the office offers and how to access it;\n- request and keep track of counseling appointments;\n- complete the Individual Inventory and other guidance forms;\n- follow graduating-student requirements such as Exit Interview, Graduate Tracer, and Good Moral requests; and\n- find announcements, resources, privacy information, and a safe way to ask where to start.\n\n## The Guidance and Counseling Office\n\nThe GCO supports students across UCN's colleges and programs. A counselor may help you make sense of a concern, plan a next step, or connect you with the right office or support. You do not need to have the perfect words before asking for help.\n\nCOMPASS supports the office's work; it does not replace a conversation with a counselor. For an urgent concern, use **Urgent Student Support** in the portal. If someone is in immediate danger, contact local emergency services or go to the nearest emergency facility.\n\n## About UCN\n\nCOMPASS is built for the University of Camarines Norte, formerly Camarines Norte State College. Visit the [official UCN website](https://ucn.edu.ph/UCN/) for university-wide information, offices, and institutional announcements.\n\n## Privacy matters\n\nCounseling conversations and student records are not public. COMPASS uses controlled access, audit trails, and governed content so that public information stays separate from personal records. Read the [UCN Data Privacy Notice](https://ucn.edu.ph/UCN/data-privacy-notice/) for the institution-wide privacy information.",
                status=ContentStatus.PUBLISHED,
                audience=AudienceChoices.PUBLIC,
            ),
        )
        return int(created)

    def _seed_announcements(self):
        seeds = [
            {
                "slug": "gco-welcome-ay-2026-2027",
                "title": "Welcome to A.Y. 2026–2027",
                "summary": "A new school year can feel exciting, busy, or a little overwhelming. The Guidance and Counseling Office is here when you need a place to begin.",
                "body_markdown": "Whether you are finding your way around campus, adjusting to a new workload, or simply have something on your mind, you do not need to wait for a crisis before reaching out.\n\nYou can sign in to COMPASS to:\n\n- request an in-person or online counseling appointment;\n- check an assigned session and its next step; and\n- review the forms and services available to you.\n\nIf you are not sure which option fits, start with the service guide or send a general inquiry through **Contact and help**. For an urgent student concern, use **Urgent Student Support** or contact the office directly during office hours.",
                "featured": True,
            },
            {
                "slug": "graduating-students-start-guidance-requirements-early",
                "title": "Graduating students: start your guidance requirements early",
                "summary": "If you are preparing for graduation, give yourself time to complete the guidance steps and check what still needs attention.",
                "body_markdown": "Depending on your graduation checklist, you may need to complete an Exit Interview, Graduate Tracer, or Good Moral request. Open your portal to see your own status and the next step.\n\nIf you need a Good Moral Certificate, submit the request through COMPASS, follow the payment and claiming instructions, and keep your reference details. Cashier and Registrar checkpoints are separate from the Guidance and Counseling Office request.\n\nPlease avoid submitting the same request again while one is still being processed. If something does not look right, contact the GCO so the office can help you sort it out.",
                "featured": False,
            },
            {
                "slug": "gco-appointments-and-e-counseling",
                "title": "Need to talk with someone? Start with an appointment",
                "summary": "Request an in-person or online counseling session from your COMPASS account and keep an eye on the appointment status.",
                "body_markdown": "Choose a schedule you can attend and tell us a little about what you need. The office will review the request and your portal will show the next step.\n\nFor an online session, join only within the scheduled window. An expired session cannot be reopened as a live room, so request a new schedule if you still need support. If you miss an appointment, you can ask for another available slot.\n\nCounseling conversations are handled with care and according to the office's privacy and safety procedures.",
                "featured": False,
            },
        ]
        count = 0
        for seed in seeds:
            _, created = seed_demo_content(
                Announcement,
                ContentSeedCommand(
                    slug=seed["slug"],
                    title=seed["title"],
                    summary=seed["summary"],
                    body_markdown=seed["body_markdown"],
                    status=ContentStatus.PUBLISHED,
                    audience=AudienceChoices.PUBLIC,
                    featured=seed["featured"],
                    dashboard_preview_enabled=True,
                ),
            )
            if created:
                count += 1
        return count

    def _seed_resources(self):
        seeds = [
            {
                "slug": "how-to-access-services",
                "title": "How to Access Services",
                "summary": "A plain-language starting point for appointments, counseling forms, document requests, and graduating-student requirements.",
                "body_markdown": "## Start here\n\nUse this guide to identify the service you need and the information to prepare. Public pages explain what each service is for; sign in to see your own status, submit a request, or continue a form.\n\n## Official Citizen’s Charter / Service Standards\n\nThis is the office's reference point for who may request a service, what to prepare, where an external step applies, and how to follow up. Processing times, fees, and release or claiming steps follow the office-approved version for that service.\n\n## Before you submit\n\n- Read the service instructions before starting.\n- Use your own account and check that your contact details are current.\n- Keep the confirmation number or receipt shown after submission.\n- If you are unsure, ask before submitting another request.\n\nFor a personal concern, use the signed-in portal. For a general question, use **Contact and help**.",
                "category": ResourceCategory.GUIDELINES,
            },
            {
                "slug": "graduating-student-preparation-guide",
                "title": "Graduating student preparation guide",
                "summary": "A practical checklist for students completing guidance requirements before graduation.",
                "body_markdown": "## Check your portal\n\nLook for the forms or invitations assigned to you. Depending on your program and graduation schedule, these may include:\n\n- an Exit Interview;\n- a Graduate Tracer response; and\n- a Good Moral request, if you need a certificate.\n\n## Before visiting the office\n\nFinish the online step first when the service asks you to do so. Save your confirmation or reference number, prepare a valid school or government ID if requested, and check the office instructions for claiming or follow-up. Payment and Registrar steps are handled by the responsible office, even when the request is tracked in COMPASS.\n\nIf your status is missing, stuck, or incorrect, contact the GCO instead of creating a duplicate submission.",
                "category": ResourceCategory.GENERAL,
            },
            {
                "slug": "privacy-and-counseling-records",
                "title": "Your privacy and counseling records",
                "summary": "What you share with the Guidance and Counseling Office is handled within privacy, safety, and records-management rules.",
                "body_markdown": "COMPASS asks for information needed to provide a service, keep an accurate record, and support safe follow-up. Access to counseling records is limited to authorized personnel and is logged.\n\nBefore submitting a form, read the privacy notice and the consent or information sheet shown for that service. The UCN Data Privacy Notice provides the institution-wide explanation of how personal data is handled:\n\n[Read the UCN Data Privacy Notice](https://ucn.edu.ph/UCN/data-privacy-notice/)\n\nIf you have a privacy question or want to clarify how a record is used, contact the office through the available help channel. Please do not include sensitive details in a public inquiry unless the form asks for them.",
                "category": ResourceCategory.GUIDELINES,
            },
            {
                "slug": "urgent-student-support-guide",
                "title": "If you need help right now",
                "summary": "Use the quickest safe option for an urgent concern, and keep public inquiries free of sensitive details.",
                "body_markdown": "COMPASS is not an emergency dispatch service. If someone is in immediate danger, contact local emergency services or go to the nearest emergency facility.\n\nFor an urgent but non-life-threatening student concern, use **Urgent Student Support** in the portal or contact the Guidance and Counseling Office during office hours. Share only what the office needs to understand the concern; the counselor can ask for more information in a private channel.\n\nIf you are not sure where to start, a general inquiry is okay. We will help point you to the right next step.",
                "category": ResourceCategory.GENERAL,
            },
        ]
        count = 0
        for seed in seeds:
            _, created = seed_demo_content(
                Resource,
                ContentSeedCommand(
                    slug=seed["slug"],
                    title=seed["title"],
                    summary=seed["summary"],
                    body_markdown=seed["body_markdown"],
                    category=seed["category"],
                    status="published",
                    audience=AudienceChoices.PUBLIC,
                    resource_type=ResourceType.PAGE,
                ),
            )
            if created:
                count += 1
        return count

    def _retire_superseded_demo_records(self, institution):
        Announcement.objects.filter(
            slug__in=("ucn-transition-compass-demo", "guidance-services-public-reminder")
        ).update(status=ContentStatus.ARCHIVED)
        Resource.objects.filter(
            slug__in=("guidance-services-guide", "office-contact-guide", "quality-management-note")
        ).update(status=ContentStatus.ARCHIVED)
        PublicLink.objects.filter(
            owner_type=PublicLinkOwnerChoices.INSTITUTION,
            institution=institution,
            office__isnull=True,
            label="Official CNSC/UCN Facebook page",
        ).update(status=GovernanceStatusChoices.ARCHIVED)
        BrandAsset.objects.filter(
            institution=institution,
            source_note__startswith="Demo seed from static/images/",
            usage_context__in=(
                "PUBLIC_FOOTER_LOGO",
                "PUBLIC_FOOTER_CERTIFICATION",
                "PUBLIC_HEADER",
                "PUBLIC_FOOTER_IDENTITY_ROW",
            ),
            original_filename="ucn-logo.png",
        ).update(
            status=AssetStatusChoices.RETIRED,
            retired_at=timezone.now(),
        )
        BrandAsset.objects.filter(
            institution=institution,
            source_note__startswith="Demo seed from static/images/",
            usage_context="PUBLIC_FOOTER_PRIVACY_CREDENTIAL",
            original_filename="data-privacy_page-00021.jpg",
        ).update(
            status=AssetStatusChoices.RETIRED,
            retired_at=timezone.now(),
        )
        # Older runs placed the ISO mark in a separate certification slot;
        # the current governed identity row already contains that same mark.
        # Retire the legacy duplicate so reruns cannot reintroduce a second
        # Certifications section in the public footer.
        BrandAsset.objects.filter(
            institution=institution,
            source_note__startswith="Demo seed from static/images/",
            usage_context="PUBLIC_FOOTER_CERTIFICATION",
            original_filename="cnsc-iso-9001.jpg",
        ).update(
            status=AssetStatusChoices.RETIRED,
            retired_at=timezone.now(),
        )
