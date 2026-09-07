"""Focused tests for the Content vertical API and domain boundary."""

import os
from datetime import date, datetime
from types import SimpleNamespace
from unittest import mock

from cryptography.fernet import Fernet
from django.core.cache import cache
from django.test import Client, SimpleTestCase, TestCase

from apps.account_security.api_tokens import issue_token_pair
from apps.accounts.models import RoleChoices, User
from apps.common.exceptions import PermissionDeniedError
from apps.content.api import (
    ContactDeliveryMetadataResultSchema,
    ContactDetailSchema,
    ContactMetadataPageSchema,
    ContactNoResponseProjectionSchema,
    ContactReplyPageSchema,
    ContactReplySchema,
    ContentWorkspacePageSchema,
    ContentWorkspaceProjectionSchema,
    ContentWorkspaceReplaySchema,
    ContactSubmissionCreateSchema,
)
from apps.content.commands import (
    AnnouncementCreateCommand,
    AnnouncementUpdateCommand,
    ServiceGuideCreateCommand,
)
from apps.content.models import (
    Announcement,
    AudienceChoices,
    ContentStatus,
    TargetScopeChoices,
)
from apps.content.services import create_announcement, update_announcement
from apps.content.projections import (
    project_contact_reply,
    project_contact_submission_detail,
    project_contact_submission_metadata,
    project_content_workspace_item,
    project_no_response_disposition,
    project_public_service_guide,
)
from apps.content.service_guide import (
    GUIDE_CONFIRMATION_FIELDS,
    SERVICE_GUIDE_ENTRIES,
    get_public_service_guide_context,
)
from apps.profiles.models import CounselorProfile
from apps.security.models import EncryptionKeyVersion, KeyPurposeChoices, KeyStatusChoices


def make_user(email, role, *, active=True, superuser=False):
    actor = User.objects.create_user(
        email=email,
        password="correct-horse-battery-staple",
        first_name="Content",
        last_name="Tester",
        role=role,
        is_active=active,
    )
    if superuser:
        actor.is_superuser = True
        actor.save(update_fields=["is_superuser"])
    return actor


class ContentTypedCommandContractTests(SimpleTestCase):
    def test_commands_are_explicit_and_do_not_accept_arbitrary_mappings(self):
        with self.assertRaises(TypeError):
            AnnouncementCreateCommand(
                slug="notice",
                title="Notice",
                summary="Summary",
                body_markdown="Body",
                unsupported_field="must-not-cross-boundary",
            )

    def test_service_guide_command_copies_mutable_input(self):
        entries = [{"key": "good_moral", "fields": {}}]
        command = ServiceGuideCreateCommand(version_label="2026.1", entries_json=entries)
        entries.append({"key": "unexpected"})
        self.assertEqual(len(command.entries_json), 1)


class ContentPublicContractTests(SimpleTestCase):
    def test_contact_request_schema_has_bounded_enums_and_lengths(self):
        payload = ContactSubmissionCreateSchema(
            submission_type="concern",
            affiliation="parent",
            name="A parent",
            email="parent@example.test",
            phone="+63 917 000 0000",
            subject="A bounded subject",
            message_body="A message",
            privacy_acknowledged=True,
            urgent_support_disclaimer_acknowledged=True,
        )
        self.assertEqual(payload.submission_type, "concern")
        self.assertEqual(payload.affiliation, "parent")

        with self.assertRaises(Exception):
            ContactSubmissionCreateSchema(
                submission_type="unsupported",
                subject="A subject",
                privacy_acknowledged=True,
                urgent_support_disclaimer_acknowledged=True,
            )
        with self.assertRaises(Exception):
            ContactSubmissionCreateSchema(
                subject="",
                privacy_acknowledged=True,
                urgent_support_disclaimer_acknowledged=True,
            )
        with self.assertRaises(Exception):
            ContactSubmissionCreateSchema(
                subject="A subject",
                message_body="x" * 32_769,
                privacy_acknowledged=True,
                urgent_support_disclaimer_acknowledged=True,
            )

    def test_service_guide_projection_keeps_current_metadata_and_iso_date(self):
        result = project_public_service_guide({
            "guide_key": "public-service-guide",
            "title": "Official guide",
            "summary": "Safe summary",
            "version_label": "2026.1",
            "effective_date": date(2026, 8, 28),
            "owner_office": "Guidance Office",
            "publication_state": "Published",
            "has_approved_revision": True,
            "readiness": {"official": True},
            "entries": [],
            "status": "stale-internal-key",
            "published_at": "stale-internal-key",
            "body_html": "must-not-cross-boundary",
        })

        self.assertEqual(result["effective_date"], "2026-08-28")
        self.assertEqual(result["owner_office"], "Guidance Office")
        self.assertEqual(result["publication_state"], "Published")
        self.assertTrue(result["has_approved_revision"])
        self.assertNotIn("status", result)
        self.assertNotIn("published_at", result)
        self.assertNotIn("body_html", result)

    def test_pending_service_guide_is_explicitly_not_official(self):
        with (
            mock.patch(
                "apps.content.service_guide._revision_source",
                return_value=(None, None),
            ),
            mock.patch(
                "apps.documents.governance.resolve_document_readiness",
                return_value=SimpleNamespace(label="PREVIEW — PENDING APPROVAL", is_official=False),
            ),
        ):
            result = get_public_service_guide_context()

        self.assertFalse(result["has_approved_revision"])
        self.assertFalse(result["readiness"]["official"])
        self.assertEqual(result["readiness"]["display_state"], "Service guide is not yet available")
        self.assertTrue(result["readiness"]["missing_fields"])

    def test_approved_service_guide_exposes_confirmed_nested_content(self):
        owner_office = SimpleNamespace(office_name="Guidance Office")
        entries = [
            {
                "key": definition.key,
                "fields": {
                    key: {
                        "value": f"Confirmed {key}",
                        "confirmed": True,
                        "owner": "Guidance Office",
                    }
                    for key, _ in GUIDE_CONFIRMATION_FIELDS
                },
                "steps": [
                    {
                        "key": "step-1",
                        "label": "Submit",
                        "description": "Submit through the approved channel.",
                        "boundary": "COMPASS intake",
                    }
                ],
            }
            for definition in SERVICE_GUIDE_ENTRIES
        ]
        guide = SimpleNamespace(
            version_label="2026.1",
            effective_date=date(2026, 8, 28),
            owner_office_id=1,
            owner_office=owner_office,
            entries_json=entries,
        )
        revision = SimpleNamespace(
            snapshot={
                "summary": "Approved summary",
                "version_label": "2026.1",
                "effective_date": "2026-08-28",
                "entries_json": entries,
                "readiness_metadata_json": {},
            },
            status="published",
        )

        with (
            mock.patch(
                "apps.content.service_guide._revision_source",
                return_value=(guide, revision),
            ),
            mock.patch(
                "apps.documents.governance.resolve_document_readiness",
                return_value=SimpleNamespace(label="OFFICIAL", is_official=True),
            ),
        ):
            result = get_public_service_guide_context()

        self.assertTrue(result["has_approved_revision"])
        self.assertTrue(result["readiness"]["official"])
        self.assertEqual(result["owner_office"], "Guidance Office")
        self.assertEqual(result["effective_date"], "2026-08-28")
        self.assertEqual(result["entries"][0]["fields"]["contact"]["confirmed"], True)
        self.assertEqual(result["entries"][0]["steps"][0]["label"], "Submit")


class ContentResponseContractTests(SimpleTestCase):
    def test_workspace_projection_and_replay_are_bounded(self):
        now = datetime(2026, 8, 31, 9, 30, 0)
        item = SimpleNamespace(
            pk="content-1",
            title="Workspace announcement",
            summary="Safe summary",
            status="draft",
            audience="public",
            target_scope_mode="ORGANIZATION",
            target_campus="Main Campus",
            target_college="CCMS",
            target_department=None,
            target_program=None,
            publish_start=None,
            publish_end=None,
            published_at=None,
            updated_at=now,
            created_at=now,
            featured=True,
            slug="workspace-announcement",
            page_key=None,
            guide_key=None,
            category=None,
            resource_type=None,
            external_url=None,
            body_markdown="Safe source copy",
            version_label=None,
            effective_date=None,
            owner_office_id=None,
            entries_json=[
                {
                    "key": "service",
                    "summary": "Service summary",
                    "description": "Service description",
                    "owner": "Guidance Office",
                    "fields": {
                        "contact": {
                            "label": "Contact",
                            "value": "contact@example.test",
                            "confirmed": True,
                            "owner": "Guidance Office",
                            "metadata_json": "must-not-cross-boundary",
                        },
                    },
                    "steps": [
                        {
                            "key": "submit",
                            "label": "Submit",
                            "description": "Submit the request.",
                            "boundary": "COMPASS intake",
                            "internal_note": "must-not-cross-boundary",
                        },
                    ],
                    "metadata_json": "must-not-cross-boundary",
                },
            ],
        )
        review = SimpleNamespace(
            pk="revision-1",
            revision_number=2,
            status="review",
            created_at=now,
            reviewed_at=None,
            published_at=None,
            body_markdown="Revision source copy",
        )

        projection = project_content_workspace_item(
            item,
            content_type="announcement",
            effective_status="review",
            latest_review=review,
        )
        self.assertEqual(
            set(projection),
            {
                "id", "content_type", "title", "summary", "status", "effective_status",
                "audience", "publish_start", "publish_end", "published_at", "updated_at",
                "created_at", "featured", "target", "slug", "page_key", "guide_key",
                "category", "resource_type", "external_url", "body_markdown", "version_label",
                "effective_date", "owner_office_id", "entries_json", "latest_review",
            },
        )
        validated = ContentWorkspaceProjectionSchema(**projection)
        self.assertEqual(validated.target.target_scope_mode, "ORGANIZATION")
        self.assertEqual(validated.latest_review.revision_number, 2)
        self.assertEqual(validated.entries_json[0].fields.contact.value, "contact@example.test")
        self.assertNotIn("metadata_json", validated.dict())
        self.assertNotIn("metadata_json", validated.dict()["entries_json"][0])
        self.assertNotIn("internal_note", validated.dict()["entries_json"][0]["steps"][0])

        replay = ContentWorkspaceReplaySchema(
            id="content-1",
            content_type="announcement",
            title="Workspace announcement",
            status="draft",
            slug="workspace-announcement",
            page_key=None,
            guide_key=None,
            updated_at=now.isoformat(),
        )
        self.assertNotIn("expected_updated_at", replay.dict())
        ContentWorkspacePageSchema(
            items=[projection],
            page=1,
            page_size=25,
            total=1,
        )

    def test_contact_projections_and_pages_keep_sensitive_fields_bounded(self):
        now = datetime(2026, 8, 31, 10, 0, 0)
        submission = SimpleNamespace(
            pk="contact-1",
            reference_code="CNT-2026-0001",
            created_at=now,
            updated_at=now,
            status="new",
            priority="normal",
            submission_type="inquiry",
            affiliation="student",
            assigned_to_id=7,
            name="A Student",
            email="student@example.test",
            phone="09170000000",
            subject="Question",
            privacy_acknowledged=True,
            urgent_support_disclaimer_acknowledged=False,
            privacy_actioned_at=None,
            get_message_body_for_staff=lambda: "Private message body",
        )
        metadata = project_contact_submission_metadata(submission)
        detail = project_contact_submission_detail(submission)
        self.assertEqual(
            set(metadata),
            {
                "id", "reference_code", "created_at", "updated_at", "status", "priority",
                "submission_type", "affiliation", "assigned_to_id",
            },
        )
        self.assertEqual(
            set(detail),
            set(metadata) | {
                "name", "email", "phone", "subject", "message_body",
                "privacy_acknowledged", "urgent_support_disclaimer_acknowledged",
                "privacy_actioned_at",
            },
        )
        self.assertNotIn("message_body_encrypted", detail)
        self.assertNotIn("metadata_json", detail)
        ContactDetailSchema(**metadata)
        self.assertEqual(ContactDetailSchema(**detail).message_body, "Private message body")
        ContactMetadataPageSchema(items=[metadata], page=1, page_size=25, total=1)

        reply = SimpleNamespace(
            pk="reply-1",
            submission_id="contact-1",
            status="draft",
            created_at=now,
            updated_at=now,
            approved_at=None,
            delivery_state="",
            evidence_scope="local_backend",
            evidence_recorded_at=None,
            sent_at=None,
            last_failure_code="",
            get_body_for_send=lambda: "Private reply body",
        )
        reply_projection = project_contact_reply(reply, include_body=True)
        ContactReplySchema(**reply_projection)
        ContactReplyPageSchema(items=[reply_projection], page=1, page_size=25, total=1)
        self.assertNotIn("recipient_channel_hash", reply_projection)
        self.assertNotIn("approval_evidence_json", reply_projection)

        disposition = SimpleNamespace(
            pk="disposition-1",
            submission_id="contact-1",
            reason_code="informational_only",
            created_at=now,
        )
        no_response = project_no_response_disposition(disposition)
        self.assertEqual(
            set(no_response), {"id", "submission_id", "reason_code", "created_at"},
        )
        ContactNoResponseProjectionSchema(**no_response)

    def test_delivery_metadata_uses_fixed_counts_and_item_schema(self):
        payload = {
            "counts": {"sent": 2, "failed": 1},
            "items": [
                {
                    "delivery_state": "sent",
                    "status": "sent",
                    "created_at": "2026-08-31T10:00:00+00:00",
                    "sent_at": "2026-08-31T10:00:01+00:00",
                    "provider_status_updated_at": None,
                    "recipient_email": "must-not-cross-boundary",
                },
            ],
            "page": 1,
            "page_size": 25,
            "total": 1,
        }
        validated = ContactDeliveryMetadataResultSchema(**payload)
        self.assertEqual(validated.counts.sent, 2)
        self.assertEqual(validated.items[0].delivery_state, "sent")
        self.assertNotIn("recipient_email", validated.dict()["items"][0])


class ContentDomainBoundaryTests(TestCase):
    def setUp(self):
        self.head = make_user("content-head@example.test", RoleChoices.COUNSELOR)
        CounselorProfile.objects.create(user=self.head, is_head_guidance=True)
        self.counselor = make_user("content-counselor@example.test", RoleChoices.COUNSELOR)

    def announcement_command(self, **overrides):
        values = {
            "slug": "domain-announcement",
            "title": "Domain announcement",
            "summary": "Safe summary",
            "body_markdown": "Safe body",
        }
        values.update(overrides)
        return AnnouncementCreateCommand(**values)

    def test_mutations_use_stable_target_id_and_require_target_authority(self):
        announcement = create_announcement(self.head, self.announcement_command())
        updated = update_announcement(
            self.head,
            announcement.pk,
            AnnouncementUpdateCommand(title="Updated title"),
        )
        self.assertEqual(updated.title, "Updated title")
        with self.assertRaises(PermissionDeniedError):
            update_announcement(
                self.counselor,
                announcement.pk,
                AnnouncementUpdateCommand(title="Unauthorized"),
            )

    def test_inactive_and_legacy_actors_cannot_mutate_content(self):
        inactive = make_user(
            "inactive-content@example.test", RoleChoices.COUNSELOR, active=False,
        )
        legacy = make_user(
            "legacy-content@example.test", RoleChoices.COUNSELOR, superuser=True,
        )
        command = self.announcement_command(slug="blocked-announcement")
        for actor in (inactive, legacy):
            with self.subTest(actor=actor.email):
                with self.assertRaises(PermissionDeniedError):
                    create_announcement(actor, command)


class ContentApiTests(TestCase):
    def setUp(self):
        cache.clear()
        self._encryption_key_patcher = mock.patch.dict(
            os.environ,
            {"COMPASS_TEST_FIELD_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii")},
        )
        self._encryption_key_patcher.start()
        self.addCleanup(self._encryption_key_patcher.stop)
        EncryptionKeyVersion.objects.create(
            key_version="content-api-test-v1",
            key_purpose=KeyPurposeChoices.FIELD_ENCRYPTION,
            status=KeyStatusChoices.ACTIVE,
            source_alias="env",
            secret_reference="COMPASS_TEST_FIELD_ENCRYPTION_KEY",
            algorithm="Fernet",
        )
        self.client = Client()
        self.head = make_user("content-api-head@example.test", RoleChoices.COUNSELOR)
        CounselorProfile.objects.create(user=self.head, is_head_guidance=True)
        self.token = issue_token_pair(self.head, assurance_verified=True).access_token

    def tearDown(self):
        cache.clear()

    def auth_headers(self):
        return {"HTTP_AUTHORIZATION": f"Bearer {self.token}"}

    def test_anonymous_contact_submission_uses_compass_privacy_and_safe_receipt(self):
        message = "I would like to ask about the office process."
        payload = {
            "submission_type": "inquiry",
            "name": "A Student",
            "email": "student@example.test",
            "phone": "+63 917 000 0000",
            "affiliation": "student",
            "subject": "Office process question",
            "message_body": message,
            "privacy_acknowledged": True,
            "urgent_support_disclaimer_acknowledged": True,
        }
        with (
            mock.patch("apps.content.services._notify_staff_of_submission") as notify,
            mock.patch(
                "apps.orchestration.use_cases.record_privacy_acceptance_for_composition"
            ) as record_privacy,
        ):
            response = self.client.post(
                "/api/v1/content/contact-submissions/",
                data=payload,
                content_type="application/json",
                HTTP_IDEMPOTENCY_KEY="public-contact-test-001",
            )

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(
            set(response.json()), {"id", "reference_code", "status", "created_at"}
        )
        self.assertNotIn(message, response.content.decode())
        notify.assert_called_once()
        privacy_command = record_privacy.call_args.args[1]
        self.assertEqual(privacy_command.notice_identifier, "compass-gco-privacy")
        self.assertEqual(privacy_command.purpose_workflow, "compass_public")

    def test_anonymous_contact_submission_rejects_missing_disclaimer_and_oversized_fields(self):
        base_payload = {
            "subject": "A subject",
            "privacy_acknowledged": True,
            "urgent_support_disclaimer_acknowledged": False,
        }
        response = self.client.post(
            "/api/v1/content/contact-submissions/",
            data=base_payload,
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 422, response.content)

        oversized = {
            **base_payload,
            "urgent_support_disclaimer_acknowledged": True,
            "message_body": "x" * 32_769,
        }
        response = self.client.post(
            "/api/v1/content/contact-submissions/",
            data=oversized,
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 422, response.content)

        utf8_oversized = {
            **base_payload,
            "urgent_support_disclaimer_acknowledged": True,
            "message_body": "é" * 16_385,
        }
        response = self.client.post(
            "/api/v1/content/contact-submissions/",
            data=utf8_oversized,
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 422, response.content)

    def test_delivery_metadata_endpoint_returns_bounded_typed_items(self):
        with mock.patch(
            "apps.content.api.contact_delivery_metadata",
            return_value={
                "counts": {"sent": 2, "failed": 1},
                "items": [
                    {
                        "delivery_state": "sent",
                        "status": "sent",
                        "created_at": "2026-08-31T10:00:00+00:00",
                        "sent_at": "2026-08-31T10:00:01+00:00",
                        "provider_status_updated_at": None,
                        "recipient_email": "must-not-cross-boundary",
                    },
                ],
                "page": 1,
                "page_size": 25,
                "total": 1,
            },
        ):
            response = self.client.get(
                "/api/v1/content/contact-delivery/metadata/?page=1&page_size=25",
                **self.auth_headers(),
            )

        self.assertEqual(response.status_code, 200, response.content)
        payload = response.json()
        self.assertEqual(payload["counts"]["sent"], 2)
        self.assertEqual(payload["items"][0]["delivery_state"], "sent")
        self.assertNotIn("recipient_email", payload["items"][0])

    def test_public_feed_contains_only_institution_wide_published_content(self):
        Announcement.objects.create(
            slug="api-public-announcement",
            title="Public announcement",
            summary="Public summary",
            body_markdown="Public body",
            status=ContentStatus.PUBLISHED,
            audience=AudienceChoices.PUBLIC,
            target_scope_mode=TargetScopeChoices.INSTITUTION_WIDE,
        )
        Announcement.objects.create(
            slug="api-draft-announcement",
            title="Draft announcement",
            summary="Draft summary",
            body_markdown="Draft body",
            status=ContentStatus.DRAFT,
            audience=AudienceChoices.PUBLIC,
            target_scope_mode=TargetScopeChoices.INSTITUTION_WIDE,
        )
        Announcement.objects.create(
            slug="api-local-announcement",
            title="Local announcement",
            summary="Local summary",
            body_markdown="Local body",
            status=ContentStatus.PUBLISHED,
            audience=AudienceChoices.PUBLIC,
            target_scope_mode=TargetScopeChoices.ORGANIZATION,
            target_campus="Main Campus",
        )
        response = self.client.get("/api/v1/content/announcements/?page=1&page_size=100")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [item["slug"] for item in response.json()["items"]],
            ["api-public-announcement"],
        )
        self.assertTrue(response["X-Request-ID"].startswith("REQ-"))

    def test_public_missing_content_is_not_found_with_standard_error(self):
        response = self.client.get("/api/v1/content/announcements/missing-announcement/")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["code"], "not_found")
        self.assertEqual(response["Cache-Control"], "no-store")

    def test_content_page_is_head_governed_and_workspace_projected(self):
        response = self.client.post(
            "/api/v1/content/pages/",
            data={
                "page_key": "api-about",
                "title": "About COMPASS",
                "summary": "About",
                "body_markdown": "About body",
                "status": "draft",
            },
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="content-page-create-001",
            **self.auth_headers(),
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["content_type"], "page")
        listing = self.client.get("/api/v1/content/workspace/?page=1&page_size=100", **self.auth_headers())
        self.assertEqual(listing.status_code, 200, listing.content)
        self.assertTrue(any(item["content_type"] == "page" for item in listing.json()["items"]))

    def test_content_mutation_requires_idempotency_and_replays_safe_projection(self):
        payload = {
            "slug": "api-created-announcement",
            "title": "Created",
            "summary": "Summary",
            "body_markdown": "Body",
            "status": "draft",
        }
        missing = self.client.post(
            "/api/v1/content/announcements/",
            data=payload,
            content_type="application/json",
            **self.auth_headers(),
        )
        self.assertEqual(missing.status_code, 422)
        self.assertEqual(missing.json()["code"], "validation")

        first = self.client.post(
            "/api/v1/content/announcements/",
            data=payload,
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="content-announcement-create-001",
            **self.auth_headers(),
        )
        replay = self.client.post(
            "/api/v1/content/announcements/",
            data=payload,
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="content-announcement-create-001",
            **self.auth_headers(),
        )
        self.assertEqual(first.status_code, 200, first.content)
        self.assertEqual(replay.status_code, 200, replay.content)
        self.assertEqual(replay.json()["id"], first.json()["id"])
