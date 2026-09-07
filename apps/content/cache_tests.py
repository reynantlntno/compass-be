from django.core.cache import cache
from django.test import TestCase

from apps.content.cache import get_cached_public_announcements, get_cached_public_resources
from apps.content.models import (
    Announcement,
    AudienceChoices,
    ContentStatus,
    Resource,
    ResourceType,
    TargetScopeChoices,
)


class PublicContentCacheTests(TestCase):
    def setUp(self):
        cache.clear()

    def tearDown(self):
        cache.clear()

    def test_public_cache_excludes_drafts_and_local_content(self):
        Announcement.objects.create(
            slug="public-cache-announcement",
            title="Public announcement",
            summary="Safe summary",
            body_markdown="Public body",
            status=ContentStatus.PUBLISHED,
            audience=AudienceChoices.PUBLIC,
            target_scope_mode=TargetScopeChoices.INSTITUTION_WIDE,
        )
        Announcement.objects.create(
            slug="draft-cache-announcement",
            title="Draft announcement",
            summary="Draft summary",
            body_markdown="Draft body",
            status=ContentStatus.DRAFT,
            audience=AudienceChoices.PUBLIC,
            target_scope_mode=TargetScopeChoices.INSTITUTION_WIDE,
        )
        Announcement.objects.create(
            slug="local-cache-announcement",
            title="Local announcement",
            summary="Local summary",
            body_markdown="Local body",
            status=ContentStatus.PUBLISHED,
            audience=AudienceChoices.PUBLIC,
            target_scope_mode=TargetScopeChoices.ORGANIZATION,
            target_campus="Main Campus",
        )
        values = get_cached_public_announcements()
        self.assertEqual([item["slug"] for item in values], ["public-cache-announcement"])
        self.assertTrue(all("created_by" not in item and "metadata_json" not in item for item in values))

    def test_resource_projection_is_model_free(self):
        Resource.objects.create(
            slug="public-cache-resource",
            title="Public resource",
            summary="Safe summary",
            resource_type=ResourceType.LINK,
            external_url="https://example.test/resource",
            status=ContentStatus.PUBLISHED,
            audience=AudienceChoices.PUBLIC,
            target_scope_mode=TargetScopeChoices.INSTITUTION_WIDE,
        )
        values = get_cached_public_resources()
        self.assertEqual(values[0]["content_type"], "resource")
        self.assertNotIn("published_revision", values[0])
