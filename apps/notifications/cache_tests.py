from django.core.cache import cache
from django.test import TestCase

from apps.notifications.cache import get_cached_notification_template
from apps.notifications.models import NotificationTemplate


class NotificationTemplateCacheTests(TestCase):
    def setUp(self):
        cache.clear()

    def tearDown(self):
        cache.clear()

    def test_cached_template_contains_definition_only(self):
        NotificationTemplate.objects.create(
            stable_key="cache-template",
            display_name="Cache template",
            channel="email",
            subject_template="Subject",
            body_template="emails/v1/generic.txt",
            required_context_schema_json={"required": [], "properties": {}},
            status="active",
        )
        value = get_cached_notification_template("cache-template")
        self.assertEqual(value["stable_key"], "cache-template")
        self.assertIn("required_context_schema", value)
        self.assertNotIn("recipient_user", value)
        self.assertNotIn("context_json", value)
        self.assertNotIn("raw_token", value)
