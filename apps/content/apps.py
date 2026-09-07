from django.apps import AppConfig


class ContentConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.content"

    def ready(self):
        from apps.content.encryption_targets import register_content_encryption_targets
        from apps.content import signals  # noqa: F401
        from apps.content.policy import CONTENT_INSTITUTION_POLICY_DEFINITION
        from apps.governance.registry import register_policy_definition

        register_content_encryption_targets()
        register_policy_definition(CONTENT_INSTITUTION_POLICY_DEFINITION)
