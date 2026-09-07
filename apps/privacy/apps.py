from django.apps import AppConfig


class PrivacyConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.privacy"
    verbose_name = "Privacy governance"

    def ready(self):
        from apps.governance.registry import register_policy_definition
        from apps.privacy.policy import (
            PRIVACY_INCIDENT_CONTAINMENT_POLICY_DEFINITION,
            PRIVACY_INCIDENTS_POLICY_DEFINITION,
            PRIVACY_NOTICES_POLICY_DEFINITION,
            PRIVACY_RETENTION_POLICY_DEFINITION,
            PRIVACY_REVIEWER_AUTHORIZATIONS_POLICY_DEFINITION,
        )

        register_policy_definition(PRIVACY_RETENTION_POLICY_DEFINITION)
        for definition in (
            PRIVACY_NOTICES_POLICY_DEFINITION,
            PRIVACY_REVIEWER_AUTHORIZATIONS_POLICY_DEFINITION,
            PRIVACY_INCIDENTS_POLICY_DEFINITION,
            PRIVACY_INCIDENT_CONTAINMENT_POLICY_DEFINITION,
        ):
            register_policy_definition(definition)
