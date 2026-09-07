from django.apps import AppConfig


class AccountSecurityConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.account_security"
    verbose_name = "Account Security"

    def ready(self):
        from apps.account_security.policy import (
            ABUSE_CONTROLS_POLICY_DEFINITION,
            SECURITY_ACCOUNT_SECURITY_POLICY_DEFINITION,
        )
        from apps.governance.registry import register_policy_definition

        register_policy_definition(ABUSE_CONTROLS_POLICY_DEFINITION)
        register_policy_definition(SECURITY_ACCOUNT_SECURITY_POLICY_DEFINITION)
