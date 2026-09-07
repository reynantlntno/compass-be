from django.apps import AppConfig


class GoodMoralConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.good_moral"

    def ready(self):
        # We will register generated document access policies here
        from apps.good_moral.policies import register_policies
        from apps.good_moral.policy import GOOD_MORAL_POLICY_DEFINITION
        from apps.governance.registry import register_policy_definition

        register_policies()
        register_policy_definition(GOOD_MORAL_POLICY_DEFINITION)
