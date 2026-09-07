from django.apps import AppConfig


class GovernanceConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.governance"
    verbose_name = "COMPASS Governance"

    def ready(self):
        from apps.governance import checks  # noqa: F401
        from apps.governance import signals  # noqa: F401
