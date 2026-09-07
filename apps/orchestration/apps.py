from django.apps import AppConfig


class OrchestrationConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.orchestration"

    def ready(self):
        # The composition boundary owns event-to-handler registration.  The
        # workflow app owns only outbox persistence and worker mechanics.
        from apps.orchestration.notification_handlers import register_notification_handlers

        register_notification_handlers()
