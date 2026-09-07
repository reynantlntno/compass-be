from django.apps import AppConfig


class CallSlipsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.call_slips"
    verbose_name = "Call Slips"

    def ready(self):
        from apps.call_slips import checks  # noqa: F401
        from apps.call_slips.encryption_targets import register_call_slip_encryption_targets

        register_call_slip_encryption_targets()
