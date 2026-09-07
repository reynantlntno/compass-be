# Project: COMPASS
# File: apps/security/apps.py
# Module: apps.security
# Purpose: Django app configuration for security foundation

from django.apps import AppConfig


class SecurityConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.security"
    verbose_name = "Security"

    def ready(self):
        from apps.security import checks  # noqa: F401
        from apps.governance.registry import register_policy_definition
        from apps.security.policy import (
            ASSESSMENT_UPLOAD_POLICY_DEFINITION,
            PROTECTED_STORAGE_POLICY_DEFINITION,
        )

        register_policy_definition(ASSESSMENT_UPLOAD_POLICY_DEFINITION)
        register_policy_definition(PROTECTED_STORAGE_POLICY_DEFINITION)
