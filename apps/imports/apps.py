# Project: COMPASS
# File: apps/imports/apps.py
# Module: apps.imports
# Purpose: Django AppConfig for imports app
# Domain boundary and service policy.

from django.apps import AppConfig


class ImportsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.imports"

    def ready(self):
        from apps.imports import signals  # noqa: F401
        from apps.imports.policy import STUDENT_IMPORT_POLICY_DEFINITION
        from apps.governance.registry import register_policy_definition

        register_policy_definition(STUDENT_IMPORT_POLICY_DEFINITION)
