# Project: COMPASS
# File: apps/system/apps.py
# Module: apps.system
# Purpose: Django AppConfig for system app
# Domain boundary and service policy.

from django.apps import AppConfig


class SystemConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.system'

    def ready(self):
        import apps.system.checks  # noqa: F401
        from apps.governance.registry import register_policy_definition
        from apps.system.policy import FEATURE_FLAGS_POLICY_DEFINITION
        from config.runtime_settings import (
            TECHNICAL_BACKUP_METADATA_POLICY_DEFINITION,
            TECHNICAL_CONFIGURATION_POLICY_DEFINITION,
            TECHNICAL_DELIVERY_OPERATIONS_POLICY_DEFINITION,
            TECHNICAL_RENDERER_POLICY_DEFINITION,
        )

        for definition in (
            FEATURE_FLAGS_POLICY_DEFINITION,
            TECHNICAL_CONFIGURATION_POLICY_DEFINITION,
            TECHNICAL_RENDERER_POLICY_DEFINITION,
            TECHNICAL_BACKUP_METADATA_POLICY_DEFINITION,
            TECHNICAL_DELIVERY_OPERATIONS_POLICY_DEFINITION,
        ):
            register_policy_definition(definition)
