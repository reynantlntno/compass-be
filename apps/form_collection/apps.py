# Project: COMPASS
# File: apps/form_collection/apps.py
# Module: apps.form_collection
# Purpose: Django AppConfig registration for form_collection
# Domain boundary and service policy.

from django.apps import AppConfig


class FormCollectionConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.form_collection"
    label = "form_collection"
    verbose_name = "Form Collection"

    def ready(self):
        from apps.form_collection.policy import (
            FORM_COLLECTION_GOVERNANCE_POLICY_DEFINITION,
            FORM_COLLECTION_INVITATION_POLICY_DEFINITION,
        )
        from apps.governance.registry import register_policy_definition

        register_policy_definition(FORM_COLLECTION_GOVERNANCE_POLICY_DEFINITION)
        register_policy_definition(FORM_COLLECTION_INVITATION_POLICY_DEFINITION)
