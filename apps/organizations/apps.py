# Project: COMPASS
# File: apps/organizations/apps.py
# Module: organizations
# Purpose: Django app configuration for organizations
# Notes: None

from django.apps import AppConfig


class OrganizationsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.organizations"
    verbose_name = "Organizations"

    def ready(self):
        from apps.security.file_policies import register_file_policy
        from apps.organizations.policies import can_view_form_source_content
        from apps.organizations import signals  # noqa: F401
        from apps.organizations.policy import ORGANIZATIONS_GOVERNANCE_POLICY_DEFINITION
        from apps.governance.registry import register_policy_definition

        def form_revision_source_policy(user, protected_file, action):
            if action in {"read_metadata", "inspect"}:
                return bool(user and user.is_authenticated and user.is_active)
            return can_view_form_source_content(user)

        register_file_policy("form_revision_source", form_revision_source_policy)
        register_policy_definition(ORGANIZATIONS_GOVERNANCE_POLICY_DEFINITION)
