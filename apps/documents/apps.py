# Project: COMPASS
# File: apps/documents/apps.py
# Module: apps.documents
# Purpose: Django app configuration for document generation and template foundation

from django.apps import AppConfig


class DocumentsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.documents"
    verbose_name = "Documents"

    def ready(self):
        from apps.documents.policies import generated_document_file_policy
        from apps.security.file_policies import register_file_policy
        from apps.documents import signals  # noqa: F401
        from apps.documents.workflow_output import register_workflow_document_policies
        from apps.documents.policy import DOCUMENTS_TEMPLATES_POLICY_DEFINITION
        from apps.governance.registry import register_policy_definition

        register_file_policy("generated_document", generated_document_file_policy)
        register_workflow_document_policies()
        register_policy_definition(DOCUMENTS_TEMPLATES_POLICY_DEFINITION)
