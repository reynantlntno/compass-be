# Project: COMPASS
# File: apps/reports/apps.py
# Module: apps.reports
# Purpose: Configuration file for the reports application

from django.apps import AppConfig


class ReportsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.reports"

    def ready(self):
        from apps.documents.policies import register_generated_document_policy
        from apps.security.file_policies import register_file_policy
        from apps.governance.registry import register_policy_definition
        from apps.reports.policy import (
            REPORTS_DEFINITIONS_POLICY_DEFINITION,
            REPORTS_EXECUTION_CONTROLS_POLICY_DEFINITION,
            REPORT_SUPPRESSION_POLICY_DEFINITION,
        )
        from apps.reports.policies import (
            report_export_file_policy,
            report_export_generated_document_policy,
        )
        register_file_policy("REPORT_EXPORT", report_export_file_policy)
        register_generated_document_policy("REPORT_EXPORT", report_export_generated_document_policy)
        register_policy_definition(REPORT_SUPPRESSION_POLICY_DEFINITION)
        register_policy_definition(REPORTS_DEFINITIONS_POLICY_DEFINITION)
        register_policy_definition(REPORTS_EXECUTION_CONTROLS_POLICY_DEFINITION)
