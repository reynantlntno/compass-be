# Project: COMPASS
# File: apps/counseling/apps.py
# Module: apps.counseling
# Purpose: App configuration for counseling session foundation
# Domain boundary and service policy.

from django.apps import AppConfig


class CounselingConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.counseling"
    verbose_name = "Counseling"

    def ready(self):
        from apps.counseling import checks  # noqa: F401
        from apps.counseling.encryption_targets import register_counseling_encryption_targets
        from apps.counseling.recording_services import (
            RECORDING_FILE_POLICY_KEY,
            TRANSCRIPT_FILE_POLICY_KEY,
            recording_file_policy,
            transcript_file_policy,
        )
        from apps.security.file_policies import register_file_policy
        from apps.counseling.policy import ECOUNSELING_CONTROLS_POLICY_DEFINITION
        from apps.governance.registry import register_policy_definition

        register_counseling_encryption_targets()
        register_file_policy(RECORDING_FILE_POLICY_KEY, recording_file_policy)
        register_file_policy(TRANSCRIPT_FILE_POLICY_KEY, transcript_file_policy)
        register_policy_definition(ECOUNSELING_CONTROLS_POLICY_DEFINITION)
