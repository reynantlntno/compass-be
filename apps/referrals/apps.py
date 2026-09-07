# Project: COMPASS
# File: apps/referrals/apps.py
# Module: apps.referrals
# Purpose: Django application configuration for referral operations.
# Domain boundary and service policy.

from django.apps import AppConfig


class ReferralsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.referrals"
    verbose_name = "Referrals"

    def ready(self):
        from apps.referrals import checks  # noqa: F401
        from apps.referrals.encryption_targets import register_referral_encryption_targets

        register_referral_encryption_targets()
