# Project: COMPASS
# File: apps/accounts/apps.py
# Module: accounts
# Purpose: Django app configuration for accounts
# Notes: None

from django.apps import AppConfig


class AccountsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.accounts"
    verbose_name = "Accounts"

    def ready(self):
        from apps.accounts import checks  # noqa: F401
