# Project: COMPASS
# File: apps/access_control/apps.py
# Module: apps.access_control
# Purpose: Django AppConfig for access_control app
# Domain boundary and service policy.

from django.apps import AppConfig


class AccessControlConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.access_control"

    def ready(self):
        from apps.access_control import checks  # noqa: F401
