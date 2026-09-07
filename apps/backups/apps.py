# Project: COMPASS
# File: apps/backups/apps.py
# Module: apps.backups
# Purpose: Django app configuration for backups and restore operations foundation

from django.apps import AppConfig


class BackupsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.backups"
    verbose_name = "Backups"
