# Project: COMPASS
# File: apps/audit/apps.py
# Module: apps.audit
# Purpose: Django AppConfig for audit app
# Domain boundary and service policy.

from django.apps import AppConfig


class AuditConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.audit'
