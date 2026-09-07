# Project: COMPASS
# File: apps/profiles/apps.py
# Module: apps.profiles
# Purpose: Django AppConfig for profiles app
# Domain boundary and service policy.

from django.apps import AppConfig


class ProfilesConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.profiles"
