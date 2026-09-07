# Project: COMPASS
# File: apps/common/models.py
# Module: common
# Purpose: Shared abstract base models used across COMPASS apps
# Domain boundary and service policy.
# Notes: TimestampedModel provides created_at/updated_at for all domain models.

from django.db import models


class TimestampedModel(models.Model):
    """Abstract base model providing created_at and updated_at timestamps.

    All COMPASS domain models should inherit from this unless there
    is a specific reason not to (e.g., Django's built-in User model
    which has its own date_joined field).
    """

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True
