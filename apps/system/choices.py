# Project: COMPASS
# File: apps/system/choices.py
# Module: apps.system
# Purpose: Choices for system models (application error events)
# Domain boundary and service policy.
# Notes: Choices are intentionally operational and non-sensitive.

from django.db import models


class ErrorSeverityChoices(models.TextChoices):
    """Severity of an application error event."""

    INFO = "info", "Info"
    WARNING = "warning", "Warning"
    ERROR = "error", "Error"
    CRITICAL = "critical", "Critical"


class ErrorCategoryChoices(models.TextChoices):
    """Operational category of an application error event.

    Categories are deliberately coarse and non-sensitive.
    """

    VALIDATION = "validation", "Validation"
    PERMISSION = "permission", "Permission"
    EXTERNAL_SERVICE = "external_service", "External Service"
    BACKGROUND_JOB = "background_job", "Background Job"
    DATABASE = "database", "Database"
    SECURITY = "security", "Security"
    UNKNOWN = "unknown", "Unknown"


class ErrorEnvironmentChoices(models.TextChoices):
    """Environment where an error event was captured."""

    DEVELOPMENT = "development", "Development"
    TESTING = "testing", "Testing"
    STAGING = "staging", "Staging"
    PRODUCTION = "production", "Production"


class MaintenanceStatusChoices(models.TextChoices):
    """Lifecycle status of a maintenance window."""

    SCHEDULED = "scheduled", "Scheduled"
    ACTIVE = "active", "Active"
    COMPLETED = "completed", "Completed"
    CANCELLED = "cancelled", "Cancelled"