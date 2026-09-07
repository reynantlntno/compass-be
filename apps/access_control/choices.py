"""Choices for per-account workflow authority."""

from django.db import models


class ScopeMode(models.TextChoices):
    COUNSELOR_COVERAGE = "COUNSELOR_COVERAGE", "Counselor coverage"
    EXPLICIT_ORGANIZATION = "EXPLICIT_ORGANIZATION", "Explicit organization"
    ASSIGNED_RECORDS = "ASSIGNED_RECORDS", "Assigned records"
    OFFICE_WIDE = "OFFICE_WIDE", "Office-wide"


class GrantStatus(models.TextChoices):
    ACTIVE = "ACTIVE", "Active"
    REVOKED = "REVOKED", "Revoked"


class GrantSourceType(models.TextChoices):
    MANUAL = "MANUAL", "Manual"
    BULK = "BULK", "Bulk assignment"
    MIGRATION = "MIGRATION", "Legacy migration"
    SYSTEM = "SYSTEM", "System"


class GrantReasonCode(models.TextChoices):
    OFFICE_DELEGATION = "OFFICE_DELEGATION", "Office delegation"
    LOCAL_WORKFLOW = "LOCAL_WORKFLOW", "Local workflow"
    TEMPORARY_COVERAGE = "TEMPORARY_COVERAGE", "Temporary coverage"
    ABSENCE_COVER = "ABSENCE_COVER", "Absence cover"
    ROLE_DUTY = "ROLE_DUTY", "Role duty"
    MIGRATED_ASSIGNMENT = "MIGRATED_ASSIGNMENT", "Migrated assignment"


class RevocationReasonCode(models.TextChoices):
    POLICY_CHANGE = "POLICY_CHANGE", "Policy change"
    ROLE_CHANGE = "ROLE_CHANGE", "Role change"
    ACCOUNT_DEACTIVATED = "ACCOUNT_DEACTIVATED", "Account deactivated"
    EXPIRED = "EXPIRED", "Expired"
    NO_LONGER_NEEDED = "NO_LONGER_NEEDED", "No longer needed"
    SECURITY = "SECURITY", "Security"
