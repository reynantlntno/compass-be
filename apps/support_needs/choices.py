# Project: COMPASS
# File: apps/support_needs/choices.py
# Module: apps.support_needs
# Purpose: Text choices for support-need types, statuses, source types, and sensitivity levels.

from django.db import models


class SupportNeedCategory(models.TextChoices):
    HOUSEHOLD_SUPPORT = "household_support", "Household Support"
    DISABILITY_SUPPORT = "disability_support", "Disability Support"
    FAMILY_CONTEXT = "family_context", "Family Context"
    EMPLOYMENT_CONTEXT = "employment_context", "Employment Context"
    FINANCIAL_CONTEXT = "financial_context", "Financial Context"
    LIVING_CONDITION = "living_condition", "Living Condition"
    EDUCATIONAL_SUPPORT = "educational_support", "Educational Support"
    OFFICE_APPROVED_OTHER = "office_approved_other", "Office Approved Other"


class SupportNeedStatus(models.TextChoices):
    DRAFT = "draft", "Candidate"
    ACTIVE = "active", "Active"
    NEEDS_REVIEW = "needs_review", "Needs Review"
    VERIFIED = "verified", "Verified"
    DISPUTED = "disputed", "Disputed"
    INACTIVE = "inactive", "Inactive"
    ARCHIVED = "archived", "Archived"


class SupportNeedSourceType(models.TextChoices):
    INDIVIDUAL_INVENTORY = "individual_inventory", "Individual Inventory"
    STUDENT_PROVIDED = "student_provided", "Student Provided"
    COUNSELOR_STAFF_VERIFICATION = "counselor_staff_verification", "Counselor/Staff Verification"
    OFFICIAL_DOCUMENT_PRESENTED = "official_document_presented", "Official Document Presented"
    MANUAL_OFFICE_VALIDATION = "manual_office_validation", "Manual Office Validation"
    IMPORTED_OFFICIAL_LIST_FUTURE = "imported_official_list_future", "Imported Official List (Future)"


class SupportNeedSensitivity(models.TextChoices):
    INTERNAL = "internal", "Internal"
    PROTECTED = "protected", "Protected"
    CONFIDENTIAL = "confidential", "Confidential"
