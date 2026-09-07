# Project: COMPASS
# File: apps/assessments/choices.py
# Module: apps.assessments
# Purpose: Text choices for assessment instrument categories, statuses, and interpretation visibility.

from django.db import models


class AssessmentInstrumentCategory(models.TextChoices):
    ACADEMIC = "academic", "Academic"
    CAREER = "career", "Career"
    GUIDANCE = "guidance", "Guidance"
    WELLNESS_SCREENING_NON_DIAGNOSTIC = "wellness_screening_non_diagnostic", "Wellness Screening (Non-Diagnostic)"
    OFFICE_APPROVED_OTHER = "office_approved_other", "Office Approved Other"


class AssessmentRecordStatus(models.TextChoices):
    DRAFT = "draft", "Draft"
    RECORDED = "recorded", "Recorded"
    UNDER_REVIEW = "under_review", "Under Review"
    REVIEWED = "reviewed", "Reviewed"
    RELEASED_TO_STUDENT = "released_to_student", "Released to Student"
    SUPERSEDED = "superseded", "Superseded"
    VOIDED = "voided", "Voided"
    ARCHIVED = "archived", "Archived"


class AssessmentInterpretationVisibility(models.TextChoices):
    COUNSELOR_ONLY = "counselor_only", "Counselor Only"
    HEAD_GUIDANCE_REVIEW = "head_guidance_review", "Head Guidance Review"
    RELEASED_TO_STUDENT_SAFE_SUMMARY = "released_to_student_safe_summary", "Released to Student Safe Summary"
