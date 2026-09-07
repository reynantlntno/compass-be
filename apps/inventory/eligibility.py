# Project: COMPASS
# File: apps/inventory/eligibility.py
# Module: apps.inventory
# Purpose: Pure reusable eligibility helpers to determine inventory completion.
# Domain boundary and service policy.

from apps.common.exceptions import ValidationError, WorkflowError
from apps.inventory.models import StudentInventorySnapshot, InventoryStatusChoices


def has_current_submitted_inventory(student_profile, academic_year: str) -> bool:
    """Return True if the student has a submitted locked snapshot for the year.
    
    Requires explicit academic_year parameter.
    """
    if not academic_year or not academic_year.strip():
        raise ValidationError("Academic year must be explicitly provided.")
    
    return StudentInventorySnapshot.objects.filter(
        student_profile=student_profile,
        academic_year=academic_year,
        status=InventoryStatusChoices.SUBMITTED
    ).exists()


def assert_inventory_requirement_met(student_profile, academic_year: str) -> None:
    """Assert that the student has submitted their inventory for the academic year.
    
    Raises WorkflowError if the requirement is not met.
    """
    if not has_current_submitted_inventory(student_profile, academic_year):
        raise WorkflowError(
            f"Access Denied: Submission of the Individual Inventory for academic year "
            f"{academic_year} is required before accessing student services."
        )
