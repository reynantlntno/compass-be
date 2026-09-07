# Project: COMPASS
# File: apps/inventory/selectors.py
# Module: apps.inventory
# Purpose: Side-effect free query selectors for inventory snapshots
# Domain boundary and service policy.

from typing import Optional
from django.db import models

from apps.access_control.selectors import get_students_visible_to
from apps.access_control.rules import (
    is_active_nonlegacy_actor,
    is_it_admin,
    is_student,
    is_counselor,
    owns_student_profile,
)
from apps.access_control.policies import can_view_student_profile
from apps.inventory.models import StudentInventorySnapshot, InventoryStatusChoices


def get_inventory_snapshots_visible_to(user) -> models.QuerySet:
    """Return a side-effect free queryset of StudentInventorySnapshots visible to the user.
    
    Strictly filters records to match the StudentProfiles visible to the actor.
    If the actor is an IT Admin or Django superuser, returns StudentInventorySnapshot.objects.none().
    """
    if not is_active_nonlegacy_actor(user):
        return StudentInventorySnapshot.objects.none()

    if is_it_admin(user) or user.is_superuser:
        return StudentInventorySnapshot.objects.none()

    visible_students = get_students_visible_to(user)
    return StudentInventorySnapshot.objects.filter(student_profile__in=visible_students)


def _can_read_inventory_target(actor, student_profile) -> bool:
    if not is_active_nonlegacy_actor(actor) or student_profile is None:
        return False
    if is_student(actor):
        return owns_student_profile(actor, student_profile)
    return bool(is_counselor(actor) and can_view_student_profile(actor, student_profile))


def get_current_inventory_snapshot(
    actor, student_profile, academic_year: str
) -> Optional[StudentInventorySnapshot]:
    """Retrieve a target inventory snapshot only within the actor's scope."""
    if not academic_year or not _can_read_inventory_target(actor, student_profile):
        return None
    return StudentInventorySnapshot.objects.filter(
        student_profile=student_profile,
        academic_year=academic_year
    ).first()


def get_latest_submitted_inventory(
    actor, student_profile
) -> Optional[StudentInventorySnapshot]:
    """Retrieve the latest submitted snapshot only within actor scope."""
    if not _can_read_inventory_target(actor, student_profile):
        return None
    return StudentInventorySnapshot.objects.filter(
        student_profile=student_profile,
        status=InventoryStatusChoices.SUBMITTED
    ).order_by("-submitted_at", "-created_at").first()


def get_latest_guidance_inventory(
    actor, student_profile,
) -> Optional[StudentInventorySnapshot]:
    """Return the latest non-draft snapshot only within actor scope."""
    if not _can_read_inventory_target(actor, student_profile):
        return None

    return (
        StudentInventorySnapshot.objects.filter(
            student_profile=student_profile,
            status__in=(
                InventoryStatusChoices.SUBMITTED,
                InventoryStatusChoices.REOPENED_FOR_CORRECTION,
            ),
        )
        .order_by("-submitted_at", "-created_at")
        .first()
    )
