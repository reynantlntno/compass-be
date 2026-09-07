# Project: COMPASS
# File: apps/access_control/selectors.py
# Module: apps.access_control
# Purpose: Side-effect free query selectors for access scope filtering
# Domain boundary and service policy.

from django.db import models
from django.db.models import Q

from apps.access_control.authority import has_capability
from apps.access_control.capabilities import Capability
from apps.access_control.rules import (
    is_active_nonlegacy_actor,
    is_counselor,
    is_gco_staff,
    is_student,
    is_it_admin,
)
from apps.access_control.scopes import (
    build_geographic_scope_q,
    get_live_counselor_coverages,
)
from apps.profiles.models import StudentProfile


def get_students_visible_to(user) -> models.QuerySet:
    """Return a side-effect free queryset of StudentProfiles visible to the user.
    
    - Student: Returns only their own profile.
    - Head Guidance: Returns all student profiles.
    - Counselor: Returns profiles matching active coverage scopes.
    - GCO Staff: Returns an empty queryset; staff workflows require explicit purpose.
    - IT Admin / Anonymous / Unauthenticated: Returns empty queryset.
    """
    if not is_active_nonlegacy_actor(user):
        return StudentProfile.objects.none()

    # 1. Student self-access
    if is_student(user):
        return StudentProfile.objects.filter(user=user)

    # 2. IT Admin access (blocked from student data)
    if is_it_admin(user):
        return StudentProfile.objects.none()

    # 3. Counselor access
    if is_counselor(user):
        if has_capability(user, Capability.STUDENT_RECORDS_VIEW_INSTITUTION):
            return StudentProfile.objects.all()

        coverages = get_live_counselor_coverages(user)
        if not coverages.exists():
            return StudentProfile.objects.none()

        return StudentProfile.objects.filter(
            build_geographic_scope_q(
                coverages,
                {
                    "campus": "campus",
                    "college": "college",
                    "department": "department",
                    "program": "program",
                },
            )
        )

    # 4. GCO Staff access
    if is_gco_staff(user):
        return StudentProfile.objects.none()

    return StudentProfile.objects.none()
