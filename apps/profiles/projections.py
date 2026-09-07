"""Fixed JSON projection boundary for the profiles domain.

Only named projection functions with explicit allowlists may be added here.
Raw model instances, QuerySets, encrypted fields, secrets, and arbitrary
metadata must not be returned to a client.  Control numbers, email addresses,
license numbers, employee numbers, tokens, and security metadata are never
projected for any actor.
"""

from apps.accounts.models import RoleChoices


# Fixed self-profile allowlist.  Every self-projection below returns a subset
# of exactly these keys; ``student_number`` is owner-only by construction
# because a self projection is only ever composed from the actor's own row.
SELF_PROFILE_KEYS = frozenset({
    "user_id",
    "display_name",
    "role",
    "profile_type",
    "student_number",
    "lifecycle_status",
    "campus",
    "college",
    "department",
    "program",
    "year_level",
    "designation",
    "is_head_guidance",
})

# Fixed directory-entry allowlist shared by every support contact entry.
DIRECTORY_ENTRY_KEYS = frozenset({"user_id", "display_name", "role", "designation"})


def _display_name(user) -> str:
    name = " ".join(
        part for part in (getattr(user, "first_name", ""), getattr(user, "last_name", ""))
        if part
    ).strip()
    return name or getattr(user, "username", "") or "Guidance Office Staff"


def project_self_student_profile(profile) -> dict:
    """Return the owner-only safe projection of one student profile.

    Imported academic fields and lifecycle status are system-owned values that
    are surfaced read-only here; the control number is deliberately excluded.
    """
    return {
        "user_id": profile.user_id,
        "display_name": _display_name(profile.user),
        "role": RoleChoices.STUDENT,
        "profile_type": "STUDENT",
        "student_number": profile.student_number,
        "lifecycle_status": profile.lifecycle_status,
        "campus": profile.campus,
        "college": profile.college,
        "department": profile.department,
        "program": profile.program,
        "year_level": profile.year_level,
    }


def project_self_counselor_profile(profile) -> dict:
    """Return the safe counselor self projection without license details."""
    return {
        "user_id": profile.user_id,
        "display_name": _display_name(profile.user),
        "role": RoleChoices.COUNSELOR,
        "profile_type": "COUNSELOR",
        "designation": "Head Guidance" if profile.is_head_guidance else "Counselor",
        "is_head_guidance": bool(profile.is_head_guidance),
    }


def project_self_staff_profile(profile) -> dict:
    """Return the safe GCO staff self projection without employee number."""
    return {
        "user_id": profile.user_id,
        "display_name": _display_name(profile.user),
        "role": RoleChoices.GCO_STAFF,
        "profile_type": "GCO_STAFF",
        "designation": profile.designation or "GCO Staff",
    }


def project_base_profile(user) -> dict:
    """Return the minimal role-safe projection used when no role profile exists."""
    return {
        "user_id": user.pk,
        "display_name": _display_name(user),
        "role": user.role,
    }


def project_counselor_directory_entry(profile) -> dict:
    """Return the minimal student-facing counselor directory entry."""
    return {
        "user_id": profile.user_id,
        "display_name": _display_name(profile.user),
        "role": RoleChoices.COUNSELOR,
        "designation": "Head Guidance" if profile.is_head_guidance else "Counselor",
    }


def project_staff_directory_entry(profile) -> dict:
    """Return the minimal student-facing GCO staff directory entry."""
    return {
        "user_id": profile.user_id,
        "display_name": _display_name(profile.user),
        "role": RoleChoices.GCO_STAFF,
        "designation": profile.designation or "GCO Staff",
    }
