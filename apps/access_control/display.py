"""Shared privacy-safe display helpers for scoped student workflows.

These helpers are presentation-only. Callers normally apply the owning policy
before asking for a label; the compatibility helper can also fail closed when
given an actor. The returned label is composed only from name fields and never
falls back to an email address, student number, control number, database
primary key, or other identifier.
"""

from __future__ import annotations


def _bounded_plain_text(value: object, *, limit: int = 120) -> str:
    """Normalize a display fragment without introducing HTML or identifiers."""
    if value is None:
        return ""
    return " ".join(str(value).split()).strip()[:limit]


def safe_student_display_label(student_profile, *, fallback: str = "Student") -> str:
    """Return a safe human-facing label for an authorized student profile.

    ``StudentProfile.__str__`` is intentionally not used because it includes
    the student number. This helper is presentation-only; authorization and
    lifecycle checks remain with the caller's policy/selector.
    """
    user = getattr(student_profile, "user", None)
    if user is None:
        return fallback

    name = " ".join(
        part
        for part in (
            _bounded_plain_text(getattr(user, "first_name", "")),
            _bounded_plain_text(getattr(user, "last_name", "")),
        )
        if part
    )
    return name or fallback


def office_student_display_label(student_profile, *, fallback: str = "Student") -> str:
    """Return the standard masked label for authorized office workflows.

    This deliberately keeps the raw student number out of rendered markup while
    retaining enough approved context for staff to distinguish similar names.
    Authorization remains the responsibility of the owning selector/policy.
    """
    name = safe_student_display_label(student_profile, fallback=fallback)
    number = _bounded_plain_text(getattr(student_profile, "student_number", ""), limit=50)
    masked_number = f"****{number[-4:]}" if len(number) > 4 else "****"
    parts = [name, masked_number]
    program = _bounded_plain_text(getattr(student_profile, "program", ""), limit=100)
    if program:
        parts.append(program)
    year_level = getattr(student_profile, "year_level", None)
    if year_level:
        parts.append(f"Year {year_level}")
    return " · ".join(parts)


def get_safe_student_label(student_profile, *, actor=None, fallback: str = "Student") -> str:
    """Return a safe label after an optional student-profile policy check.

    Existing callers use :func:`safe_student_display_label` after applying
    their owning policy.  New aggregate projections may pass an actor so the
    helper itself fails closed rather than displaying a name to an actor who
    cannot view that profile.
    """
    if actor is not None:
        from apps.access_control.policies import can_view_student_profile

        if not can_view_student_profile(actor, student_profile):
            return fallback
    return safe_student_display_label(student_profile, fallback=fallback)


def safe_user_display_label(user, *, fallback: str = "User") -> str:
    """Return the same identifier-free display label for a user object."""
    if user is None:
        return fallback
    name = " ".join(
        part
        for part in (
            _bounded_plain_text(getattr(user, "first_name", "")),
            _bounded_plain_text(getattr(user, "last_name", "")),
        )
        if part
    )
    return name or fallback
