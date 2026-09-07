"""Shared, bounded student search and opaque selection helpers."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.db.models import Q

from apps.access_control.display import office_student_display_label
from apps.access_control.authority import has_capability
from apps.access_control.rules import is_active_nonlegacy_actor, is_counselor, is_gco_staff
from apps.access_control.capabilities import Capability
from apps.access_control.scopes import build_workflow_authority_scope_q
from apps.access_control.selectors import get_students_visible_to
from apps.profiles.models import StudentProfile
from apps.accounts.models import RoleChoices


# A selector workflow is deliberately more specific than a role.  Tokens are
# bound to this value so a valid choice for one operational action cannot be
# replayed into another action with a different policy boundary.
WORKFLOWS = {
    "counseling_case", "counseling_session", "ecounseling", "assessment",
    "urgent_support_request", "support_need", "referral", "call_slip",
}
PAGE_SIZE = 25
MAX_QUERY_LENGTH = 80
TOKEN_SALT = "compass.student-selector.v1"
TOKEN_MAX_AGE = 4 * 60 * 60


@dataclass(frozen=True)
class StudentSelectorPage:
    results: tuple[StudentProfile, ...]
    query: str
    page: int
    has_next: bool


def _active_actor(actor) -> bool:
    return is_active_nonlegacy_actor(actor)


def workflow_allowed(actor, workflow: str) -> bool:
    if workflow not in WORKFLOWS or not _active_actor(actor):
        return False
    if workflow == "urgent_support_request":
        return has_capability(actor, Capability.URGENT_SUPPORT_QUEUE_REVIEW)
    if workflow in {"referral", "call_slip"}:
        return is_counselor(actor) or is_gco_staff(actor)
    return is_counselor(actor)


def visible_students_for_workflow(actor, workflow: str):
    if not workflow_allowed(actor, workflow):
        return StudentProfile.objects.none()
    # Counselor-facing workflows share current counselor coverage.  The
    # referral/call-slip staff path is intentionally separate: staff receive
    # only their explicitly assigned workflow scope, never counselor coverage.
    if workflow in {"referral", "call_slip"} and is_gco_staff(actor):
        capability = (
            Capability.REFERRALS_QUEUE_PROCESS
            if workflow == "referral"
            else Capability.CALL_SLIPS_PREPARE
        )
        scoped_q = build_workflow_authority_scope_q(
            actor,
            capability=capability,
            field_map={"campus": "campus", "college": "college", "department": "department", "program": "program"},
        )
        return StudentProfile.objects.filter(scoped_q, user__is_active=True, user__role=RoleChoices.STUDENT).select_related("user")
    return get_students_visible_to(actor).filter(user__is_active=True, user__role=RoleChoices.STUDENT).select_related("user")


def normalize_query(value: object) -> str:
    return " ".join(str(value or "").split())[:MAX_QUERY_LENGTH]


def search_students(actor, workflow: str, query: object = "", page: object = 1) -> StudentSelectorPage:
    query = normalize_query(query)
    try:
        page = max(1, int(page))
    except (TypeError, ValueError):
        page = 1
    queryset = visible_students_for_workflow(actor, workflow)
    if len(query) < 2:
        return StudentSelectorPage((), query, page, False)
    terms = query.split()
    name_filters = Q()
    for term in terms:
        name_filters &= Q(user__first_name__icontains=term) | Q(user__last_name__icontains=term)
    filters = Q(student_number__icontains=query) | name_filters
    ordered = queryset.filter(filters).order_by("user__last_name", "user__first_name", "student_number", "pk")
    rows = list(ordered[(page - 1) * PAGE_SIZE : page * PAGE_SIZE + 1])
    return StudentSelectorPage(tuple(rows[:PAGE_SIZE]), query, page, len(rows) > PAGE_SIZE)


def issue_student_selection_token(actor, workflow: str, student_profile: StudentProfile) -> str:
    if not visible_students_for_workflow(actor, workflow).filter(pk=student_profile.pk).exists():
        raise ValueError("Student is not available in this workflow.")
    payload = json.dumps(
        {"actor": actor.pk, "workflow": workflow, "student": student_profile.pk},
        separators=(",", ":"),
    ).encode("utf-8")
    return _selection_fernet().encrypt(payload).decode("ascii")


def _selection_fernet() -> Fernet:
    """Return a deployment-secret-bound authenticated encryption key.

    Django signing authenticates data but its payload is base64-readable.  The
    selector token also carries an internal profile key, so use authenticated
    encryption to keep it opaque in markup and fallback URLs.
    """
    material = hashlib.sha256(f"{settings.SECRET_KEY}:{TOKEN_SALT}".encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(material))


def resolve_student_selection_token(actor, workflow: str, token: object):
    if not isinstance(token, str) or not workflow_allowed(actor, workflow):
        return None
    try:
        payload = json.loads(_selection_fernet().decrypt(token.encode("ascii"), ttl=TOKEN_MAX_AGE).decode("utf-8"))
    except (InvalidToken, UnicodeError, ValueError, TypeError):
        return None
    if not isinstance(payload, dict) or payload.get("actor") != actor.pk or payload.get("workflow") != workflow:
        return None
    student_pk = payload.get("student")
    if not isinstance(student_pk, int):
        return None
    # Query current scope again; the signed result is not an authorization grant.
    return visible_students_for_workflow(actor, workflow).filter(pk=student_pk).first()


def selector_result(student_profile, *, actor, workflow: str) -> dict:
    return {
        "token": issue_student_selection_token(actor, workflow, student_profile),
        "label": office_student_display_label(student_profile),
    }
