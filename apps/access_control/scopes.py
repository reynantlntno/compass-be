"""Side-effect-free coverage and account-grant scope primitives."""

from django.db.models import Q, QuerySet
from django.utils import timezone

from apps.access_control.authority import matching_grants, build_authority_context
from apps.access_control.capabilities import Capability
from apps.access_control.choices import GrantStatus, ScopeMode
from apps.access_control.models import CounselorCoverage, WorkflowAuthorityGrant
from apps.access_control.rules import is_active_nonlegacy_actor, is_counselor, is_gco_staff


SCOPE_FIELDS = ("campus", "college", "department", "program")


def get_live_counselor_coverages(counselor=None, *, on_date=None) -> QuerySet:
    effective_date = on_date or timezone.localdate()
    coverages = CounselorCoverage.objects.filter(
        counselor__is_active=True, counselor__is_superuser=False,
        is_active=True, starts_at__lte=effective_date,
    ).filter(Q(ends_at__isnull=True) | Q(ends_at__gte=effective_date))
    return coverages.filter(counselor=counselor) if counselor is not None else coverages


def scope_matches_student_profile(scope, student_profile) -> bool:
    if student_profile is None:
        return False
    return all(
        not getattr(scope, field, None) or getattr(scope, field, None) == getattr(student_profile, field, None)
        for field in SCOPE_FIELDS
    )


def build_scope_match_q(target, *, require_non_empty=False) -> Q:
    """Build the database equivalent of ``scope_matches_student_profile``.

    A blank scope value is a wildcard, while a non-blank scope value must
    equal the concrete target.  When ``require_non_empty`` is true, at least
    one scope dimension must be populated; this is required for explicit
    organization grants so malformed rows can never become office-wide.
    """
    if target is None and not require_non_empty:
        return Q(pk__in=[])

    match_q = Q()
    populated_q = Q(pk__in=[])
    for field in SCOPE_FIELDS:
        if target is not None:
            value = getattr(target, field, None) or ""
            field_q = Q(**{f"{field}__isnull": True}) | Q(**{field: ""})
            if value:
                field_q |= Q(**{field: value})
            match_q &= field_q
        populated_q |= (Q(**{f"{field}__isnull": False}) & ~Q(**{field: ""}))

    return match_q & populated_q if require_non_empty else match_q


def build_geographic_scope_q(scopes, field_map: dict[str, str]) -> Q:
    scoped_q = None
    for scope in scopes:
        item_q = Q()
        for scope_field, model_field in field_map.items():
            value = getattr(scope, scope_field, None)
            if value:
                item_q &= Q(**{model_field: value})
        if not item_q:
            return Q()
        scoped_q = item_q if scoped_q is None else scoped_q | item_q
    return scoped_q if scoped_q is not None else Q(pk__in=[])


def counselor_has_live_coverage_for_student(counselor, student_profile, *, on_date=None) -> bool:
    if not is_active_nonlegacy_actor(counselor) or not is_counselor(counselor):
        return False
    return any(scope_matches_student_profile(row, student_profile)
               for row in get_live_counselor_coverages(counselor, on_date=on_date))


def get_active_workflow_authority_grants(grantee, *, capability=None, on_date=None) -> QuerySet:
    """Return active, dated grants for one account and optional capability."""
    if not is_active_nonlegacy_actor(grantee):
        return WorkflowAuthorityGrant.objects.none()
    if not (is_counselor(grantee) or is_gco_staff(grantee)):
        return WorkflowAuthorityGrant.objects.none()
    effective = on_date or timezone.localdate()
    query = WorkflowAuthorityGrant.objects.filter(
        grantee=grantee, grantee__is_active=True, status=GrantStatus.ACTIVE,
        valid_from__lte=effective,
    ).filter(Q(valid_until__isnull=True) | Q(valid_until__gte=effective))
    if capability:
        value = capability.value if isinstance(capability, Capability) else str(capability)
        query = query.filter(capability=value)
    return query


def has_active_workflow_authority(grantee, *, capability, target=None, on_date=None) -> bool:
    context = build_authority_context(grantee, on_date=on_date)
    return bool(matching_grants(context, capability, target=target))


def workflow_authority_authorizes_record(grantee, *, capability, student_profile=None,
                                         assigned_counselor=None, on_date=None) -> bool:
    # Build a small immutable-looking target carrying both organizational
    # scope and assignment ownership.  Passing only StudentProfile would make
    # ASSIGNED_RECORDS grants indistinguishable from any in-scope student.
    target = type("AuthorityRecordTarget", (), {})()
    for field in SCOPE_FIELDS:
        setattr(target, field, getattr(student_profile, field, None) if student_profile is not None else None)
    assigned_id = getattr(assigned_counselor, "pk", assigned_counselor)
    target.assigned_counselor_id = assigned_id
    target.assigned_reviewer_id = assigned_id
    context = build_authority_context(grantee, on_date=on_date)
    for grant in matching_grants(context, capability, target=target):
        return True
    return False


def build_workflow_authority_scope_q(grantee, *, capability, field_map: dict[str, str],
                                     counselor_field: str | None = None,
                                     context=None) -> Q:
    """Build a queryset scope for the actor's current authority snapshot.

    ``COUNSELOR_COVERAGE`` grants are the intersection of the live coverage
    rows and any narrower organization values on the grant.  Earlier versions
    treated such grants as an empty queryset because they had no literal
    organization fields to put in a ``Q`` expression.  Keeping this
    translation here makes list selectors and object policies use the same
    scope semantics without exposing ORM models as authorization state.
    """
    context = context or build_authority_context(grantee)
    scoped_q = None
    for grant in matching_grants(context, capability):
        if grant.scope_mode == ScopeMode.OFFICE_WIDE.value:
            return Q()

        if grant.scope_mode == ScopeMode.ASSIGNED_RECORDS.value:
            if not counselor_field:
                continue
            item_q = Q(**{counselor_field: grantee.pk})
            scoped_q = item_q if scoped_q is None else scoped_q | item_q
            continue

        if grant.scope_mode == ScopeMode.COUNSELOR_COVERAGE.value:
            coverages = context.coverages
            for coverage in coverages:
                item_q = Q()
                compatible = True
                for scope_field, model_field in field_map.items():
                    grant_value = getattr(grant, scope_field, None)
                    coverage_value = getattr(coverage, scope_field, None)
                    if grant_value and coverage_value and grant_value != coverage_value:
                        compatible = False
                        break
                    value = grant_value or coverage_value
                    if value:
                        item_q &= Q(**{model_field: value})
                if compatible and item_q:
                    scoped_q = item_q if scoped_q is None else scoped_q | item_q
            continue

        # EXPLICIT_ORGANIZATION: a validated grant must contain at least one
        # organization value.  An empty expression is never interpreted as
        # office-wide.
        item_q = Q()
        has_scope_value = False
        for grant_field, model_field in field_map.items():
            value = getattr(grant, grant_field, None)
            if value:
                has_scope_value = True
                item_q &= Q(**{model_field: value})
        if has_scope_value:
            scoped_q = item_q if scoped_q is None else scoped_q | item_q
    return scoped_q if scoped_q is not None else Q(pk__in=[])
