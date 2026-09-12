"""The single, code-owned COMPASS authority catalog.

Roles establish eligibility and inherent work. Optional workflow authority is
granted to an individual account through ``WorkflowAuthorityGrant``. The
catalog is the only place that describes which authority sources can satisfy
an action; domain ownership, counselor relationships, privacy grants, and
technical system context remain outside this resolver.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from apps.accounts.models import RoleChoices
from apps.access_control.choices import ScopeMode


class AuthoritySource(str, Enum):
    COUNSELOR_BASELINE = "COUNSELOR_BASELINE"
    HEAD_FIXED = "HEAD_FIXED"
    IT_FIXED = "IT_FIXED"
    ACCOUNT_GRANT = "ACCOUNT_GRANT"


class Capability(str, Enum):
    """Stable dotted identifiers used by policies and the authority API."""

    STUDENT_RECORDS_VIEW_SCOPED = "student_support_needs.view_scoped"
    STUDENT_RECORDS_VIEW_INSTITUTION = "student_support_needs.view_institution"
    REPORTS_VIEW_DEFINITIONS = "reports.view_definitions"
    REPORTS_RUN = "reports.run"
    REPORTS_VIEW_INSTITUTION = "reports.view_institution"
    REPORTS_VIEW_SENSITIVE_AGGREGATES = "reports.view_sensitive_aggregates"
    REPORTS_DEFINITIONS_MANAGE = "reports.definitions.manage"
    REPORTS_EXPORT_REQUEST = "reports.export.request"
    REPORTS_EXPORT_APPROVE = "reports.export.approve"
    REPORTS_EXPORT_OPERATE = "reports.export.operate"
    REPORTS_EXPORT_MAINTAIN = "reports.export.maintain"
    COUNSELOR_COVERAGE_MANAGE = "counselor_coverage.manage"
    WORKFLOW_AUTHORITY_MANAGE = "workflow_authority.manage"
    TOKENS_REVOKE = "tokens.revoke"
    SYSTEM_ERRORS_VIEW = "system.errors.view"
    AUDIT_VIEW = "audit.view"

    COUNSELING_SESSIONS_QUEUE_VIEW = "counseling.sessions.queue.view"
    INVENTORY_QUEUE_VIEW = "inventory.queue.view"
    EXIT_INTERVIEWS_QUEUE_VIEW = "exit_interviews.queue.view"
    REFERRALS_QUEUE_VIEW = "referrals.queue.view"
    CALL_SLIPS_QUEUE_VIEW = "call_slips.queue.view"
    COUNSELING_SESSION_METADATA_VIEW_INSTITUTION = "counseling_sessions.metadata.view_institution"
    COUNSELING_SESSION_ASSIGN = "counseling_sessions.assign"
    COUNSELING_SESSION_LOCK = "counseling_sessions.lock"
    ROUTINE_INTERVIEW_REOPEN = "routine_interviews.reopen"
    COUNSELING_CASE_COLLABORATION_MANAGE = "counseling_cases.collaboration.manage"
    ECOUNSELING_PARTICIPANTS_MANAGE = "ecounseling.participants.manage"
    URGENT_SUPPORT_TEMPORARY_ACCESS_MANAGE = "urgent_support.temporary_access.manage"
    FORM_COLLECTION_MANAGE = "form_collection.manage"
    GRADUATE_TRACER_COLLECTION_MANAGE = "graduate_tracer.collection.manage"
    ORGANIZATION_GOVERNANCE_MANAGE = "organization_governance.manage"
    DOCUMENT_TEMPLATES_MANAGE = "document_templates.manage"
    STUDENT_IMPORTS_APPROVE = "student_imports.approve"
    STUDENT_IMPORTS_EXECUTE = "student_imports.execute"
    WORKFLOW_METADATA_VIEW = "workflow.metadata.view"
    APPOINTMENTS_AVAILABILITY_MANAGE = "appointments.availability.manage"
    OFFICE_CLOSURES_MANAGE = "office_closures.manage"
    CONTENT_INSTITUTION_MANAGE = "content.institution.manage"
    STAFF_ACCOUNTS_MANAGE = "staff_accounts.manage"
    HEAD_GUIDANCE_DESIGNATION_MANAGE = "head_guidance_designation.manage"

    APPOINTMENTS_ASSIGN = "appointments.assign"
    APPOINTMENTS_QUEUE_VIEW = "appointments.queue.view"
    APPOINTMENTS_REVIEW = "appointments.review"
    APPOINTMENTS_SCHEDULE = "appointments.schedule"
    APPOINTMENTS_CANCEL = "appointments.cancel"
    APPOINTMENTS_OUTCOME_MANAGE = "appointments.outcome.manage"
    REFERRALS_ASSIGN = "referrals.assign"
    REFERRALS_REASSIGN = "referrals.reassign"
    REFERRALS_CLOSE = "referrals.close"
    REFERRALS_REOPEN = "referrals.reopen"
    REFERRALS_INTAKE = "referrals.intake"
    REFERRALS_ROUTE = "referrals.route"
    REFERRALS_QUEUE_PROCESS = "referrals.queue.process"
    REFERRALS_CANCEL = "referrals.cancel"
    CALL_SLIPS_ASSIGN = "call_slips.assign"
    CALL_SLIPS_REASSIGN = "call_slips.reassign"
    CALL_SLIPS_PREPARE = "call_slips.prepare"
    CALL_SLIPS_ISSUE = "call_slips.issue"
    CALL_SLIPS_RESCHEDULE_DECIDE = "call_slips.reschedule.decide"
    CALL_SLIPS_ATTENDANCE_RECORD = "call_slips.attendance.record"
    CALL_SLIPS_CANCEL = "call_slips.cancel"

    GOOD_MORAL_REVIEW = "good_moral.review"
    GOOD_MORAL_REJECT = "good_moral.reject"
    GOOD_MORAL_APPROVE = "good_moral.approve"
    GOOD_MORAL_VOID = "good_moral.void"
    GOOD_MORAL_SUPERSEDE = "good_moral.supersede"
    GOOD_MORAL_ARCHIVE = "good_moral.archive"
    GOOD_MORAL_RECEIPT_ENCODE = "good_moral.receipt.encode"
    GOOD_MORAL_RECEIPT_VERIFY = "good_moral.receipt.verify"
    GOOD_MORAL_CANCEL = "good_moral.cancel"
    GOOD_MORAL_DOCUMENT_GENERATE = "good_moral.document.generate"
    GOOD_MORAL_PRINT = "good_moral.print"
    GOOD_MORAL_REGISTRAR_SEAL_CONFIRM = "good_moral.registrar_seal.confirm"
    GOOD_MORAL_RELEASE = "good_moral.release"

    EXIT_INTERVIEWS_PROCESS = "exit_interviews.process"
    EXIT_INTERVIEWS_ACKNOWLEDGE = "exit_interviews.acknowledge"
    EXIT_INTERVIEWS_ASSIGN = "exit_interviews.assign"
    EXIT_INTERVIEWS_REOPEN = "exit_interviews.reopen"
    EXIT_INTERVIEWS_VOID = "exit_interviews.void"
    EXIT_INTERVIEWS_ARCHIVE = "exit_interviews.archive"
    GRADUATE_TRACER_PROCESS = "graduate_tracer.process"
    GRADUATE_TRACER_REOPEN = "graduate_tracer.reopen"
    GRADUATE_TRACER_VOID = "graduate_tracer.void"
    GRADUATE_TRACER_ARCHIVE = "graduate_tracer.archive"

    CONTENT_LOCAL_VIEW = "content.local.view"
    CONTENT_LOCAL_PREPARE = "content.local.prepare"
    CONTENT_LOCAL_PUBLISH = "content.local.publish"
    CONTENT_LOCAL_SCHEDULE = "content.local.schedule"
    CONTENT_LOCAL_ARCHIVE = "content.local.archive"
    CONTACT_QUEUE_TRIAGE = "contact_queue.triage"
    CONTACT_QUEUE_ASSIGN = "contact_queue.assign"
    CONTACT_REPLY_PREPARE = "contact_reply.prepare"
    CONTACT_REPLY_APPROVE = "contact_reply.approve"
    CONTACT_QUEUE_CLOSE = "contact_queue.close"
    STUDENT_IMPORTS_PREPARE = "student_imports.prepare"
    STUDENT_IMPORTS_REVIEW = "student_imports.review"
    STUDENT_ACTIVATION_INVITATIONS_MANAGE = "student_activation.invitations.manage"
    STUDENT_ACTIVATION_DELIVERY_OPERATE = "student_activation.delivery.operate"
    ASSESSMENTS_REVIEW = "assessments.review"
    ASSESSMENTS_RELEASE = "assessments.release"
    ASSESSMENTS_LIFECYCLE_MANAGE = "assessments.lifecycle.manage"
    SUPPORT_NEEDS_VERIFY = "support_needs.verify"
    SUPPORT_NEEDS_DISPUTE = "support_needs.dispute"
    SUPPORT_NEEDS_ARCHIVE = "support_needs.archive"
    INVENTORY_CORRECTION_REVIEW = "inventory.correction.review"
    INVENTORY_REOPEN = "inventory.reopen"
    COUNSELING_CASES_ASSIGN = "counseling_cases.assign"
    COUNSELING_CASES_CLOSE = "counseling_cases.close"
    COUNSELING_CASES_REOPEN = "counseling_cases.reopen"
    URGENT_SUPPORT_QUEUE_REVIEW = "urgent_support.queue.review"
    URGENT_SUPPORT_ASSIGN = "urgent_support.assign"
    URGENT_SUPPORT_LIFECYCLE_MANAGE = "urgent_support.lifecycle.manage"

    # Technical-only fixed authority.
    ACCOUNT_SECURITY_RECOVERY_ASSIST = "account_security.recovery.assist"
    BACKUPS_VIEW = "backups.view"
    BACKUPS_OPERATE = "backups.operate"
    RESTORES_OPERATE = "restores.operate"
    SYSTEM_HEALTH_VIEW = "system.health.view"
    SYSTEM_ENVIRONMENT_VIEW = "system.environment.view"
    SYSTEM_OPERATIONS_MANAGE = "system.operations.manage"
    NOTIFICATIONS_DELIVERY_OPERATE = "notifications.delivery.operate"
    PROTECTED_FILES_METADATA_INSPECT = "protected_files.metadata.inspect"
    FIELD_ENCRYPTION_OPERATE = "field_encryption.operate"
    CONTENT_DELIVERY_METADATA_VIEW = "content.delivery_metadata.view"
    DOCUMENTS_TECHNICAL_METADATA_VIEW = "documents.technical_metadata.view"
    PRIVACY_INCIDENTS_TECHNICAL_OPERATE = "privacy_incidents.technical.operate"


ROLE_COUNSELOR = RoleChoices.COUNSELOR
ROLE_GCO_STAFF = RoleChoices.GCO_STAFF
ROLE_IT_ADMIN = RoleChoices.IT_ADMIN
ROLE_STUDENT = RoleChoices.STUDENT

_COUNSELOR_SCOPE = frozenset({ScopeMode.COUNSELOR_COVERAGE, ScopeMode.ASSIGNED_RECORDS})
_GCO_SCOPE = frozenset({ScopeMode.EXPLICIT_ORGANIZATION, ScopeMode.ASSIGNED_RECORDS, ScopeMode.OFFICE_WIDE})
_OFFICE_SCOPE = frozenset({ScopeMode.OFFICE_WIDE})


@dataclass(frozen=True)
class CapabilitySpec:
    capability: Capability
    authority_sources: frozenset[AuthoritySource]
    grant_eligible_roles: frozenset
    grant_scope_modes: frozenset[ScopeMode]
    office_wide_grant_allowed: bool = False
    expiry_required: bool = False
    sensitivity: str = "operational"
    impact_scope: str = "scoped"
    ui_bundle: str = "general"


_definitions: dict[Capability, dict] = {}


def _declare(capabilities, *, sources, grant_roles=(), grant_scopes=(), expiry=False,
             sensitivity="operational", impact="scoped", bundle="general", office_wide=False):
    for capability in capabilities:
        prior = _definitions.get(capability)
        if prior is None:
            prior = {
                "authority_sources": frozenset(),
                "grant_eligible_roles": frozenset(),
                "grant_scope_modes": frozenset(),
                "office_wide_grant_allowed": False,
                "expiry_required": False,
                "sensitivity": "operational",
                "impact_scope": "scoped",
                "ui_bundle": "general",
            }
        _definitions[capability] = {
            "authority_sources": prior["authority_sources"] | frozenset(sources),
            "grant_eligible_roles": prior["grant_eligible_roles"] | frozenset(grant_roles),
            "grant_scope_modes": prior["grant_scope_modes"] | frozenset(grant_scopes),
            "office_wide_grant_allowed": prior["office_wide_grant_allowed"] or office_wide,
            "expiry_required": prior["expiry_required"] or expiry,
            "sensitivity": sensitivity if sensitivity != "operational" else prior["sensitivity"],
            "impact_scope": impact if impact != "scoped" else prior["impact_scope"],
            "ui_bundle": bundle if bundle != "general" else prior["ui_bundle"],
        }


_declare(
    (Capability.STUDENT_RECORDS_VIEW_SCOPED, Capability.COUNSELING_SESSIONS_QUEUE_VIEW),
    sources={AuthoritySource.COUNSELOR_BASELINE}, bundle="students",
)
_declare(
    (Capability.INVENTORY_QUEUE_VIEW,),
    sources={AuthoritySource.COUNSELOR_BASELINE}, bundle="forms",
)
_declare(
    (Capability.EXIT_INTERVIEWS_QUEUE_VIEW,),
    sources={AuthoritySource.COUNSELOR_BASELINE, AuthoritySource.ACCOUNT_GRANT},
    grant_roles={ROLE_GCO_STAFF}, grant_scopes=_GCO_SCOPE, bundle="forms",
)
_declare(
    (Capability.REFERRALS_QUEUE_VIEW,),
    sources={AuthoritySource.COUNSELOR_BASELINE, AuthoritySource.ACCOUNT_GRANT},
    grant_roles={ROLE_GCO_STAFF}, grant_scopes=_GCO_SCOPE, bundle="referrals",
)
_declare(
    (Capability.CALL_SLIPS_QUEUE_VIEW,),
    sources={AuthoritySource.COUNSELOR_BASELINE, AuthoritySource.ACCOUNT_GRANT},
    grant_roles={ROLE_GCO_STAFF}, grant_scopes=_GCO_SCOPE, bundle="call_slips",
)
_declare(
    (Capability.APPOINTMENTS_QUEUE_VIEW,),
    sources={
        AuthoritySource.COUNSELOR_BASELINE,
        AuthoritySource.HEAD_FIXED,
        AuthoritySource.ACCOUNT_GRANT,
    },
    grant_roles={ROLE_GCO_STAFF},
    grant_scopes=_GCO_SCOPE,
    bundle="appointments",
)
_declare(
    (Capability.REPORTS_VIEW_DEFINITIONS, Capability.REPORTS_RUN),
    sources={AuthoritySource.COUNSELOR_BASELINE, AuthoritySource.ACCOUNT_GRANT},
    grant_roles={ROLE_GCO_STAFF}, grant_scopes=_GCO_SCOPE, bundle="reports", office_wide=True,
)
_declare(
    (Capability.STUDENT_RECORDS_VIEW_INSTITUTION, Capability.COUNSELOR_COVERAGE_MANAGE,
     Capability.WORKFLOW_AUTHORITY_MANAGE, Capability.COUNSELING_SESSION_METADATA_VIEW_INSTITUTION,
     Capability.COUNSELING_SESSION_ASSIGN, Capability.COUNSELING_SESSION_LOCK,
     Capability.ROUTINE_INTERVIEW_REOPEN, Capability.COUNSELING_CASE_COLLABORATION_MANAGE,
     Capability.ECOUNSELING_PARTICIPANTS_MANAGE, Capability.URGENT_SUPPORT_TEMPORARY_ACCESS_MANAGE,
     Capability.FORM_COLLECTION_MANAGE, Capability.GRADUATE_TRACER_COLLECTION_MANAGE,
     Capability.ORGANIZATION_GOVERNANCE_MANAGE, Capability.DOCUMENT_TEMPLATES_MANAGE,
     Capability.STUDENT_IMPORTS_APPROVE, Capability.STUDENT_IMPORTS_EXECUTE,
     Capability.WORKFLOW_METADATA_VIEW, Capability.APPOINTMENTS_AVAILABILITY_MANAGE,
     Capability.OFFICE_CLOSURES_MANAGE, Capability.CONTENT_INSTITUTION_MANAGE,
     Capability.STAFF_ACCOUNTS_MANAGE, Capability.HEAD_GUIDANCE_DESIGNATION_MANAGE),
    sources={AuthoritySource.HEAD_FIXED}, impact="institution", sensitivity="governance", bundle="head",
)
_declare(
    (Capability.AUDIT_VIEW,),
    sources={AuthoritySource.HEAD_FIXED}, impact="institution", sensitivity="sensitive", bundle="audit",
)
_declare(
    (Capability.REPORTS_VIEW_INSTITUTION, Capability.REPORTS_VIEW_SENSITIVE_AGGREGATES,
     Capability.REPORTS_DEFINITIONS_MANAGE, Capability.REPORTS_EXPORT_APPROVE),
    sources={AuthoritySource.HEAD_FIXED}, sensitivity="sensitive", impact="institution", bundle="reports",
)
_declare(
    (Capability.REPORTS_EXPORT_REQUEST, Capability.REPORTS_EXPORT_OPERATE),
    sources={AuthoritySource.HEAD_FIXED, AuthoritySource.ACCOUNT_GRANT},
    grant_roles={ROLE_GCO_STAFF}, grant_scopes=_GCO_SCOPE,
    sensitivity="sensitive", bundle="reports", office_wide=True,
)

# Existing per-account values, preserved exactly. The registry, not these
# tuples, is the source of authorization truth; the tuples are declarations.
_COUNSELOR_ONLY = (
    Capability.APPOINTMENTS_ASSIGN, Capability.REFERRALS_ASSIGN, Capability.REFERRALS_REASSIGN,
    Capability.REFERRALS_CLOSE, Capability.REFERRALS_REOPEN, Capability.CALL_SLIPS_ASSIGN,
    Capability.CALL_SLIPS_REASSIGN, Capability.GOOD_MORAL_REVIEW, Capability.GOOD_MORAL_REJECT,
    Capability.GOOD_MORAL_APPROVE, Capability.GOOD_MORAL_VOID, Capability.GOOD_MORAL_SUPERSEDE,
    Capability.GOOD_MORAL_ARCHIVE, Capability.EXIT_INTERVIEWS_PROCESS, Capability.EXIT_INTERVIEWS_ACKNOWLEDGE,
    Capability.EXIT_INTERVIEWS_ASSIGN, Capability.EXIT_INTERVIEWS_REOPEN, Capability.EXIT_INTERVIEWS_VOID,
    Capability.EXIT_INTERVIEWS_ARCHIVE, Capability.GRADUATE_TRACER_PROCESS, Capability.GRADUATE_TRACER_REOPEN,
    Capability.GRADUATE_TRACER_VOID, Capability.GRADUATE_TRACER_ARCHIVE, Capability.CONTENT_LOCAL_PREPARE,
    Capability.CONTENT_LOCAL_PUBLISH, Capability.CONTENT_LOCAL_SCHEDULE, Capability.CONTENT_LOCAL_ARCHIVE,
    Capability.CONTACT_QUEUE_TRIAGE, Capability.CONTACT_QUEUE_ASSIGN, Capability.CONTACT_REPLY_PREPARE,
    Capability.CONTACT_REPLY_APPROVE, Capability.CONTACT_QUEUE_CLOSE, Capability.STUDENT_IMPORTS_PREPARE,
    Capability.STUDENT_IMPORTS_REVIEW, Capability.STUDENT_ACTIVATION_INVITATIONS_MANAGE,
    Capability.STUDENT_ACTIVATION_DELIVERY_OPERATE, Capability.ASSESSMENTS_REVIEW, Capability.ASSESSMENTS_RELEASE,
    Capability.ASSESSMENTS_LIFECYCLE_MANAGE, Capability.SUPPORT_NEEDS_VERIFY, Capability.SUPPORT_NEEDS_DISPUTE,
    Capability.SUPPORT_NEEDS_ARCHIVE, Capability.INVENTORY_CORRECTION_REVIEW, Capability.INVENTORY_REOPEN,
    Capability.COUNSELING_CASES_ASSIGN, Capability.COUNSELING_CASES_CLOSE, Capability.COUNSELING_CASES_REOPEN,
    Capability.URGENT_SUPPORT_QUEUE_REVIEW, Capability.URGENT_SUPPORT_ASSIGN, Capability.URGENT_SUPPORT_LIFECYCLE_MANAGE,
    # Local counselors may be granted the same scoped Good Moral operational
    # actions as GCO Staff when the office workflow assigns those duties.
    Capability.GOOD_MORAL_RECEIPT_ENCODE, Capability.GOOD_MORAL_RECEIPT_VERIFY,
    Capability.GOOD_MORAL_CANCEL, Capability.GOOD_MORAL_DOCUMENT_GENERATE,
    Capability.GOOD_MORAL_PRINT, Capability.GOOD_MORAL_REGISTRAR_SEAL_CONFIRM,
    Capability.GOOD_MORAL_RELEASE,
)
_GCO_ONLY = (
    Capability.APPOINTMENTS_REVIEW, Capability.APPOINTMENTS_SCHEDULE, Capability.APPOINTMENTS_CANCEL,
    Capability.APPOINTMENTS_OUTCOME_MANAGE, Capability.REFERRALS_INTAKE, Capability.REFERRALS_ROUTE,
    Capability.REFERRALS_QUEUE_PROCESS, Capability.REFERRALS_CANCEL, Capability.CALL_SLIPS_PREPARE,
    Capability.CALL_SLIPS_ISSUE, Capability.CALL_SLIPS_RESCHEDULE_DECIDE, Capability.CALL_SLIPS_ATTENDANCE_RECORD,
    Capability.CALL_SLIPS_CANCEL, Capability.GOOD_MORAL_RECEIPT_ENCODE, Capability.GOOD_MORAL_RECEIPT_VERIFY,
    Capability.GOOD_MORAL_CANCEL, Capability.GOOD_MORAL_DOCUMENT_GENERATE, Capability.GOOD_MORAL_PRINT,
    Capability.GOOD_MORAL_REGISTRAR_SEAL_CONFIRM, Capability.GOOD_MORAL_RELEASE, Capability.EXIT_INTERVIEWS_PROCESS,
    Capability.EXIT_INTERVIEWS_REOPEN, Capability.GRADUATE_TRACER_PROCESS, Capability.CONTENT_LOCAL_VIEW,
    Capability.CONTENT_LOCAL_PREPARE, Capability.CONTENT_LOCAL_PUBLISH, Capability.CONTENT_LOCAL_SCHEDULE,
    Capability.CONTENT_LOCAL_ARCHIVE, Capability.CONTACT_QUEUE_TRIAGE, Capability.CONTACT_REPLY_PREPARE,
    Capability.CONTACT_QUEUE_CLOSE, Capability.REPORTS_VIEW_DEFINITIONS, Capability.REPORTS_RUN,
    Capability.REPORTS_EXPORT_REQUEST, Capability.REPORTS_EXPORT_OPERATE,
)
_high_risk = frozenset({
    Capability.GOOD_MORAL_APPROVE, Capability.GOOD_MORAL_RELEASE, Capability.EXIT_INTERVIEWS_REOPEN,
    Capability.GRADUATE_TRACER_REOPEN, Capability.ASSESSMENTS_RELEASE, Capability.ASSESSMENTS_LIFECYCLE_MANAGE,
    Capability.URGENT_SUPPORT_ASSIGN, Capability.URGENT_SUPPORT_LIFECYCLE_MANAGE, Capability.CONTACT_REPLY_APPROVE,
    Capability.APPOINTMENTS_SCHEDULE, Capability.APPOINTMENTS_CANCEL, Capability.APPOINTMENTS_OUTCOME_MANAGE,
    Capability.GOOD_MORAL_DOCUMENT_GENERATE, Capability.GOOD_MORAL_VOID, Capability.GOOD_MORAL_SUPERSEDE,
    Capability.GOOD_MORAL_REGISTRAR_SEAL_CONFIRM,
    Capability.REPORTS_EXPORT_REQUEST, Capability.REPORTS_EXPORT_OPERATE,
})
_GCO_OFFICE_WIDE = frozenset({
    Capability.APPOINTMENTS_REVIEW, Capability.APPOINTMENTS_SCHEDULE, Capability.APPOINTMENTS_CANCEL,
    Capability.APPOINTMENTS_OUTCOME_MANAGE, Capability.REFERRALS_INTAKE, Capability.REFERRALS_ROUTE,
    Capability.REFERRALS_QUEUE_PROCESS, Capability.REFERRALS_CANCEL, Capability.CALL_SLIPS_PREPARE,
    Capability.CALL_SLIPS_ISSUE, Capability.CALL_SLIPS_RESCHEDULE_DECIDE, Capability.CALL_SLIPS_ATTENDANCE_RECORD,
    Capability.CALL_SLIPS_CANCEL, Capability.GOOD_MORAL_RECEIPT_ENCODE, Capability.GOOD_MORAL_RECEIPT_VERIFY,
    Capability.GOOD_MORAL_CANCEL, Capability.GOOD_MORAL_DOCUMENT_GENERATE, Capability.GOOD_MORAL_PRINT,
    Capability.GOOD_MORAL_REGISTRAR_SEAL_CONFIRM, Capability.GOOD_MORAL_RELEASE, Capability.EXIT_INTERVIEWS_PROCESS,
    Capability.EXIT_INTERVIEWS_REOPEN, Capability.GRADUATE_TRACER_PROCESS, Capability.CONTACT_QUEUE_TRIAGE,
    Capability.CONTACT_REPLY_PREPARE, Capability.CONTACT_QUEUE_CLOSE, Capability.REPORTS_VIEW_DEFINITIONS,
    Capability.REPORTS_RUN, Capability.REPORTS_EXPORT_REQUEST,
})

# The operational catalogs are explicitly declared by source and role. Shared
# capabilities are declared once for both eligible grantee roles.
for cap in set(_COUNSELOR_ONLY) & set(_GCO_ONLY):
    _declare((cap,), sources={AuthoritySource.HEAD_FIXED, AuthoritySource.ACCOUNT_GRANT},
             grant_roles={ROLE_COUNSELOR, ROLE_GCO_STAFF}, grant_scopes=_COUNSELOR_SCOPE | _GCO_SCOPE,
             expiry=cap in _high_risk, bundle=cap.value.split(".", 1)[0], office_wide=cap in _GCO_OFFICE_WIDE)
for cap in set(_COUNSELOR_ONLY) - set(_GCO_ONLY):
    _declare((cap,), sources={AuthoritySource.HEAD_FIXED, AuthoritySource.ACCOUNT_GRANT},
             grant_roles={ROLE_COUNSELOR}, grant_scopes=_COUNSELOR_SCOPE,
             expiry=cap in _high_risk, bundle=cap.value.split(".", 1)[0])
for cap in set(_GCO_ONLY) - set(_COUNSELOR_ONLY):
    _declare((cap,), sources={AuthoritySource.HEAD_FIXED, AuthoritySource.ACCOUNT_GRANT},
             grant_roles={ROLE_GCO_STAFF}, grant_scopes=_GCO_SCOPE,
             expiry=cap in _high_risk, bundle=cap.value.split(".", 1)[0], office_wide=cap in _GCO_OFFICE_WIDE)

# Fixed technical authority. Template governance is intentionally not listed.
_declare(
    (Capability.TOKENS_REVOKE, Capability.SYSTEM_ERRORS_VIEW, Capability.STUDENT_IMPORTS_EXECUTE,
     Capability.AUDIT_VIEW,
     Capability.STUDENT_ACTIVATION_DELIVERY_OPERATE, Capability.WORKFLOW_METADATA_VIEW,
     Capability.ACCOUNT_SECURITY_RECOVERY_ASSIST, Capability.BACKUPS_VIEW, Capability.BACKUPS_OPERATE,
     Capability.RESTORES_OPERATE, Capability.SYSTEM_HEALTH_VIEW, Capability.SYSTEM_ENVIRONMENT_VIEW,
     Capability.SYSTEM_OPERATIONS_MANAGE, Capability.NOTIFICATIONS_DELIVERY_OPERATE,
     Capability.PROTECTED_FILES_METADATA_INSPECT, Capability.FIELD_ENCRYPTION_OPERATE,
     Capability.REPORTS_EXPORT_MAINTAIN, Capability.CONTENT_DELIVERY_METADATA_VIEW,
     Capability.DOCUMENTS_TECHNICAL_METADATA_VIEW, Capability.PRIVACY_INCIDENTS_TECHNICAL_OPERATE),
    sources={AuthoritySource.IT_FIXED}, grant_scopes=_OFFICE_SCOPE,
    sensitivity="technical", impact="technical", bundle="it",
)

CAPABILITY_SPECS = {
    cap: CapabilitySpec(capability=cap, **values)
    for cap, values in _definitions.items()
}

# All convenience sets are derived from the one registry.
COUNSELOR_DIRECT_CAPABILITIES = frozenset(
    cap for cap, spec in CAPABILITY_SPECS.items()
    if AuthoritySource.COUNSELOR_BASELINE in spec.authority_sources
)
HEAD_FIXED_CAPABILITIES = frozenset(
    cap for cap, spec in CAPABILITY_SPECS.items()
    if AuthoritySource.HEAD_FIXED in spec.authority_sources
)
IT_FIXED_CAPABILITIES = frozenset(
    cap for cap, spec in CAPABILITY_SPECS.items()
    if AuthoritySource.IT_FIXED in spec.authority_sources
)
ALL_DELEGABLE_CAPABILITIES = frozenset(
    cap for cap, spec in CAPABILITY_SPECS.items()
    if AuthoritySource.ACCOUNT_GRANT in spec.authority_sources
)
COUNSELOR_DELEGABLE = frozenset(
    cap for cap in ALL_DELEGABLE_CAPABILITIES
    if ROLE_COUNSELOR in CAPABILITY_SPECS[cap].grant_eligible_roles
)
GCO_DELEGABLE = frozenset(
    cap for cap in ALL_DELEGABLE_CAPABILITIES
    if ROLE_GCO_STAFF in CAPABILITY_SPECS[cap].grant_eligible_roles
)
NONDELEGABLE_CAPABILITIES = frozenset(
    cap for cap, spec in CAPABILITY_SPECS.items()
    if AuthoritySource.ACCOUNT_GRANT not in spec.authority_sources
)


def get_capability_spec(capability):
    try:
        cap = capability if isinstance(capability, Capability) else Capability(capability)
    except (TypeError, ValueError):
        return None
    return CAPABILITY_SPECS.get(cap)


def validate_capability_catalog():
    errors = []
    for cap in Capability:
        spec = CAPABILITY_SPECS.get(cap)
        if spec is None or not spec.authority_sources or not spec.ui_bundle:
            errors.append(f"Capability {cap.value} has an incomplete specification.")
        if spec and AuthoritySource.ACCOUNT_GRANT in spec.authority_sources:
            if not spec.grant_eligible_roles or not spec.grant_scope_modes:
                errors.append(f"Grant capability {cap.value} has incomplete grant metadata.")
            if spec.impact_scope == "institution":
                errors.append(f"Institution-wide capability {cap.value} cannot be an account grant.")
            if any(role not in {ROLE_COUNSELOR, ROLE_GCO_STAFF} for role in spec.grant_eligible_roles):
                errors.append(f"Grant capability {cap.value} has an invalid grantee role.")
    return errors


def effective_fixed_capabilities(role, *, is_head_guidance=False):
    """Derive fixed authority from the registry for an active actor context."""
    if role == ROLE_IT_ADMIN:
        sources = {AuthoritySource.IT_FIXED}
    elif role == ROLE_COUNSELOR:
        # Head Guidance is still a counselor.  Add the named supervisory
        # catalog to the ordinary counselor baseline; never replace it.
        sources = {AuthoritySource.COUNSELOR_BASELINE}
        if is_head_guidance:
            sources.add(AuthoritySource.HEAD_FIXED)
    else:
        return frozenset()
    return frozenset(
        cap for cap, spec in CAPABILITY_SPECS.items()
        if spec.authority_sources.intersection(sources)
    )
