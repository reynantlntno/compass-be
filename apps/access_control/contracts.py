"""Application-level authority-source contracts.

This is an architecture manifest, not a permission engine.  It records which
kind of authority a domain policy is allowed to consult so reviews and system
checks can detect accidental role or grant shortcuts.
"""

from enum import Enum


class AuthorityContractSource(str, Enum):
    OWNER = "OWNER"
    COUNSELOR_RELATIONSHIP = "COUNSELOR_RELATIONSHIP"
    CAPABILITY = "CAPABILITY"
    PRIVACY_AUTHORIZATION = "PRIVACY_AUTHORIZATION"
    TECHNICAL_FIXED = "TECHNICAL_FIXED"
    SYSTEM_CONTEXT = "SYSTEM_CONTEXT"
    PUBLIC_TOKEN = "PUBLIC_TOKEN"


_ALL = frozenset(AuthorityContractSource)

# Every policy-bearing app must name its accepted authority sources.  The
# catalog intentionally permits multiple sources because field sensitivity and
# resource ownership still belong to the domain policy.
AUTHORITY_CONTRACTS = {
    "access_control": frozenset({AuthorityContractSource.CAPABILITY, AuthorityContractSource.SYSTEM_CONTEXT}),
    "account_security": frozenset({AuthorityContractSource.OWNER, AuthorityContractSource.CAPABILITY, AuthorityContractSource.TECHNICAL_FIXED}),
    "audit": frozenset({AuthorityContractSource.CAPABILITY, AuthorityContractSource.PRIVACY_AUTHORIZATION, AuthorityContractSource.TECHNICAL_FIXED}),
    "accounts": frozenset({AuthorityContractSource.OWNER, AuthorityContractSource.SYSTEM_CONTEXT}),
    "appointments": frozenset({AuthorityContractSource.OWNER, AuthorityContractSource.COUNSELOR_RELATIONSHIP, AuthorityContractSource.CAPABILITY}),
    "assessments": frozenset({AuthorityContractSource.OWNER, AuthorityContractSource.COUNSELOR_RELATIONSHIP, AuthorityContractSource.CAPABILITY, AuthorityContractSource.TECHNICAL_FIXED}),
    "backups": frozenset({AuthorityContractSource.TECHNICAL_FIXED, AuthorityContractSource.SYSTEM_CONTEXT}),
    "call_slips": frozenset({AuthorityContractSource.OWNER, AuthorityContractSource.COUNSELOR_RELATIONSHIP, AuthorityContractSource.CAPABILITY}),
    "content": frozenset({AuthorityContractSource.PUBLIC_TOKEN, AuthorityContractSource.CAPABILITY}),
    "counseling": frozenset({AuthorityContractSource.OWNER, AuthorityContractSource.COUNSELOR_RELATIONSHIP, AuthorityContractSource.CAPABILITY}),
    "documents": frozenset({AuthorityContractSource.OWNER, AuthorityContractSource.CAPABILITY, AuthorityContractSource.TECHNICAL_FIXED}),
    "exit_interviews": frozenset({AuthorityContractSource.OWNER, AuthorityContractSource.COUNSELOR_RELATIONSHIP, AuthorityContractSource.CAPABILITY}),
    "feedback": frozenset({AuthorityContractSource.OWNER, AuthorityContractSource.COUNSELOR_RELATIONSHIP, AuthorityContractSource.CAPABILITY}),
    "form_collection": frozenset({AuthorityContractSource.OWNER, AuthorityContractSource.CAPABILITY, AuthorityContractSource.PUBLIC_TOKEN}),
    "good_moral": frozenset({AuthorityContractSource.OWNER, AuthorityContractSource.COUNSELOR_RELATIONSHIP, AuthorityContractSource.CAPABILITY}),
    "graduate_tracer": frozenset({AuthorityContractSource.OWNER, AuthorityContractSource.COUNSELOR_RELATIONSHIP, AuthorityContractSource.CAPABILITY}),
    "imports": frozenset({AuthorityContractSource.CAPABILITY, AuthorityContractSource.SYSTEM_CONTEXT}),
    "inventory": frozenset({AuthorityContractSource.OWNER, AuthorityContractSource.COUNSELOR_RELATIONSHIP, AuthorityContractSource.CAPABILITY}),
    "notifications": frozenset({AuthorityContractSource.OWNER, AuthorityContractSource.TECHNICAL_FIXED, AuthorityContractSource.SYSTEM_CONTEXT}),
    "organizations": frozenset({AuthorityContractSource.CAPABILITY, AuthorityContractSource.SYSTEM_CONTEXT}),
    "privacy": frozenset({AuthorityContractSource.OWNER, AuthorityContractSource.PRIVACY_AUTHORIZATION, AuthorityContractSource.TECHNICAL_FIXED, AuthorityContractSource.SYSTEM_CONTEXT}),
    "profiles": frozenset({AuthorityContractSource.OWNER, AuthorityContractSource.COUNSELOR_RELATIONSHIP, AuthorityContractSource.CAPABILITY}),
    "referrals": frozenset({AuthorityContractSource.OWNER, AuthorityContractSource.COUNSELOR_RELATIONSHIP, AuthorityContractSource.CAPABILITY}),
    "reports": frozenset({AuthorityContractSource.COUNSELOR_RELATIONSHIP, AuthorityContractSource.CAPABILITY, AuthorityContractSource.TECHNICAL_FIXED}),
    "student_activation": frozenset({AuthorityContractSource.OWNER, AuthorityContractSource.CAPABILITY, AuthorityContractSource.SYSTEM_CONTEXT}),
    "support_needs": frozenset({AuthorityContractSource.OWNER, AuthorityContractSource.COUNSELOR_RELATIONSHIP, AuthorityContractSource.CAPABILITY}),
    "system": frozenset({AuthorityContractSource.TECHNICAL_FIXED, AuthorityContractSource.SYSTEM_CONTEXT}),
    "workflow": frozenset({AuthorityContractSource.CAPABILITY, AuthorityContractSource.SYSTEM_CONTEXT}),
}


def validate_authority_contracts():
    errors = []
    for app_label, sources in AUTHORITY_CONTRACTS.items():
        if not sources:
            errors.append(f"Authority contract for {app_label} is empty.")
        unknown = set(sources) - _ALL
        if unknown:
            errors.append(f"Authority contract for {app_label} contains unknown sources.")
    return errors
