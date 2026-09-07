"""Inventory-to-Support-Needs mapping owned by the orchestration boundary.

This module is the only place where raw Inventory answers are read to derive
support-need candidates.  Its output is a bounded candidate DTO (safe codes,
section names, and observed categories); raw answers never cross into the
Support Needs domain, events, audits, or API responses.
"""

from __future__ import annotations

from dataclasses import dataclass

from apps.common.exceptions import ValidationError


SUPPORT_CONTEXT_MAPPING_VERSION = "support-needs-v1"

# Controlled response values accepted from the support_context section.
_POSITIVE_RESPONSE = "YES"
_SOURCE_CHANGED_RESPONSES = frozenset({"NO", "DECLINE_TO_ANSWER"})

INVENTORY_SUPPORT_MAPPINGS = {
    "pwd_status": {
        "support_need_key": "pwd_disability",
        "category": "disability_support",
        "source_field": "pwd_support",
    },
    "indigenous_peoples_status": {
        "support_need_key": "indigenous_peoples",
        "category": "household_support",
        "source_field": "indigenous_peoples_affiliation",
    },
    "solo_parent_status": {
        "support_need_key": "solo_parent_household",
        "category": "household_support",
        "source_field": "solo_parent_household",
    },
}


@dataclass(frozen=True)
class InventorySupportCandidate:
    """Bounded candidate DTO; carries no raw answer content."""

    response_field: str
    support_need_key: str
    category: str
    source_field: str
    response: str

    @property
    def is_positive(self) -> bool:
        return self.response == _POSITIVE_RESPONSE

    @property
    def is_source_changed(self) -> bool:
        return self.response in _SOURCE_CHANGED_RESPONSES


def build_support_need_candidates(answers: dict) -> list[InventorySupportCandidate]:
    """Derive bounded candidates from already-read confidential answers."""

    if not isinstance(answers, dict):
        raise ValidationError("Inventory confidential source is unavailable.")
    support_context = answers.get("support_context") or {}
    if not isinstance(support_context, dict):
        raise ValidationError("Inventory support mapping is unavailable.")
    if support_context.get("mapping_version") != SUPPORT_CONTEXT_MAPPING_VERSION:
        raise ValidationError("Inventory support mapping is unavailable.")

    candidates = []
    for response_field, mapping in INVENTORY_SUPPORT_MAPPINGS.items():
        response = support_context.get(response_field)
        if response in (None, ""):
            continue
        if response not in {_POSITIVE_RESPONSE} | set(_SOURCE_CHANGED_RESPONSES):
            continue
        candidates.append(
            InventorySupportCandidate(
                response_field=response_field,
                support_need_key=mapping["support_need_key"],
                category=mapping["category"],
                source_field=mapping["source_field"],
                response=str(response),
            )
        )
    return candidates


def build_candidate_evidence(
    *, snapshot_meta: dict, submission_sequence, candidate: InventorySupportCandidate
) -> dict:
    """Build only bounded provenance/evidence codes for an Inventory source.

    ``snapshot_meta`` carries safe metadata only: academic year, schema
    version.  Raw answers are never accepted here.
    """

    return {
        "source_section": "SUPPORT_CONTEXT",
        "source_field": candidate.source_field,
        "observed_category": "reported_yes",
        "academic_year": snapshot_meta["academic_year"],
        "schema_version": snapshot_meta["schema_version"],
        "mapping_version": SUPPORT_CONTEXT_MAPPING_VERSION,
        "submission_sequence": submission_sequence,
    }


def build_source_label(*, academic_year: str, schema_version: str) -> str:
    return f"AY {academic_year} (Inventory {schema_version})"
