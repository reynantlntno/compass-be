# Project: COMPASS
# File: apps/reports/suppression.py
# Module: apps.reports
# Purpose: Small-count cell suppression and complementary disclosure protection

import json
import hashlib
import hmac
import copy
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from django.conf import settings
from django.utils import timezone
from apps.common.exceptions import ValidationError
from apps.reports.sensitivity import classify_field_sensitivity
from apps.reports.choices import FieldSensitivity, SuppressionMode

SUPPRESSION_LABEL = "Suppressed for privacy"
MIN_SUPPRESSION_THRESHOLD = 5

DEFAULT_COUNT_KEYS = [
    "count",
    "total_count",
    "cell_count",
    "submissions_count",
    "responses_count",
    "draft_count",
    "submitted_count",
    "reviewed_count",
    "closed_count",
    "spam_count",
    "issued",
    "opened",
    "verified",
    "draft_started",
    "submitted",
    "expired",
    "revoked",
    "linked",
    "total",
    "denominator",
]

DERIVED_METRIC_KEYS = {
    "avg_satisfaction",
    "avg_sqd",
    "average",
    "percentage",
    "rate",
    "ratio",
    "completion_rate",
    "employment_rate",
    "job_relevance_rate",
}

_SAFE_CATEGORY_KEY = re.compile(r"^[a-z][a-z0-9_]{0,79}$")
MAX_CONFIGURED_CATEGORY_KEYS = 100


@dataclass(frozen=True)
class ResolvedSuppressionPolicy:
    """Immutable, runtime-ready suppression settings for one report definition."""

    mode: SuppressionMode
    threshold: int
    count_keys: tuple[str, ...]
    sensitive_categories: tuple[str, ...]
    policy_id: str | None = None
    policy_effective_from: Any = None
    policy_effective_until: Any = None
    policy_source_reference: str | None = None


def normalize_suppression_categories(categories: Any) -> tuple[str, ...]:
    """Validate and normalize additive, report-output category keys.

    The configured list can add protected keys but can never remove the
    baseline ``DEFAULT_COUNT_KEYS``. Forbidden fields are rejected because a
    suppression policy must not become a side door for raw-data configuration.
    """

    if categories == []:
        return ()
    if not isinstance(categories, list):
        raise ValidationError("Sensitive categories must be a JSON list of output keys.")
    if len(categories) > MAX_CONFIGURED_CATEGORY_KEYS:
        raise ValidationError("Sensitive categories exceed the configured limit.")

    normalized = []
    for category in categories:
        if not isinstance(category, str):
            raise ValidationError("Sensitive category keys must be strings.")
        key = category.strip().lower()
        if not _SAFE_CATEGORY_KEY.fullmatch(key):
            raise ValidationError("Sensitive category keys must be bounded snake_case identifiers.")
        if classify_field_sensitivity(key) == FieldSensitivity.FORBIDDEN:
            raise ValidationError("Forbidden fields cannot be configured as report categories.")
        if key not in normalized:
            normalized.append(key)
    return tuple(normalized)


def build_safe_filter_hash(filters: Dict[str, Any]) -> str:
    """Computes a deterministic HMAC from sanitized/redacted filters."""
    if not filters:
        serialized = "{}"
    else:
        sorted_filters = {k: str(v) for k, v in sorted(filters.items())}
        serialized = json.dumps(sorted_filters, sort_keys=True)
    
    secret = getattr(settings, "AUDIT_HASH_SECRET", None)
    if not secret:
        raise ValidationError("Report filter hashing is unavailable.")
    return hmac.new(secret.encode("utf-8"), serialized.encode("utf-8"), hashlib.sha256).hexdigest()


def redact_report_filters(filters: Dict[str, Any], actor) -> Dict[str, Any]:
    """Redacts PII or sensitive values from filter parameters for safe storage/auditing."""
    if not filters:
        return {}
        
    redacted = {}
    for key, val in filters.items():
        sensitivity = classify_field_sensitivity(key)
        if sensitivity in (FieldSensitivity.SENSITIVE, FieldSensitivity.RESTRICTED, FieldSensitivity.FORBIDDEN):
            redacted[key] = "[REDACTED]"
        else:
            # Check for potential value leaks in list/tuple elements
            if isinstance(val, (list, tuple)):
                redacted[key] = [
                    "[REDACTED]" if classify_field_sensitivity(str(v)) in (FieldSensitivity.SENSITIVE, FieldSensitivity.FORBIDDEN) else v
                    for v in val
                ]
            else:
                redacted[key] = val
    return redacted


def enforce_suppression_floor(threshold: int | None) -> int:
    """Apply the hard five privacy floor to all suppressible report datasets."""
    try:
        normalized = int(threshold or MIN_SUPPRESSION_THRESHOLD)
    except (TypeError, ValueError):
        normalized = MIN_SUPPRESSION_THRESHOLD
    return max(MIN_SUPPRESSION_THRESHOLD, normalized)


def _strict_policy_threshold(value: Any, field_name: str) -> int:
    """Validate persisted policy thresholds without permitting unsafe coercion."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError({field_name: "Suppression threshold must be an integer."})
    if value < MIN_SUPPRESSION_THRESHOLD:
        raise ValidationError({field_name: "Suppression threshold cannot be lower than 5."})
    return value


def resolve_report_suppression_policy(report_definition, *, now=None) -> ResolvedSuppressionPolicy:
    """Resolve one report's safe, time-aware suppression configuration.

    Governance owns the target-scoped mode, baseline, threshold overlay, and
    additive protected categories. A missing or expired policy is a fail-closed
    configuration error; report-definition metadata is not a second source of
    truth.
    """

    from apps.reports.models import allowed_suppression_modes_for_definition
    from apps.governance.selectors import resolve_effective_policy

    central_policy = resolve_effective_policy(
        "reports.suppression",
        target=report_definition,
        at=now,
    )
    if central_policy is None:
        raise ValidationError("Report suppression policy is not configured for this definition.")
    central_config = central_policy.configuration_json or {}
    try:
        mode = SuppressionMode(central_config.get("mode"))
    except (TypeError, ValueError) as exc:
        raise ValidationError("Report definition has an invalid suppression mode.") from exc
    allowed_modes = allowed_suppression_modes_for_definition(
        key=report_definition.key,
        family=report_definition.family,
    )
    if mode not in allowed_modes:
        raise ValidationError("Report definition has an invalid suppression mode.")
    requires_suppression = central_config.get("requires_suppression")
    if mode == SuppressionMode.NONE and requires_suppression:
        raise ValidationError("A suppression-required report cannot use NONE mode.")
    if mode != SuppressionMode.NONE and not requires_suppression:
        raise ValidationError("A suppressing report must require suppression.")

    baseline_threshold = _strict_policy_threshold(
        central_config.get("default_threshold"),
        "default_suppression_threshold",
    )
    resolved_threshold = baseline_threshold
    sensitive_categories: tuple[str, ...] = ()
    active_policy = central_policy
    current_time = now or timezone.now()
    policy_threshold = _strict_policy_threshold(central_config.get("threshold"), "threshold")
    resolved_threshold = max(resolved_threshold, policy_threshold)
    sensitive_categories = normalize_suppression_categories(central_config.get("sensitive_categories", []))

    count_keys = tuple(dict.fromkeys([*DEFAULT_COUNT_KEYS, *sensitive_categories]))
    return ResolvedSuppressionPolicy(
        mode=mode,
        threshold=resolved_threshold,
        count_keys=count_keys,
        sensitive_categories=sensitive_categories,
        policy_id=str(active_policy.id) if active_policy else None,
        policy_effective_from=active_policy.effective_from if active_policy else None,
        policy_effective_until=active_policy.effective_until if active_policy else None,
        policy_source_reference=(str(active_policy.source_reference or "")[:160] or None) if active_policy else None,
    )


def suppression_policy_audit_metadata(policy: ResolvedSuppressionPolicy | None) -> dict[str, Any]:
    """Return only stable suppression-policy provenance for audit metadata."""
    if policy is None:
        return {}
    return {
        "suppression_policy_id": policy.policy_id,
        "suppression_policy_effective_from": (
            policy.policy_effective_from.isoformat() if policy.policy_effective_from else None
        ),
        "suppression_policy_effective_until": (
            policy.policy_effective_until.isoformat() if policy.policy_effective_until else None
        ),
        "suppression_policy_source_reference": policy.policy_source_reference,
    }


def is_suppressed(value: Any) -> bool:
    return value == SUPPRESSION_LABEL


def _supporting_count(row: Dict[str, Any], count_keys: List[str]) -> Any:
    for key in ("count", "total_count", "responses_count", "submissions_count", "denominator", "total"):
        if key in row:
            return row[key]
    for key in count_keys:
        if key in row:
            return row[key]
    return None


def _is_derived_metric(key: str) -> bool:
    key_lower = str(key).lower()
    return (
        key_lower in DERIVED_METRIC_KEYS
        or key_lower.startswith("avg_")
        or key_lower.endswith("_avg")
        or key_lower.endswith("_average")
        or key_lower.endswith("_percentage")
        or key_lower.endswith("_rate")
        or key_lower.endswith("_ratio")
    )


def suppress_derived_metrics(row: Dict[str, Any], threshold: int, count_keys: List[str]) -> Dict[str, Any]:
    supporting_count = _supporting_count(row, count_keys)
    should_suppress = supporting_count == SUPPRESSION_LABEL or (
        isinstance(supporting_count, (int, float)) and 0 < supporting_count < threshold
    )
    if not should_suppress:
        return row

    for key in list(row.keys()):
        if _is_derived_metric(key):
            row[key] = SUPPRESSION_LABEL
    return row


def suppress_small_counts(
    dataset: List[Dict[str, Any]],
    threshold: int = 5,
    count_keys: Optional[List[str]] = None,
    sensitive_categories: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    """Suppresses cell counts that are below the specified threshold.

    Replaces suppressed integers with the SUPPRESSION_LABEL.
    Prevents exposure of small cohorts for privacy.
    """
    if not dataset:
        return []
        
    if count_keys is None:
        count_keys = DEFAULT_COUNT_KEYS
    threshold = enforce_suppression_floor(threshold)
        
    processed_dataset = []
    
    for row in dataset:
        new_row = {
            key: suppress_report_data(value, threshold=threshold, count_keys=count_keys)[0]
            if isinstance(value, (list, dict)) else value
            for key, value in row.items()
        }
        
        for key in count_keys:
            if key in new_row:
                val = new_row[key]
                if isinstance(val, (int, float)):
                    # Under threshold (and greater than 0, to preserve true 0s unless they disclose cells)
                    # Note: we suppress values > 0 and < threshold. 0 count does not need suppression usually,
                    # but if it exposes something, it could. Standard policy is 0 < count < threshold.
                    if 0 < val < threshold:
                        new_row[key] = SUPPRESSION_LABEL
                    elif val < 0:
                        new_row[key] = SUPPRESSION_LABEL
        processed_dataset.append(new_row)
        
    # Apply complementary suppression to protect against simple arithmetic disclosure
    for key in count_keys:
        processed_dataset = apply_complementary_suppression(processed_dataset, key, threshold)
    processed_dataset = [suppress_derived_metrics(row, threshold, count_keys) for row in processed_dataset]
        
    return processed_dataset


def apply_complementary_suppression(
    dataset: List[Dict[str, Any]],
    count_key: str,
    threshold: int = 5
) -> List[Dict[str, Any]]:
    """Checks if exactly one cell is suppressed in a column.

    If so, suppresses the next smallest cell count to prevent complementary disclosure.
    """
    if len(dataset) < 2:
        return dataset
        
    # Count how many are already suppressed
    suppressed_indices = []
    valid_numeric_indices = []
    
    for idx, row in enumerate(dataset):
        if count_key in row:
            val = row[count_key]
            if val == SUPPRESSION_LABEL:
                suppressed_indices.append(idx)
            elif isinstance(val, (int, float)) and val > 0:
                valid_numeric_indices.append((idx, val))
                
    # If exactly 1 cell is suppressed, we must suppress another one to prevent recovery of the suppressed value
    if len(suppressed_indices) == 1 and valid_numeric_indices:
        # Sort remaining numeric non-suppressed cells by value ascending
        valid_numeric_indices.sort(key=lambda x: x[1])
        # Suppress the smallest non-suppressed cell
        target_idx = valid_numeric_indices[0][0]
        dataset[target_idx][count_key] = SUPPRESSION_LABEL
        
    return dataset


def validate_report_scope(actor, report_key: str, filters: Dict[str, Any]) -> bool:
    """Verifies if the actor has the required permissions and scopes for the given report/filters."""
    # Defer details to policy file
    from apps.reports.policies import can_run_report
    return can_run_report(actor, report_key, filters)


def suppress_report_data(
    value: Any,
    threshold: int = MIN_SUPPRESSION_THRESHOLD,
    count_keys: Optional[List[str]] = None,
) -> Tuple[Any, int]:
    """Recursively suppress nested report data before it reaches templates."""
    threshold = enforce_suppression_floor(threshold)
    count_keys = count_keys or DEFAULT_COUNT_KEYS

    if isinstance(value, list):
        if all(isinstance(item, dict) for item in value):
            suppressed_rows = suppress_small_counts(value, threshold=threshold, count_keys=count_keys)
            suppressed_count = _count_suppressed_cells(suppressed_rows)
            return suppressed_rows, suppressed_count
        suppressed_items = []
        suppressed_count = 0
        for item in value:
            safe_item, item_count = suppress_report_data(item, threshold=threshold, count_keys=count_keys)
            suppressed_items.append(safe_item)
            suppressed_count += item_count
        return suppressed_items, suppressed_count

    if isinstance(value, dict):
        safe_dict = {}
        suppressed_count = 0
        for key, item in value.items():
            if isinstance(item, (list, dict)):
                safe_item, item_count = suppress_report_data(item, threshold=threshold, count_keys=count_keys)
                safe_dict[key] = safe_item
                suppressed_count += item_count
            elif key in count_keys and isinstance(item, (int, float)) and 0 < item < threshold:
                safe_dict[key] = SUPPRESSION_LABEL
                suppressed_count += 1
            else:
                safe_dict[key] = item
        safe_dict = suppress_derived_metrics(safe_dict, threshold, count_keys)
        suppressed_count += sum(1 for item in safe_dict.values() if item == SUPPRESSION_LABEL)
        return safe_dict, suppressed_count

    return value, 0


def suppress_csm_disclosure_set(
    dataset: Dict[str, Any],
    threshold: int,
) -> Tuple[Dict[str, Any], bool]:
    """Apply conservative cross-table protection to fixed-shape CSM rows.

    CSM omits user-selected filters and categorical breakdowns. Within the
    remaining rating tables, a small denominator or a small difference between
    any two denominators could reveal unanswered/null participation. In either
    case the whole related disclosure set is suppressed so totals and sibling
    tables cannot reconstruct a protected value.
    """
    threshold = enforce_suppression_floor(threshold)
    denominators = []
    for rows in dataset.values():
        if not isinstance(rows, list):
            raise ValidationError("CSM aggregate sections must contain flat row lists.")
        for row in rows:
            if not isinstance(row, dict):
                raise ValidationError("CSM aggregate sections must contain flat rows.")
            value = row.get("denominator")
            if isinstance(value, (int, float)):
                denominators.append(value)

    has_primary_risk = not denominators or any(value < threshold for value in denominators)
    has_difference_risk = any(
        0 < abs(left - right) < threshold
        for index, left in enumerate(denominators)
        for right in denominators[index + 1:]
    )
    if not (has_primary_risk or has_difference_risk):
        return copy.deepcopy(dataset), False

    safe_dataset = copy.deepcopy(dataset)
    for rows in safe_dataset.values():
        for row in rows:
            for key in list(row.keys()):
                if key in DEFAULT_COUNT_KEYS or _is_derived_metric(key):
                    row[key] = SUPPRESSION_LABEL
    return safe_dataset, True


def _count_suppressed_cells(value: Any) -> int:
    if isinstance(value, dict):
        return sum(_count_suppressed_cells(item) for item in value.values())
    if isinstance(value, list):
        return sum(_count_suppressed_cells(item) for item in value)
    return 1 if value == SUPPRESSION_LABEL else 0
