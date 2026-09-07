"""Strictly read-only encryption deployment-readiness evidence."""

from __future__ import annotations

import re
from collections import Counter

from django.conf import settings
from django.db import connection

from apps.security.checks import validate_field_encryption_settings
from apps.security.exceptions import SecurityError
from apps.security.field_encryption import (
    get_active_field_key,
    get_field_key_for_decryption,
    parse_outer_envelope,
)
from apps.security.field_operations import FieldOperationTarget, registered_targets
from apps.security.key_sources import load_fernet_for_metadata
from apps.security.models import EncryptionKeyVersion, KeyPurposeChoices, KeyStatusChoices
from apps.system.readiness_services import ReadinessCheck, is_deployment_environment


EXPECTED_TARGET_COUNTS = {
    "inventory": 3,
    "counseling": 25,
    "referrals": 6,
    "call_slips": 7,
    "content": 1,
}
EXPECTED_TARGET_TOTAL = sum(EXPECTED_TARGET_COUNTS.values())
UNSAFE_REFERENCE_TOKEN_RE = re.compile(
    r"(?:^|[-_.])(?:demo|dev|development|test|testing|change|default|placeholder|example)(?:$|[-_.])",
    re.IGNORECASE,
)
MAX_HISTORICAL_KEY_IDS = 128
RAW_SCAN_BATCH_SIZE = 500


def _safe_key_configuration_checks() -> list[ReadinessCheck]:
    checks: list[ReadinessCheck] = []
    setting_errors = validate_field_encryption_settings()
    if setting_errors:
        checks.append(
            ReadinessCheck(
                name="field_encryption_settings",
                status="FAIL",
                required=True,
                reason_code=setting_errors[0][0],
                message="Field-encryption settings failed safe validation.",
                evidence_type="configuration",
            )
        )
    else:
        checks.append(
            ReadinessCheck(
                name="field_encryption_settings",
                status="PASS",
                required=True,
                reason_code="FIELD_SETTINGS_OK",
                message="Field-encryption settings passed safe validation.",
                evidence_type="configuration",
            )
        )

    environment = str(getattr(settings, "COMPASS_ENVIRONMENT", "") or "").lower()
    source = str(getattr(settings, "KEY_SOURCE_PROVIDER", "") or "").lower()
    deployment_source_ok = not is_deployment_environment() or source == "podman_secret"
    checks.append(
        ReadinessCheck(
            name="deployment_key_source_policy",
            status="PASS" if deployment_source_ok else "FAIL",
            required=True,
            reason_code="KEY_SOURCE_POLICY_OK" if deployment_source_ok else "KEY_SOURCE_POLICY_UNSAFE",
            message=(
                "Deployment field-encryption source policy is configured."
                if deployment_source_ok
                else "Staging/production field encryption must use the podman_secret source."
            ),
            evidence_type="configuration",
            details={"deployment_environment": environment in {"production", "prod", "staging", "stage"}},
        )
    )
    return checks


def _unsafe_reference(value: str) -> bool:
    return bool(UNSAFE_REFERENCE_TOKEN_RE.search(str(value or "")))


def _active_key_checks() -> list[ReadinessCheck]:
    checks: list[ReadinessCheck] = []
    active_keys = list(
        EncryptionKeyVersion.objects.filter(
            key_purpose=KeyPurposeChoices.FIELD_ENCRYPTION,
            status=KeyStatusChoices.ACTIVE,
        )[:2]
    )
    if len(active_keys) != 1:
        checks.append(
            ReadinessCheck(
                name="active_field_encryption_key",
                status="FAIL",
                required=True,
                reason_code="FIELD_ACTIVE_KEY_COUNT_INVALID",
                message="Exactly one active field-encryption key metadata row is required.",
                evidence_type="read_only_query",
            )
        )
        return checks

    key = active_keys[0]
    metadata_ok = (
        key.algorithm == "Fernet"
        and key.source_alias == str(key.source_alias or "").strip().lower()
        and key.source_alias in {"env", "podman_secret"}
        and (not is_deployment_environment() or key.source_alias == "podman_secret")
        and (
            not is_deployment_environment()
            or (not _unsafe_reference(key.key_version) and not _unsafe_reference(key.secret_reference))
        )
    )
    if not metadata_ok:
        checks.append(
            ReadinessCheck(
                name="active_field_encryption_key",
                status="FAIL",
                required=True,
                reason_code="FIELD_ACTIVE_KEY_METADATA_UNSAFE",
                message="Active field-encryption key metadata is unsafe for deployment readiness.",
                evidence_type="read_only_query",
            )
        )
        return checks

    try:
        get_active_field_key()
        load_fernet_for_metadata(key)
    except SecurityError:
        checks.append(
            ReadinessCheck(
                name="active_field_encryption_key",
                status="FAIL",
                required=True,
                reason_code="FIELD_ACTIVE_KEY_UNAVAILABLE",
                message="Active field-encryption key material could not be validated through its configured source.",
                evidence_type="read_only_query",
            )
        )
        return checks
    except Exception:
        checks.append(
            ReadinessCheck(
                name="active_field_encryption_key",
                status="FAIL",
                required=True,
                reason_code="FIELD_ACTIVE_KEY_CHECK_FAILED",
                message="Active field-encryption key validation failed safely.",
                evidence_type="read_only_query",
            )
        )
        return checks

    checks.append(
        ReadinessCheck(
            name="active_field_encryption_key",
            status="PASS",
            required=True,
            reason_code="FIELD_ACTIVE_KEY_OK",
            message="Exactly one active field-encryption key was validated without exposing key material.",
            evidence_type="read_only_query",
        )
    )
    return checks


def _target_registry_checks(targets) -> list[ReadinessCheck]:
    counts = Counter()
    invalid_kind = False
    invalid_target = False
    for target in targets:
        if not isinstance(target, FieldOperationTarget):
            invalid_kind = True
            continue
        app_label = target.model._meta.app_label
        if app_label in EXPECTED_TARGET_COUNTS:
            counts[app_label] += 1
        try:
            target.validate()
        except SecurityError:
            invalid_target = True

    counts_match = dict(counts) == EXPECTED_TARGET_COUNTS and len(targets) == EXPECTED_TARGET_TOTAL
    status = "PASS" if counts_match and not invalid_kind and not invalid_target else "FAIL"
    reason_code = "DATA002_TARGET_REGISTRY_OK" if status == "PASS" else "DATA002_TARGET_REGISTRY_INVALID"
    checks = [
        ReadinessCheck(
            name="data002_target_registry",
            status=status,
            required=True,
            reason_code=reason_code,
            message=(
                "DATA-002 inventory, counseling, referrals, and call-slip target coverage is registered."
                if status == "PASS"
                else "DATA-002 target registration is incomplete or invalid."
            ),
            evidence_type="repository_query",
            details={
                "target_total": len(targets),
                "inventory": counts.get("inventory", 0),
                "counseling": counts.get("counseling", 0),
                "referrals": counts.get("referrals", 0),
                "call_slips": counts.get("call_slips", 0),
                "content": counts.get("content", 0),
            },
        ),
    ]
    return checks


def _scan_target_raw_values(target) -> dict:
    table = connection.ops.quote_name(target.model._meta.db_table)
    destination = target.model._meta.get_field(target.destination_field)
    column = connection.ops.quote_name(destination.column)
    rows = 0
    null_rows = 0
    valid_rows = 0
    key_ids = set()
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT {column} FROM {table}")
        while True:
            batch = cursor.fetchmany(RAW_SCAN_BATCH_SIZE)
            if not batch:
                break
            for (raw,) in batch:
                rows += 1
                if raw is None:
                    null_rows += 1
                    continue
                envelope = parse_outer_envelope(raw)
                valid_rows += 1
                key_ids.add(envelope["key_id"])
                if len(key_ids) > MAX_HISTORICAL_KEY_IDS:
                    raise SecurityError("field_encryption_key_set_too_large")
    for key_id in key_ids:
        load_fernet_for_metadata(get_field_key_for_decryption(key_id))
    return {
        "rows": rows,
        "null_rows": null_rows,
        "valid_rows": valid_rows,
        "historical_keys": len(key_ids),
    }


def _target_raw_checks(targets) -> list[ReadinessCheck]:
    checks = []
    for app_label in EXPECTED_TARGET_COUNTS:
        domain_targets = [
            target
            for target in targets
            if isinstance(target, FieldOperationTarget)
            and target.model._meta.app_label == app_label
        ]
        domain_rows = 0
        domain_null_rows = 0
        domain_valid_rows = 0
        domain_historical_keys = 0
        failed = False
        for target in domain_targets:
            try:
                target.validate()
                result = _scan_target_raw_values(target)
                domain_rows += result["rows"]
                domain_null_rows += result["null_rows"]
                domain_valid_rows += result["valid_rows"]
                domain_historical_keys += result["historical_keys"]
            except SecurityError:
                failed = True
                break
            except Exception:
                failed = True
                break

        if failed:
            status = "FAIL"
            reason_code = "DATA002_RAW_ENVELOPE_INVALID"
            message = "Raw encrypted-destination envelope validation failed."
        elif domain_rows == 0:
            status = "PENDING"
            reason_code = "PENDING_NO_SAMPLE"
            message = "No rows were available for content-blind raw-envelope proof."
        elif domain_null_rows > 0:
            status = "PENDING"
            reason_code = "DATA002_RAW_UNINITIALIZED_ROWS"
            message = "Raw encrypted-destination proof found uninitialized rows."
        elif domain_valid_rows != domain_rows:
            status = "FAIL"
            reason_code = "DATA002_RAW_ENVELOPE_COUNT_MISMATCH"
            message = "Raw encrypted-destination envelope counts did not reconcile."
        else:
            status = "PASS"
            reason_code = "DATA002_RAW_ENVELOPES_OK"
            message = "All observed encrypted-destination values passed content-blind envelope proof."
        checks.append(
            ReadinessCheck(
                name=f"data002_raw_envelopes_{app_label}",
                status=status,
                required=True,
                reason_code=reason_code,
                message=message,
                evidence_type="content_blind_raw_query",
                details={
                    "rows": domain_rows,
                    "null_rows": domain_null_rows,
                    "valid_rows": domain_valid_rows,
                    "historical_keys": domain_historical_keys,
                },
            )
        )
    return checks


def collect_encryption_readiness() -> list[ReadinessCheck]:
    """Collect encryption evidence without audit, ORM decryption, or writes."""

    checks = _safe_key_configuration_checks()
    try:
        checks.extend(_active_key_checks())
    except Exception:
        checks.append(
            ReadinessCheck(
                name="active_field_encryption_key",
                status="FAIL",
                required=True,
                reason_code="FIELD_ACTIVE_KEY_QUERY_FAILED",
                message="Active field-encryption key metadata could not be inspected safely.",
                evidence_type="read_only_query",
            )
        )

    try:
        targets = registered_targets()
        checks.extend(_target_registry_checks(targets))
        checks.extend(_target_raw_checks(targets))
    except Exception:
        checks.append(
            ReadinessCheck(
                name="data002_target_registry",
                status="FAIL",
                required=True,
                reason_code="DATA002_TARGET_QUERY_FAILED",
                message="DATA-002 encryption target evidence could not be inspected safely.",
                evidence_type="repository_query",
            )
        )

    checks.append(
        ReadinessCheck(
            name="plaintext_contraction",
            status="NOT_CLAIMED",
            required=False,
            reason_code="DATA002_PLAINTEXT_CONTRACTION_NOT_CLAIMED",
            message="Release 1 raw-envelope proof does not claim plaintext-source contraction or final DATA-002 closure.",
            evidence_type="manual_authorization",
        )
    )
    return checks


def collect_encryption_configuration_readiness() -> list[ReadinessCheck]:
    """Collect key-source and active-key evidence without scanning domain rows."""

    checks = _safe_key_configuration_checks()
    try:
        checks.extend(_active_key_checks())
    except Exception:
        checks.append(
            ReadinessCheck(
                name="active_field_encryption_key",
                status="FAIL",
                required=True,
                reason_code="FIELD_ACTIVE_KEY_QUERY_FAILED",
                message="Active field-encryption key metadata could not be inspected safely.",
                evidence_type="read_only_query",
            )
        )
    return checks
