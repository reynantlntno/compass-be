"""Shared, side-effect-free result handling for deployment readiness checks.

The readiness commands deliberately report evidence classes separately.  A
configuration check or an opt-in read-only provider probe is not a production
release claim, and the renderer keeps that distinction visible in every
machine-readable result.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field

from django.conf import settings


_RELEASE_IDENTITY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}$")


READINESS_STATUSES = frozenset(
    {"PASS", "FAIL", "WARN", "SKIP", "PENDING", "NOT_CLAIMED"}
)
HEALTH_STATUS_MAP = {
    "ok": "PASS",
    "error": "FAIL",
    "warning": "WARN",
    "skipped": "SKIP",
}


@dataclass(frozen=True)
class ReadinessCheck:
    """One safe readiness result with no sensitive payload fields."""

    name: str
    status: str
    required: bool
    reason_code: str
    message: str
    evidence_type: str = "configuration"
    details: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.status not in READINESS_STATUSES:
            raise ValueError("unknown_readiness_status")

    def to_dict(self) -> dict:
        return asdict(self)


def check_from_health_status(health_status, *, required: bool, evidence_type: str = "read_only_query"):
    """Convert an existing safe health DTO without exposing extra fields."""

    status = HEALTH_STATUS_MAP.get(health_status.status, "FAIL")
    return ReadinessCheck(
        name=health_status.component,
        status=status,
        required=required,
        reason_code=health_status.reason_code,
        message=health_status.message,
        evidence_type=evidence_type,
    )


def environment_name() -> str:
    value = getattr(settings, "COMPASS_ENVIRONMENT", "development")
    return str(value or "development").strip().lower() or "unknown"


def is_deployment_environment() -> bool:
    return environment_name() in {"production", "prod", "staging", "stage"}


def is_external_probe_enabled(options: dict) -> bool:
    return bool(options.get("probe_external"))


def release_identity() -> dict:
    """Return only safe deployment identity fields for readiness evidence."""

    version = str(getattr(settings, "COMPASS_RELEASE_VERSION", "") or "").strip()
    build_id = str(getattr(settings, "COMPASS_BUILD_ID", "") or "").strip()
    return {
        "version": version if _RELEASE_IDENTITY_PATTERN.fullmatch(version) else "NOT_CONFIGURED",
        "build_id": build_id if _RELEASE_IDENTITY_PATTERN.fullmatch(build_id) else "NOT_CONFIGURED",
        "configured": bool(
            _RELEASE_IDENTITY_PATTERN.fullmatch(version)
            and _RELEASE_IDENTITY_PATTERN.fullmatch(build_id)
        ),
    }


def is_blocking(check: ReadinessCheck, *, strict: bool) -> bool:
    if check.status == "FAIL":
        return True
    if strict and check.required and check.status != "PASS":
        return True
    return False


def build_report(command: str, checks: list[ReadinessCheck], *, strict: bool, probe_external: bool) -> dict:
    """Build a stable report; only callers supply already-safe detail values."""

    blocking = [check for check in checks if is_blocking(check, strict=strict)]
    counts = {status: sum(check.status == status for check in checks) for status in sorted(READINESS_STATUSES)}
    return {
        "command": command,
        "environment": environment_name(),
        "release": release_identity(),
        "probe_external": bool(probe_external),
        "strict": bool(strict),
        "passed": not blocking,
        "automated_checks": [check.to_dict() for check in checks],
        "summary": {
            "total": len(checks),
            "blocking": len(blocking),
            "counts": counts,
        },
        # This field is intentionally unconditional.  These commands never
        # approve a release or turn repository/probe evidence into a claim.
        "release_claim": "NOT_CLAIMED",
    }


def render_report(report: dict, *, output_format: str, stdout) -> None:
    """Render only safe report fields in either human or JSON form."""

    if output_format == "json":
        stdout.write(json.dumps(report, sort_keys=True, separators=(",", ":")))
        stdout.write("\n")
        return

    for check in report["automated_checks"]:
        stdout.write(
            f"{check['status']} {check['name']}: {check['message']} "
            f"[{check['reason_code']}]\n"
        )
    summary = report["summary"]
    result = "PASS" if report["passed"] else "FAIL"
    release = report["release"]
    stdout.write(
        "RELEASE_IDENTITY="
        f"version={release['version']} build={release['build_id']} "
        f"configured={'yes' if release['configured'] else 'no'}\n"
    )
    stdout.write(f"AUTOMATED_CHECKS={result} blocking={summary['blocking']}\n")
    stdout.write("RELEASE_CLAIM=NOT_CLAIMED\n")


def assert_report_passed(report: dict, *, strict: bool):
    """Return a safe command-level result and let callers raise CommandError."""

    return bool(report.get("passed"))
