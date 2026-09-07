"""Safe release/operations projections and command-history recording."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime

from django.conf import settings
from django.utils import timezone

from apps.audit.services import audit_log
from apps.system.models import OperationalCommandRun
from apps.system.readiness_services import environment_name, release_identity


OPERATIONAL_COMMAND_CATALOG = (
    {"key": "seed_form_registry", "label": "Reconcile form-family catalog", "rollback": "Catalog reconciliation is idempotent; restore source metadata through a reviewed draft.", "mode": "dry-run-or-execute"},
    {"key": "seed_document_templates", "label": "Reconcile document-template catalog", "rollback": "Disable the affected template version and keep output PREVIEW — PENDING APPROVAL.", "mode": "dry-run-or-execute"},
    {"key": "seed_report_definitions", "label": "Reconcile report-definition catalog", "rollback": "Retain prior approved report definition; no destructive rollback is automatic.", "mode": "dry-run-or-execute"},
    {"key": "check_field_encryption_readiness", "label": "Check encryption readiness", "rollback": "Read-only check; no data rollback required.", "mode": "read-only"},
    {"key": "verify_health", "label": "Verify health and release readiness", "rollback": "Read-only check; follow the component runbook for remediation.", "mode": "read-only"},
)


def _bounded_summary(value):
    if isinstance(value, dict):
        return {str(k)[:80]: _bounded_summary(v) for k, v in list(value.items())[:25] if str(k).lower() not in {"argv", "output", "raw_output", "settings", "payload", "student_data"}}
    if isinstance(value, (list, tuple)):
        return [_bounded_summary(v) for v in list(value)[:25]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return str(value)[:255] if isinstance(value, str) else value
    return str(value)[:80]


def record_operational_command_run(*, command_key, mode, actor=None, reason_code,
                                   configuration_identifier="", outcome="COMPLETED",
                                   outcome_reason_code="", summary=None,
                                   started_at=None, finished_at=None):
    identity = release_identity()
    run = OperationalCommandRun.objects.create(
        command_key=command_key[:100], mode=mode[:20], actor_user=actor,
        actor_identity=(getattr(actor, "role", "system") if actor else "system")[:120],
        environment=environment_name()[:40], reason_code=reason_code[:100],
        configuration_identifier=configuration_identifier[:160],
        started_at=started_at or timezone.now(), finished_at=finished_at or timezone.now(),
        outcome=outcome[:30], outcome_reason_code=outcome_reason_code[:100],
        release_version=identity["version"][:64], build_id=identity["build_id"][:128],
        summary_json=_bounded_summary(summary or {}),
    )
    audit_log(
        action_type="OPERATIONAL_COMMAND_RECORDED", event_category="SYSTEM",
        target_model="system.OperationalCommandRun", target_object_id=str(run.pk),
        actor_user=actor, metadata={"command_key": run.command_key, "mode": run.mode,
                                    "environment": run.environment, "outcome": run.outcome,
                                    "reason_code": run.reason_code, "summary": run.summary_json},
        source_app="apps.system",
    )
    return run


@contextmanager
def operational_command(*, command_key, mode="execute", actor=None, reason_code,
                        configuration_identifier="", summary=None):
    started = timezone.now()
    outcome = "COMPLETED"
    reason = ""
    try:
        yield summary if summary is not None else {}
    except Exception as exc:
        outcome = "BLOCKED"
        reason = getattr(exc, "code", "COMMAND_FAILED") or "COMMAND_FAILED"
        raise
    finally:
        record_operational_command_run(
            command_key=command_key, mode=mode, actor=actor, reason_code=reason_code,
            configuration_identifier=configuration_identifier, outcome=outcome,
            outcome_reason_code=reason, summary=summary, started_at=started,
        )


def release_operations_summary(*, actor=None) -> dict:
    from apps.organizations.models import FormRevision, FormRevisionStatusChoices
    from apps.organizations.academic_year import AcademicYearConfigurationError, get_current_academic_term
    from apps.documents.models import DocumentTemplateVersion
    from apps.system.models import MaintenanceWindow
    from apps.counseling.recording_policy import recording_availability_projection

    try:
        current_term = get_current_academic_term()
    except AcademicYearConfigurationError:
        # A readiness projection must not invent a current year when the
        # canonical source is missing or contradictory.
        current_term = None
    active_revisions = FormRevision.objects.filter(status=FormRevisionStatusChoices.ACTIVE).count()
    maintenance = MaintenanceWindow.objects.filter(status="ACTIVE").exists()
    recording = recording_availability_projection()
    return {
        "release": release_identity(),
        "environment": environment_name(),
        "migration": {"status": "CHECK_ON_DEPLOY", "reason_code": "READINESS_PROVIDER"},
        "active_term_count": 1 if current_term else 0,
        "academic_year": current_term.academic_year if current_term else None,
        "academic_year_source": "organizations.AcademicTerm",
        "active_revision_count": active_revisions,
        "document_readiness": {"status": "RECONCILE_REQUIRED", "template_version_count": DocumentTemplateVersion.objects.count()},
        "worker_outbox": {"status": "READINESS_PROVIDER", "count": 0},
        "backup": {"status": "READINESS_PROVIDER"},
        "maintenance": {"status": "ACTIVE" if maintenance else "INACTIVE"},
        "recording": {
            "status": "READY" if not recording.blocked else "POLICY_DISABLED",
            "state": recording.state.value,
            "reason_code": recording.reason_code,
            "message": recording.operations_message,
            "available_scopes": list(recording.available_scopes),
            "transcription_available": recording.transcription_available,
            "scheduled_deletion": "ENABLED" if recording.scheduled_deletion_enabled else "DISABLED",
        },
        "recent_command_runs": list(OperationalCommandRun.objects.values(
            "command_key", "mode", "environment", "reason_code", "configuration_identifier",
            "outcome", "outcome_reason_code", "release_version", "build_id", "started_at", "summary_json",
        )[:20]),
        "command_catalog": OPERATIONAL_COMMAND_CATALOG,
    }
