"""Canonical inventory for runtime controls.

This module is deliberately independent of Django and Governance.  It is the
source of truth for type, immutable safety bounds, ownership, and deployment
reload behavior.  Governance may still store historical records for settings
that moved to deployment ownership, but those records are not runtime
sources.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True, slots=True)
class RuntimeSettingSpec:
    key: str
    default: object
    kind: str
    minimum: int | None
    maximum: int | None
    owner: str
    source: str
    env_name: str | None
    reload_mode: str
    affected_services: tuple[str, ...]
    policy_approval_required: bool
    deprecation_status: str = "active"

    @property
    def safety_rule(self) -> tuple[str, int | None, int | None]:
        return self.kind, self.minimum, self.maximum

    def validate(self, value):
        if self.kind == "bool":
            if not isinstance(value, bool):
                raise ValueError(f"{self.key} must be a boolean.")
            return value
        if self.kind == "int":
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{self.key} must be an integer.")
            if self.minimum is not None and value < self.minimum:
                raise ValueError(f"{self.key} is below its safety floor.")
            if self.maximum is not None and value > self.maximum:
                raise ValueError(f"{self.key} exceeds its safety ceiling.")
            return value
        raise ValueError(f"{self.key} has an unsupported runtime-setting type.")


_ENV_OWNED_KEYS = frozenset(
    {
        "MAINTENANCE_ENFORCEMENT_ENABLED",
        "DOCUMENT_PDF_RENDERER_ENABLED",
        "DOCUMENT_PDF_RENDERER_TIMEOUT_MS",
        "ACCOUNT_SECURITY_CAPTCHA_TIMEOUT_SECONDS",
        "EMAIL_TIMEOUT",
        "NOTIFICATION_WORKER_ENABLED",
        "NOTIFICATION_WORKER_INTERVAL_SECONDS",
        "NOTIFICATION_WORKER_BATCH_SIZE",
        "NOTIFICATION_WORKER_LOCK_TIMEOUT_SECONDS",
        "BACKUP_WORKER_POLL_INTERVAL_SECONDS",
        "REPORT_SYNC_MAX_OUTPUT_BYTES",
        "REPORT_SYNC_MAX_WORK_UNITS",
        "REPORT_ASYNC_AFTER_WORK_UNITS",
        "REPORT_RUN_TIMEOUT_SECONDS",
        "REPORT_EXPORT_MAX_OUTPUT_BYTES",
        "PROTECTED_STORAGE_MAX_FILE_SIZE_BYTES",
    }
)


def _spec(
    key: str,
    default,
    kind: str,
    minimum: int | None,
    maximum: int | None,
    owner: str,
    *services: str,
) -> RuntimeSettingSpec:
    environment_owned = key in _ENV_OWNED_KEYS
    return RuntimeSettingSpec(
        key=key,
        default=default,
        kind=kind,
        minimum=minimum,
        maximum=maximum,
        owner=owner,
        source="environment" if environment_owned else "policy",
        env_name=key if environment_owned else None,
        reload_mode="restart" if environment_owned else "database-effective",
        affected_services=tuple(services),
        policy_approval_required=not environment_owned,
        deprecation_status="migrated-to-environment" if environment_owned else "active",
    )


_SPECS = (
    _spec("MAINTENANCE_ENFORCEMENT_ENABLED", False, "bool", None, None, "platform", "web"),
    _spec("ACCOUNT_ACTIVATION_TOKEN_VALIDITY_DAYS", 3, "int", 1, 30, "student_activation", "web"),
    _spec("ACCOUNT_SECURITY_ENFORCE_2FA_FOR_INTERNAL_USERS", True, "bool", None, None, "account_security", "web"),
    _spec("API_ACCESS_TOKEN_TTL_SECONDS", 900, "int", 60, 3600, "account_security", "web"),
    _spec("API_REFRESH_TOKEN_TTL_SECONDS", 30 * 24 * 60 * 60, "int", 86400, 90 * 86400, "account_security", "web"),
    _spec("ACCOUNT_SECURITY_ASSURANCE_MAX_AGE_SECONDS", 14 * 24 * 60 * 60, "int", 300, 30 * 86400, "account_security", "web"),
    _spec("ACCOUNT_SECURITY_SENSITIVE_ASSURANCE_MAX_AGE_SECONDS", 10 * 60, "int", 300, 1800, "account_security", "web"),
    _spec("ACCOUNT_SECURITY_OTP_EXPIRY_SECONDS", 300, "int", 60, 600, "account_security", "web"),
    _spec("ACCOUNT_SECURITY_OTP_MAX_ATTEMPTS", 5, "int", 1, 10, "account_security", "web"),
    _spec("ACCOUNT_SECURITY_OTP_RESEND_COOLDOWN_SECONDS", 60, "int", 30, 300, "account_security", "web"),
    _spec("ACCOUNT_SECURITY_OTP_MAX_RESENDS", 5, "int", 1, 5, "account_security", "web"),
    _spec("ACCOUNT_SECURITY_LOGIN_CHALLENGE_MAX_LIFETIME_SECONDS", 900, "int", 300, 1800, "account_security", "web"),
    _spec("ACCOUNT_SECURITY_RECOVERY_TOKEN_EXPIRY_SECONDS", 1800, "int", 300, 86400, "account_security", "web"),
    _spec("ACCOUNT_SECURITY_RECOVERY_MAX_ATTEMPTS", 3, "int", 1, 10, "account_security", "web"),
    _spec("ACCOUNT_SECURITY_RECOVERY_RESEND_COOLDOWN_SECONDS", 60, "int", 30, 300, "account_security", "web"),
    _spec("ACCOUNT_SECURITY_TRUSTED_DEVICE_DAYS_STUDENT", 30, "int", 1, 30, "account_security", "web"),
    _spec("ACCOUNT_SECURITY_TRUSTED_DEVICE_DAYS_STAFF", 14, "int", 1, 14, "account_security", "web"),
    _spec("ACCOUNT_SECURITY_TRUSTED_DEVICE_DAYS_IT_ADMIN", 7, "int", 0, 7, "account_security", "web"),
    _spec("ACCOUNT_SECURITY_DISABLE_IT_ADMIN_TRUSTED_DEVICES", True, "bool", None, None, "account_security", "web"),
    _spec("ACCOUNT_SECURITY_TRUSTED_DEVICE_MAX_ACTIVE", 5, "int", 1, 5, "account_security", "web"),
    _spec("DOCUMENT_PDF_RENDERER_ENABLED", False, "bool", None, None, "platform", "web"),
    _spec("DOCUMENT_PDF_RENDERER_TIMEOUT_MS", 30000, "int", 1000, 120000, "platform", "web"),
    _spec("ACCOUNT_SECURITY_CAPTCHA_TIMEOUT_SECONDS", 5, "int", 1, 15, "platform", "web"),
    _spec("EMAIL_TIMEOUT", 10, "int", 1, 60, "platform", "web", "notification-worker"),
    _spec("NOTIFICATION_WORKER_ENABLED", False, "bool", None, None, "platform", "notification-worker"),
    _spec("NOTIFICATION_WORKER_INTERVAL_SECONDS", 5, "int", 1, 3600, "platform", "notification-worker"),
    _spec("NOTIFICATION_WORKER_BATCH_SIZE", 20, "int", 1, 500, "platform", "notification-worker"),
    _spec("NOTIFICATION_WORKER_LOCK_TIMEOUT_SECONDS", 300, "int", 1, 3600, "platform", "notification-worker"),
    _spec("BACKUP_RETENTION_DAILY_DAYS", 7, "int", 1, 365, "privacy", "web", "backup-worker"),
    _spec("BACKUP_RETENTION_WEEKLY_WEEKS", 4, "int", 1, 52, "privacy", "web", "backup-worker"),
    _spec("BACKUP_RETENTION_MONTHLY_ENABLED", True, "bool", None, None, "privacy", "web", "backup-worker"),
    _spec("BACKUP_WORKER_POLL_INTERVAL_SECONDS", 15, "int", 1, 3600, "platform", "backup-worker"),
    _spec("PROTECTED_STORAGE_MAX_FILE_SIZE_BYTES", 10 * 1024 * 1024, "int", 1024, 2 * 1024 * 1024 * 1024, "platform", "web", "backup-worker"),
    _spec("PROTECTED_STORAGE_SIGNED_URL_TTL_SECONDS", 300, "int", 60, 3600, "privacy", "web"),
    _spec("APPOINTMENT_SLOT_DURATION_MINUTES", 60, "int", 1, 240, "appointments", "web"),
    _spec("APPOINTMENT_STUDENT_CANCELLATION_CUTOFF_MINUTES", 60, "int", 1, 1440, "appointments", "web"),
    _spec("APPOINTMENT_STUDENT_GRACE_PERIOD_MINUTES", 15, "int", 1, 120, "appointments", "web"),
    _spec("ECOUNSELING_JOIN_WINDOW_BEFORE_MINUTES", 15, "int", 0, 1440, "counseling", "web"),
    _spec("ECOUNSELING_JOIN_WINDOW_AFTER_MINUTES", 30, "int", 0, 1440, "counseling", "web"),
    _spec("ECOUNSELING_DAILY_MEETING_TOKEN_TTL_SECONDS", 300, "int", 60, 3600, "counseling", "web"),
    _spec("ECOUNSELING_RECORDING_ENABLED", False, "bool", None, None, "privacy", "web", "ecounseling-recording-worker"),
    _spec("ECOUNSELING_RECORDING_WORKER_ENABLED", False, "bool", None, None, "privacy", "ecounseling-recording-worker"),
    _spec("ECOUNSELING_RECORDING_AUDIO_VIDEO_ENABLED", False, "bool", None, None, "privacy", "web"),
    _spec("ECOUNSELING_RECORDING_TRANSCRIPTION_ENABLED", False, "bool", None, None, "privacy", "web"),
    _spec("ECOUNSELING_RECORDING_TRANSCRIPTION_WORKER_ENABLED", False, "bool", None, None, "privacy", "ecounseling-recording-worker"),
    _spec("ECOUNSELING_RECORDING_MAX_FILE_SIZE_BYTES", 0, "int", 0, 2 * 1024 * 1024 * 1024, "privacy", "web", "ecounseling-recording-worker"),
    _spec("ECOUNSELING_RECORDING_TRANSCRIPTION_MAX_FILE_SIZE_BYTES", 0, "int", 0, 50 * 1024 * 1024, "privacy", "web", "ecounseling-recording-worker"),
    _spec("REPORT_SYNC_MAX_OUTPUT_BYTES", 262144, "int", 64 * 1024, 2 * 1024 * 1024, "platform", "web"),
    _spec("REPORT_SYNC_MAX_WORK_UNITS", 1000, "int", 100, 10000, "platform", "web"),
    _spec("REPORT_ASYNC_AFTER_WORK_UNITS", 3000, "int", 1001, 100000, "platform", "web"),
    _spec("REPORT_RUN_TIMEOUT_SECONDS", 60, "int", 5, 300, "platform", "web"),
    _spec("REPORT_EXPORT_MAX_OUTPUT_BYTES", 8 * 1024 * 1024, "int", 256 * 1024, 50 * 1024 * 1024, "platform", "web"),
    _spec("REPORT_EXPORT_EXPIRY_DAYS", 7, "int", 1, 30, "privacy", "web"),
    _spec("REPORT_RUN_RETENTION_DAYS", 30, "int", 1, 90, "privacy", "web"),
)


RUNTIME_SETTING_INVENTORY = MappingProxyType({spec.key: spec for spec in _SPECS})
RUNTIME_SETTING_DEFAULTS = MappingProxyType(
    {key: spec.default for key, spec in RUNTIME_SETTING_INVENTORY.items()}
)
RUNTIME_SETTING_RULES = MappingProxyType(
    {key: spec.safety_rule for key, spec in RUNTIME_SETTING_INVENTORY.items()}
)
ENVIRONMENT_RUNTIME_SETTINGS = frozenset(
    key for key, spec in RUNTIME_SETTING_INVENTORY.items() if spec.source == "environment"
)


# Policy-family ownership for the settings that are still database-effective.
# This belongs beside the canonical inventory, not in Governance's catalog.
RUNTIME_SETTING_KEYS_BY_POLICY = MappingProxyType(
    {
        "technical.configuration": frozenset({"MAINTENANCE_ENFORCEMENT_ENABLED"}),
        "technical.renderer": frozenset({"DOCUMENT_PDF_RENDERER_ENABLED", "DOCUMENT_PDF_RENDERER_TIMEOUT_MS"}),
        "technical.backup_metadata": frozenset({
            "BACKUP_RETENTION_DAILY_DAYS",
            "BACKUP_RETENTION_WEEKLY_WEEKS",
            "BACKUP_RETENTION_MONTHLY_ENABLED",
            "BACKUP_WORKER_POLL_INTERVAL_SECONDS",
        }),
        "reports.execution_controls": frozenset({
            "REPORT_SYNC_MAX_OUTPUT_BYTES",
            "REPORT_SYNC_MAX_WORK_UNITS",
            "REPORT_ASYNC_AFTER_WORK_UNITS",
            "REPORT_RUN_TIMEOUT_SECONDS",
            "REPORT_EXPORT_MAX_OUTPUT_BYTES",
            "REPORT_EXPORT_EXPIRY_DAYS",
            "REPORT_RUN_RETENTION_DAYS",
        }),
        "technical.delivery_operations": frozenset({
            "ACCOUNT_SECURITY_CAPTCHA_TIMEOUT_SECONDS",
            "EMAIL_TIMEOUT",
            "NOTIFICATION_WORKER_ENABLED",
            "NOTIFICATION_WORKER_INTERVAL_SECONDS",
            "NOTIFICATION_WORKER_BATCH_SIZE",
            "NOTIFICATION_WORKER_LOCK_TIMEOUT_SECONDS",
        }),
        "security.account_security_controls": frozenset({
            "ACCOUNT_ACTIVATION_TOKEN_VALIDITY_DAYS",
            "ACCOUNT_SECURITY_ENFORCE_2FA_FOR_INTERNAL_USERS",
            "API_ACCESS_TOKEN_TTL_SECONDS",
            "API_REFRESH_TOKEN_TTL_SECONDS",
            "ACCOUNT_SECURITY_ASSURANCE_MAX_AGE_SECONDS",
            "ACCOUNT_SECURITY_SENSITIVE_ASSURANCE_MAX_AGE_SECONDS",
            "ACCOUNT_SECURITY_OTP_EXPIRY_SECONDS",
            "ACCOUNT_SECURITY_OTP_MAX_ATTEMPTS",
            "ACCOUNT_SECURITY_OTP_RESEND_COOLDOWN_SECONDS",
            "ACCOUNT_SECURITY_OTP_MAX_RESENDS",
            "ACCOUNT_SECURITY_LOGIN_CHALLENGE_MAX_LIFETIME_SECONDS",
            "ACCOUNT_SECURITY_RECOVERY_TOKEN_EXPIRY_SECONDS",
            "ACCOUNT_SECURITY_RECOVERY_MAX_ATTEMPTS",
            "ACCOUNT_SECURITY_RECOVERY_RESEND_COOLDOWN_SECONDS",
            "ACCOUNT_SECURITY_TRUSTED_DEVICE_DAYS_STUDENT",
            "ACCOUNT_SECURITY_TRUSTED_DEVICE_DAYS_STAFF",
            "ACCOUNT_SECURITY_TRUSTED_DEVICE_DAYS_IT_ADMIN",
            "ACCOUNT_SECURITY_DISABLE_IT_ADMIN_TRUSTED_DEVICES",
            "ACCOUNT_SECURITY_TRUSTED_DEVICE_MAX_ACTIVE",
        }),
        "appointments.scheduling_controls": frozenset({
            "APPOINTMENT_SLOT_DURATION_MINUTES",
            "APPOINTMENT_STUDENT_CANCELLATION_CUTOFF_MINUTES",
            "APPOINTMENT_STUDENT_GRACE_PERIOD_MINUTES",
        }),
        "security.protected_storage": frozenset({
            "PROTECTED_STORAGE_MAX_FILE_SIZE_BYTES",
            "PROTECTED_STORAGE_SIGNED_URL_TTL_SECONDS",
        }),
        "counseling.ecounseling_controls": frozenset({
            "ECOUNSELING_JOIN_WINDOW_BEFORE_MINUTES",
            "ECOUNSELING_JOIN_WINDOW_AFTER_MINUTES",
            "ECOUNSELING_DAILY_MEETING_TOKEN_TTL_SECONDS",
            "ECOUNSELING_RECORDING_ENABLED",
            "ECOUNSELING_RECORDING_WORKER_ENABLED",
            "ECOUNSELING_RECORDING_AUDIO_VIDEO_ENABLED",
            "ECOUNSELING_RECORDING_TRANSCRIPTION_ENABLED",
            "ECOUNSELING_RECORDING_TRANSCRIPTION_WORKER_ENABLED",
            "ECOUNSELING_RECORDING_MAX_FILE_SIZE_BYTES",
            "ECOUNSELING_RECORDING_TRANSCRIPTION_MAX_FILE_SIZE_BYTES",
        }),
    }
)


def get_runtime_setting_spec(setting_key: str) -> RuntimeSettingSpec:
    try:
        return RUNTIME_SETTING_INVENTORY[str(setting_key)]
    except KeyError as exc:
        raise KeyError(f"Unknown runtime setting: {setting_key!r}") from exc


def read_environment_setting(setting_key: str, environ=None):
    """Parse one environment-owned setting with its immutable safety bounds."""

    spec = get_runtime_setting_spec(setting_key)
    if spec.source != "environment" or not spec.env_name:
        raise ValueError(f"{setting_key} is not environment-owned.")
    values = os.environ if environ is None else environ
    raw = values.get(spec.env_name)
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return spec.default
    if spec.kind == "bool":
        normalized = str(raw).strip().lower()
        if normalized in {"true", "1", "yes", "on"}:
            return True
        if normalized in {"false", "0", "no", "off"}:
            return False
        raise ValueError(f"{spec.env_name} must be a canonical boolean.")
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{spec.env_name} must be an integer.") from exc
    return spec.validate(value)


def validate_policy_runtime_configuration(policy_key: str, configuration) -> None:
    """Validate the stable JSON envelope used by a runtime policy family."""

    if not isinstance(configuration, dict) or set(configuration) != {"setting_key", "value", "deployment_owned"}:
        raise ValueError("Runtime policy configuration fields are incomplete or unsupported.")
    setting_key = configuration["setting_key"]
    if setting_key not in RUNTIME_SETTING_KEYS_BY_POLICY.get(policy_key, frozenset()):
        raise ValueError("The runtime setting is not registered for this policy family.")
    if not isinstance(configuration["deployment_owned"], bool):
        raise ValueError("Runtime setting ownership must be boolean.")
    spec = get_runtime_setting_spec(setting_key)
    if spec.source == "environment":
        raise ValueError("Deployment-owned runtime settings cannot be governed by PolicyRecord.")
    spec.validate(configuration["value"])


def normalize_policy_runtime_configuration(configuration):
    if not isinstance(configuration, dict) or set(configuration) != {"setting_key", "value", "deployment_owned"}:
        raise ValueError("Runtime policy configuration fields are incomplete or unsupported.")
    return dict(configuration)


def runtime_policy_definition(
    key: str,
    *,
    owner_plane: str,
    sensitivity: str,
    approval_required: bool,
    runtime_consumer: str,
    stricter_update=None,
):
    """Build a runtime-policy definition without importing Governance."""

    from apps.common.policy import PolicyDefinition

    def validate_configuration(configuration):
        validate_policy_runtime_configuration(key, configuration)

    def validate_request(request, configuration):
        validate_policy_runtime_configuration(key, configuration)
        if request.target_reference != configuration["setting_key"]:
            raise ValueError("A runtime setting policy requires a matching setting target.")

    return PolicyDefinition(
        key=key,
        configuration_fields=("setting_key", "value", "deployment_owned"),
        normalize=normalize_policy_runtime_configuration,
        validate=validate_configuration,
        request_validator=validate_request,
        stricter_update=stricter_update,
        owner_plane=owner_plane,
        sensitivity=sensitivity,
        lifecycle_actions=("DRAFT", "PENDING_APPROVAL", "ACTIVE", "RETIRED"),
        approval_required=approval_required,
        projection_fields=("setting_key", "value", "deployment_owned"),
        target_type="governance.RuntimeSetting",
        target_required=True,
        runtime_reader="apps.governance.runtime_config.resolve_runtime_setting",
        runtime_consumer=runtime_consumer,
    )


TECHNICAL_CONFIGURATION_POLICY_DEFINITION = runtime_policy_definition(
    "technical.configuration",
    owner_plane="IT_TECHNICAL",
    sensitivity="technical",
    approval_required=False,
    runtime_consumer="apps.system.maintenance_services.evaluate_maintenance_request",
)
TECHNICAL_RENDERER_POLICY_DEFINITION = runtime_policy_definition(
    "technical.renderer",
    owner_plane="IT_TECHNICAL",
    sensitivity="technical",
    approval_required=False,
    runtime_consumer="apps.governance.runtime_config.resolve_runtime_setting",
)
TECHNICAL_BACKUP_METADATA_POLICY_DEFINITION = runtime_policy_definition(
    "technical.backup_metadata",
    owner_plane="IT_TECHNICAL",
    sensitivity="technical",
    approval_required=False,
    runtime_consumer="apps.governance.runtime_config.resolve_runtime_setting",
)
TECHNICAL_DELIVERY_OPERATIONS_POLICY_DEFINITION = runtime_policy_definition(
    "technical.delivery_operations",
    owner_plane="IT_TECHNICAL",
    sensitivity="technical",
    approval_required=False,
    runtime_consumer="apps.governance.runtime_config.resolve_runtime_setting",
)
