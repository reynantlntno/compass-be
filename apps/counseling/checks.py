# Project: COMPASS
# File: apps/counseling/checks.py
# Module: apps.counseling
# Purpose: Deployment checks for secure e-counseling provider configuration

from django.conf import settings
from dataclasses import dataclass
from datetime import datetime, timezone as datetime_timezone
import re

from django.core.checks import Error, Warning, register, Tags
from django.utils import timezone

from apps.counseling.ecounseling_providers import DailyProvider
from apps.counseling.recording_policy import recording_availability_projection
from apps.governance.runtime_config import resolve_runtime_setting


_DEADLINE_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
CONFIGURATION_INVALID = "counseling_compatibility_configuration_invalid"
DEADLINE_EXPIRED = "counseling_compatibility_deadline_expired"
COMPATIBILITY_AVAILABLE = "counseling_compatibility_available"
COMPATIBILITY_DISABLED = "counseling_compatibility_disabled"


@dataclass(frozen=True)
class CounselingCompatibilityConfiguration:
    enabled: bool
    deadline: datetime | None
    valid: bool
    expired: bool
    result_code: str

    @property
    def permits_legacy_fallback(self):
        return self.valid and self.enabled and not self.expired


def _parse_deadline(raw):
    if type(raw) is not str or not _DEADLINE_RE.fullmatch(raw):
        return None
    try:
        parsed = datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None
    normalized = parsed.replace(tzinfo=datetime_timezone.utc)
    return normalized if normalized.strftime("%Y-%m-%dT%H:%M:%SZ") == raw else None


def validate_counseling_compatibility_settings(*, now=None, settings_obj=settings):
    """Validate configuration only; never query rows or load encryption keys."""
    enabled = getattr(settings_obj, "COUNSELING_ENCRYPTION_COMPATIBILITY_ENABLED", False)
    raw_deadline = getattr(settings_obj, "COUNSELING_ENCRYPTION_COMPATIBILITY_DEADLINE", None)
    if enabled is False:
        return CounselingCompatibilityConfiguration(False, None, True, False, COMPATIBILITY_DISABLED)
    if enabled is not True:
        return CounselingCompatibilityConfiguration(False, None, False, False, CONFIGURATION_INVALID)
    deadline = _parse_deadline(raw_deadline)
    if deadline is None:
        return CounselingCompatibilityConfiguration(True, None, False, False, CONFIGURATION_INVALID)
    current = now if now is not None else timezone.now()
    if not timezone.is_aware(current):
        return CounselingCompatibilityConfiguration(True, deadline, False, False, CONFIGURATION_INVALID)
    expired = current >= deadline
    return CounselingCompatibilityConfiguration(
        True,
        deadline,
        True,
        expired,
        DEADLINE_EXPIRED if expired else COMPATIBILITY_AVAILABLE,
    )


@register(Tags.security)
def counseling_encryption_compatibility_check(app_configs, **kwargs):
    result = validate_counseling_compatibility_settings()
    if result.valid:
        return []
    return [
        Error(
            "Counseling encryption compatibility configuration is invalid.",
            id="counseling.E002",
        )
    ]


@register(Tags.security, deploy=True)
def check_ecounseling_provider_auth(app_configs, **kwargs):
    if bool(getattr(settings, "DEBUG", False)):
        return []

    provider = str(getattr(settings, "ECOUNSELING_PROVIDER", "DAILY") or "").strip().lower()
    if provider in {"none", "disabled", "off"}:
        return [
            Warning(
                "E-counseling is explicitly disabled in this environment.",
                hint="Configure and verify the Daily.co provider before enabling e-counseling workflows.",
                id="counseling.W010",
            )
        ]

    require_provider_auth = bool(
        getattr(settings, "ECOUNSELING_REQUIRE_PROVIDER_AUTH_IN_PRODUCTION", True)
    )
    unsafe_acknowledged = bool(
        getattr(settings, "ECOUNSELING_UNSAFE_PROVIDER_MODE_ACKNOWLEDGED", False)
    )
    capabilities = DailyProvider(settings).capabilities()

    if require_provider_auth and not capabilities.supports_provider_auth and not unsafe_acknowledged:
        return [
            Error(
                "Production e-counseling has no implemented provider-side access protection.",
                hint=(
                    "Implement and enable provider-side authentication before production use, or keep launch disabled. "
                    "The unsafe override is for explicitly acknowledged demo posture only."
                ),
                id="counseling.E001",
            )
        ]

    if require_provider_auth and not capabilities.supports_provider_auth and unsafe_acknowledged:
        return [
            Warning(
                "E-counseling is running under an explicitly acknowledged unsafe demo override.",
                hint="This override is not production-ready and must not be used for production counseling.",
                id="counseling.W001",
            )
        ]

    projection = recording_availability_projection()
    if projection.blocked:
        # Provider-looking recording settings are a safe configuration
        # conflict while the approved policy is blocked, not evidence that
        # recording is operationally ready.
        if bool(
            resolve_runtime_setting(
                "counseling.ecounseling_controls",
                "ECOUNSELING_RECORDING_ENABLED",
            )
            or resolve_runtime_setting(
                "counseling.ecounseling_controls",
                "ECOUNSELING_RECORDING_WORKER_ENABLED",
            )
            or resolve_runtime_setting(
                "counseling.ecounseling_controls",
                "ECOUNSELING_RECORDING_TRANSCRIPTION_ENABLED",
            )
            or resolve_runtime_setting(
                "counseling.ecounseling_controls",
                "ECOUNSELING_RECORDING_TRANSCRIPTION_WORKER_ENABLED",
            )
        ):
            return [
                Warning(
                    "E-counseling recording settings are ignored while the approved recording policy is blocked.",
                    hint="Keep recording disabled until the recording.safety reactivation checklist is approved and evidenced.",
                    id="counseling.W009",
                )
            ]
        return []

    errors = []
    if bool(
        resolve_runtime_setting(
            "counseling.ecounseling_controls",
            "ECOUNSELING_RECORDING_ENABLED",
        )
    ):
        storage_backend = str(getattr(settings, "PROTECTED_STORAGE_BACKEND", "local") or "").lower()
        if storage_backend != "s3":
            errors.append(
                Error(
                    "Production e-counseling recording requires durable protected storage.",
                    id="counseling.E004",
                )
            )
        elif any(
            not getattr(settings, setting_name, "")
            for setting_name in (
                "PROTECTED_STORAGE_S3_ENDPOINT_URL",
                "PROTECTED_STORAGE_S3_ACCESS_KEY",
                "PROTECTED_STORAGE_S3_SECRET_KEY",
                "PROTECTED_STORAGE_S3_BUCKET_NAME",
            )
        ):
            errors.append(
                Error(
                    "Production e-counseling recording requires complete S3-compatible protected storage settings.",
                    id="counseling.E008",
                )
            )
        if not getattr(settings, "ECOUNSELING_DAILY_WEBHOOK_SECRET", ""):
            errors.append(
                Error(
                    "Daily recording webhooks require a signing secret.",
                    id="counseling.E005",
                )
            )
        if not getattr(settings, "ECOUNSELING_DAILY_WEBHOOK_ID", ""):
            errors.append(
                Error(
                    "Daily recording webhooks require a configured webhook id.",
                    id="counseling.E006",
                )
            )
        if not getattr(settings, "ECOUNSELING_DAILY_WEBHOOK_URL", ""):
            errors.append(
                Error(
                    "Daily recording webhooks require a configured callback URL.",
                    id="counseling.E009",
                )
            )
        if not resolve_runtime_setting(
            "counseling.ecounseling_controls",
            "ECOUNSELING_RECORDING_WORKER_ENABLED",
        ):
            errors.append(
                Error(
                    "Daily recording requires the protected recording worker.",
                    id="counseling.E007",
                )
            )
        if int(
            resolve_runtime_setting(
                "counseling.ecounseling_controls",
                "ECOUNSELING_RECORDING_MAX_FILE_SIZE_BYTES",
            )
            ) <= 0:
            errors.append(
                Error(
                    "Daily recording requires a positive download-size limit.",
                    id="counseling.E010",
                )
            )
        if not resolve_runtime_setting(
            "counseling.ecounseling_controls",
            "ECOUNSELING_RECORDING_TRANSCRIPTION_ENABLED",
        ):
            errors.append(
                Error(
                    "Daily recording requires protected transcription to be enabled.",
                    id="counseling.E012",
                )
            )
        if not resolve_runtime_setting(
            "counseling.ecounseling_controls",
            "ECOUNSELING_RECORDING_TRANSCRIPTION_WORKER_ENABLED",
        ):
            errors.append(
                Error(
                    "Daily recording requires the protected transcription worker.",
                    id="counseling.E013",
                )
            )
        if int(
            resolve_runtime_setting(
                "counseling.ecounseling_controls",
                "ECOUNSELING_RECORDING_TRANSCRIPTION_MAX_FILE_SIZE_BYTES",
            )
        ) <= 0:
            errors.append(
                Error(
                    "Daily transcription requires a positive download-size limit.",
                    id="counseling.E014",
                )
            )
        from apps.privacy.services import recording_retention_days

        if recording_retention_days() <= 0:
            errors.append(
                Error(
                    "Daily recording requires a positive retention period.",
                    id="counseling.E011",
                )
            )
    return errors
