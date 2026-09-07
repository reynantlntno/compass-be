# Project: COMPASS
# File: apps/appointments/config.py
# Module: apps.appointments
# Purpose: Runtime configuration helpers for appointment scheduling
# Domain boundary and service policy.
# Notes:
#   - Institutional appointment semantics are resolved through Governance.
#   - Deployment-only settings remain in Django settings/environment.

from apps.governance.runtime_config import resolve_runtime_setting
from config.runtime_settings import RUNTIME_SETTING_DEFAULTS


def _coerce_positive_int(value):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    if parsed <= 0:
        return None
    return parsed


def get_appointment_config_minutes(setting_name: str) -> int:
    runtime_value = resolve_runtime_setting("appointments.scheduling_controls", setting_name)
    return _coerce_positive_int(runtime_value) or int(RUNTIME_SETTING_DEFAULTS[setting_name])


def get_slot_duration_minutes() -> int:
    return get_appointment_config_minutes(
        "APPOINTMENT_SLOT_DURATION_MINUTES",
    )


def get_cancellation_cutoff_minutes() -> int:
    return get_appointment_config_minutes(
        "APPOINTMENT_STUDENT_CANCELLATION_CUTOFF_MINUTES",
    )


def get_no_show_grace_period_minutes() -> int:
    return get_appointment_config_minutes(
        "APPOINTMENT_STUDENT_GRACE_PERIOD_MINUTES",
    )
