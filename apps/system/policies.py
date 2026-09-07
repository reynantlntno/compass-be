# Project: COMPASS
# File: apps/system/policies.py
# Module: apps.system
# Purpose: Access policies for application error events
# Domain boundary and service policy.
# Notes:
#   - IT Admin only. No Django framework-flag business authorization.
#   - Students, counselors, GCO staff, and Head Guidance denied by default.
#   - Stack traces are never exposed to normal users or production UI.

from apps.access_control.authority import has_capability, has_fixed_capability
from apps.access_control.capabilities import Capability


def _can_access_application_errors(actor) -> bool:
    """Resolve the existing technical capability with fail-closed eligibility."""
    return has_capability(actor, Capability.SYSTEM_ERRORS_VIEW)


def can_list_application_error_events(actor) -> bool:
    """IT Admin only may list application error events."""
    return _can_access_application_errors(actor)


def can_view_application_error_event(actor, event) -> bool:
    """IT Admin only may view a specific application error event."""
    return _can_access_application_errors(actor)


def can_resolve_application_error_event(actor, event) -> bool:
    """IT Admin only may mark an error resolved."""
    return _can_access_application_errors(actor)


def can_reopen_application_error_event(actor, event) -> bool:
    """IT Admin only may reopen an error."""
    return _can_access_application_errors(actor)


def can_view_redacted_stack_trace(actor, event) -> bool:
    """Whether the actor may view the redacted stack trace.

    Stack trace capture and viewing remain disabled in every environment for
    this privacy-safe diagnostic slice.
    """
    return False


def can_view_system_health(actor) -> bool:
    """IT Admin only can view system health metrics."""
    return has_fixed_capability(actor, Capability.SYSTEM_HEALTH_VIEW)


def can_manage_maintenance_mode(actor) -> bool:
    """IT Admin only can schedule or manage maintenance mode."""
    return has_fixed_capability(actor, Capability.SYSTEM_OPERATIONS_MANAGE)


def can_view_environment_summary(actor) -> bool:
    """IT Admin only can view environment configuration variables configuration state."""
    return has_fixed_capability(actor, Capability.SYSTEM_ENVIRONMENT_VIEW)


def can_view_release_operations(actor) -> bool:
    """IT Admin-only release and operations visibility."""
    return has_fixed_capability(actor, Capability.SYSTEM_OPERATIONS_MANAGE)


def can_run_health_checks(actor) -> bool:
    """IT Admin only can trigger health checks rerun."""
    return has_fixed_capability(actor, Capability.SYSTEM_HEALTH_VIEW)


def can_view_component_health_detail(actor, component: str) -> bool:
    """IT Admin only can view detailed metrics of a health component."""
    return has_fixed_capability(actor, Capability.SYSTEM_HEALTH_VIEW)


def can_bypass_maintenance(actor) -> bool:
    """IT Admin only can bypass future maintenance enforcement."""
    return has_fixed_capability(actor, Capability.SYSTEM_OPERATIONS_MANAGE)


def can_view_maintenance(actor) -> bool:
    """IT Admin only can view maintenance-window metadata."""
    return has_fixed_capability(actor, Capability.SYSTEM_OPERATIONS_MANAGE)


def can_view_operational_history(actor) -> bool:
    """IT Admin only can view sanitized operational history."""
    return has_fixed_capability(actor, Capability.SYSTEM_OPERATIONS_MANAGE)
