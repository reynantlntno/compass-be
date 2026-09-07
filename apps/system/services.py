"""Framework-neutral composition helpers for the system operational API."""

from __future__ import annotations

from apps.system.commands import HealthCheckCommand
from apps.system.health_services import run_all_health_checks


def run_health_check_command(command: HealthCheckCommand) -> list[dict]:
    """Run the bounded health probe selected by a validated command."""
    results = run_all_health_checks()
    if command.component == "all":
        return results
    return [item for item in results if item.get("component") == command.component]
