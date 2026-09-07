#!/usr/bin/env python3
"""Portable, container-aware COMPASS API management and readiness runner.

This wrapper never imports Django on the host.  It invokes management commands
inside the configured Compose ``web`` service and keeps the API deployment
readiness sequence read-only.
"""

from __future__ import annotations

import argparse
import os
import shlex
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Sequence


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_HEALTH_URL = "http://localhost:8000/health/"


def compose_command() -> list[str]:
    """Resolve an explicit or installed Compose command without shell parsing."""

    configured = os.environ.get("COMPASS_COMPOSE_COMMAND", "").strip()
    if configured:
        return shlex.split(configured)
    if shutil.which("podman"):
        return ["podman", "compose"]
    if shutil.which("docker"):
        return ["docker", "compose"]
    if shutil.which("docker-compose"):
        return ["docker-compose"]
    raise RuntimeError("No supported Podman or Docker Compose command is available.")


def compose_file_arguments() -> list[str]:
    """Return optional, validated compose files from COMPASS_COMPOSE_FILES."""

    configured = os.environ.get("COMPASS_COMPOSE_FILES", "").strip()
    if not configured:
        return []
    arguments: list[str] = []
    for raw_path in configured.split(os.pathsep):
        path = Path(raw_path).expanduser()
        if not path.is_absolute():
            path = REPOSITORY_ROOT / path
        path = path.resolve()
        if not path.is_file():
            raise RuntimeError("Configured Compose file does not exist.")
        arguments.extend(["-f", str(path)])
    return arguments


def operating_demo_password_environment_name(management_args: Sequence[str]) -> str | None:
    """Forward only the explicitly requested operating-demo password, if set."""

    if not management_args or management_args[0] != "seed_operating_demo":
        return None
    password_env_name = "COMPASS_DEMO_PASSWORD"
    arguments = iter(management_args[1:])
    for argument in arguments:
        if argument == "--password-env":
            password_env_name = next(arguments, password_env_name)
            break
        if argument.startswith("--password-env="):
            password_env_name = argument.split("=", 1)[1]
            break
    if password_env_name and os.environ.get(password_env_name):
        return password_env_name
    return None


def operating_demo_seed_environment_names(management_args: Sequence[str]) -> tuple[str, ...]:
    """Return operating-seed secret names without putting values in argv."""

    password_name = operating_demo_password_environment_name(management_args)
    if password_name is None:
        return ()
    names = [password_name]
    field_key_name = "FIELD_ENCRYPTION_KEY"
    if os.environ.get(field_key_name):
        names.append(field_key_name)
    return tuple(names)


def build_manage_command(management_args: Sequence[str]) -> list[str]:
    if not management_args:
        raise ValueError("A Django management command is required.")
    command = [
        *compose_command(),
        *compose_file_arguments(),
        "exec",
        "-T",
    ]
    for environment_name in operating_demo_seed_environment_names(management_args):
        command.extend(["-e", environment_name])
    command.extend([
        "web",
        "python",
        "manage.py",
        *management_args,
    ])
    return command


def run_manage(management_args: Sequence[str]) -> int:
    """Run one Django command inside the web service and return its exit code."""

    try:
        completed = subprocess.run(build_manage_command(management_args), cwd=REPOSITORY_ROOT)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"COMPASS_RUNTIME_ERROR={type(exc).__name__}", file=sys.stderr)
        return 1
    return completed.returncode


def parse_enabled(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def check_health_endpoint(url: str) -> bool:
    """Perform only a GET liveness request; it does not mutate application state."""

    request = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": "COMPASS-readiness/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - operator-supplied probe URL
            return response.status == 200
    except (urllib.error.URLError, ValueError, TimeoutError):
        return False


def run_readiness() -> int:
    """Run the documented read-only deployment readiness sequence."""

    configured_api_url = os.environ.get("COMPASS_API_BASE_URL", "").strip().rstrip("/")
    health_url = os.environ.get("COMPASS_HEALTHCHECK_URL", "").strip()
    if not health_url:
        health_url = f"{configured_api_url}/health/" if configured_api_url else DEFAULT_HEALTH_URL
    system_identity = os.environ.get("COMPASS_READINESS_SYSTEM_IDENTITY", "").strip()
    probe_external = parse_enabled(os.environ.get("COMPASS_READINESS_PROBE_EXTERNAL"))
    health_args = ["verify_health", "--strict", "--format", "json"]
    # backup_dry_run requires the option even when no approved identity is
    # available. Passing an empty value lets its own read-only policy report an
    # authorization boundary instead of turning the readiness run into an
    # argparse usage error.
    backup_args = [
        "backup_dry_run",
        "--strict",
        "--format",
        "json",
        "--system-identity",
        system_identity,
    ]
    if system_identity:
        health_args.extend(["--system-identity", system_identity])
    if probe_external:
        health_args.append("--probe-external")
        backup_args.append("--probe-external")

    checks: list[tuple[str, Sequence[str] | None]] = [
        ("API service deployment checks", ("check", "--deploy")),
        ("Migration state (read-only)", ("migrate", "--check", "--plan")),
        ("Health liveness endpoint", None),
        ("Admin/docs static collection dry-run", ("collectstatic", "--dry-run", "--noinput")),
        ("Health verification", health_args),
        ("Encryption status", ("check_encryption_status", "--strict", "--format", "json")),
        ("Backup destination dry-run", backup_args),
        ("Canonical notification worker command availability", ("help", "process_notification_queue")),
    ]

    print("=== COMPASS API Deployment Readiness Verification ===")
    print("Health URL configured: yes")
    print(f"External probes enabled: {'yes' if probe_external else 'no'}")
    print("This run reports automated evidence only; it does not approve a release.")

    failures = 0
    for label, command in checks:
        print(f"\n--- {label} ---")
        passed = check_health_endpoint(health_url) if command is None else run_manage(command) == 0
        if passed:
            print(f"CHECK_STATUS=PASS label={label}")
        else:
            print(f"CHECK_STATUS=FAIL label={label}")
            failures += 1

    if failures:
        print(f"AUTOMATED_CHECKS=FAIL failures={failures}")
    else:
        print("AUTOMATED_CHECKS=PASS")
    print("RELEASE_CLAIM=NOT_CLAIMED")
    print(
        "Manual authorization remains required for real backup/restore, delivery, "
        "migration, key, provider, browser, and deployment gates."
    )
    return 1 if failures else 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    manage_parser = subcommands.add_parser("manage", help="Run a Django command in the web container.")
    manage_parser.add_argument("management_args", nargs=argparse.REMAINDER)
    subcommands.add_parser("readiness", help="Run the read-only readiness sequence.")
    options = parser.parse_args(argv)
    if options.command == "manage":
        return run_manage(options.management_args)
    return run_readiness()


if __name__ == "__main__":
    raise SystemExit(main())
