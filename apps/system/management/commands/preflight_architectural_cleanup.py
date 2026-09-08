"""Read-only deployment preflight for the architectural cleanup cutover."""

import json
from pathlib import Path

from django.conf import settings
from django.core.management import BaseCommand, CommandError, get_commands
from django.db import connection

from apps.organizations.academic_year import AcademicYearConfigurationError, get_current_academic_term
from config.runtime_settings import ENVIRONMENT_RUNTIME_SETTINGS, read_environment_setting


_RETIRED_COMMANDS = frozenset(
    {
        "set_" + "current_academic_year",
        "process_" + "email_deliveries",
        "process_" + "outbox_events",
        "check_" + "call_slip_encryption_cutover",
        "check_" + "counseling_encryption_cutover",
        "check_" + "inventory_encryption_cutover",
        "check_" + "referral_encryption_cutover",
    }
)
_ENV_CONTRACT_FILES = (
    ".env.example",
    "deploy/local-staging.env.example",
    "deploy/oci/staging.env.example",
    "compose.yaml",
    "compose.override.yaml",
    "compose.local-staging.yaml",
    "compose.staging.yaml",
)


def _legacy_metadata_rows():
    """Read the pre-cutover table without importing its removed model."""

    table_name = "system_systemmetadata"
    if table_name not in connection.introspection.table_names():
        return []
    quoted_table = connection.ops.quote_name(table_name)
    try:
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT key, value_json FROM {quoted_table} ORDER BY id")
            rows = cursor.fetchall()
    except Exception as exc:
        raise CommandError("Unable to inspect the legacy SystemMetadata table safely.") from exc
    decoded = []
    for key, value_json in rows:
        if isinstance(value_json, (bytes, bytearray)):
            value_json = value_json.decode("utf-8", errors="replace")
        if isinstance(value_json, str):
            try:
                value_json = json.loads(value_json)
            except (TypeError, ValueError):
                value_json = None
        decoded.append({"key": key, "value_json": value_json})
    return decoded


def _preflight_legacy_metadata(term):
    rows = _legacy_metadata_rows()
    if not rows:
        return
    unexpected = sorted({row["key"] for row in rows} - {"academic_year.current"})
    if unexpected:
        raise CommandError(
            "Legacy SystemMetadata has unexpected keys: " + ", ".join(unexpected[:20])
        )
    if len(rows) != 1 or term is None:
        raise CommandError(
            "Legacy SystemMetadata must contain exactly one academic_year.current row "
            "and exactly one active AcademicTerm before cutover."
        )
    payload = rows[0]["value_json"]
    if not isinstance(payload, dict) or set(payload) != {"academic_year"}:
        raise CommandError("Legacy academic_year.current has an invalid JSON payload.")
    if str(payload["academic_year"] or "").strip() != str(term.academic_year).strip():
        raise CommandError("Legacy academic_year.current disagrees with the active AcademicTerm.")


class Command(BaseCommand):
    help = "Fail closed unless the current deployment is ready for architectural cleanup."

    def add_arguments(self, parser):
        parser.add_argument(
            "--allow-empty",
            action="store_true",
            help="Allow a fresh database with no active AcademicTerm; never use for a cutover check.",
        )

    def handle(self, *args, **options):
        allow_empty = bool(options["allow_empty"])
        environment = str(getattr(settings, "COMPASS_ENVIRONMENT", "")).strip().lower()
        if allow_empty and environment in {"staging", "production", "prod"}:
            raise CommandError("--allow-empty is only permitted for fresh local or test databases.")
        try:
            term = get_current_academic_term()
        except AcademicYearConfigurationError as exc:
            if not allow_empty:
                raise CommandError(str(exc)) from exc
            term = None
        _preflight_legacy_metadata(term)

        command_names = get_commands()
        retired_present = sorted(_RETIRED_COMMANDS.intersection(command_names))
        if retired_present:
            raise CommandError(
                "Retired management commands are still registered: "
                + ", ".join(retired_present)
            )

        repo_root = Path(settings.BASE_DIR)
        missing_files = [path for path in _ENV_CONTRACT_FILES if not (repo_root / path).is_file()]
        if missing_files:
            raise CommandError("Missing deployment contract files: " + ", ".join(missing_files))
        missing_settings = []
        for setting_key in sorted(ENVIRONMENT_RUNTIME_SETTINGS):
            try:
                read_environment_setting(setting_key)
            except ValueError as exc:
                missing_settings.append(f"{setting_key}: {exc}")
            for relative_path in _ENV_CONTRACT_FILES:
                if setting_key not in (repo_root / relative_path).read_text(errors="replace"):
                    missing_settings.append(f"{setting_key} missing from {relative_path}")
        if missing_settings:
            raise CommandError("Runtime environment contract is incomplete: " + "; ".join(missing_settings[:20]))

        if term is None:
            self.stdout.write(self.style.WARNING("PRECHECK OK: fresh database; no active AcademicTerm yet (--allow-empty)."))
        else:
            self.stdout.write(
                self.style.SUCCESS(
                    f"PRECHECK OK: exactly one active AcademicTerm ({term.academic_year}, pk={term.pk})."
                )
            )
        self.stdout.write("PRECHECK OK: runtime environment inventory and deployment files agree.")
        self.stdout.write("PRECHECK OK: retired command entry points are absent.")
