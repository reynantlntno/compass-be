"""Export the native Django Ninja OpenAPI document."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from config.api.v1 import api_v1


METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def _json_safe(value: Any) -> Any:
    """Convert OpenAPI mapping keys to strings for stable JSON ordering."""

    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value


def _resolve_output(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = Path(settings.BASE_DIR) / path
    return path.resolve()


def _write_if_changed(path: Path, content: str) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file() and path.read_text(encoding="utf-8") == content:
        return False
    path.write_text(content, encoding="utf-8")
    return True


class Command(BaseCommand):
    help = "Export the deterministic Django Ninja OpenAPI document."

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--output",
            default="frontend/openapi/compass-api.json",
            help="Contract output path relative to the repository root.",
        )
        parser.add_argument(
            "--check",
            action="store_true",
            help="Verify that the checked-in artifact matches the current API.",
        )

    def handle(self, *args, **options) -> None:
        try:
            schema = _json_safe(api_v1.get_openapi_schema())
        except (TypeError, ValueError, KeyError) as exc:
            raise CommandError("Unable to build the OpenAPI document.") from exc

        openapi_text = json.dumps(schema, indent=2, sort_keys=True) + "\n"
        output = _resolve_output(str(options["output"]))
        operation_count = sum(
            sum(1 for method in path_item if method in METHODS)
            for path_item in schema.get("paths", {}).values()
            if isinstance(path_item, dict)
        )

        if options["check"]:
            if not output.is_file():
                raise CommandError(f"Missing OpenAPI artifact: {output}")
            try:
                current = output.read_text(encoding="utf-8")
            except OSError as exc:
                raise CommandError(f"Unable to read OpenAPI artifact: {output}") from exc
            if current != openapi_text:
                raise CommandError(
                    f"OpenAPI artifact is stale. Run export_openapi: {output}"
                )
            self.stdout.write(
                self.style.SUCCESS(
                    f"OpenAPI artifact is current ({len(schema.get('paths', {}))} paths, "
                    f"{operation_count} operations)."
                )
            )
            return

        changed = _write_if_changed(output, openapi_text)

        self.stdout.write(
            self.style.SUCCESS(
                "OpenAPI document exported "
                f"({len(schema.get('paths', {}))} paths, "
                f"{operation_count} operations)."
            )
        )
        self.stdout.write(f"artifact={'updated' if changed else 'unchanged'}")
