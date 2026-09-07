"""Controlled command for creating the first institutional IT Admin."""

from __future__ import annotations

import sys

from django.core.management.base import BaseCommand, CommandError

from apps.accounts.commands import ITAdminBootstrapCommand
from apps.accounts.services import bootstrap_it_admin
from apps.common.exceptions import CompassError


_SAFE_ERROR_CODES = frozenset({
    "validation",
    "permission",
    "lifecycle_conflict",
    "dependency_failure",
    "internal_error",
})


def _safe_error_code(error: CompassError) -> str:
    code = getattr(getattr(error, "code", None), "value", None)
    return code if code in _SAFE_ERROR_CODES else "internal_error"


def _read_confirmed_password() -> str:
    first = sys.stdin.readline()
    second = sys.stdin.readline()
    if not first or not second:
        raise CommandError("bootstrap_password_input_invalid")
    first = first.rstrip("\r\n")
    second = second.rstrip("\r\n")
    if first != second:
        raise CommandError("bootstrap_password_confirmation_mismatch")
    return first


class Command(BaseCommand):
    help = "Create the first IT Admin during controlled institutional bootstrap."

    def add_arguments(self, parser):
        parser.add_argument("--email", required=True)
        parser.add_argument("--first-name", required=True)
        parser.add_argument("--last-name", required=True)
        parser.add_argument(
            "--password-stdin",
            action="store_true",
            help="Read the password and confirmation from two secure stdin lines.",
        )
        parser.add_argument(
            "--confirm",
            action="store_true",
            help="Confirm that this one-time institutional bootstrap is intentional.",
        )

    def handle(self, *args, **options):
        if not options["confirm"]:
            raise CommandError("bootstrap_confirmation_required")
        if not options["password_stdin"]:
            raise CommandError("bootstrap_password_stdin_required")

        password = _read_confirmed_password()
        try:
            user = bootstrap_it_admin(
                ITAdminBootstrapCommand(
                    email=options["email"],
                    first_name=options["first_name"],
                    last_name=options["last_name"],
                    password=password,
                )
            )
        except CompassError as error:
            raise CommandError(f"institutional_bootstrap_failed:{_safe_error_code(error)}") from None
        except Exception:
            raise CommandError("institutional_bootstrap_failed:internal_error") from None

        self.stdout.write(
            f"IT_ADMIN_BOOTSTRAP_STATUS=created account_id={user.pk}"
        )
