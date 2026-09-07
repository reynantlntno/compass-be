"""Controlled operator command for recovering an existing IT Admin."""

from __future__ import annotations

import sys

from django.core.management.base import BaseCommand, CommandError

from apps.account_security.commands import ITAdminRecoveryCommand
from apps.account_security.application_services import recover_it_admin_password
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
    """Read two non-echoed lines supplied by the operator boundary."""
    first = sys.stdin.readline()
    second = sys.stdin.readline()
    if not first or not second:
        raise CommandError("recovery_password_input_invalid")
    first = first.rstrip("\r\n")
    second = second.rstrip("\r\n")
    if first != second:
        raise CommandError("recovery_password_confirmation_mismatch")
    return first


class Command(BaseCommand):
    help = "Recover an existing IT Admin during controlled operator recovery."

    def add_arguments(self, parser):
        parser.add_argument("--email", required=True)
        parser.add_argument(
            "--password-stdin",
            action="store_true",
            help="Read the new password and confirmation from two secure stdin lines.",
        )
        parser.add_argument(
            "--confirm",
            action="store_true",
            help="Confirm that this operator recovery is intentional.",
        )

    def handle(self, *args, **options):
        if not options["confirm"]:
            raise CommandError("recovery_confirmation_required")
        if not options["password_stdin"]:
            raise CommandError("recovery_password_stdin_required")

        password = _read_confirmed_password()
        try:
            recover_it_admin_password(
                command=ITAdminRecoveryCommand(
                    email=options["email"],
                    new_password=password,
                )
            )
        except CompassError as error:
            raise CommandError(f"it_admin_recovery_failed:{_safe_error_code(error)}") from None
        except Exception:
            raise CommandError("it_admin_recovery_failed:internal_error") from None

        self.stdout.write("IT_ADMIN_RECOVERY_STATUS=completed")
