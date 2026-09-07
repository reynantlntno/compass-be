"""Controlled command for creating the first Head Guidance counselor."""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from apps.accounts.commands import InitialHeadGuidanceBootstrapCommand
from apps.accounts.services import bootstrap_initial_head_guidance
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


class Command(BaseCommand):
    help = "Create the first inactive Head Guidance counselor during institutional bootstrap."

    def add_arguments(self, parser):
        parser.add_argument("--email", required=True)
        parser.add_argument("--first-name", required=True)
        parser.add_argument("--last-name", required=True)
        parser.add_argument("--license-number", default="")
        parser.add_argument("--validity-days", type=int, default=None)
        parser.add_argument(
            "--confirm",
            action="store_true",
            help="Confirm that this one-time institutional bootstrap is intentional.",
        )

    def handle(self, *args, **options):
        if not options["confirm"]:
            raise CommandError("bootstrap_confirmation_required")

        try:
            user, _invitation = bootstrap_initial_head_guidance(
                InitialHeadGuidanceBootstrapCommand(
                    email=options["email"],
                    first_name=options["first_name"],
                    last_name=options["last_name"],
                    license_number=options["license_number"],
                    validity_days=options["validity_days"],
                )
            )
        except CompassError as error:
            raise CommandError(f"institutional_bootstrap_failed:{_safe_error_code(error)}") from None
        except Exception:
            raise CommandError("institutional_bootstrap_failed:internal_error") from None

        self.stdout.write(
            f"INITIAL_HEAD_GUIDANCE_BOOTSTRAP_STATUS=created account_id={user.pk} invitation=queued"
        )
