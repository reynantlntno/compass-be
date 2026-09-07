import re

from django.core.management.base import BaseCommand, CommandError

from apps.system.readiness_services import environment_name, is_deployment_environment

from apps.privacy.services import evaluate_retention_rules


class Command(BaseCommand):
    help = "Run a metadata-only retention evaluation; privacy.boundary exposes no apply path."

    def add_arguments(self, parser):
        parser.add_argument("--environment", default=None, help="Safe environment label for the evidence row.")
        parser.add_argument(
            "--authorization-reference",
            default="",
            help="Recorded approval reference required for staging/production-like dry runs.",
        )

    def handle(self, *args, **options):
        environment = (options.get("environment") or environment_name()).strip().lower()
        authorization = (options.get("authorization_reference") or "").strip()
        if authorization and not re.fullmatch(r"[A-Za-z0-9._:-]{1,100}", authorization):
            raise CommandError("PRIVACY_RETENTION_REFUSED_AUTHORIZATION_REFERENCE_INVALID")
        if (is_deployment_environment() or environment in {"production", "prod", "staging", "stage"}) and not authorization:
            raise CommandError("PRIVACY_RETENTION_REFUSED_AUTHORIZATION_REQUIRED")
        if "apply" in options:
            raise CommandError("PRIVACY_RETENTION_NO_APPLY_PATH")
        rows = evaluate_retention_rules(environment=environment)
        self.stdout.write("PRIVACY_RETENTION_MODE=DRY_RUN_METADATA_ONLY")
        self.stdout.write(f"PRIVACY_RETENTION_ENVIRONMENT={environment}")
        self.stdout.write(f"PRIVACY_RETENTION_CATEGORIES={len(rows)}")
        self.stdout.write("PRIVACY_RETENTION_CANDIDATES=0")
        self.stdout.write("PRIVACY_RETENTION_RESULT_CODES=BLOCKED_RULE,LEGAL_HOLD,NO_CANDIDATES")
        self.stdout.write("PRIVACY_RETENTION_RESULT=METADATA_ONLY_NO_DISPOSAL")
