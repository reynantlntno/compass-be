from django.core.management.base import BaseCommand
from django.utils import timezone
from apps.workflow.services import expire_old_idempotency_keys
from apps.workflow.models import IdempotencyKey


class Command(BaseCommand):
    help = "Expires idempotency keys whose validity period has elapsed"

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show keys that would expire without modifying them in the database."
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        now = timezone.now()

        if dry_run:
            query = IdempotencyKey.objects.filter(
                expires_at__lt=now
            ).exclude(status="expired")
            count = query.count()
            self.stdout.write(self.style.NOTICE(f"[Dry Run] Found {count} key(s) to expire."))
        else:
            count = expire_old_idempotency_keys()
            if count > 0:
                self.stdout.write(self.style.SUCCESS(f"Expired {count} key(s) in database."))
            else:
                self.stdout.write(self.style.NOTICE("No keys needed expiration."))
