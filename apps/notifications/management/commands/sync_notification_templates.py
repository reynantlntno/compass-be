from django.core.management.base import BaseCommand

from apps.notifications.templates import sync_templates_registry


class Command(BaseCommand):
    help = "Synchronizes notification template metadata from the in-code registry"

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report template metadata changes without writing to the database.",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        summary = sync_templates_registry(dry_run=dry_run)
        prefix = "[Dry Run] " if dry_run else ""
        self.stdout.write(
            self.style.SUCCESS(
                f"{prefix}Notification templates: "
                f"{summary['created']} create, "
                f"{summary['updated']} update, "
                f"{summary['unchanged']} unchanged."
            )
        )
