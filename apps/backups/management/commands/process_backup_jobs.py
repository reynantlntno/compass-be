"""Supervised worker entry point for queued encrypted backup jobs."""

from __future__ import annotations

import time

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from apps.backups.services import run_next_queued_backup
from apps.governance.runtime_config import resolve_runtime_setting


class Command(BaseCommand):
    help = "Process queued backup jobs in the supervised backup-worker service."

    def add_arguments(self, parser):
        mode = parser.add_mutually_exclusive_group(required=True)
        mode.add_argument(
            "--once",
            action="store_true",
            help="Process at most one queued job, then exit.",
        )
        mode.add_argument(
            "--loop",
            action="store_true",
            help="Keep polling for queued jobs under process supervision.",
        )

    def handle(self, *args, **options):
        if not getattr(settings, "BACKUP_WORKER_ENABLED", False):
            raise CommandError("backup_worker_disabled")
        interval = resolve_runtime_setting(
            "technical.backup_metadata",
            "BACKUP_WORKER_POLL_INTERVAL_SECONDS",
        )
        if interval < 1 or interval > 3600:
            raise CommandError("backup_worker_interval_invalid")

        if options["once"]:
            self._process_once()
            return

        while True:
            self._process_once()
            time.sleep(interval)

    def _process_once(self):
        try:
            job = run_next_queued_backup()
        except Exception as exc:
            # Details are captured by the operation/audit boundary.  Command
            # output intentionally avoids configuration, database, and storage
            # exception text that could contain sensitive operational context.
            raise CommandError("backup_worker_execution_failed") from exc
        if job is None:
            self.stdout.write("BACKUP_WORKER=IDLE")
            return
        self.stdout.write(f"BACKUP_WORKER={str(job.status).upper()}")
