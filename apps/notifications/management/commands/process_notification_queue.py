import os
import socket
import time
import uuid

from django.core.management.base import BaseCommand

from apps.workflow.services import process_outbox_batch
from apps.notifications.services import process_email_delivery_batch
from apps.governance.runtime_config import resolve_runtime_setting


class Command(BaseCommand):
    help = "Process workflow outbox events and queued email deliveries."

    def add_arguments(self, parser):
        parser.add_argument("--batch-size", type=int, default=None)
        parser.add_argument("--lock-timeout", type=int, default=None)
        parser.add_argument("--interval", type=float, default=None)
        parser.add_argument("--loop", action="store_true", help="Keep polling until interrupted.")
        parser.add_argument("--once", action="store_true", help="Process one bounded poll (default).")

    def handle(self, *args, **options):
        worker_id = f"notification_{socket.gethostname()}_{os.getpid()}_{uuid.uuid4().hex[:8]}"
        while True:
            enabled = bool(
                resolve_runtime_setting(
                    "technical.delivery_operations",
                    "NOTIFICATION_WORKER_ENABLED",
                )
            )
            batch_size = options["batch_size"] or resolve_runtime_setting(
                "technical.delivery_operations",
                "NOTIFICATION_WORKER_BATCH_SIZE",
            )
            lock_timeout = options["lock_timeout"] or resolve_runtime_setting(
                "technical.delivery_operations",
                "NOTIFICATION_WORKER_LOCK_TIMEOUT_SECONDS",
            )
            interval = options["interval"] if options["interval"] is not None else resolve_runtime_setting(
                "technical.delivery_operations",
                "NOTIFICATION_WORKER_INTERVAL_SECONDS",
            )
            if not enabled:
                self.stdout.write("NOTIFICATION_WORKER=DISABLED")
                if not options["loop"] or options["once"]:
                    break
                time.sleep(max(0.25, float(interval)))
                continue
            outbox_count = process_outbox_batch(worker_id=worker_id, batch_size=batch_size, lock_timeout_seconds=lock_timeout)
            email_count = process_email_delivery_batch(worker_id=worker_id, batch_size=batch_size, lock_timeout_seconds=lock_timeout)
            self.stdout.write(f"Processed outbox={outbox_count} email={email_count}")
            if not options["loop"] or options["once"]:
                break
            time.sleep(max(0.25, float(interval)))
