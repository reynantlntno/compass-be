import time

from django.core.management.base import BaseCommand

from apps.counseling.recording_services import expire_recordings, monitor_recordings
from apps.counseling.recording_policy import recording_availability_projection


class Command(BaseCommand):
    help = "Stop/finalize recordings at safety limits; disposal remains governed by privacy retention policy."

    def add_arguments(self, parser):
        parser.add_argument("--loop", action="store_true")
        parser.add_argument("--interval", type=int, default=5)

    def handle(self, *args, **options):
        interval = max(options["interval"], 1)
        projection = recording_availability_projection()
        while True:
            stopped = monitor_recordings()
            deleted = expire_recordings()
            if not options["loop"]:
                self.stdout.write(
                    f"recording_policy={projection.state.value} "
                    f"stopped={stopped} disposal_candidates={deleted}"
                )
                return
            time.sleep(interval)
