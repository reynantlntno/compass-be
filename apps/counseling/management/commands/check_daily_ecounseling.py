from django.core.management.base import BaseCommand, CommandError

from apps.counseling.ecounseling_providers import (
    DailyProvider,
    ProviderConfigurationError,
    ProviderOperationError,
)
from apps.counseling.recording_policy import recording_availability_projection


class Command(BaseCommand):
    help = "Check Daily.co e-counseling join and recording readiness without changing provider state."

    def add_arguments(self, parser):
        parser.add_argument(
            "--require-recording",
            action="store_true",
            help="Return a non-zero exit code unless every recording prerequisite is ready.",
        )
        parser.add_argument(
            "--apply",
            action="store_true",
            help=(
                "Create or update the Daily webhook. Requires a URL and a base64 webhook secret; "
                "without this flag the command is read-only."
            ),
            )

    @staticmethod
    def _webhook_is_ready(webhook, *, required_events, url):
        state = str(webhook.get("state") or "").upper()
        event_types = set(webhook.get("eventTypes") or webhook.get("event_types") or [])
        missing = required_events - event_types
        url_matches = bool(url) and webhook.get("url") == url
        return state == "ACTIVE" and not missing and url_matches

    def _configured_webhook(self, provider, webhook_id, *, required_events, url, secret, apply):
        if apply:
            if not url or not secret:
                raise CommandError(
                    "--apply requires ECOUNSELING_DAILY_WEBHOOK_URL and "
                    "ECOUNSELING_DAILY_WEBHOOK_SECRET."
                )
            if webhook_id:
                try:
                    provider.api.get_webhook(webhook_id)
                except ProviderOperationError as exc:
                    if exc.safe_code != "DAILY_HTTP_404":
                        raise CommandError("Configured Daily webhook could not be read.") from exc
                    result = provider.api.create_webhook(
                        url=url,
                        event_types=required_events,
                        hmac_secret=secret,
                    )
                else:
                    result = provider.api.update_webhook(
                        webhook_id,
                        url=url,
                        event_types=required_events,
                        hmac_secret=secret,
                    )
            else:
                try:
                    matching = [item for item in provider.api.list_webhooks() if item.get("url") == url]
                except (ProviderConfigurationError, ProviderOperationError) as exc:
                    raise CommandError("Daily webhooks could not be listed.") from exc
                matching_id = (
                    matching[0].get("uuid") or matching[0].get("id")
                    if len(matching) == 1
                    else ""
                )
                if len(matching) == 1 and matching_id:
                    result = provider.api.update_webhook(
                        matching_id,
                        url=url,
                        event_types=required_events,
                        hmac_secret=secret,
                    )
                elif matching:
                    raise CommandError("Daily has multiple webhooks for the configured callback URL.")
                else:
                    result = provider.api.create_webhook(
                        url=url,
                        event_types=required_events,
                        hmac_secret=secret,
                    )
            if not isinstance(result, dict):
                raise CommandError("Daily returned an invalid webhook response.")
            webhook_id = result.get("uuid") or result.get("id") or webhook_id
            if not webhook_id:
                raise CommandError("Daily did not return a webhook identifier.")
            self.stdout.write(f"webhook_id={webhook_id}")
        if not webhook_id:
            return None
        try:
            return provider.api.get_webhook(webhook_id)
        except (ProviderConfigurationError, ProviderOperationError) as exc:
            if apply or self._require_recording:
                raise CommandError("Configured Daily webhook could not be verified.") from exc
            return {"_unreachable": True}

    def handle(self, *args, **options):
        self._require_recording = bool(options["require_recording"])
        projection = recording_availability_projection()
        if options["apply"] and projection.blocked:
            raise CommandError(
                f"{projection.reason_code}: Daily webhook mutation is disabled while recording is policy-disabled."
            )
        if options["require_recording"] and projection.blocked:
            raise CommandError(
                f"{projection.reason_code}: recording prerequisites are deferred by approved policy."
            )
        provider = DailyProvider()
        capabilities = provider.capabilities()
        if projection.blocked:
            self.stdout.write(f"recording_policy={projection.state.value}")
            self.stdout.write(f"join_ready={'yes' if capabilities.supports_provider_auth else 'no'}")
            self.stdout.write(f"meeting_tokens={'yes' if capabilities.supports_meeting_tokens else 'no'}")
            self.stdout.write(f"recording_ready=no reason={projection.reason_code}")
            return
        required = {
            "recording.started",
            "recording.ready-to-download",
            "recording.error",
            "transcript.started",
            "transcript.ready-to-download",
            "transcript.error",
        }
        webhook_id = getattr(provider.settings, "ECOUNSELING_DAILY_WEBHOOK_ID", "")
        webhook_url = getattr(provider.settings, "ECOUNSELING_DAILY_WEBHOOK_URL", "")
        webhook_secret = getattr(provider.settings, "ECOUNSELING_DAILY_WEBHOOK_SECRET", "")
        webhook = self._configured_webhook(
            provider,
            webhook_id,
            required_events=required,
            url=webhook_url,
            secret=webhook_secret,
            apply=bool(options["apply"]),
        )
        remote_webhook_ready = False
        if webhook is None:
            self.stdout.write("webhook=unconfigured")
        elif webhook.get("_unreachable"):
            self.stdout.write("webhook=unreachable-or-invalid")
        else:
            remote_webhook_ready = self._webhook_is_ready(
                webhook,
                required_events=required,
                url=webhook_url,
            )
            if remote_webhook_ready:
                self.stdout.write("webhook=ready")
            else:
                self.stdout.write("webhook=misconfigured")
                if options["require_recording"]:
                    raise CommandError("Daily webhook events or callback URL are incomplete.")

        join_ready = capabilities.supports_provider_auth
        recording_ready = capabilities.recording_prerequisites_ready and remote_webhook_ready
        self.stdout.write(f"join_ready={'yes' if join_ready else 'no'}")
        self.stdout.write(f"meeting_tokens={'yes' if capabilities.supports_meeting_tokens else 'no'}")
        self.stdout.write(f"recording_ready={'yes' if recording_ready else 'no'}")

        if options["require_recording"] and not recording_ready:
            raise CommandError("Daily recording prerequisites are not ready.")
