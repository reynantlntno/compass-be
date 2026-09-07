# Project: COMPASS
# File: apps/counseling/ecounseling_providers.py
# Module: apps.counseling
# Purpose: Authenticated Daily.co provider boundary for COMPASS-owned e-counseling

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

from django.conf import settings

from apps.counseling.models import (
    ECounselingParticipantRoleChoices,
    ECounselingProviderChoices,
    ECounselingProviderModeChoices,
)
from apps.counseling.recording_policy import (
    recording_controls_available,
    transcription_controls_available,
)
from apps.governance.runtime_config import resolve_runtime_setting
from apps.common.exceptions import DependencyFailureError


class ProviderConfigurationError(DependencyFailureError):
    pass


class ProviderOperationError(DependencyFailureError):
    def __init__(self, safe_code):
        self.safe_code = safe_code
        super().__init__(safe_code)


@dataclass(frozen=True)
class ProviderCapabilities:
    supports_provider_auth: bool
    supports_recording_controls: bool
    supports_meeting_tokens: bool
    requires_provider_auth_for_production: bool
    production_ready: bool
    recording_prerequisites_ready: bool
    private_room_enforcement_ready: bool


@dataclass(frozen=True)
class ProviderJoinContext:
    provider: str
    provider_mode: str
    room_url: str
    public_base_url: str
    room_slug: str
    meeting_token: str
    display_name: str
    recording_allowed: bool
    recording_controls_enabled: bool
    provider_auth_enabled: bool
    production_ready: bool


def normalize_daily_domain(value: str) -> str:
    """Return a canonical HTTPS host for Daily room URLs.

    Daily's REST API is independent of this value, but the room URL is sent to
    the browser.  Accepting a full HTTPS URL is useful for deployment settings;
    paths, credentials, query strings, HTTP, and ports are rejected so a bad
    setting cannot silently produce a different provider endpoint.
    """

    raw = (value or "").strip()
    if not raw:
        raise ProviderConfigurationError("Daily.co domain is not configured.")
    candidate = raw if "://" in raw else f"https://{raw}"
    parsed = urlsplit(candidate)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ProviderConfigurationError("Daily.co domain must use HTTPS.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ProviderConfigurationError("Daily.co domain must be a host only.") from exc
    if parsed.username or parsed.password or port:
        raise ProviderConfigurationError("Daily.co domain must be a host only.")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ProviderConfigurationError("Daily.co domain must not include a path or query.")
    return parsed.hostname.rstrip(".").lower()


def _room_path(room_slug: str) -> str:
    return quote(room_slug, safe="")


class DailyAPIClient:
    """Small, authenticated HTTP client for the Daily REST API."""

    def __init__(self, django_settings=settings):
        self.settings = django_settings
        self.api_key = getattr(django_settings, "ECOUNSELING_DAILY_API_KEY", "") or ""
        self.domain_setting = getattr(django_settings, "ECOUNSELING_DAILY_DOMAIN", "") or ""
        self.base_url = "https://api.daily.co/v1"
        self.timeout = 10

    @property
    def domain(self) -> str:
        return normalize_daily_domain(self.domain_setting)

    def configured(self) -> bool:
        if not self.api_key:
            return False
        try:
            self.domain
        except ProviderConfigurationError:
            return False
        return True

    def _request(self, method: str, path: str, payload: dict | None = None) -> dict | list:
        if not self.configured():
            raise ProviderConfigurationError("Daily.co API is not configured.")
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = Request(
            f"{self.base_url}{path}",
            data=body,
            method=method,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                raw = response.read(64 * 1024)
        except HTTPError as exc:
            # Never copy provider response text into application exceptions or
            # logs.  It can contain room, account, or implementation details.
            raise ProviderOperationError(f"DAILY_HTTP_{exc.code}") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise ProviderOperationError("DAILY_UNAVAILABLE") from exc
        if not raw:
            return {}
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProviderOperationError("DAILY_INVALID_RESPONSE") from exc
        if not isinstance(decoded, (dict, list)):
            raise ProviderOperationError("DAILY_INVALID_RESPONSE")
        return decoded

    def get_room(self, room_slug: str) -> dict | None:
        try:
            return self._request("GET", f"/rooms/{_room_path(room_slug)}")
        except ProviderOperationError as exc:
            if exc.safe_code == "DAILY_HTTP_404":
                return None
            raise

    def create_room(self, room_slug: str, properties: dict | None = None) -> dict:
        props = {
            "start_audio_off": True,
            "start_video_off": True,
            "enable_prejoin_ui": False,
            "enable_network_ui": False,
            "eject_at_room_exp": True,
        }
        if properties:
            props.update(properties)
        if not props.get("nbf") or not props.get("exp"):
            raise ProviderConfigurationError(
                "Daily room start and expiry must come from the appointment schedule."
            )
        return self._request(
            "POST",
            "/rooms",
            {"name": room_slug, "privacy": "private", "properties": props},
        )

    def update_room(self, room_slug: str, properties: dict, *, privacy: str = "private") -> dict:
        return self._request(
            "POST",
            f"/rooms/{_room_path(room_slug)}",
            {"privacy": privacy, "properties": properties},
        )

    def ensure_private_room(self, room_slug: str, properties: dict) -> dict:
        """Create a deterministic private room, or safely reuse one.

        A pre-existing public room is never accepted. A 409 from a concurrent
        create is resolved by reading the room and applying the same check.
        Private rooms are reconciled to the current appointment schedule and
        required safety properties before a URL can be returned.
        """

        existing = self.get_room(room_slug)
        if existing is None:
            try:
                self.create_room(room_slug, properties)
                # Do not expose a room URL until Daily confirms the resource
                # that was actually created. This also catches an unexpected
                # provider-side default or a partially successful response.
                existing = self.get_room(room_slug)
                if existing is None:
                    raise ProviderOperationError("DAILY_ROOM_NOT_FOUND_AFTER_CREATE")
            except ProviderOperationError as exc:
                if exc.safe_code != "DAILY_HTTP_409":
                    raise
                existing = self.get_room(room_slug)
                if existing is None:
                    raise
        existing_config = existing.get("config")
        if not isinstance(existing_config, dict):
            existing_config = {}
        privacy = existing.get("privacy") or existing_config.get("privacy")
        if privacy != "private":
            raise ProviderConfigurationError("Daily room is not private.")
        config = existing_config or existing.get("properties") or {}
        needs_update = False
        for field in ("nbf", "exp"):
            expected = properties.get(field)
            actual = config.get(field)
            if expected is not None and actual is None:
                needs_update = True
            if expected is not None:
                try:
                    matches = int(actual) == int(expected)
                except (TypeError, ValueError):
                    matches = False
                if not matches:
                    needs_update = True
        for field, expected in properties.items():
            if field not in {"nbf", "exp"} and config.get(field) != expected:
                needs_update = True
        if needs_update:
            merged_config = dict(config)
            merged_config.update(properties)
            updated = self.update_room(room_slug, merged_config)
            if not updated:
                updated = self.get_room(room_slug) or {}
            updated_config = updated.get("config")
            if not isinstance(updated_config, dict):
                updated_config = updated.get("properties") or {}
            if updated.get("privacy", privacy) != "private":
                raise ProviderConfigurationError("Daily room is not private.")
            for field, expected in properties.items():
                actual = updated_config.get(field)
                if field in {"nbf", "exp"}:
                    try:
                        matches = int(actual) == int(expected)
                    except (TypeError, ValueError):
                        matches = False
                else:
                    matches = actual == expected
                if not matches:
                    raise ProviderConfigurationError("Daily room configuration could not be verified.")
            return updated
        return existing

    def create_meeting_token(self, properties: dict) -> dict:
        return self._request("POST", "/meeting-tokens", {"properties": properties})

    def start_recording(
        self,
        room_slug: str,
        instance_id: str,
        *,
        scope_code: str = "AUDIO_ONLY",
        transcript_enabled: bool = False,
    ) -> dict:
        recording_type = "cloud" if scope_code == "AUDIO_VIDEO" else "cloud-audio-only"
        payload = {"instanceId": instance_id, "type": recording_type}
        if transcript_enabled:
            payload["dataOutputs"] = ["transcript-webvtt"]
        return self._request(
            "POST",
            f"/rooms/{_room_path(room_slug)}/recordings/start",
            payload,
        )

    def stop_recording(self, room_slug: str, instance_id: str, *, scope_code: str = "AUDIO_ONLY") -> dict:
        recording_type = "cloud" if scope_code == "AUDIO_VIDEO" else "cloud-audio-only"
        return self._request(
            "POST",
            f"/rooms/{_room_path(room_slug)}/recordings/stop",
            {"instanceId": instance_id, "type": recording_type},
        )

    def get_recording_info(self, recording_id: str) -> dict:
        return self._request("GET", f"/recordings/{quote(recording_id, safe='')}")

    def get_recording_download_url(self, recording_id: str) -> str:
        return self._request(
            "GET",
            f"/recordings/{quote(recording_id, safe='')}/access-link",
        ).get("download_link", "")

    def get_transcript_download_url(self, transcript_id: str) -> str:
        response = self._request(
            "GET",
            f"/transcript/{quote(transcript_id, safe='')}/access-link",
        )
        if not isinstance(response, dict):
            return ""
        return str(response.get("download_link") or response.get("access_link") or "")

    def delete_recording(self, recording_id: str) -> dict:
        return self._request("DELETE", f"/recordings/{quote(recording_id, safe='')}")

    def delete_transcript(self, transcript_id: str) -> dict:
        return self._request("DELETE", f"/transcript/{quote(transcript_id, safe='')}")

    def get_webhook(self, webhook_id: str) -> dict:
        return self._request("GET", f"/webhooks/{quote(webhook_id, safe='')}")

    def list_webhooks(self) -> list[dict]:
        response = self._request("GET", "/webhooks")
        if isinstance(response, list):
            return [item for item in response if isinstance(item, dict)]
        webhooks = response.get("data", response.get("webhooks", []))
        return webhooks if isinstance(webhooks, list) else []

    def create_webhook(self, *, url: str, event_types: set[str], hmac_secret: str) -> dict:
        return self._request(
            "POST",
            "/webhooks",
            {
                "url": url,
                "eventTypes": sorted(event_types),
                "hmac": hmac_secret,
            },
        )

    def update_webhook(self, webhook_id: str, *, url: str, event_types: set[str], hmac_secret: str) -> dict:
        return self._request(
            "POST",
            f"/webhooks/{quote(webhook_id, safe='')}",
            {
                "url": url,
                "eventTypes": sorted(event_types),
                "hmac": hmac_secret,
            },
        )


class DailyProvider:
    provider = ECounselingProviderChoices.DAILY
    provider_auth_implemented = True
    recording_controls_implemented = True
    private_room_enforcement_implemented = True

    def __init__(self, django_settings=settings):
        self.settings = django_settings
        self.api = DailyAPIClient(django_settings)

    @property
    def mode(self) -> str:
        return getattr(
            self.settings,
            "ECOUNSELING_PROVIDER_MODE",
            ECounselingProviderModeChoices.DAILY_CLOUD,
        )

    @property
    def public_base_url(self) -> str:
        try:
            return f"https://{normalize_daily_domain(self.api.domain_setting)}"
        except ProviderConfigurationError:
            return ""

    def _webhook_ready(self) -> bool:
        return bool(
            getattr(self.settings, "ECOUNSELING_DAILY_WEBHOOK_SECRET", "")
            and getattr(self.settings, "ECOUNSELING_DAILY_WEBHOOK_ID", "")
            and getattr(self.settings, "ECOUNSELING_DAILY_WEBHOOK_URL", "")
        )

    def _durable_recording_storage_ready(self) -> bool:
        backend = str(getattr(self.settings, "PROTECTED_STORAGE_BACKEND", "local") or "").lower()
        if backend != "s3":
            return False
        return all(
            getattr(self.settings, setting_name, "")
            for setting_name in (
                "PROTECTED_STORAGE_S3_ENDPOINT_URL",
                "PROTECTED_STORAGE_S3_ACCESS_KEY",
                "PROTECTED_STORAGE_S3_SECRET_KEY",
                "PROTECTED_STORAGE_S3_BUCKET_NAME",
            )
        )

    def _recording_prerequisites_ready(self) -> bool:
        if not recording_controls_available() or not transcription_controls_available():
            return False
        from apps.privacy.services import recording_retention_days

        return bool(
            resolve_runtime_setting(
                "counseling.ecounseling_controls",
                "ECOUNSELING_RECORDING_ENABLED",
            )
            and resolve_runtime_setting(
                "counseling.ecounseling_controls",
                "ECOUNSELING_RECORDING_WORKER_ENABLED",
            )
            and self.api.configured()
            and self._webhook_ready()
            and self._durable_recording_storage_ready()
            and int(
                resolve_runtime_setting(
                    "counseling.ecounseling_controls",
                    "ECOUNSELING_RECORDING_MAX_FILE_SIZE_BYTES",
                )
            )
            > 0
            and int(
                resolve_runtime_setting(
                    "counseling.ecounseling_controls",
                    "ECOUNSELING_RECORDING_TRANSCRIPTION_MAX_FILE_SIZE_BYTES",
                )
            )
            > 0
            and recording_retention_days() > 0
        )

    def room_properties(self, *, nbf: int, exp: int) -> dict:
        if nbf >= exp:
            raise ProviderConfigurationError("Daily room schedule is invalid.")
        properties = {"nbf": int(nbf), "exp": int(exp)}
        if self._recording_prerequisites_ready():
            properties.update({
                "allow_api_access": True,
                "enable_recording": "cloud",
                "enable_transcription": True,
            })
        return properties

    def ensure_private_room(self, room_slug: str, *, nbf: int, exp: int) -> dict:
        return self.api.ensure_private_room(
            room_slug,
            self.room_properties(nbf=nbf, exp=exp),
        )

    def capabilities(self) -> ProviderCapabilities:
        private_room_ready = bool(self.private_room_enforcement_implemented)
        supports_provider_auth = bool(self.api.configured() and self.public_base_url and private_room_ready)
        recording_ready = self._recording_prerequisites_ready()
        requires_provider_auth = bool(
            getattr(self.settings, "ECOUNSELING_REQUIRE_PROVIDER_AUTH_IN_PRODUCTION", True)
        )
        unsafe_override = bool(
            getattr(self.settings, "ECOUNSELING_UNSAFE_PROVIDER_MODE_ACKNOWLEDGED", False)
        )
        return ProviderCapabilities(
            supports_provider_auth=supports_provider_auth,
            supports_recording_controls=recording_ready,
            supports_meeting_tokens=supports_provider_auth,
            requires_provider_auth_for_production=requires_provider_auth,
            production_ready=bool(supports_provider_auth and not unsafe_override),
            recording_prerequisites_ready=recording_ready,
            private_room_enforcement_ready=private_room_ready,
        )

    def validate_runtime_safety(self):
        capabilities = self.capabilities()
        if not capabilities.supports_provider_auth:
            raise ProviderConfigurationError("Daily.co provider authentication is not configured.")
        if (
            not getattr(self.settings, "DEBUG", False)
            and capabilities.requires_provider_auth_for_production
            and not capabilities.production_ready
        ):
            raise ProviderConfigurationError("Production e-counseling readiness has not been proven.")
        return capabilities

    def build_join_context(
        self,
        ecounseling_session,
        *,
        display_name: str = "",
        participant_role: str = "",
        recording_allowed: bool = False,
        now: datetime | int | float | None = None,
    ):
        capabilities = self.validate_runtime_safety()
        if not ecounseling_session.room_slug:
            raise ProviderConfigurationError("E-counseling room is not configured.")
        if not capabilities.supports_meeting_tokens:
            raise ProviderConfigurationError("Daily meeting-token authentication is unavailable.")

        moderator = participant_role == ECounselingParticipantRoleChoices.COUNSELOR
        if now is None:
            current_epoch = int(time.time())
        elif hasattr(now, "timestamp"):
            current_epoch = int(now.timestamp())
        else:
            current_epoch = int(now)
        ttl = max(
            int(
                resolve_runtime_setting(
                    "counseling.ecounseling_controls",
                    "ECOUNSELING_DAILY_MEETING_TOKEN_TTL_SECONDS",
                )
            ),
            60,
        )
        window_end = int(ecounseling_session.join_window_end_at.timestamp())
        token_exp = min(current_epoch + min(ttl, 300), window_end)
        if token_exp <= current_epoch:
            raise ProviderConfigurationError("Daily meeting-token window has expired.")
        token_response = self.api.create_meeting_token(
            {
                "room_name": ecounseling_session.room_slug,
                "is_owner": moderator,
                "user_name": display_name or "COMPASS participant",
                "exp": token_exp,
                "eject_at_token_exp": True,
                "start_audio_off": True,
                "start_video_off": True,
            }
        )
        token = token_response.get("token") if isinstance(token_response, dict) else ""
        if not token:
            raise ProviderOperationError("DAILY_TOKEN_MISSING")

        return ProviderJoinContext(
            provider=self.provider,
            provider_mode=self.mode,
            room_url=f"{self.public_base_url.rstrip('/')}/{quote(ecounseling_session.room_slug, safe='')}",
            public_base_url=self.public_base_url.rstrip("/"),
            room_slug=ecounseling_session.room_slug,
            meeting_token=token,
            display_name=display_name or "COMPASS participant",
            recording_allowed=bool(recording_allowed and capabilities.supports_recording_controls),
            recording_controls_enabled=bool(
                recording_allowed and capabilities.supports_recording_controls and moderator
            ),
            provider_auth_enabled=capabilities.supports_provider_auth,
            production_ready=capabilities.production_ready,
        )


def get_ecounseling_provider():
    provider = getattr(settings, "ECOUNSELING_PROVIDER", ECounselingProviderChoices.DAILY)
    if provider != ECounselingProviderChoices.DAILY:
        raise ProviderConfigurationError("Unsupported e-counseling provider.")
    return DailyProvider(settings)
