"""Server-side CAPTCHA adapters and the shared safe verification result."""

from __future__ import annotations

import json
import logging
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from apps.governance.runtime_config import resolve_runtime_setting
from django.utils.module_loading import import_string

logger = logging.getLogger(__name__)

CAPTCHA_WIDGET_ACTIONS = frozenset(
    {
        "login",
        "recovery",
        "contact",
        "activation",
    }
)


@dataclass(frozen=True)
class CaptchaVerificationResult:
    """Allowlisted provider outcome; never carry provider payloads or secrets."""

    status: str
    reason_code: str
    # Opaque in-memory retry grant.  It is never a provider payload and is
    # never written to logs, durable metadata, or cache keys in the clear.
    grant: str | None = None

    _ALLOWED_STATUSES = frozenset({"valid", "invalid", "unavailable", "configuration_error"})
    _ALLOWED_REASONS = frozenset(
        {
            "CAPTCHA_VERIFIED",
            "CAPTCHA_RESPONSE_MISSING",
            "CAPTCHA_RESPONSE_INVALID",
            "CAPTCHA_PROVIDER_REJECTED",
            "CAPTCHA_PROVIDER_UNAVAILABLE",
            "CAPTCHA_ACTION_MISMATCH",
            "CAPTCHA_HOSTNAME_MISMATCH",
            "CAPTCHA_CONFIGURATION_INVALID",
            "CAPTCHA_ADAPTER_CONTRACT_INVALID",
        }
    )

    def __post_init__(self):
        if self.status not in self._ALLOWED_STATUSES or self.reason_code not in self._ALLOWED_REASONS:
            raise ValueError("CAPTCHA result is not allowlisted.")
        if self.grant is not None and (self.status != "valid" or not self.grant or len(self.grant) > 256):
            raise ValueError("CAPTCHA grant is invalid.")

    @property
    def valid(self) -> bool:
        return self.status == "valid"

    @property
    def invalid(self) -> bool:
        return self.status == "invalid"

    @property
    def unavailable(self) -> bool:
        return self.status == "unavailable"

    @property
    def configuration_error(self) -> bool:
        return self.status == "configuration_error"

    def __bool__(self) -> bool:
        """Preserve the old boolean adapter contract for untouched callers."""
        return self.valid


CAPTCHA_VALID = CaptchaVerificationResult("valid", "CAPTCHA_VERIFIED")


def _result(status: str, reason_code: str) -> CaptchaVerificationResult:
    return CaptchaVerificationResult(status, reason_code)


class BaseCaptchaAdapter(ABC):
    """Abstract base class for CAPTCHA verification adapters."""

    @abstractmethod
    def verify(
        self,
        response_token: str,
        expected_action: str = "",
        idempotency_key: str | None = None,
    ) -> CaptchaVerificationResult:
        """Verify the CAPTCHA response token."""
        pass


class FakeCaptchaAdapter(BaseCaptchaAdapter):
    """A deterministic fake CAPTCHA adapter for local development and testing."""

    def verify(
        self,
        response_token: str,
        expected_action: str = "",
        idempotency_key: str | None = None,
    ) -> CaptchaVerificationResult:
        if not response_token:
            return _result("invalid", "CAPTCHA_RESPONSE_MISSING")
        # Allow testing pathways to easily succeed or fail based on token content
        if response_token in ["valid", "correct-captcha", "pass", "test-passed"]:
            return CAPTCHA_VALID
        return _result("invalid", "CAPTCHA_RESPONSE_INVALID")


class CloudflareTurnstileAdapter(BaseCaptchaAdapter):
    """Small stdlib-only Turnstile Siteverify adapter.

    Siteverify is deliberately called only from the backend.  The provider
    response is reduced to an allowlisted result before it can reach callers.
    """

    endpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

    def __init__(self):
        self.secret = str(getattr(settings, "ACCOUNT_SECURITY_TURNSTILE_SECRET", "") or "").strip()
        self.timeout = int(
            resolve_runtime_setting(
                "technical.delivery_operations",
                "ACCOUNT_SECURITY_CAPTCHA_TIMEOUT_SECONDS",
            )
        )
        configured = getattr(settings, "ACCOUNT_SECURITY_TURNSTILE_HOSTNAMES", ())
        if isinstance(configured, str):
            configured = tuple(item.strip().lower() for item in configured.split(",") if item.strip())
        self.hostnames = frozenset(str(item).strip().lower() for item in configured if str(item).strip())
        if not self.secret or not 1 <= self.timeout <= 15 or not self.hostnames:
            raise ImproperlyConfigured("Turnstile CAPTCHA configuration is incomplete.")

    def verify(
        self,
        response_token: str,
        expected_action: str = "",
        idempotency_key: str | None = None,
    ) -> CaptchaVerificationResult:
        token = str(response_token or "").strip()
        if not token or len(token) > 2048:
            return _result("invalid", "CAPTCHA_RESPONSE_INVALID")
        idem = idempotency_key or str(uuid.uuid4())
        payload = {
            "secret": self.secret,
            "response": token,
            "idempotency_key": idem,
        }
        request = Request(
            self.endpoint,
            data=urlencode(payload).encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        body = None
        for _attempt in range(2):
            try:
                with urlopen(request, timeout=self.timeout) as response:
                    body = response.read(64 * 1024)
                break
            except (HTTPError, URLError, TimeoutError, OSError):
                continue
        if body is None:
            logger.warning("CAPTCHA provider unavailable.")
            return _result("unavailable", "CAPTCHA_PROVIDER_UNAVAILABLE")
        try:
            provider = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeError):
            return _result("invalid", "CAPTCHA_PROVIDER_REJECTED")
        if not isinstance(provider, dict) or not provider.get("success"):
            return _result("invalid", "CAPTCHA_PROVIDER_REJECTED")
        if expected_action and provider.get("action") != expected_action:
            return _result("invalid", "CAPTCHA_ACTION_MISMATCH")
        hostname = str(provider.get("hostname") or "").lower()
        if hostname not in self.hostnames:
            return _result("invalid", "CAPTCHA_HOSTNAME_MISMATCH")
        return CAPTCHA_VALID


def get_captcha_adapter() -> BaseCaptchaAdapter:
    """Load and return the CAPTCHA adapter configured in Django settings."""
    adapter_path = str(getattr(settings, "ACCOUNT_SECURITY_CAPTCHA_ADAPTER", "") or "").strip()
    if not adapter_path:
        raise ImproperlyConfigured("CAPTCHA adapter is not configured.")
    adapter_class = import_string(adapter_path)
    if not isinstance(adapter_class, type) or not issubclass(adapter_class, BaseCaptchaAdapter):
        raise ImproperlyConfigured("CAPTCHA adapter is invalid.")
    if (
        issubclass(adapter_class, FakeCaptchaAdapter)
        and getattr(settings, "COMPASS_ENVIRONMENT", "development") not in {"development", "testing"}
    ):
        raise ImproperlyConfigured("Fake CAPTCHA is not available in deployment.")
    return adapter_class()


def is_live_captcha_configured() -> bool:
    """Return True only when settings point to a non-fake CAPTCHA adapter."""
    adapter_path = str(getattr(settings, "ACCOUNT_SECURITY_CAPTCHA_ADAPTER", "") or "").strip()
    if not adapter_path:
        return False
    try:
        adapter_class = import_string(adapter_path)
    except (ImportError, AttributeError, ValueError):
        return False

    try:
        return issubclass(adapter_class, CloudflareTurnstileAdapter)
    except TypeError:
        return False


def verify_captcha(
    response_token: str,
    *,
    action: str,
    ip_address: str | None = None,
    idempotency_key: str | None = None,
) -> CaptchaVerificationResult:
    """Verify through the configured adapter and fail closed on configuration."""

    try:
        adapter = get_captcha_adapter()
    except (ImportError, AttributeError, TypeError, ValueError, ImproperlyConfigured):
        return _result("configuration_error", "CAPTCHA_CONFIGURATION_INVALID")
    try:
        result = adapter.verify(
            response_token,
            expected_action=action,
            idempotency_key=idempotency_key,
        )
    except TypeError:
        return _result("configuration_error", "CAPTCHA_ADAPTER_CONTRACT_INVALID")
    except ImproperlyConfigured:
        return _result("configuration_error", "CAPTCHA_CONFIGURATION_INVALID")
    except (OSError, ValueError):
        return _result("unavailable", "CAPTCHA_PROVIDER_UNAVAILABLE")
    except Exception:
        # Provider/adapter failures are deliberately reduced to a safe state;
        # no raw exception text is returned or logged.
        return _result("unavailable", "CAPTCHA_PROVIDER_UNAVAILABLE")
    if isinstance(result, CaptchaVerificationResult):
        return result
    # Keep legacy/custom adapters fail closed rather than trusting a boolean.
    return _result("configuration_error", "CAPTCHA_ADAPTER_CONTRACT_INVALID")
