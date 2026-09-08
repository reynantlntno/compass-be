import hashlib
import hmac
import secrets
import uuid
from django.core.signing import BadSignature, Signer
from django.conf import settings


RECOVERY_TOKEN_VERSION = "recovery-v1"
RECOVERY_TOKEN_SALT = "compass.account-recovery.v1"


def hash_identifier(value: str) -> str:
    """Consistently hash sensitive identifiers (e.g., email, IP, token) using HMAC-SHA256."""
    if not value:
        return ""
    key = settings.ACCOUNT_SECURITY_HASH_SECRET.encode("utf-8")
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()


def generate_random_token() -> str:
    """Generate a high-entropy cryptographically secure random token."""
    return secrets.token_hex(32)


def build_recovery_token(recovery_request_id) -> str:
    """Create a purpose-bound, reconstructable token for a recovery request.

    Only the request UUID is signed.  The raw token is intentionally never
    persisted; the request row stores its HMAC instead.
    """
    request_id = str(recovery_request_id)
    uuid.UUID(request_id)
    return Signer(salt=RECOVERY_TOKEN_SALT).sign(f"{RECOVERY_TOKEN_VERSION}:{request_id}")


def parse_recovery_token(raw_token: str):
    """Return the request UUID from a valid recovery token, or ``None``."""
    if not raw_token or not isinstance(raw_token, str) or len(raw_token) > 512:
        return None
    try:
        value = Signer(salt=RECOVERY_TOKEN_SALT).unsign(raw_token)
        version, request_id = value.split(":", 1)
        if version != RECOVERY_TOKEN_VERSION:
            return None
        return uuid.UUID(request_id)
    except (BadSignature, ValueError, TypeError, AttributeError):
        return None


def generate_otp() -> str:
    """Generate a 6-digit numeric OTP."""
    # Using secrets.choice for cryptographic security
    choices = "0123456789"
    return "".join(secrets.choice(choices) for _ in range(6))


def hash_token(token: str) -> str:
    """Hash a token or OTP before storing or looking it up."""
    return hash_identifier(token)


def get_session_action_token(session_identifier: str) -> str:
    """Return an opaque user-scoped action token for an API session UUID."""
    if not session_identifier:
        return ""
    return hash_identifier(f"account-session:{session_identifier}")


def compare_tokens(val1: str, val2: str) -> bool:
    """Constant-time comparison helper to prevent timing attacks."""
    if not val1 or not val2:
        return False
    return secrets.compare_digest(val1, val2)


def get_safe_user_agent_summary(user_agent_str: str) -> str:
    """Parse a raw User-Agent string into a privacy-safe browser/OS summary."""
    if not user_agent_str:
        return "Unknown Device"

    ua = user_agent_str.lower()
    os_name = "Unknown OS"
    if "windows" in ua:
        os_name = "Windows"
    elif "macintosh" in ua or "mac os" in ua:
        os_name = "macOS"
    elif "iphone" in ua or "ipad" in ua:
        os_name = "iOS"
    elif "android" in ua:
        os_name = "Android"
    elif "linux" in ua:
        os_name = "Linux"

    browser = "Unknown Browser"
    if "edge" in ua or "edg/" in ua:
        browser = "Edge"
    elif "opera" in ua or "opr/" in ua:
        browser = "Opera"
    elif "chrome" in ua:
        browser = "Chrome"
    elif "safari" in ua:
        browser = "Safari"
    elif "firefox" in ua:
        browser = "Firefox"

    return f"{browser} on {os_name}"
