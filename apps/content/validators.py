import re
from urllib.parse import urlparse
import ipaddress
from django.core.exceptions import ValidationError as DjangoValidationError
from apps.common.exceptions import ValidationError


def validate_model(obj) -> None:
    """Translate Django model validation into a framework-neutral domain error."""
    try:
        obj.full_clean()
    except DjangoValidationError as exc:
        field_errors = {}
        for field, messages in getattr(exc, "message_dict", {}).items():
            if isinstance(messages, (list, tuple)):
                field_errors[str(field)] = [str(message) for message in messages[:4]]
            else:
                field_errors[str(field)] = [str(messages)]
        raise ValidationError(field_errors=field_errors) from exc


def validate_safe_slug(value):
    """Ensure slug contains only lowercase alphanumeric characters and hyphens, and no double hyphens."""
    if not re.match(r"^[a-z0-9]+(?:-[a-z0-9]+)*$", value):
        raise ValidationError(
            "Slug must contain only lowercase letters, numbers, and single hyphens, with no leading or trailing hyphens."
        )


def validate_local_path(value):
    """Validate CTA path is a safe local relative path (starts with / and doesn't contain external URLs or javascript)."""
    if not value:
        return
    if not value.startswith("/"):
        raise ValidationError("Path must start with a single slash (/).")
    if value.startswith("//"):
        raise ValidationError("Path cannot start with a double slash to prevent external scheme redirection.")
    if "javascript:" in value.lower():
        raise ValidationError("Path cannot contain javascript: schemes.")
    parsed = urlparse(value)
    if parsed.netloc:
        raise ValidationError("Path must be relative, not absolute or external.")


_DENIED_EXTERNAL_HOSTS = {
    "cdn.jsdelivr.net",
    "unpkg.com",
    "cdnjs.cloudflare.com",
}


def _has_control_or_whitespace(value: str) -> bool:
    return any(ord(ch) < 32 or ch.isspace() for ch in value)


def validate_safe_external_url(value):
    """Validate external resource URL for public resource links."""
    if not value:
        return
    if _has_control_or_whitespace(value):
        raise ValidationError("URL cannot contain whitespace or control characters.")
    if "\\" in value:
        raise ValidationError("URL cannot contain backslashes.")
    if value.startswith("//"):
        raise ValidationError("URL cannot be scheme-relative.")
    parsed = urlparse(value)
    if parsed.scheme != "https":
        raise ValidationError("URL scheme must be https.")
    if not parsed.hostname:
        raise ValidationError("URL must include a valid host.")
    if parsed.username or parsed.password:
        raise ValidationError("URL user information is not allowed.")
    try:
        parsed.port
    except ValueError as exc:
        raise ValidationError("URL must include a valid port.") from exc
    if "javascript:" in value.lower():
        raise ValidationError("URL cannot contain javascript: schemes.")
    hostname = parsed.hostname.lower().rstrip(".")
    if hostname in _DENIED_EXTERNAL_HOSTS:
        raise ValidationError("CDN resource hosts are not allowed.")
    if hostname in {"localhost", "localhost.localdomain"}:
        raise ValidationError("Localhost URLs are not allowed.")
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        return
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        raise ValidationError("Private, loopback, or reserved IP hosts are not allowed.")


def validate_no_html_or_scripts(value):
    """Ensure text content contains no HTML tags or script elements or javascript: links."""
    if not value:
        return
    if "<" in value or ">" in value:
        raise ValidationError("HTML elements and tag delimiters are not allowed.")
    if "javascript:" in value.lower():
        raise ValidationError("javascript: schemes are not allowed.")
    if "cdn.jsdelivr" in value or "unpkg.com" in value or "cdnjs.cloudflare" in value:
        raise ValidationError("CDN or script injection patterns are not allowed.")
