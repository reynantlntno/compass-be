# Project: COMPASS
# File: apps/documents/renderers.py
# Module: apps.documents
# Purpose: Renderer adapter interface and HTML renderer for document generation
# Domain boundary and service policy.
# Notes:
#   HTML renderer uses Django template rendering with validated safe context.
#   Playwright PDF adapter is real but settings/runtime gated.
#   Unit tests must not require a browser/Chromium.
#   Templates contain presentation only — no business rules, permissions,
#   workflow transitions, or storage access.

import importlib.util
import logging
import os
from html import escape
from abc import ABC, abstractmethod
from pathlib import PurePosixPath
import re

from django.conf import settings
from django.contrib.staticfiles import finders
from django.template.loader import get_template
from django.template import TemplateDoesNotExist
from apps.governance.runtime_config import resolve_runtime_setting
from apps.common.exceptions import DependencyFailureError, ErrorCode, ValidationError

logger = logging.getLogger(__name__)


def _renderer_enabled() -> bool:
    return bool(resolve_runtime_setting(
        "technical.renderer",
        "DOCUMENT_PDF_RENDERER_ENABLED",
    ))


def _renderer_timeout_ms() -> int:
    value = resolve_runtime_setting(
        "technical.renderer",
        "DOCUMENT_PDF_RENDERER_TIMEOUT_MS",
    )
    return max(1000, min(int(value), 120000))


class RendererError(ValidationError):
    """Raised when a rendering operation fails."""


class RendererUnavailableError(RendererError):
    """Raised when the requested renderer backend is not available."""

    code = ErrorCode.DEPENDENCY_FAILURE
    public_message = DependencyFailureError.public_message


ALLOWED_TEMPLATE_PREFIXES = ("documents/print/",)
ALLOWED_STYLESHEET_PREFIXES = (
    "documents/print/",
    "documents/css/",
    "css/documents/",
)
ALLOWED_TEMPLATE_EXTENSIONS = (".html",)
ALLOWED_STYLESHEET_EXTENSIONS = (".css",)
SUPPORTED_PDF_PAGE_SIZES = {
    "LETTER": "Letter",
    "A4": "A4",
    "LEGAL": "Legal",
}
PRIVATE_OR_RAW_FILE_URL_PATTERNS = (
    re.compile(r"""(?:src|href)\s*=\s*["'][^"']*/media/[^"']*["']""", re.IGNORECASE),
    re.compile(r"""(?:src|href)\s*=\s*["'][^"']*protected/[^"']*["']""", re.IGNORECASE),
    re.compile(r"""(?:src|href)\s*=\s*["']file://[^"']*["']""", re.IGNORECASE),
    re.compile(r"x-amz-signature", re.IGNORECASE),
    re.compile(r"presigned", re.IGNORECASE),
)


def _validate_controlled_path(path: str, *, prefixes: tuple[str, ...], extensions: tuple[str, ...], label: str) -> str:
    normalized = str(path or "").strip()
    if not normalized:
        raise RendererError(f"{label} path is required.")
    if normalized.startswith("/") or "\\" in normalized:
        raise RendererError(f"{label} path is outside the controlled document path boundary.")
    posix_path = PurePosixPath(normalized)
    if posix_path.is_absolute() or ".." in posix_path.parts:
        raise RendererError(f"{label} path is outside the controlled document path boundary.")
    if not normalized.startswith(prefixes):
        raise RendererError(f"{label} path must use an approved document prefix.")
    if not normalized.endswith(extensions):
        raise RendererError(f"{label} path uses an unsupported extension.")
    return normalized


def validate_template_path_safety(template_path: str) -> str:
    """Validate syntax for controlled Django document templates.

    This foundation validates prefix, traversal, and extension. Template
    existence is checked by the renderer at render/activation time.
    """
    return _validate_controlled_path(
        template_path,
        prefixes=ALLOWED_TEMPLATE_PREFIXES,
        extensions=ALLOWED_TEMPLATE_EXTENSIONS,
        label="Template",
    )


def validate_stylesheet_path_safety(stylesheet_path: str) -> str:
    """Validate syntax for controlled local document stylesheet paths."""
    if not str(stylesheet_path or "").strip():
        return ""
    return _validate_controlled_path(
        stylesheet_path,
        prefixes=ALLOWED_STYLESHEET_PREFIXES,
        extensions=ALLOWED_STYLESHEET_EXTENSIONS,
        label="Stylesheet",
    )


def ensure_template_exists(template_path: str) -> None:
    """Fail closed unless a controlled template exists in Django loaders."""
    controlled_path = validate_template_path_safety(template_path)
    try:
        get_template(controlled_path)
    except TemplateDoesNotExist as exc:
        raise RendererError("Template path does not resolve to a controlled template.") from exc


def _playwright_package_available() -> bool:
    try:
        return importlib.util.find_spec("playwright") is not None
    except (ImportError, ValueError):
        return False


def _get_playwright_runtime():
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright
    return PlaywrightError, sync_playwright


def _validate_chromium_executable_path(path: str) -> str:
    executable_path = str(path or "").strip()
    if not executable_path:
        return ""
    if "\x00" in executable_path:
        raise RendererUnavailableError("Configured Chromium executable path is invalid.")
    if not os.path.isabs(executable_path):
        raise RendererUnavailableError("Configured Chromium executable path must be absolute.")
    if not os.path.isfile(executable_path) or not os.access(executable_path, os.X_OK):
        raise RendererUnavailableError("Configured Chromium executable path is unavailable.")
    return executable_path


def _load_controlled_stylesheet(stylesheet_path: str) -> str:
    controlled_path = validate_stylesheet_path_safety(stylesheet_path)
    if not controlled_path:
        return ""
    resolved_path = finders.find(controlled_path)
    if not resolved_path:
        raise RendererError("Stylesheet path does not resolve to a controlled static file.")
    if isinstance(resolved_path, (list, tuple)):
        resolved_path = resolved_path[0]
    try:
        with open(resolved_path, encoding="utf-8") as stylesheet_file:
            return stylesheet_file.read()
    except OSError as exc:
        raise RendererError("Stylesheet file could not be read.") from exc


def _assert_no_raw_file_urls(html_content: str) -> None:
    content = str(html_content or "")
    if any(pattern.search(content) for pattern in PRIVATE_OR_RAW_FILE_URL_PATTERNS):
        raise RendererError("Rendered document contains disallowed private or raw file URLs.")


def _inject_print_css(html_content: str, stylesheet_path: str) -> str:
    css = _load_controlled_stylesheet(stylesheet_path)
    if not css:
        return html_content
    style_block = f"<style data-compass-document-css>\n{css}\n</style>"
    if "</head>" in html_content:
        return html_content.replace("</head>", f"{style_block}\n</head>", 1)
    return f"{style_block}\n{html_content}"


def _normalize_pdf_options(page_settings: dict) -> dict:
    page_settings = page_settings or {}
    page_size = str(page_settings.get("page_size") or "LETTER").upper()
    if page_size not in SUPPORTED_PDF_PAGE_SIZES:
        raise RendererError("Unsupported PDF page size.")

    orientation = str(page_settings.get("page_orientation") or "portrait").lower()
    if orientation not in {"portrait", "landscape"}:
        raise RendererError("Unsupported PDF page orientation.")

    margins = page_settings.get("margins") or {}
    if not isinstance(margins, dict):
        raise RendererError("Unsupported PDF margin settings.")

    margin = {}
    for key in ("top", "right", "bottom", "left"):
        value = margins.get(key, 0)
        if value in ("", None):
            value = 0
        try:
            numeric_value = float(value)
        except (TypeError, ValueError) as exc:
            raise RendererError("Unsupported PDF margin value.") from exc
        if numeric_value < 0 or numeric_value > 100:
            raise RendererError("Unsupported PDF margin value.")
        margin[key] = f"{numeric_value:g}mm"

    options = {
        "format": SUPPORTED_PDF_PAGE_SIZES[page_size],
        "landscape": orientation == "landscape",
        "margin": margin,
        "print_background": True,
        # The governed template version owns paper size/orientation. A
        # template stylesheet must not silently override those settings.
        "prefer_css_page_size": False,
    }
    if page_settings.get("page_number_footer"):
        header_label = escape(str(page_settings.get("header_label") or "").strip()[:300])
        footer_label = escape(str(page_settings.get("footer_label") or "").strip()[:160])
        page_number = page_settings.get("footer_page_number")
        page_total = page_settings.get("footer_page_total")
        if (page_number is None) != (page_total is None):
            raise RendererError("Controlled PDF page footer requires both page number values.")
        if page_number is not None:
            if isinstance(page_number, bool) or isinstance(page_total, bool):
                raise RendererError("Controlled PDF page footer values are invalid.")
            try:
                page_number = int(page_number)
                page_total = int(page_total)
            except (TypeError, ValueError) as exc:
                raise RendererError("Controlled PDF page footer values are invalid.") from exc
            if not 1 <= page_number <= page_total <= 10_000:
                raise RendererError("Controlled PDF page footer values are invalid.")
        label_html = f"<span>{footer_label}</span>" if footer_label else ""
        page_html = (
            f"<span>Page {page_number} of {page_total}</span>"
            if page_number is not None
            else '<span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>'
        )
        options.update({
            "display_header_footer": True,
            "header_template": (
                '<div style="box-sizing:border-box;color:#444;font-family:Arial,sans-serif;'
                'font-size:7px;padding:0 10mm;text-align:right;width:100%;">'
                f"{header_label}</div>" if header_label else "<span></span>"
            ),
            "footer_template": (
                '<div style="box-sizing:border-box;font-size:7px;width:100%;padding:0 10mm;'
                'display:flex;justify-content:space-between;color:#444;font-family:Arial,sans-serif;">'
                f"{label_html}"
                f"{page_html}"
                "</div>"
            ),
        })
    return options


def _validate_pdf_bytes(content: bytes) -> bytes:
    if not isinstance(content, bytes) or not content.startswith(b"%PDF-"):
        raise RendererError("PDF renderer returned invalid output.")
    return content


class BaseRenderer(ABC):
    """Abstract renderer interface for document generation."""

    @abstractmethod
    def render_to_html(self, template_path: str, context: dict) -> str:
        """Render a Django template to HTML string.

        Args:
            template_path: Path to the Django template file.
            context: Safe, validated context dictionary.

        Returns:
            Rendered HTML string.

        Raises:
            RendererError: If rendering fails.
        """

    @abstractmethod
    def render_to_pdf(self, html_content: str, page_settings: dict) -> bytes:
        """Render HTML content to PDF bytes.

        Args:
            html_content: Rendered HTML string.
            page_settings: Page size, orientation, margins.

        Returns:
            PDF file bytes.

        Raises:
            RendererError: If PDF rendering fails.
            RendererUnavailableError: If the PDF backend is not available.
        """

    @abstractmethod
    def is_pdf_available(self) -> bool:
        """Check if PDF rendering is available."""

    def get_backend_info(self) -> dict:
        """Return safe metadata about this renderer for snapshot purposes."""
        return {
            "backend": self.__class__.__name__,
            "pdf_available": self.is_pdf_available(),
        }


class HTMLRenderer(BaseRenderer):
    """HTML-only renderer using Django template engine.

    This is the primary renderer for this foundation slice.
    """

    def render_to_html(self, template_path: str, context: dict) -> str:
        """Render a Django template to HTML string."""
        try:
            controlled_path = validate_template_path_safety(template_path)
            template = get_template(controlled_path)
            return template.render(context)
        except Exception as exc:
            logger.error("HTML render failed for template %s: %s", template_path, type(exc).__name__)
            raise RendererError(f"HTML render failed: {type(exc).__name__}") from exc

    def render_to_pdf(self, html_content: str, page_settings: dict) -> bytes:
        """PDF rendering not available in HTML-only renderer."""
        raise RendererUnavailableError(
            "PDF rendering is not available with HTML_ONLY backend. "
            "Playwright/Chromium is required for PDF output."
        )

    def is_pdf_available(self) -> bool:
        return False


class PlaywrightPDFRenderer(BaseRenderer):
    """Settings-gated Playwright/Chromium PDF renderer."""

    def render_to_html(self, template_path: str, context: dict) -> str:
        """Delegates HTML rendering to Django template engine."""
        try:
            controlled_path = validate_template_path_safety(template_path)
            template = get_template(controlled_path)
            return template.render(context)
        except Exception as exc:
            logger.error("HTML render failed for template %s: %s", template_path, type(exc).__name__)
            raise RendererError(f"HTML render failed: {type(exc).__name__}") from exc

    def render_to_pdf(self, html_content: str, page_settings: dict) -> bytes:
        """Render controlled HTML to PDF bytes using Playwright Chromium."""
        if not _renderer_enabled():
            raise RendererUnavailableError("PDF renderer is disabled by configuration.")
        if not _playwright_package_available():
            raise RendererUnavailableError("Playwright is not installed.")

        PlaywrightError, sync_playwright = _get_playwright_runtime()

        _assert_no_raw_file_urls(html_content)
        html_for_pdf = _inject_print_css(html_content, (page_settings or {}).get("stylesheet_path", ""))
        _assert_no_raw_file_urls(html_for_pdf)
        pdf_options = _normalize_pdf_options(page_settings)
        timeout_ms = _renderer_timeout_ms()
        executable_path = _validate_chromium_executable_path(
            getattr(settings, "DOCUMENT_PDF_CHROMIUM_EXECUTABLE_PATH", "")
        )
        launch_options = {"headless": True}
        if executable_path:
            launch_options["executable_path"] = executable_path

        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(**launch_options)
                try:
                    page = browser.new_page()
                    page.set_default_timeout(timeout_ms)
                    page.set_content(html_for_pdf, wait_until="load", timeout=timeout_ms)
                    page.emulate_media(media="print")
                    return _validate_pdf_bytes(page.pdf(**pdf_options))
                finally:
                    browser.close()
        except RendererError:
            raise
        except (PlaywrightError, OSError, RuntimeError) as exc:
            raise RendererUnavailableError("Playwright PDF renderer could not produce output.") from exc

    def is_pdf_available(self) -> bool:
        """Check if the configured Playwright/Chromium runtime can launch."""
        if not _renderer_enabled():
            return False
        if not _playwright_package_available():
            return False
        try:
            _, sync_playwright = _get_playwright_runtime()
            executable_path = _validate_chromium_executable_path(
                getattr(settings, "DOCUMENT_PDF_CHROMIUM_EXECUTABLE_PATH", "")
            )
            launch_options = {"headless": True}
            if executable_path:
                launch_options["executable_path"] = executable_path
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(**launch_options)
                browser.close()
            return True
        except Exception:
            return False

    def get_backend_info(self) -> dict:
        return {
            "backend": "PlaywrightPDFRenderer",
            "pdf_available": self.is_pdf_available(),
            "config_enabled": _renderer_enabled(),
        }


def get_renderer(backend: str) -> BaseRenderer:
    """Factory for renderer backends.

    Args:
        backend: One of RendererBackendChoices values.

    Returns:
        A renderer instance.

    Raises:
        RendererUnavailableError: If the requested backend is unknown.
    """
    if backend == "HTML_ONLY":
        return HTMLRenderer()
    elif backend == "PLAYWRIGHT_PDF":
        return PlaywrightPDFRenderer()
    else:
        raise RendererUnavailableError(f"Unknown renderer backend: {backend}")
