"""Bounded, backend-owned rich-text rendering for public projections."""

from __future__ import annotations

import html
import re
from enum import StrEnum
from urllib.parse import urlsplit

import markdown
import nh3

from apps.common.exceptions import ValidationError as CompassValidationError
from apps.content.validators import validate_safe_external_url


MAX_RICH_TEXT_INPUT_LENGTH = 64_000
MAX_RICH_TEXT_OUTPUT_LENGTH = 100_000
MAX_PRIVACY_BLOCKS = 128
MAX_PRIVACY_PARAGRAPH_LENGTH = 4_000
MAX_PRIVACY_HEADING_LENGTH = 200


class RichTextProfile(StrEnum):
    """Explicit public formats supported by the renderer."""

    PUBLIC_CONTENT = "public_content"
    PRIVACY_NOTICE = "privacy_notice"


class RichTextValidationError(ValueError):
    """Raised when source text cannot be rendered by an approved profile."""


_PUBLIC_CONTENT_TAGS = {
    "p", "br", "strong", "em", "del", "ul", "ol", "li", "blockquote",
    "pre", "code", "a", "h2", "h3", "h4", "h5", "h6", "hr",
}
_PUBLIC_CONTENT_ATTRIBUTES = {"a": {"href", "title"}}
_CLEAN_CONTENT_TAGS = {"script", "style", "iframe", "object", "embed", "form", "svg"}


def _markdown_attribute_filter(tag: str, attribute: str, value: str) -> str | None:
    """Keep Markdown links local or on validated HTTPS destinations only."""
    if tag != "a" or attribute != "href":
        return value
    if not value or any(character.isspace() for character in value):
        return None
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    if parsed.scheme or parsed.netloc:
        if parsed.scheme != "https" or parsed.username or parsed.password:
            return None
        try:
            validate_safe_external_url(value)
        except (CompassValidationError, ValueError):
            return None
    return value


def _normalize_source(value: str | None) -> str:
    if not isinstance(value, str):
        raise RichTextValidationError("Rich-text source must be text.")
    source = value.replace("\r\n", "\n").replace("\r", "\n")
    if len(source) > MAX_RICH_TEXT_INPUT_LENGTH:
        raise RichTextValidationError("Rich-text source is too large.")
    return source


def _render_public_content(source: str) -> str:
    if "<" in source or ">" in source:
        raise RichTextValidationError("Public content cannot contain raw HTML.")

    image_match = re.search(r"!\[[^\]]*\]\([^)]*\)", source)
    if image_match:
        raise RichTextValidationError("Public content cannot contain images.")

    link_matches = re.findall(r"(?<!!)\[[^\]]*\]\(([^)\s]+)(?:\s+[^)]*)?\)", source)
    for href in link_matches:
        if href.startswith("/") and not href.startswith("//"):
            continue
        try:
            validate_safe_external_url(href)
        except (CompassValidationError, ValueError) as exc:
            raise RichTextValidationError("Public content contains an unsafe link.") from exc

    rendered = markdown.markdown(
        html.escape(source, quote=False),
        extensions=["fenced_code"],
        output_format="html",
    )
    if "<img" in rendered.lower():
        raise RichTextValidationError("Public content cannot contain images.")
    result = nh3.clean(
        rendered,
        tags=_PUBLIC_CONTENT_TAGS,
        attributes=_PUBLIC_CONTENT_ATTRIBUTES,
        attribute_filter=_markdown_attribute_filter,
        url_schemes={"https"},
        clean_content_tags=_CLEAN_CONTENT_TAGS,
    )
    if len(result) > MAX_RICH_TEXT_OUTPUT_LENGTH:
        raise RichTextValidationError("Rendered rich text is too large.")
    return result


_UNSUPPORTED_PRIVACY_MARKUP = re.compile(
    r"(?:^\s*#{1,6}(?:\s|$)|^\s*(?:[-*+]|\d+[.)])\s+|^\s*>|^\s*```|"
    r"!?(?:\[[^\]]*\])(?:\([^)]*\)|\[[^]]*\])|[`*_~|{}])"
)


def _render_privacy_notice(source: str) -> str:
    """Render only level-two headings and plain paragraph blocks."""
    if "<" in source or ">" in source:
        raise RichTextValidationError("Privacy notices cannot contain HTML.")

    blocks: list[str] = []
    paragraph_lines: list[str] = []

    def flush_paragraph() -> None:
        if not paragraph_lines:
            return
        paragraph = " ".join(paragraph_lines).strip()
        paragraph_lines.clear()
        if not paragraph or len(paragraph) > MAX_PRIVACY_PARAGRAPH_LENGTH:
            raise RichTextValidationError("Privacy paragraph is invalid.")
        blocks.append(f"<p>{html.escape(paragraph)}</p>")

    for line in source.strip().split("\n"):
        if len(line) > MAX_PRIVACY_PARAGRAPH_LENGTH:
            raise RichTextValidationError("Privacy line is too large.")
        trimmed = line.strip()
        if not trimmed:
            flush_paragraph()
            continue
        if trimmed.startswith("## ") and trimmed[3:].strip():
            flush_paragraph()
            heading = trimmed[3:].strip()
            if len(heading) > MAX_PRIVACY_HEADING_LENGTH or _UNSUPPORTED_PRIVACY_MARKUP.search(heading):
                raise RichTextValidationError("Privacy heading is invalid.")
            blocks.append(f"<h2>{html.escape(heading)}</h2>")
        elif _UNSUPPORTED_PRIVACY_MARKUP.search(trimmed):
            raise RichTextValidationError("Privacy markup is not supported.")
        else:
            paragraph_lines.append(trimmed)
            if len(paragraph_lines) > 32:
                raise RichTextValidationError("Privacy paragraph has too many lines.")
        if len(blocks) > MAX_PRIVACY_BLOCKS:
            raise RichTextValidationError("Privacy notice has too many sections.")

    flush_paragraph()
    result = "\n".join(blocks)
    if not result or len(result) > MAX_RICH_TEXT_OUTPUT_LENGTH:
        raise RichTextValidationError("Privacy notice output is invalid.")
    return result


def render_rich_text(
    source: str | None,
    *,
    profile: RichTextProfile = RichTextProfile.PUBLIC_CONTENT,
) -> str:
    """Render a bounded source using one explicit, approved public profile."""
    normalized = _normalize_source(source)
    if profile == RichTextProfile.PUBLIC_CONTENT:
        return _render_public_content(normalized)
    if profile == RichTextProfile.PRIVACY_NOTICE:
        return _render_privacy_notice(normalized)
    raise RichTextValidationError("Unknown rich-text profile.")
