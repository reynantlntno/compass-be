"""Framework-neutral rendered-artifact boundary for governed previews."""

from dataclasses import dataclass

from apps.documents.governance import (
    DocumentOutputIntent,
    DocumentReadiness,
    get_preview_template_version,
)
from apps.documents.renderers import RendererError
from apps.documents.services import DocumentServiceError, render_document_preview


@dataclass(frozen=True, slots=True)
class RenderedArtifact:
    """Rendered content plus adapter-owned response metadata."""

    content: bytes | str
    content_type: str
    filename: str
    cache_control: str = "private, no-store, max-age=0"
    robots: str = "noindex, nofollow, noarchive"


def render_family_preview(*, stable_key: str, render_context: dict,
                          form_revision=None) -> RenderedArtifact:
    """Render a non-stored, server-governed preview artifact.

    Authorization is intentionally performed by the workflow adapter before
    this function is called.  HTTP response headers belong to that adapter.
    """
    try:
        template_version = get_preview_template_version(stable_key)
        if not template_version:
            raise DocumentServiceError("A draft or active preview template is required.")
        content, content_type = render_document_preview(
            template_version=template_version,
            render_context=render_context,
            form_revision=form_revision,
            output_intent=DocumentOutputIntent.PREVIEW,
        )
    except (DocumentServiceError, RendererError) as exc:
        raise DocumentServiceError("Document preview is unavailable right now.") from exc
    extension = "pdf" if content_type == "application/pdf" else "html"
    return RenderedArtifact(
        content=content,
        content_type=content_type,
        filename=f"{stable_key}-preview.{extension}",
    )
