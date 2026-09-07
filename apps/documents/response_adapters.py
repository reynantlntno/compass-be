"""Django response adapter for framework-neutral rendered artifacts."""

from django.http import HttpResponse

from apps.common.api.headers import apply_noindex_header
from apps.documents.preview_services import RenderedArtifact


def rendered_artifact_response(artifact: RenderedArtifact) -> HttpResponse:
    response = HttpResponse(artifact.content, content_type=artifact.content_type)
    response["Content-Disposition"] = f'inline; filename="{artifact.filename}"'
    response["Cache-Control"] = artifact.cache_control
    response["Pragma"] = "no-cache"
    response["Expires"] = "0"
    return apply_noindex_header(response)


def response_for_artifact(artifact: RenderedArtifact) -> HttpResponse:
    """Return a private inline response for workflow-owned PDF output."""

    response = HttpResponse(artifact.content, content_type=artifact.content_type)
    response["Content-Disposition"] = f'inline; filename="{artifact.filename}"'
    response["Cache-Control"] = "no-store, private"
    response["Pragma"] = "no-cache"
    response["Expires"] = "0"
    response["X-Content-Type-Options"] = "nosniff"
    return apply_noindex_header(response)
