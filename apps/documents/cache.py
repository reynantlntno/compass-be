"""Safe cached metadata for active document templates and versions."""

from __future__ import annotations

from apps.common.cache.backend import cached_read
from apps.common.cache.invalidation import invalidate_after_commit
from apps.documents.selectors import template_metadata_dto, template_version_metadata_dto


def get_cached_template_metadata(stable_key: str) -> dict:
    def load():
        from apps.documents.selectors import get_active_template

        return template_metadata_dto(get_active_template(stable_key))

    return cached_read("document_metadata", stable_key, ("template", stable_key), load)


def get_cached_template_version_metadata(stable_key: str) -> dict:
    def load():
        from apps.documents.selectors import get_active_template_version

        return template_version_metadata_dto(get_active_template_version(stable_key))

    return cached_read("document_metadata", stable_key, ("version", stable_key), load)


def get_cached_document_family_metadata(stable_key: str) -> dict:
    def load():
        from apps.documents.governance import DOCUMENT_FAMILY_REGISTRY

        family = DOCUMENT_FAMILY_REGISTRY.get(stable_key)
        if family is None:
            return {}
        return {
            "stable_key": family.stable_key,
            "display_name": family.display_name,
            "source_label": family.source_label,
            "source_kind": family.source_kind,
            "official_form_code": family.official_form_code,
            "official_revision": family.official_revision,
            "template_key": family.template_key,
        }

    return cached_read("document_metadata", stable_key, ("family", stable_key), load)


def invalidate_document_metadata_after_commit(target: object = "global") -> None:
    invalidate_after_commit("document_metadata", target)
    # The Organizations public metadata endpoint uses one aggregate target;
    # template/version saves must invalidate it along with per-template keys.
    invalidate_after_commit("document_metadata", "public-templates")
    if target != "global":
        invalidate_after_commit("document_metadata", "global")
