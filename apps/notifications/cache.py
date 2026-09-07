"""Safe read-through cache for active notification template definitions."""

from __future__ import annotations

from apps.common.cache.backend import cached_read
from apps.common.cache.invalidation import invalidate_after_commit


def _template_snapshot(template) -> dict:
    if template is None:
        return {}
    schema = template.required_context_schema_json
    if not isinstance(schema, dict):
        return {}
    return {
        "stable_key": template.stable_key,
        "display_name": template.display_name,
        "channel": template.channel,
        "subject_template": template.subject_template,
        "body_template": template.body_template,
        "html_body_template": template.html_body_template,
        "template_version": template.template_version,
        "required_context_schema": schema,
        "preference_policy": template.preference_policy,
        "sensitivity_classification": template.sensitivity_classification,
    }


def get_cached_notification_template(template_key: str) -> dict | None:
    def load():
        from apps.notifications.models import NotificationTemplate

        try:
            template = NotificationTemplate.objects.get(
                stable_key=template_key,
                status="active",
            )
        except NotificationTemplate.DoesNotExist:
            return None
        snapshot = _template_snapshot(template)
        return snapshot or None

    value = cached_read(
        "notification_template",
        template_key,
        (template_key,),
        load,
    )
    return value if isinstance(value, dict) and value else None


def invalidate_notification_template_after_commit(template_key: object = "global") -> None:
    invalidate_after_commit("notification_template", template_key or "global")
