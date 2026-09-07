from django.core.checks import Error, register

from apps.governance.registry import validate_policy_registry


@register()
def governance_policy_registry_check(app_configs, **kwargs):
    try:
        validate_policy_registry()
    except RuntimeError as exc:
        return [Error(str(exc), id="governance.E001")]
    return []
