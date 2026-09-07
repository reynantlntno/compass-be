from django.core.checks import Error, register

from apps.common.cache.registry import validate_cache_registry
from apps.common.api.operations import validate_operation_registry


@register()
def cache_registry_check(app_configs, **kwargs):
    return [Error(message, id="common.cache.E001") for message in validate_cache_registry()]


@register()
def api_operation_registry_check(app_configs, **kwargs):
    return [Error(message, id="common.api.E001") for message in validate_operation_registry()]
