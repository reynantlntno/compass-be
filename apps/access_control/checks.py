"""Django system checks for the code-owned authority catalog."""

from django.core.checks import Error, register

from apps.access_control.capabilities import validate_capability_catalog
from apps.access_control.contracts import validate_authority_contracts


@register()
def capability_catalog_check(app_configs, **kwargs):
    """Fail startup when a capability lacks a complete safe specification."""

    return [
        Error(message, id="access_control.E001")
        for message in validate_capability_catalog()
    ] + [
        Error(message, id="access_control.E002")
        for message in validate_authority_contracts()
    ]
