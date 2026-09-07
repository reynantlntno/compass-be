"""Narrow framework adapters for unavoidable Django model/validator errors.

Application services import these named adapters instead of Django exception
classes directly.  The dependency is intentionally isolated here until the
model layer is replaced by a framework-neutral persistence boundary.
"""

from django.core.exceptions import PermissionDenied as DjangoPermissionDenied
from django.core.exceptions import ValidationError as DjangoValidationError


ModelValidationError = DjangoValidationError

__all__ = ["DjangoPermissionDenied", "ModelValidationError"]
