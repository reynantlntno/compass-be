# Project: COMPASS
# File: apps/common/exceptions.py
# Module: common
# Purpose: Shared exception classes for COMPASS business logic
# Domain boundary and service policy.
# Notes: Services should raise these instead of generic Django exceptions
#   when the error is a COMPASS business rule violation.


from enum import StrEnum


class ErrorCode(StrEnum):
    """Stable codes mapped to transport statuses only by an outer adapter.

    Domain code should use the business categories below.  ``UNAUTHENTICATED``
    and the transport-only values are included here so every JSON error still
    has one canonical code vocabulary.
    """

    BAD_REQUEST = "bad_request"
    UNAUTHENTICATED = "unauthenticated"
    VALIDATION = "validation"
    PERMISSION = "permission"
    NOT_FOUND = "not_found"
    METHOD_NOT_ALLOWED = "method_not_allowed"
    LIFECYCLE_CONFLICT = "lifecycle_conflict"
    STALE_STATE = "stale_state"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    RATE_LIMITED = "rate_limited"
    DEPENDENCY_FAILURE = "dependency_failure"
    ASSURANCE_REQUIRED = "assurance_required"
    INTERNAL_ERROR = "internal_error"


class CompassError(Exception):
    """Base exception for all COMPASS business logic errors."""

    code = ErrorCode.VALIDATION
    public_message = "The operation could not be completed."

    def __init__(
        self,
        message: str = "The operation could not be completed.",
        *,
        code=None,
        field_errors: dict[str, list[str]] | None = None,
        retry_after: int | None = None,
    ):
        self.message = str(message)
        if code is not None:
            self.code = ErrorCode(code)
        self.field_errors = field_errors or {}
        self.retry_after = retry_after
        super().__init__(self.message)

    @property
    def messages(self) -> list[str]:
        """Small compatibility-free diagnostic view for bounded logging."""
        return [self.message]


class DomainError(CompassError):
    """Base for safe application errors returned to an API adapter."""

    public_message = "The operation could not be completed."

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code.value, "detail": self.public_message}


class BadRequestError(DomainError):
    code = ErrorCode.BAD_REQUEST
    public_message = "The request could not be understood."


class UnauthenticatedError(DomainError):
    code = ErrorCode.UNAUTHENTICATED
    public_message = "Authentication is required."


class InvalidCredentialsError(UnauthenticatedError):
    """Safe authentication failure that does not reveal which fact failed."""

    public_message = "Invalid credentials."


class MethodNotAllowedError(DomainError):
    code = ErrorCode.METHOD_NOT_ALLOWED
    public_message = "This method is not allowed."


class PayloadTooLargeError(DomainError):
    code = ErrorCode.PAYLOAD_TOO_LARGE
    public_message = "The request payload is too large."


class InternalError(DomainError):
    code = ErrorCode.INTERNAL_ERROR
    public_message = "Internal server error."


class PermissionDeniedError(DomainError):
    """Raised when a user does not have scoped access to a resource.

    This is distinct from Django's PermissionDenied — it should be used
    in services and policies where the denial is a COMPASS business rule
    (role + scope + assignment), not just a missing Django permission.
    """

    code = ErrorCode.PERMISSION
    public_message = "You do not have permission to perform this action."


class AssuranceRequiredError(DomainError):
    """Raised when a sensitive action needs a recent OTP step-up."""

    code = ErrorCode.ASSURANCE_REQUIRED
    public_message = "Additional verification is required."


class WorkflowError(DomainError):
    """Raised when a workflow transition is invalid.

    Example: trying to approve a request that is already approved,
    or cancelling an appointment past the cutoff.
    """

    code = ErrorCode.LIFECYCLE_CONFLICT
    public_message = "The resource is not in a state that permits this action."


class ValidationError(DomainError):
    """Raised when business-level validation fails in a service.

    This is for service-layer validation distinct from Django form
    validation. Example: duplicate inventory submission for the same
    academic year.
    """

    code = ErrorCode.VALIDATION
    public_message = "The submitted data is invalid."


class NotFoundError(DomainError):
    code = ErrorCode.NOT_FOUND
    public_message = "The requested resource was not found."


class LifecycleConflictError(WorkflowError):
    code = ErrorCode.LIFECYCLE_CONFLICT


class StaleStateError(DomainError):
    code = ErrorCode.STALE_STATE
    public_message = "The resource changed before the operation completed."


class RateLimitError(DomainError):
    code = ErrorCode.RATE_LIMITED
    public_message = "Too many requests. Please try again later."


class ConditionalChallengeError(RateLimitError):
    """Ask a client for an endpoint-scoped abuse challenge.

    The transport layer turns this into the ordinary rate-limit envelope and
    exposes only the small allowlisted action label needed to mount a widget.
    """

    _ALLOWED_ACTIONS = frozenset({"login", "recovery", "activation", "contact"})

    def __init__(self, challenge_action: str, *, retry_after: int | None = None):
        action = str(challenge_action)
        if action not in self._ALLOWED_ACTIONS:
            raise ValueError("Challenge action is not allowlisted.")
        self.challenge_required = True
        self.challenge_action = action
        super().__init__(retry_after=retry_after)


class DependencyFailureError(DomainError):
    code = ErrorCode.DEPENDENCY_FAILURE
    public_message = "A required service is temporarily unavailable."


class GovernanceError(DomainError):
    """A controlled institution or workflow governance violation."""

    code = ErrorCode.PERMISSION
    public_message = "The requested governance operation is not permitted."
