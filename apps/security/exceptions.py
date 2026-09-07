# Project: COMPASS
# File: apps/security/exceptions.py
# Module: apps.security
# Purpose: Shared security exceptions for storage, key sources, and encryption

class SecurityError(Exception):
    """Base exception whose public string is always a stable, non-secret code."""

    code = "security_error"

    def __init__(self, code=None, *, safe_metadata=None):
        self.safe_metadata = dict(safe_metadata or {})
        super().__init__(code or self.code)


class KeyNotFoundError(SecurityError):
    """Raised when an encryption key cannot be loaded or found."""
    code = "field_encryption_key_unavailable"


class KeyMalformedError(SecurityError):
    """Raised when an encryption key is malformed or invalid."""
    code = "field_encryption_configuration_invalid"


class FieldEncryptionError(SecurityError):
    code = "field_encryption_error"


class FieldEncryptionConfigurationError(FieldEncryptionError):
    code = "field_encryption_configuration_invalid"


class FieldEncryptionKeyUnavailable(FieldEncryptionError):
    code = "field_encryption_key_unavailable"


class FieldEncryptionKeyStateInvalid(FieldEncryptionError):
    code = "field_encryption_key_state_invalid"


class FieldEncryptionKeySourceUnavailable(FieldEncryptionError, KeyNotFoundError):
    code = "field_encryption_key_source_unavailable"


class FieldEncryptionMalformedEnvelope(FieldEncryptionError):
    code = "field_encryption_malformed"


class FieldEncryptionUnsupportedVersion(FieldEncryptionError):
    code = "field_encryption_version_unsupported"


class FieldEncryptionUnsupportedAlgorithm(FieldEncryptionError):
    code = "field_encryption_algorithm_unsupported"


class FieldEncryptionAuthenticationFailed(FieldEncryptionError):
    code = "field_encryption_auth_failed"


class FieldEncryptionInnerContractMismatch(FieldEncryptionError):
    code = "field_encryption_inner_contract_mismatch"


class FieldEncryptionContextMismatch(FieldEncryptionError):
    code = "field_encryption_context_mismatch"


class FieldEncryptionPayloadTypeMismatch(FieldEncryptionError):
    code = "field_encryption_payload_type_mismatch"


class FieldEncryptionPayloadInvalid(FieldEncryptionError):
    code = "field_encryption_payload_invalid"


class FieldEncryptionPayloadTooLarge(FieldEncryptionError):
    code = "field_encryption_payload_too_large"


class FieldEncryptionUnsupportedORMOperation(FieldEncryptionError):
    code = "field_encryption_orm_operation_unsupported"


class FieldEncryptionUnknownTarget(FieldEncryptionError):
    code = "field_encryption_target_unknown"


class FieldEncryptionUnsafeCommand(FieldEncryptionError):
    code = "field_encryption_command_unsafe"


class FieldEncryptionConcurrentMutation(FieldEncryptionError):
    code = "field_encryption_concurrent_mutation"


class FieldEncryptionCheckpointInvalid(FieldEncryptionError):
    code = "field_encryption_checkpoint_invalid"


class StorageError(SecurityError):
    """Base exception class for storage adapter errors."""
    pass


class ProtectedFileNotFoundError(StorageError):
    """Raised when a protected file is not found in the storage backend."""
    pass


class StorageUnavailableError(StorageError):
    """Raised when the storage backend is down, misconfigured, or unreachable."""
    pass


class PolicyValidationError(SecurityError):
    """Raised when access is denied by a security policy check."""
    pass
