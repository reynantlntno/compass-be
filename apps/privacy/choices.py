from django.db import models


class PrivacyNoticeStatusChoices(models.TextChoices):
    PROPOSED = "PROPOSED", "Proposed"
    PUBLISHED = "PUBLISHED", "Published"
    RETIRED = "RETIRED", "Retired"
    BLOCKED = "BLOCKED", "Blocked"


class PrivacyApprovalStateChoices(models.TextChoices):
    PENDING = "PENDING", "Approval pending"
    APPROVED = "APPROVED", "Approved"
    REJECTED = "REJECTED", "Rejected"


class PrivacyAcceptanceDecisionChoices(models.TextChoices):
    ACCEPTED = "ACCEPTED", "Accepted"
    DECLINED = "DECLINED", "Declined"
    WITHDRAWN = "WITHDRAWN", "Withdrawn"


class PrivacyActorTypeChoices(models.TextChoices):
    ANONYMOUS = "ANONYMOUS", "Anonymous visitor"
    STUDENT = "STUDENT", "Student"
    COUNSELOR = "COUNSELOR", "Counselor"
    GCO_STAFF = "GCO_STAFF", "GCO Staff"
    HEAD_GUIDANCE = "HEAD_GUIDANCE", "Head Guidance"
    IT_ADMIN = "IT_ADMIN", "IT Admin"
    VERIFIED_TOKEN = "VERIFIED_TOKEN", "Verified token"
    SYSTEM = "SYSTEM", "System"


class RetentionRuleStateChoices(models.TextChoices):
    PROPOSED = "PROPOSED", "Proposed"
    APPROVED = "APPROVED", "Approved"
    ACTIVE = "ACTIVE", "Active"
    BLOCKED = "BLOCKED", "Blocked"
    RETIRED = "RETIRED", "Retired"


class RetentionTriggerChoices(models.TextChoices):
    ACTION_COMPLETED = "ACTION_COMPLETED", "After documented action"
    LAST_ACTIVITY = "LAST_ACTIVITY", "After last activity"
    SUBMISSION = "SUBMISSION", "After submission"
    RECORD_CREATED = "RECORD_CREATED", "After record creation"
    REVIEW_DATE = "REVIEW_DATE", "On review date"
    OTHER = "OTHER", "Other approved trigger"


class LegalHoldStatusChoices(models.TextChoices):
    ACTIVE = "ACTIVE", "Active"
    RELEASED = "RELEASED", "Released"


class PrivacyRequestTypeChoices(models.TextChoices):
    ACCESS = "ACCESS", "Access"
    CORRECTION = "CORRECTION", "Correction"
    REVIEW = "REVIEW", "Review"
    OTHER = "OTHER", "Other approved request"


class PrivacyRequestStatusChoices(models.TextChoices):
    SUBMITTED = "SUBMITTED", "Submitted"
    IDENTITY_VERIFICATION_REQUIRED = "IDENTITY_VERIFICATION_REQUIRED", "Identity verification required"
    UNDER_REVIEW = "UNDER_REVIEW", "Under review"
    MORE_INFORMATION_REQUIRED = "MORE_INFORMATION_REQUIRED", "More information required"
    APPROVED = "APPROVED", "Approved"
    PARTIALLY_FULFILLED = "PARTIALLY_FULFILLED", "Partially fulfilled"
    DENIED = "DENIED", "Denied"
    COMPLETED = "COMPLETED", "Completed"
    WITHDRAWN = "WITHDRAWN", "Withdrawn"
    CLOSED = "CLOSED", "Closed"


class PrivacyRequestDecisionChoices(models.TextChoices):
    APPROVE = "APPROVE", "Approve"
    PARTIAL = "PARTIAL", "Partially fulfill"
    DENY = "DENY", "Deny"
    MORE_INFORMATION = "MORE_INFORMATION", "Request more information"
    COMPLETE = "COMPLETE", "Complete"
    WITHDRAW = "WITHDRAW", "Withdraw"
    CLOSE = "CLOSE", "Close"


class ReviewerAuthorizationStatusChoices(models.TextChoices):
    ACTIVE = "ACTIVE", "Active"
    EXPIRED = "EXPIRED", "Expired"
    REVOKED = "REVOKED", "Revoked"


class PrivacyIncidentCategoryChoices(models.TextChoices):
    UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS", "Unauthorized access"
    TOKEN_OTP_ABUSE = "TOKEN_OTP_ABUSE", "Token or OTP abuse"
    SENSITIVE_EXPORT = "SENSITIVE_EXPORT", "Sensitive export"
    BACKUP_RESTORE_EXPOSURE = "BACKUP_RESTORE_EXPOSURE", "Backup or restore exposure"
    ACCIDENTAL_DISCLOSURE = "ACCIDENTAL_DISCLOSURE", "Accidental disclosure"
    SUSPECTED_DATA_LOSS = "SUSPECTED_DATA_LOSS", "Suspected data loss"
    RETENTION_DISPOSAL_FAILURE = "RETENTION_DISPOSAL_FAILURE", "Retention or disposal failure"


class PrivacyIncidentSeverityChoices(models.TextChoices):
    LOW = "LOW", "Low"
    MEDIUM = "MEDIUM", "Medium"
    HIGH = "HIGH", "High"
    CRITICAL = "CRITICAL", "Critical"


class PrivacyIncidentStatusChoices(models.TextChoices):
    OPEN = "OPEN", "Open"
    INVESTIGATING = "INVESTIGATING", "Investigating"
    CONTAINED = "CONTAINED", "Contained"
    RESOLVED = "RESOLVED", "Resolved"
    DISMISSED = "DISMISSED", "Dismissed"


class PrivacyIncidentNotificationDecisionChoices(models.TextChoices):
    PENDING = "PENDING", "Pending assessment"
    NOT_REQUIRED = "NOT_REQUIRED", "Notification not required"
    REQUIRED = "REQUIRED", "Notification required"
    COMPLETED = "COMPLETED", "Notification completed"
