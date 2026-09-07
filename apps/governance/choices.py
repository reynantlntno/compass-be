from django.db import models


class PolicyPlane(models.TextChoices):
    HEAD_BUSINESS = "HEAD_BUSINESS", "Head Guidance business governance"
    DPO_PRIVACY = "DPO_PRIVACY", "DPO privacy governance"
    IT_TECHNICAL = "IT_TECHNICAL", "IT technical operations"


class PolicyLifecycleStatus(models.TextChoices):
    DRAFT = "DRAFT", "Draft"
    PENDING_APPROVAL = "PENDING_APPROVAL", "Pending approval"
    ACTIVE = "ACTIVE", "Active"
    RETIRED = "RETIRED", "Retired"


class PolicyEffectivenessChoices(models.TextChoices):
    """Whether a retained policy row may participate in runtime resolution."""

    EFFECTIVE = "EFFECTIVE", "Effective"
    DEPRECATED = "DEPRECATED", "Deprecated — retained for audit only"


class PolicyTransitionAction(models.TextChoices):
    DRAFT_CREATED = "DRAFT_CREATED", "Draft created"
    DRAFT_UPDATED = "DRAFT_UPDATED", "Draft updated"
    SUBMITTED = "SUBMITTED", "Submitted for approval"
    APPROVED = "APPROVED", "Approved"
    ACTIVATED = "ACTIVATED", "Activated"
    RETIRED = "RETIRED", "Retired"
    REJECTED = "REJECTED", "Rejected"


class DPOAppointmentStatus(models.TextChoices):
    ACTIVE = "ACTIVE", "Active"
    RETIRED = "RETIRED", "Retired"
