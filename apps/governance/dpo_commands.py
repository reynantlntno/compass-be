"""Input contract for the Governance-owned DPO appointment aggregate."""

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class DPOAppointmentRequest:
    holder_id: int
    valid_from: datetime
    valid_until: datetime | None
    appointment_reference: str
    contact_email: str
