"""Canonical allocator for non-secret human workflow reference codes.

The counter table remains owned by Organizations as shared infrastructure,
but all allocation, formatting, validation, locking, and overflow rules live
here. Domain modules provide only their fixed prefix and period source.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from django.db import IntegrityError, transaction

from apps.common.exceptions import ValidationError


MAX_REFERENCE_SEQUENCE = 999_999
_ACADEMIC_YEAR_RE = re.compile(r"\A(?P<start>\d{4})-(?P<end>\d{4})\Z")


@dataclass(frozen=True, slots=True)
class ReferenceCodeSpec:
    prefix: str
    label: str

    def __post_init__(self):
        if not re.fullmatch(r"[A-Z]{3}", self.prefix):
            raise ValueError("Reference prefixes must be exactly three uppercase letters.")


CANONICAL_REFERENCE_SPECS = {
    spec.prefix: spec
    for spec in (
        ReferenceCodeSpec("APT", "Appointment"),
        ReferenceCodeSpec("REF", "Referral"),
        ReferenceCodeSpec("CSL", "Call Slip"),
        ReferenceCodeSpec("SES", "Counseling Session"),
        ReferenceCodeSpec("CAS", "Counseling Case"),
        ReferenceCodeSpec("ECS", "E-Counseling"),
        ReferenceCodeSpec("ESC", "Urgent Support"),
        ReferenceCodeSpec("GMC", "Good Moral"),
        ReferenceCodeSpec("EIT", "Exit Interview"),
        ReferenceCodeSpec("GTS", "Graduate Tracer"),
        ReferenceCodeSpec("FBK", "Feedback"),
        ReferenceCodeSpec("DOC", "Generated Document"),
        ReferenceCodeSpec("CNT", "Public Contact"),
    )
}


def academic_year_to_segment(period_key: str) -> str:
    match = _ACADEMIC_YEAR_RE.fullmatch(str(period_key or ""))
    if not match or int(match.group("end")) != int(match.group("start")) + 1:
        raise ValidationError("The academic-year period is invalid.")
    return f"AY{match.group('start')[2:]}{match.group('end')[2:]}"


def format_reference_code(prefix: str, period_key: str, sequence: int) -> str:
    spec = CANONICAL_REFERENCE_SPECS.get(prefix)
    if spec is None:
        raise ValidationError("The workflow reference prefix is not registered.")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or not 1 <= sequence <= MAX_REFERENCE_SEQUENCE:
        raise ValidationError("The workflow reference sequence is outside the safe range.")
    return f"{spec.prefix}-{academic_year_to_segment(period_key)}-{sequence:06d}"


def validate_reference_code(code: str) -> bool:
    if not isinstance(code, str):
        return False
    match = re.fullmatch(r"([A-Z]{3})-AY(\d{4})-([0-9]{6})", code)
    if not match or match.group(1) not in CANONICAL_REFERENCE_SPECS:
        return False
    sequence = int(match.group(3))
    if sequence < 1 or sequence > MAX_REFERENCE_SEQUENCE:
        return False
    start_short = int(match.group(2)[:2])
    end_short = int(match.group(2)[2:])
    return end_short == (start_short + 1) % 100


def allocate_reference_code(spec: ReferenceCodeSpec, period_key: str) -> str:
    """Allocate the next code from the canonical WorkflowReferenceCounter."""
    # Lazy import keeps common mechanics importable while Django models load.
    from apps.organizations.models import WorkflowReferenceCounter

    academic_year_to_segment(period_key)
    with transaction.atomic():
        counter = (
            WorkflowReferenceCounter.objects.select_for_update()
            .filter(prefix=spec.prefix, period_key=period_key)
            .first()
        )
        if counter is None:
            try:
                with transaction.atomic():
                    WorkflowReferenceCounter.objects.create(
                        prefix=spec.prefix,
                        period_key=period_key,
                        last_sequence=0,
                        description=spec.label,
                    )
            except IntegrityError:
                pass
            counter = WorkflowReferenceCounter.objects.select_for_update().get(
                prefix=spec.prefix,
                period_key=period_key,
            )
        if counter.last_sequence >= MAX_REFERENCE_SEQUENCE:
            raise ValidationError("The workflow reference sequence is exhausted.")
        counter.last_sequence += 1
        counter.save(update_fields=["last_sequence", "updated_at"])
        return format_reference_code(spec.prefix, period_key, counter.last_sequence)
