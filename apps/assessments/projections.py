"""Fixed JSON-safe projections for the assessments API."""

from apps.assessments.choices import AssessmentInterpretationVisibility
from apps.common.exceptions import DependencyFailureError


def _mask_identifier(value: str | None) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    return f"••••{value[-4:]}" if len(value) > 4 else "••••"


def instrument_projection(instrument) -> dict:
    return {
        "id": instrument.id,
        "key": instrument.key,
        "title": instrument.title,
        "category": instrument.category,
        "allows_scores": bool(instrument.allows_scores),
        "allows_interpretation": bool(instrument.allows_interpretation),
        "active": bool(instrument.is_active),
    }


def assessment_staff_projection(record) -> dict:
    if record is None:
        return {}
    profile = record.student_profile
    return {
        "id": record.id,
        "student_reference": _mask_identifier(getattr(profile, "student_number", "")),
        "instrument": instrument_projection(record.instrument),
        "status": record.status,
        "administered_at": record.administered_at,
        "reviewed_at": record.reviewed_at,
        "released_to_student": bool(record.released_to_student),
        "released_at": record.released_to_student_at,
        "interpretation_visibility": record.interpretation_visibility,
        "has_protected_file": bool(record.protected_file_id),
    }


def assessment_sensitive_projection(record) -> dict:
    """Purpose-gated counselor/Head output; caller must authorize and audit."""
    try:
        interpretation = record.interpretation_text
    except Exception as exc:
        raise DependencyFailureError() from exc
    return {
        **assessment_staff_projection(record),
        "raw_score": record.raw_score,
        "scaled_score": record.scaled_score,
        "score_label": record.score_label,
        "interpretation": interpretation,
    }


def student_summary_projection(record) -> dict:
    """Student output intentionally omits scores, identifiers, files, and notes."""
    summary = ""
    if record.interpretation_visibility == AssessmentInterpretationVisibility.RELEASED_TO_STUDENT_SAFE_SUMMARY:
        try:
            summary = record.interpretation_text
        except Exception as exc:
            raise DependencyFailureError() from exc
    return {
        "id": record.id,
        "instrument": {
            "key": record.instrument.key,
            "title": record.instrument.title,
            "category": record.instrument.category,
        },
        "status": record.status,
        "administered_at": record.administered_at,
        "released_at": record.released_to_student_at,
        "safe_summary": summary,
    }


def protected_file_metadata_projection(metadata: dict | None) -> dict:
    if not metadata:
        return {}
    return {
        key: metadata[key]
        for key in ("id", "filename", "content_type", "size_bytes", "classification", "purpose", "status")
        if key in metadata
    }
