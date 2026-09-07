"""Fixed JSON projection boundary for the student onboarding API."""

from __future__ import annotations

from datetime import datetime


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _mask_email(value: str | None) -> str:
    raw = str(value or "")
    if "@" not in raw:
        return ""
    local, domain = raw.split("@", 1)
    return f"{local[:1]}***{local[-1:] if len(local) > 1 else ''}@{domain}"


def batch_projection(batch) -> dict:
    summary = dict(batch.execution_summary or {})
    row_count = getattr(batch, "_row_count", None)
    if row_count is None:
        row_count = batch.rows.count()
    return {
        "id": str(batch.pk),
        "source_name": str(batch.source_name),
        "academic_year": str(batch.academic_year),
        "status": str(batch.status),
        "template_version": str(batch.template_version),
        "catalog_version": str(batch.catalog_version),
        "content_present": bool(batch.content_hmac),
        "row_count": int(row_count),
        "validation_revision": int(batch.validation_revision),
        "validated_at": _iso(batch.validated_at),
        "approved_at": _iso(batch.approved_at),
        "approval_revoked_at": _iso(batch.approval_revoked_at),
        "executed_at": _iso(batch.executed_at),
        "execution_summary": {
            key: int(summary.get(key, 0) or 0)
            for key in ("success", "reconciled", "excluded", "total")
            if key in summary
        },
    }


def row_projection(row) -> dict:
    return {
        "id": str(row.pk),
        "row_number": int(row.row_number),
        "status": str(row.validation_status),
        "error_code": str(row.error_code or ""),
        "error": str(row.error_message or "")[:300],
        "masked_email": _mask_email(row.email),
        "has_student_number": bool(row.student_number),
        "has_control_number": bool(row.control_number),
        "initials": f"{(row.first_name or '')[:1]}{(row.last_name or '')[:1]}".upper(),
        "placement": {
            "campus": str(row.campus or ""),
            "college": str(row.college or ""),
            "department": str(row.department or ""),
            "program": str(row.program or ""),
            "program_code": str(row.program_code or ""),
            "year_level": row.year_level,
        },
        "correction_revision": int(row.correction_revision),
        "reviewed_at": _iso(row.reviewed_at),
    }


def row_editor_projection(row) -> dict:
    value = row_projection(row)
    value["editable_fields"] = {
        "student_number": row.student_number or "",
        "control_number": row.control_number or "",
        "email": row.email or "",
        "first_name": row.first_name,
        "last_name": row.last_name,
        "program_code": row.program_code,
        "campus": row.campus,
        "college": row.college,
        "department": row.department,
        "program": row.program,
        "year_level": row.year_level,
        "lifecycle_status": row.lifecycle_status,
    }
    return value


def invitation_projection(invitation, *, delivery_state: str = "") -> dict:
    from django.utils import timezone

    if invitation.used_at:
        status = "USED"
    elif invitation.revoked_at:
        status = "REVOKED"
    elif invitation.expires_at <= timezone.now():
        status = "EXPIRED"
    else:
        status = "ACTIVE"
    return {
        "id": str(invitation.pk),
        "status": status,
        "expires_at": _iso(invitation.expires_at),
        "used_at": _iso(invitation.used_at),
        "revoked_at": _iso(invitation.revoked_at),
        "delivery_state": delivery_state,
    }


def catalog_projection(value: dict) -> dict:
    return {
        "version": str(value.get("version", "")),
        "demo_only": bool(value.get("demo_only", False)),
        "placements": [
            {
                "program_code": str(item.get("program_code", "")),
                "campus": str(item.get("campus", "")),
                "college": str(item.get("college", "")),
                "department": str(item.get("department", "")),
                "program": str(item.get("program", "")),
                "max_year_level": int(item.get("max_year_level", 0)),
            }
            for item in value.get("placements", [])
        ],
    }
