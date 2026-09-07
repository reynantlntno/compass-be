"""Public Service Guide projection and server-owned readiness rules."""

from __future__ import annotations

from dataclasses import dataclass

from django.utils import timezone

from apps.content.models import ContentStatus, ServiceGuide


@dataclass(frozen=True)
class ServiceGuideEntry:
    """Backend-owned catalog metadata used by service-guide projections."""

    key: str
    label: str
    short_description: str
    workflow_state: str
    privacy_level: str
    guide_anchor: str
    guide_summary: str


SERVICE_GUIDE_ENTRIES = (
    ServiceGuideEntry(
        key="individual_inventory",
        label="Student Individual Inventory",
        short_description="Complete your annual Individual Inventory form.",
        workflow_state="implemented",
        privacy_level="personal",
        guide_anchor="guide-individual-inventory",
        guide_summary="Complete the Individual Inventory from your account when it is available.",
    ),
    ServiceGuideEntry(
        key="appointment_status",
        label="My Appointments",
        short_description="Request appointments and view schedules.",
        workflow_state="implemented",
        privacy_level="internal",
        guide_anchor="guide-appointments",
        guide_summary="Use your account to request an appointment and view appointment status.",
    ),
    ServiceGuideEntry(
        key="counseling_session",
        label="My Counseling",
        short_description="View your counseling session records and join e-counseling.",
        workflow_state="implemented",
        privacy_level="counseling_confidential",
        guide_anchor="guide-counseling",
        guide_summary="Use the authenticated counseling area for assigned sessions and related status.",
    ),
    ServiceGuideEntry(
        key="ecounseling",
        label="E-Counseling",
        short_description="Join a remote counseling session online.",
        workflow_state="implemented",
        privacy_level="counseling_confidential",
        guide_anchor="guide-e-counseling",
        guide_summary="E-Counseling is available through the authenticated counseling area when assigned.",
    ),
    ServiceGuideEntry(
        key="routine_interview",
        label="Routine Interview",
        short_description="Complete your routine guidance interview.",
        workflow_state="implemented",
        privacy_level="counseling_confidential",
        guide_anchor="guide-routine-interview",
        guide_summary="Complete a routine interview through the authenticated counseling area when assigned.",
    ),
    ServiceGuideEntry(
        key="student_call_slips",
        label="Call Slips",
        short_description="View Guidance Office call slips.",
        workflow_state="implemented",
        privacy_level="sensitive",
        guide_anchor="guide-call-slips",
        guide_summary="View a call slip from your authenticated account when the office issues one.",
    ),
    ServiceGuideEntry(
        key="good_moral",
        label="Good Moral Certificate",
        short_description="Request and track your Good Moral Certificate.",
        workflow_state="implemented",
        privacy_level="personal",
        guide_anchor="guide-good-moral",
        guide_summary="Request and track a Good Moral Certificate through the authenticated service.",
    ),
    ServiceGuideEntry(
        key="csm_feedback",
        label="Customer Satisfaction Survey",
        short_description="Share feedback after a completed Guidance Office service.",
        workflow_state="implemented",
        privacy_level="internal",
        guide_anchor="guide-feedback",
        guide_summary="Share service feedback through an approved invitation or feedback link.",
    ),
    ServiceGuideEntry(
        key="exit_interview",
        label="Exit Interview",
        short_description="Complete your exit interview before graduation.",
        workflow_state="implemented",
        privacy_level="personal",
        guide_anchor="guide-exit-interview",
        guide_summary="Complete the Exit Interview through the official authenticated intake.",
    ),
    ServiceGuideEntry(
        key="graduate_tracer",
        label="Graduate Tracer Survey",
        short_description="Tell the university about your education and employment after graduation.",
        workflow_state="implemented",
        privacy_level="personal",
        guide_anchor="guide-graduate-tracer",
        guide_summary="Complete the Graduate Tracer through the official authenticated or approved intake.",
    ),
)


# These are intentionally descriptive confirmation slots, not office policy.
# A published revision may replace a slot with approved copy; otherwise the
# public DTO keeps the explicit safe state below.
GUIDE_CONFIRMATION_FIELDS = (
    ("requirements", "Requirements"),
    ("fees", "Fees"),
    ("timelines", "Timelines"),
    ("receipt_rules", "Receipt rules"),
    ("claim_rules", "Release / claim rules"),
    ("proxy_claims", "Proxy claims"),
    ("office_hours", "Office hours"),
    ("contact", "Office contact"),
)

GUIDE_METADATA_FIELDS = (
    ("version_label", "Version label"),
    ("effective_date", "Effective date"),
    ("owner_office", "Owner office"),
)

GUIDE_PENDING_FIELD_VALUE = "This information is being confirmed by the office."
GUIDE_PENDING_STEP_VALUE = "These service details are being confirmed by the office."
GUIDE_PENDING_NOTICE = "Some service details are still being confirmed by the office."
GUIDE_PENDING_DISPLAY_STATE = "Some service details are still being confirmed"
GUIDE_UNAVAILABLE_DISPLAY_STATE = "Service guide is not yet available"
GUIDE_NO_APPROVED_REVISION_LABEL = "No approved service guide is available yet"
_LEGACY_GUIDE_PENDING_VALUES = frozenset({"To be confirmed by the office"})

GOOD_MORAL_STEPS = (
    {
        "key": "request",
        "label": "Request",
        "description": "Submit the Good Moral request through the authenticated COMPASS service.",
        "boundary": "COMPASS intake",
    },
    {
        "key": "cashier-payment",
        "label": "External Cashier/payment checkpoint",
        "description": "Complete any required Cashier or payment checkpoint outside COMPASS.",
        "boundary": "External Cashier / payment",
    },
    {
        "key": "gco-verification",
        "label": "GCO verification/processing",
        "description": "The Guidance and Counseling Office verifies and processes the request.",
        "boundary": "GCO processing",
    },
    {
        "key": "printed-release-claim",
        "label": "Printed, signed, and released",
        "description": "The GCO prints and signs the certificate, then releases the printed certificate to the student.",
        "boundary": "GCO printed handoff",
    },
    {
        "key": "registrar-dry-seal",
        "label": "External Registrar dry-seal confirmation",
        "description": "The Registrar applies the dry seal outside COMPASS. The student or authorized GCO personnel may record confirmation after the certificate is released.",
        "boundary": "External Registrar checkpoint",
    },
)


def _safe_text(value, fallback="", limit=500):
    if value is None:
        return fallback
    text = " ".join(str(value).split()).strip()
    if not text or len(text) > limit:
        return fallback
    return text


def _service_guide_entries():
    """Return the backend catalog without client navigation metadata."""
    rows = []
    for definition in SERVICE_GUIDE_ENTRIES:
        available = definition.workflow_state == "implemented"
        rows.append((definition, available))
    return rows


def _fallback_field_values():
    return {
        key: {
            "label": label,
            "value": GUIDE_PENDING_FIELD_VALUE,
            "confirmed": False,
            "owner": "Responsible service owner",
        }
        for key, label in GUIDE_CONFIRMATION_FIELDS
    }


def _guide_metadata_missing(guide):
    """Return missing top-level office-owned guide metadata.

    The publication window and status are server-controlled workflow state, so
    they are deliberately not treated as office-confirmation slots here.
    """
    missing = []
    for field, label in GUIDE_METADATA_FIELDS:
        if guide is None:
            present = False
        elif field == "owner_office":
            present = bool(getattr(guide, "owner_office_id", None))
        else:
            present = bool(getattr(guide, field, None))
        if not present:
            missing.append({
                "entry_key": "__guide__",
                "field": field,
                "label": label,
                "owner": "Responsible service owner",
            })
    return missing


def _entry_readiness(entry, *, entry_key, owner):
    fields = entry.get("fields") if isinstance(entry.get("fields"), dict) else {}
    missing = []
    normalized_fields = {}
    for key, label in GUIDE_CONFIRMATION_FIELDS:
        candidate = fields.get(key) if isinstance(fields, dict) else None
        if isinstance(candidate, dict):
            value = _safe_text(candidate.get("value"), GUIDE_PENDING_FIELD_VALUE)
            if value in _LEGACY_GUIDE_PENDING_VALUES:
                value = GUIDE_PENDING_FIELD_VALUE
            confirmed = bool(candidate.get("confirmed")) and value != GUIDE_PENDING_FIELD_VALUE
            field_owner = _safe_text(candidate.get("owner"), owner or "Responsible service owner", 160)
        else:
            value = GUIDE_PENDING_FIELD_VALUE
            confirmed = False
            field_owner = owner or "Responsible service owner"
        if not confirmed:
            missing.append({"entry_key": entry_key, "field": key, "label": label, "owner": field_owner})
        normalized_fields[key] = {
            "label": label,
            "value": value,
            "confirmed": confirmed,
            "owner": field_owner,
        }
    return normalized_fields, missing


def _revision_source():
    """Return the currently public source, never a future/draft revision."""
    now = timezone.now()
    candidates = ServiceGuide.objects.select_related("owner_office", "published_revision").filter(
        guide_key="public-service-guide", status=ContentStatus.PUBLISHED, audience="public"
    ).order_by("-published_at", "-effective_date", "-updated_at")
    for candidate in candidates:
        if candidate.publish_start and candidate.publish_start > now:
            continue
        if candidate.publish_end and candidate.publish_end <= now:
            continue
        revision = candidate.published_revision
        if not revision or revision.status != "published":
            continue
        return candidate, revision
    return None, None


def get_public_service_guide_context():
    """Build the canonical, public-safe Service Guide DTO.

    A safe fallback is always returned for internal consumers, but it contains
    no office-specific claims. It is assembled from backend-owned catalog data;
    client navigation is deliberately outside this service. Public templates
    show a neutral empty state until an approved revision exists.
    """
    guide, revision = _revision_source()
    approved_guide = guide if revision else None
    snapshot = revision.snapshot if revision else {}
    authored = snapshot.get("entries_json", guide.entries_json if guide else [])
    authored_map = {
        item.get("key"): item
        for item in authored
        if isinstance(item, dict) and _safe_text(item.get("key"))
    } if isinstance(authored, list) else {}

    entries = []
    missing = _guide_metadata_missing(approved_guide)
    for definition, available in _service_guide_entries():
        authored_entry = authored_map.get(definition.key, {})
        owner = _safe_text(authored_entry.get("owner"), "Responsible service owner", 160)
        fields, entry_missing = _entry_readiness(authored_entry, entry_key=definition.key, owner=owner)
        missing.extend(entry_missing)
        steps = authored_entry.get("steps") if isinstance(authored_entry.get("steps"), list) else []
        steps = [
            {
                "key": _safe_text(step.get("key"), f"step-{index}"),
                "label": _safe_text(step.get("label"), "Service step"),
                "description": _safe_text(step.get("description"), GUIDE_PENDING_STEP_VALUE),
                "boundary": _safe_text(step.get("boundary"), GUIDE_PENDING_FIELD_VALUE),
            }
            for index, step in enumerate(steps)
            if isinstance(step, dict)
        ][:12]
        if definition.key == "good_moral":
            # The boundary sequence is fixed by service_guide.ordering and cannot be edited
            # through JSON authoring.  Office-specific details remain fields.
            steps = list(GOOD_MORAL_STEPS)
        elif not steps:
            steps = []
        summary = _safe_text(
            authored_entry.get("summary"),
            definition.guide_summary or definition.short_description,
        )
        entries.append({
            "key": definition.key,
            "anchor": definition.guide_anchor or f"guide-{definition.key}",
            "label": definition.label,
            "summary": summary,
            "description": _safe_text(authored_entry.get("description"), definition.short_description),
            "available": available,
            "privacy_level": definition.privacy_level,
            "availability_label": "Available through COMPASS" if available else "Currently unavailable",
            "fields": fields,
            "steps": steps,
        })

    readiness = snapshot.get("readiness_metadata_json") if isinstance(snapshot, dict) else None
    if not isinstance(readiness, dict):
        readiness = {}
    document_readiness = "PENDING_APPROVAL"
    document_official = False
    try:
        from apps.documents.governance import DocumentOutputIntent, resolve_document_readiness

        document_result = resolve_document_readiness(
            stable_key="public_service_guide",
            intent=DocumentOutputIntent.PREVIEW,
        )
        document_readiness = document_result.label
        document_official = document_result.is_official
    except Exception:
        # Public rendering remains available while document metadata, identity,
        # or the optional PDF renderer is not configured.
        document_readiness = "PREVIEW — PENDING APPROVAL"
    readiness = {
        "state": "READY FOR OFFICE CONFIRMATION" if not missing else "PREVIEW — PENDING APPROVAL",
        "official": bool(guide and revision and not missing),
        "missing_fields": missing,
        "document_readiness": document_readiness,
        "document_official": document_official,
    }
    readiness["display_state"] = (
        "Published and confirmed"
        if readiness["official"]
        else GUIDE_PENDING_DISPLAY_STATE
        if guide and revision
        else GUIDE_UNAVAILABLE_DISPLAY_STATE
    )
    readiness["pending_notice"] = GUIDE_PENDING_NOTICE
    owner_name = ""
    if guide and guide.owner_office:
        owner_name = _safe_text(
            getattr(guide.owner_office, "office_name", ""),
            "",
            180,
        )
    return {
        "guide_key": "public-service-guide",
        # The public heading is a governed label, not office-editable copy.
        "title": "Official Citizen’s Charter / Service Standards",
        "summary": _safe_text(snapshot.get("summary"), "Public service access information from the Guidance and Counseling Office."),
        "version_label": _safe_text(snapshot.get("version_label"), GUIDE_PENDING_FIELD_VALUE),
        "effective_date": snapshot.get("effective_date"),
        "owner_office": owner_name or GUIDE_PENDING_FIELD_VALUE,
        "publication_state": "Published" if guide and revision else GUIDE_NO_APPROVED_REVISION_LABEL,
        "has_approved_revision": bool(guide and revision),
        "readiness": readiness,
        "entries": entries,
    }


def compute_service_guide_readiness(entries, guide=None):
    """Server-side readiness metadata persisted with each immutable revision."""
    authored = {
        item.get("key"): item
        for item in (entries if isinstance(entries, list) else [])
        if isinstance(item, dict) and _safe_text(item.get("key"))
    }
    missing = _guide_metadata_missing(guide) if guide is not None else []
    # Readiness covers the complete implemented public catalog, not just the
    # entries an author happened to include in a draft.  This keeps an empty
    # or partial revision visibly pending and records each owner-bound field.
    for definition in SERVICE_GUIDE_ENTRIES:
        item = authored.get(definition.key, {})
        _, entry_missing = _entry_readiness(
            item,
            entry_key=definition.key,
            owner=_safe_text(item.get("owner"), "Responsible service owner", 160),
        )
        missing.extend(entry_missing)
    official = not missing
    return {
        "state": "READY FOR OFFICE CONFIRMATION" if not missing else "PREVIEW — PENDING APPROVAL",
        "display_state": "Published and confirmed" if official else GUIDE_PENDING_DISPLAY_STATE,
        "pending_notice": GUIDE_PENDING_NOTICE,
        "official": official,
        "missing_fields": missing,
    }
