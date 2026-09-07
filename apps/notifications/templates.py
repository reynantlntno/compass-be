from urllib.parse import urljoin

from django.conf import settings
from apps.organizations.defaults import ORGANIZATION_IDENTITY_FALLBACKS
from apps.notifications.models import NotificationTemplate


TEMPLATES_REGISTRY = {
    "workflow_status_update": {
        "display_name": "Request Update",
        "channel": "both",
        "subject_template": "COMPASS: Request update available",
        "body_template": "notifications/workflow_status_update.txt",
        "required_context_schema": {
            "required": ["action", "status"],
            "properties": {
                "action": {"type": "string"},
                "status": {"type": "string"},
                "reference_code": {"type": "string"},
                "actor_name": {"type": "string"},
            }
        }
    },
    "document_request_update": {
        "display_name": "Document Request Update",
        "channel": "both",
        "subject_template": "COMPASS: Document Request Status Update",
        "body_template": "notifications/document_request_update.txt",
        "required_context_schema": {
            "required": ["request_type", "status"],
            "properties": {
                "request_type": {"type": "string"},
                "status": {"type": "string"},
                "reference_code": {"type": "string"},
            }
        }
    },
    "appointment_update": {
        "display_name": "Appointment Update",
        "channel": "both",
        "subject_template": "COMPASS: Appointment Update",
        "body_template": "notifications/appointment_update.txt",
        "required_context_schema": {
            "required": ["action", "status"],
            "properties": {
                "action": {"type": "string"},
                "status": {"type": "string"},
                "reference_code": {"type": "string"},
                "counselor_name": {"type": "string"},
            },
        },
    },
    "call_slip_update": {
        "display_name": "Call Slip Update",
        "channel": "both",
        "subject_template": "COMPASS: Call Slip Update",
        "body_template": "notifications/call_slip_update.txt",
        "required_context_schema": {
            "required": ["action", "status"],
            "properties": {
                "action": {"type": "string"},
                "status": {"type": "string"},
                "reference_code": {"type": "string"},
                "office_name": {"type": "string"},
            },
        },
    },
    "referral_update": {
        "display_name": "Referral Update",
        "channel": "both",
        "subject_template": "COMPASS: Referral Update",
        "body_template": "notifications/referral_update.txt",
        "required_context_schema": {
            "required": ["action", "status"],
            "properties": {
                "action": {"type": "string"},
                "status": {"type": "string"},
                "reference_code": {"type": "string"},
                "student_name": {"type": "string"},
                "counselor_name": {"type": "string"},
            },
        },
    },
    "good_moral_update": {
        "display_name": "Good Moral Update",
        "channel": "both",
        "subject_template": "COMPASS: Good Moral Request Update",
        "body_template": "notifications/good_moral_update.txt",
        "required_context_schema": {
            "required": ["action", "status"],
            "properties": {
                "action": {"type": "string"},
                "status": {"type": "string"},
                "reference_code": {"type": "string"},
                "reason_label": {"type": "string"},
            },
        },
    },
    "csm_invitation": {
        "display_name": "CSM Feedback Invitation",
        "channel": "both",
        "subject_template": "COMPASS: Feedback Invitation Available",
        "body_template": "notifications/csm_invitation.txt",
        "required_context_schema": {
            "required": ["action", "status", "service_label", "expires_on"],
            "properties": {
                "action": {"type": "string"},
                "status": {"type": "string"},
                "service_label": {"type": "string"},
                "expires_on": {"type": "string"},
            },
        },
    },
    "exit_interview_reminder": {
        "display_name": "Exit Interview Reminder",
        "channel": "both",
        "subject_template": "COMPASS: Exit Interview Update",
        "body_template": "notifications/exit_interview_reminder.txt",
        "required_context_schema": {
            "required": ["action", "status"],
            "properties": {
                "action": {"type": "string"},
                "status": {"type": "string"},
                "reference_code": {"type": "string"},
            },
        },
    },
    "gts_reminder": {
        "display_name": "Graduate Tracer Reminder",
        "channel": "both",
        "subject_template": "COMPASS: Graduate Tracer Update",
        "body_template": "notifications/gts_reminder.txt",
        "required_context_schema": {
            "required": ["action", "status"],
            "properties": {
                "action": {"type": "string"},
                "status": {"type": "string"},
                "reference_code": {"type": "string"},
            },
        },
    },
    "collection_delivered": {
        "display_name": "Form Collection Available",
        "channel": "both",
        "subject_template": "COMPASS: Form Collection Available",
        "body_template": "notifications/collection_delivered.txt",
        "required_context_schema": {
            "required": ["action", "status", "collection_title"],
            "properties": {
                "action": {"type": "string"},
                "status": {"type": "string"},
                "collection_title": {"type": "string"},
            },
        },
    },
    "security_event": {
        "display_name": "Account Security Event",
        "channel": "in_app",
        "subject_template": "COMPASS: Account Security Event",
        "body_template": "notifications/security_event.txt",
        "required_context_schema": {
            "required": ["action", "status"],
            "properties": {
                "action": {"type": "string"},
                "status": {"type": "string"},
                "device_label": {"type": "string"},
            },
        },
    },
    "inventory_correction_requested": {
        "display_name": "Individual Inventory Correction Requested",
        "channel": "both",
        "subject_template": "COMPASS: Individual Inventory Update Requested",
        "body_template": "notifications/inventory_correction_requested.txt",
        "required_context_schema": {
            "required": ["action", "status", "action_path"],
            "properties": {
                "action": {"type": "string"},
                "status": {"type": "string"},
                "action_path": {"type": "string"},
            },
        },
    },
    "account_recovery": {
        "display_name": "Account Recovery",
        "channel": "email",
        "subject_template": "COMPASS account recovery",
        "body_template": "emails/v1/generic.txt",
        "required_context_schema": {
            "required": ["recovery_request_id"],
            "properties": {"recovery_request_id": {"type": "string"}},
        },
        "preference_policy": "mandatory_security",
        "sensitivity_classification": "RESTRICTED",
    },
    "two_step_code": {
        "display_name": "Two-step Verification Code",
        "channel": "email",
        "subject_template": "COMPASS verification code",
        "body_template": "emails/v1/generic.txt",
        "required_context_schema": {
            "required": ["purpose"],
            "properties": {"purpose": {"type": "string"}},
        },
        "preference_policy": "mandatory_security",
        "sensitivity_classification": "RESTRICTED",
    },
    "student_activation": {
        "display_name": "Student Activation",
        "channel": "email",
        "subject_template": "COMPASS student account activation",
        "body_template": "emails/v1/generic.txt",
        "required_context_schema": {
            "required": ["invitation_id"],
            "properties": {"invitation_id": {"type": "string"}},
        },
        "preference_policy": "mandatory_security",
        "sensitivity_classification": "RESTRICTED",
    },
    "staff_activation": {
        "display_name": "Staff Account Activation",
        "channel": "email",
        "subject_template": "COMPASS staff account activation",
        "body_template": "emails/v1/generic.txt",
        "required_context_schema": {
            "required": ["invitation_id"],
            "properties": {"invitation_id": {"type": "string"}},
        },
        "preference_policy": "mandatory_security",
        "sensitivity_classification": "RESTRICTED",
    },
    "contact_reply": {
        "display_name": "Contact correspondence",
        "channel": "email",
        "subject_template": "COMPASS contact response",
        "body_template": "emails/v1/contact_reply.txt",
        "html_body_template": "emails/v1/contact_reply.html",
        "required_context_schema": {
            "required": ["reply_id"],
            "properties": {"reply_id": {"type": "string"}},
        },
        "preference_policy": "mandatory_security",
        "sensitivity_classification": "RESTRICTED",
    },
}

# Every template receives immutable v1 metadata and the same approved shell.
# Keep each established text-template path as the controlled fallback; those
# files inherit ``emails/v1/base.txt`` while the shared HTML path inherits the
# corresponding HTML shell.
for _template_key, _template_data in TEMPLATES_REGISTRY.items():
    _template_data.setdefault("html_body_template", "emails/v1/generic.html")
    _template_data.setdefault("template_version", "v1")
    _template_data.setdefault("preference_policy", "user")


FORBIDDEN_CONTEXT_KEYWORDS = {
    "student_number", "control_number", "counseling_notes", "referral_reason",
    "case_details", "signed_url", "x-amz-signature",
    "object_key", "storage_key", "raw_token", "otp", "password", "secret",
    "smtp_password", "api_key", "daily_link", "meeting_link",
    "certificate_link", "download_link", "protected_url",
}


def _check_forbidden_context_keys(value, path="context") -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            key_lower = str(key).lower()
            if any(forbidden in key_lower for forbidden in FORBIDDEN_CONTEXT_KEYWORDS):
                raise ValueError(f"Forbidden context variable: {path}.{key}")
            _check_forbidden_context_keys(nested, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, nested in enumerate(value):
            _check_forbidden_context_keys(nested, f"{path}[{index}]")


def validate_context_schema(schema: dict, context: dict) -> None:
    """
    Validates that context keys are present and conform to basic types.
    Avoids external jsonschema dependency.
    """
    if not isinstance(context, dict):
        raise TypeError("Template context must be a dictionary")

    _check_forbidden_context_keys(context)

    required = schema.get("required", [])
    properties = schema.get("properties", {})
    allowed_keys = set(properties.keys())

    for req in required:
        if req not in context:
            raise ValueError(f"Missing required context variable: {req}")

    unknown_keys = set(context.keys()) - allowed_keys
    if unknown_keys:
        unknown = ", ".join(sorted(str(key) for key in unknown_keys))
        raise ValueError(f"Unknown context variable(s): {unknown}")

    safe_context = {}
    for key, val in context.items():
        expected_type = properties[key].get("type")
        if expected_type == "string" and not isinstance(val, str):
            raise TypeError(f"Context variable '{key}' must be a string")
        elif expected_type == "integer" and not isinstance(val, int):
            raise TypeError(f"Context variable '{key}' must be an integer")
        elif expected_type == "number" and not isinstance(val, (int, float)):
            raise TypeError(f"Context variable '{key}' must be a number")
        elif expected_type == "boolean" and not isinstance(val, bool):
            raise TypeError(f"Context variable '{key}' must be a boolean")
        safe_context[key] = val

    return safe_context


def sync_templates_registry(dry_run: bool = False) -> dict:
    """Syncs the python templates registry into the database."""
    from apps.notifications.models import NotificationTemplate

    summary = {"created": 0, "updated": 0, "unchanged": 0}
    for key, data in TEMPLATES_REGISTRY.items():
        defaults = {
            "display_name": data["display_name"],
            "channel": data["channel"],
            "subject_template": data["subject_template"],
            "body_template": data["body_template"],
            "html_body_template": data["html_body_template"],
            "template_version": data["template_version"],
            "preference_policy": data["preference_policy"],
            "required_context_schema_json": data["required_context_schema"],
            "status": "active",
            "sensitivity_classification": data.get("sensitivity_classification", "GENERAL"),
            "audit_category": "NOTIFICATION_SYNC"
        }
        existing = NotificationTemplate.objects.filter(stable_key=key).first()
        if existing is None:
            summary["created"] += 1
            if not dry_run:
                NotificationTemplate.objects.create(stable_key=key, **defaults)
            continue

        changed = any(getattr(existing, field) != value for field, value in defaults.items())
        if changed:
            summary["updated"] += 1
            if not dry_run:
                for field, value in defaults.items():
                    setattr(existing, field, value)
                existing.save(update_fields=[*defaults.keys(), "updated_at"])
        else:
            summary["unchanged"] += 1
    return summary


def build_shared_email_context(*, template_key: str = "", runtime_context=None) -> dict:
    """Return non-sensitive configured identity/support values for the shell."""
    runtime_context = runtime_context or {}
    support = str(getattr(settings, "COMPASS_EMAIL_REPLY_TO", "") or "").strip()
    institution_name = ORGANIZATION_IDENTITY_FALLBACKS["institution_name"]
    office_name = ORGANIZATION_IDENTITY_FALLBACKS["office_name"]
    support_phone = ORGANIZATION_IDENTITY_FALLBACKS["support_phone"]

    # The active, governed organization profiles are the source of truth when
    # available.  This lookup is intentionally best-effort: notification
    # rendering must remain safe during migrations, health checks, and other
    # startup paths where the organization tables may not exist yet.  We use
    # names/contact text only; repository/demo logos and seals are never part
    # of an email context.
    try:
        from apps.organizations.cache import (
            get_institution_identity_snapshot,
            get_office_identity_snapshot,
        )

        institution = get_institution_identity_snapshot()
        office = get_office_identity_snapshot(institution_id=institution.get("id"))
        if institution.get("legal_name"):
            institution_name = str(institution["legal_name"]).strip()
        if office:
            if office.get("office_name"):
                office_name = str(office["office_name"]).strip()
            if not support:
                support = str(office.get("contact_email") or "").strip()
            if not support_phone:
                support_phone = str(office.get("contact_number") or "").strip()
    except Exception:
        # Identity text is non-critical to queueing and must not turn a safe
        # notification into a disclosure or availability failure.
        pass

    base_url = str(getattr(settings, "COMPASS_CLIENT_BASE_URL", "") or "").strip().rstrip("/")
    return {
        "template_key": template_key,
        "institution_name": institution_name,
        "office_name": office_name,
        "configured_institution_name": institution_name,
        "configured_office_name": office_name,
        "support_email": support,
        "support_phone": support_phone,
        "client_base_url": base_url,
        **runtime_context,
    }


def render_email_message(template_key: str, context: dict, *, runtime_context=None):
    """Render text and HTML while keeping secrets in ephemeral runtime context."""
    from django.template.loader import render_to_string

    from apps.notifications.cache import get_cached_notification_template

    data = get_cached_notification_template(template_key)
    if data is None:
        data = TEMPLATES_REGISTRY.get(template_key)
    if not data:
        raise ValueError(f"Unknown notification template: {template_key}")
    schema = data.get("required_context_schema", data.get("required_context_schema_json", {}))
    body_template = data["body_template"]
    html_body_template = data.get("html_body_template", "emails/v1/generic.html")
    safe_context = validate_context_schema(schema, context)
    merged = build_shared_email_context(template_key=template_key, runtime_context=runtime_context)
    merged.update(safe_context)
    action_path = merged.get("action_path")
    if isinstance(action_path, str) and action_path.startswith("/") and merged.get("client_base_url"):
        merged["action_path"] = urljoin(
            merged["client_base_url"].rstrip("/") + "/",
            action_path.lstrip("/"),
        )
    text_content = render_to_string(body_template, merged)
    html_path = html_body_template or "emails/v1/generic.html"
    html_content = render_to_string(html_path, merged)
    return text_content, html_content
