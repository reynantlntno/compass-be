"""Allowlisted notification event catalog.

This module is deliberately data-only.  Domain services use it to select a
stable notification type, while the preferences UI uses the same catalog to
avoid accepting arbitrary user-supplied preference keys.
"""


def _entry(
    category,
    label,
    description,
    *,
    channel="both",
    template_key=None,
    priority="normal",
    preference_policy="user",
):
    return {
        "category": category,
        "label": label,
        "description": description,
        "channel": channel,
        "template_key": template_key,
        "priority": priority,
        "preference_policy": preference_policy,
    }


NOTIFICATION_CATALOG = {
    "appointment_scheduled": _entry("Appointments", "Appointment scheduled", "A confirmed appointment is ready.", template_key="appointment_update"),
    "appointment_declined": _entry("Appointments", "Appointment decision", "An appointment request has been reviewed.", template_key="appointment_update"),
    "appointment_late_cancellation_requested": _entry("Appointments", "Cancellation request", "A late cancellation request needs review.", template_key="appointment_update"),
    "appointment_late_cancellation_approved": _entry("Appointments", "Cancellation approved", "A late cancellation request was approved.", priority="high", template_key="appointment_update"),
    "appointment_late_cancellation_declined": _entry("Appointments", "Appointment remains scheduled", "A late cancellation request was declined.", template_key="appointment_update"),
    "appointment_cancelled_by_student": _entry("Appointments", "Appointment cancelled", "An appointment was cancelled by the student.", priority="high", template_key="appointment_update"),
    "appointment_cancelled_by_office": _entry("Appointments", "Appointment cancelled", "An appointment was cancelled by the Guidance Office.", priority="high", template_key="appointment_update"),
    "appointment_session_ready": _entry("Counseling", "Counseling session ready", "A counseling session is ready in COMPASS.", priority="high", template_key="appointment_update"),
    "appointment_completed": _entry("Appointments", "Appointment completed", "An appointment has been marked completed.", template_key="appointment_update"),
    "appointment_no_show": _entry("Appointments", "Appointment update", "An appointment was marked as not attended.", template_key="appointment_update"),
    "counselor_assigned": _entry("Counseling", "Counselor assigned", "A counselor assignment has been updated.", template_key="appointment_update"),

    "call_slip_issued": _entry("Call slips", "Call slip issued", "A call slip has been issued.", priority="high", template_key="call_slip_update"),
    "call_slip_rescheduled": _entry("Call slips", "Call slip reschedule", "A call slip reschedule decision is available.", template_key="call_slip_update"),
    "call_slip_completed": _entry("Call slips", "Call slip completed", "A call slip has been marked completed.", template_key="call_slip_update"),
    "call_slip_no_show": _entry("Call slips", "Call slip update", "A call slip was marked as not attended.", template_key="call_slip_update"),
    "call_slip_cancelled": _entry("Call slips", "Call slip cancelled", "A call slip was cancelled.", priority="high", template_key="call_slip_update"),
    "call_slip_expired": _entry("Call slips", "Call slip expired", "A call slip is no longer active.", template_key="call_slip_update"),

    "referral_created": _entry("Referrals", "New referral", "A referral is ready for Guidance processing.", template_key="referral_update"),
    "referral_assigned": _entry("Referrals", "Referral assignment", "A referral counselor assignment has changed.", template_key="referral_update"),
    "referral_status_update": _entry("Referrals", "Referral status update", "A safe referral status update is available.", template_key="referral_update"),

    "good_moral_generated": _entry("Documents", "Good Moral document generated", "Your Good Moral document is being prepared for release.", channel="in_app", template_key="good_moral_update"),
    "good_moral_released": _entry("Documents", "Good Moral document released", "Your Good Moral document has been released.", template_key="good_moral_update"),
    "good_moral_rejected": _entry("Documents", "Good Moral request update", "Your Good Moral request requires attention.", template_key="good_moral_update"),

    "csm_invitation": _entry("Surveys", "Feedback invitation", "A feedback invitation is available for a completed service.", template_key="csm_invitation"),
    "exit_interview_reminder": _entry("Surveys", "Exit Interview reminder", "An Exit Interview is ready in COMPASS.", template_key="exit_interview_reminder"),
    "exit_interview_submitted": _entry("Surveys", "Exit Interview submitted", "An Exit Interview submission is ready for queue review.", channel="in_app", template_key="exit_interview_reminder"),
    "exit_interview_status_update": _entry("Surveys", "Exit Interview status", "Your Exit Interview status has changed.", template_key="exit_interview_reminder"),
    "gts_reminder": _entry("Surveys", "Graduate Tracer reminder", "A Graduate Tracer Survey is ready in COMPASS.", template_key="gts_reminder"),
    "gts_submitted": _entry("Surveys", "Graduate Tracer submitted", "A Graduate Tracer submission is ready for queue review.", channel="in_app", template_key="gts_reminder"),
    "gts_status_update": _entry("Surveys", "Graduate Tracer status", "Your Graduate Tracer status has changed.", template_key="gts_reminder"),
    "collection_delivered": _entry("Form Collections", "Collection available", "A COMPASS form collection is available.", template_key="collection_delivered"),

    "password_changed": _entry("Security", "Password changed", "Your COMPASS password was changed.", channel="in_app", priority="high", template_key="security_event", preference_policy="mandatory_security"),
    "device_revoked": _entry("Security", "Trusted device revoked", "A trusted device was revoked from your account.", channel="in_app", template_key="security_event", preference_policy="mandatory_security"),
    "session_terminated": _entry("Security", "Session terminated", "A COMPASS session was terminated.", channel="in_app", template_key="security_event", preference_policy="mandatory_security"),
    "account_recovery": _entry("Security", "Account recovery", "Account recovery instructions are available.", channel="email", priority="high", template_key="account_recovery", preference_policy="mandatory_security"),
    "student_activation": _entry("Security", "Student activation", "Student account activation instructions are queued.", channel="email", priority="high", template_key="student_activation", preference_policy="mandatory_security"),
    "staff_activation": _entry("Security", "Staff activation", "Staff account activation instructions are queued.", channel="email", priority="high", template_key="staff_activation", preference_policy="mandatory_security"),

    "contact_submission_received": _entry("Office contact", "New contact submission", "A public contact submission is ready for review.", channel="in_app"),
    "ecounseling_recording_consent_requested": _entry("Counseling", "Recording consent request", "Please review the optional recording notice in COMPASS.", channel="in_app"),
    "inventory_correction_requested": _entry("Individual Inventory", "Inventory correction requested", "Your Individual Inventory was reopened for correction.", template_key="inventory_correction_requested"),

    # These entries are retained for existing records and legacy producers.
    "workflow_status_update": _entry("Legacy", "Workflow status update", "A workflow status update is available.", template_key="workflow_status_update"),
    "document_request_update": _entry("Legacy", "Document request update", "A document request update is available.", template_key="document_request_update"),
}


def _event(notification_types, recipient_rule, channel, priority, template_keys, privacy_rule):
    return {
        "notification_types": tuple(notification_types),
        "recipient_rule": recipient_rule,
        "channel": channel,
        "priority": priority,
        "template_keys": tuple(template_keys),
        "privacy_rule": privacy_rule,
    }


# Runtime event contract.  Domain handlers remain responsible for resolving
# the current record policy, but every event must declare the safe fan-out
# contract here before it can be considered covered by the matrix.
NOTIFICATION_EVENT_CATALOG = {
    "appointments.scheduled": _event(("appointment_scheduled",), "student_and_assigned_counselor", "both", "normal", ("appointment_update",), "reference_code_and_safe_status"),
    "appointments.declined": _event(("appointment_declined",), "student", "both", "normal", ("appointment_update",), "safe_status_only"),
    "appointments.late_cancellation_requested": _event(("appointment_late_cancellation_requested",), "assigned_counselor", "both", "normal", ("appointment_update",), "safe_status_only_no_reason"),
    "appointments.late_cancellation_approved": _event(("appointment_late_cancellation_approved",), "student", "both", "high", ("appointment_update",), "safe_status_only"),
    "appointments.late_cancellation_declined": _event(("appointment_late_cancellation_declined",), "student", "both", "normal", ("appointment_update",), "safe_status_only"),
    "appointments.cancelled_by_student": _event(("appointment_cancelled_by_student",), "student_and_assigned_counselor", "both", "high", ("appointment_update",), "safe_status_only_no_reason"),
    "appointments.cancelled_by_office": _event(("appointment_cancelled_by_office",), "student_and_assigned_counselor", "both", "high", ("appointment_update",), "safe_status_only_no_reason"),
    "appointments.session_ready": _event(("appointment_session_ready",), "student_and_assigned_counselor", "both", "high", ("appointment_update",), "no_meeting_link_or_room_data"),
    "appointments.completed": _event(("appointment_completed",), "student", "both", "normal", ("appointment_update",), "safe_status_only"),
    "appointments.no_show": _event(("appointment_no_show",), "student_and_assigned_counselor", "both", "normal", ("appointment_update",), "safe_status_only"),
    "appointments.counselor_assigned": _event(("counselor_assigned",), "student", "both", "normal", ("appointment_update",), "counselor_name_only"),
    "call_slip.issued": _event(("call_slip_issued",), "student", "both", "high", ("call_slip_update",), "reference_code_and_office_name_only"),
    "call_slip.rescheduled": _event(("call_slip_rescheduled",), "student", "both", "normal", ("call_slip_update",), "reference_code_and_safe_status"),
    "call_slip.completed": _event(("call_slip_completed",), "student", "both", "normal", ("call_slip_update",), "safe_status_only"),
    "call_slip.no_show": _event(("call_slip_no_show",), "student", "both", "normal", ("call_slip_update",), "safe_status_only"),
    "call_slip.cancelled": _event(("call_slip_cancelled",), "student", "both", "high", ("call_slip_update",), "safe_status_only"),
    "call_slip.expired": _event(("call_slip_expired",), "student", "both", "normal", ("call_slip_update",), "safe_status_only"),
    "referral.created": _event(("referral_created",), "assigned_counselor_and_authorized_queue", "both", "normal", ("referral_update",), "authorized_staff_student_name_and_reference_only"),
    "referral.assigned": _event(("referral_assigned", "counselor_assigned"), "assigned_counselor_authorized_queue_and_student", "both", "normal", ("referral_update", "appointment_update"), "counselor_name_only_and_no_reason"),
    "referral.status_changed": _event(("referral_status_update",), "authorized_queue_and_student_safe_status", "both", "normal", ("referral_update",), "student_safe_status_only_no_record_link"),
    "good_moral.generated": _event(("good_moral_generated",), "requesting_student", "in_app", "normal", ("good_moral_update",), "no_download_link"),
    "good_moral.released": _event(("good_moral_released",), "requesting_student", "both", "normal", ("good_moral_update",), "reference_code_only_no_protected_url"),
    "good_moral.rejected": _event(("good_moral_rejected",), "requesting_student", "both", "normal", ("good_moral_update",), "safe_reason_code_only_no_office_note"),
    "feedback.csm_invitation": _event(("csm_invitation",), "service_bound_student", "both", "normal", ("csm_invitation",), "service_label_and_expiry_only_no_survey_link"),
    "exit_interview.reminder": _event(("exit_interview_reminder",), "assigned_or_linked_student", "both", "normal", ("exit_interview_reminder",), "no_form_link_or_token"),
    "exit_interview.submitted": _event(("exit_interview_submitted",), "authorized_guidance_queue", "in_app", "normal", ("exit_interview_reminder",), "authorized_student_name_and_reference_only"),
    "exit_interview.status_changed": _event(("exit_interview_status_update",), "student_for_visible_status", "both", "normal", ("exit_interview_reminder",), "safe_status_only_no_reason_or_form_link"),
    "graduate_tracer.reminder": _event(("gts_reminder",), "linked_student", "both", "normal", ("gts_reminder",), "no_form_link_or_token"),
    "graduate_tracer.submitted": _event(("gts_submitted",), "authorized_guidance_queue", "in_app", "normal", ("gts_reminder",), "authorized_student_name_and_reference_only"),
    "graduate_tracer.status_changed": _event(("gts_status_update",), "student_for_visible_status", "both", "normal", ("gts_reminder",), "safe_status_only"),
    "form_collection.delivered": _event(("collection_delivered",), "linked_student_only", "both", "normal", ("collection_delivered",), "collection_title_only_unlinked_silent"),
    "account_security.password_changed": _event(("password_changed",), "account_owner", "in_app", "high", ("security_event",), "confirmation_only_no_security_detail"),
    "account_security.device_revoked": _event(("device_revoked",), "account_owner", "in_app", "normal", ("security_event",), "safe_device_label_only"),
    "account_security.session_terminated": _event(("session_terminated",), "account_owner", "in_app", "normal", ("security_event",), "confirmation_only_no_session_detail"),
    "account_security.recovery_requested": _event(("account_recovery",), "account_owner", "email", "high", ("account_recovery",), "recovery_link_only_no_account_details"),
    "student_activation.invitation_requested": _event(("student_activation",), "student_account_owner", "email", "high", ("student_activation",), "activation_link_only_no_account_details"),
    "content.contact_submission": _event(("contact_submission_received",), "head_guidance_contact_queue", "in_app", "normal", (), "submission_type_only_no_message_body"),
    "ecounseling.recording_consent_requested": _event(("ecounseling_recording_consent_requested",), "student", "in_app", "normal", (), "notice_prompt_only_no_meeting_or_recording_link"),
    "inventory.correction_requested": _event(("inventory_correction_requested",), "student_owner", "both", "high", ("inventory_correction_requested",), "safe_status_and_local_action_path_no_answers_or_reason"),
}


def canonical_notification_type(notification_type: str) -> str:
    return notification_type


def notification_preference_keys(notification_type: str) -> tuple[str, ...]:
    """Return the single canonical notification preference key."""
    return (canonical_notification_type(notification_type),)


def get_notification_definition(notification_type: str) -> dict:
    canonical = canonical_notification_type(notification_type)
    try:
        return NOTIFICATION_CATALOG[canonical]
    except KeyError as exc:
        raise ValueError(f"Unsupported notification type: {notification_type}") from exc


def get_event_definition(event_type: str) -> dict:
    try:
        return NOTIFICATION_EVENT_CATALOG[event_type]
    except KeyError as exc:
        raise ValueError(f"Unsupported notification event: {event_type}") from exc


def preference_catalog() -> list[tuple[str, dict]]:
    """Return stable, grouped preference rows in display order."""
    return list(NOTIFICATION_CATALOG.items())
