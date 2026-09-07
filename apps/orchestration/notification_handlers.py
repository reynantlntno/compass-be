"""Cross-domain outbox handler registration.

This is the sole composition module allowed to import business-domain event
handlers.  ``apps.workflow`` owns persistence and delivery mechanics only.
"""


def register_notification_handlers():
    from apps.workflow.services import register_outbox_handler

    from apps.appointments.notification_services import handle_appointment_event
    from apps.call_slips.notification_services import handle_call_slip_event
    from apps.referrals.notification_services import handle_referral_event
    from apps.good_moral.notification_services import handle_good_moral_event
    from apps.exit_interviews.notification_services import handle_exit_interview_event
    from apps.graduate_tracer.notification_services import handle_gts_event, handle_gts_reminder
    from apps.form_collection.notification_services import handle_collection_event
    from apps.inventory.notification_services import handle_inventory_correction_event
    from apps.account_security.notification_services import handle_security_event
    from apps.account_security.notification_services import handle_recovery_requested_event
    from apps.orchestration.notification_outbox_handlers import (
        handle_contact_submission_event,
        handle_contact_reply_event,
        handle_ecounseling_consent_event,
        handle_csm_invitation_event,
        handle_student_activation_invitation_event,
        handle_staff_account_invitation_event,
        handle_feedback_lifecycle_event,
    )

    handlers = {
        **{f"appointments.{event}": handle_appointment_event for event in (
            "scheduled", "declined", "late_cancellation_requested",
            "late_cancellation_approved", "late_cancellation_declined",
            "cancelled_by_student", "cancelled_by_office", "session_ready",
            "completed", "no_show", "counselor_assigned",
        )},
        **{f"call_slip.{event}": handle_call_slip_event for event in (
            "issued", "rescheduled", "completed", "no_show", "cancelled", "expired",
        )},
        "referral.created": handle_referral_event,
        "referral.assigned": handle_referral_event,
        "referral.status_changed": handle_referral_event,
        "good_moral.generated": handle_good_moral_event,
        "good_moral.released": handle_good_moral_event,
        "good_moral.rejected": handle_good_moral_event,
        "exit_interview.reminder": handle_exit_interview_event,
        "exit_interview.submitted": handle_exit_interview_event,
        "exit_interview.status_changed": handle_exit_interview_event,
        "graduate_tracer.reminder": handle_gts_reminder,
        "graduate_tracer.submitted": handle_gts_event,
        "graduate_tracer.status_changed": handle_gts_event,
        "form_collection.delivered": handle_collection_event,
        "account_security.password_changed": handle_security_event,
        "account_security.device_revoked": handle_security_event,
        "account_security.session_terminated": handle_security_event,
        "account_security.recovery_requested": handle_recovery_requested_event,
        "feedback.csm_invitation": handle_csm_invitation_event,
        "feedback.submitted": handle_feedback_lifecycle_event,
        "feedback.responded": handle_feedback_lifecycle_event,
        "content.contact_submission": handle_contact_submission_event,
        "content.contact_reply": handle_contact_reply_event,
        "ecounseling.recording_consent_requested": handle_ecounseling_consent_event,
        "inventory.correction_requested": handle_inventory_correction_event,
        "student_activation.invitation_requested": handle_student_activation_invitation_event,
        "staff_account.invitation_requested": handle_staff_account_invitation_event,
    }
    for event_type, handler in handlers.items():
        register_outbox_handler(event_type, handler)
