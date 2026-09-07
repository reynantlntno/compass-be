"""Central operation contracts for the existing API surface."""

from __future__ import annotations

from dataclasses import dataclass

from apps.account_security.abuse_controls import AbuseAction, evaluate, record_volume
from apps.account_security.network import get_client_ip_from_headers
from apps.common.api.idempotency import require_idempotency_key
from apps.common.exceptions import RateLimitError


@dataclass(frozen=True, slots=True)
class ApiOperationSpec:
    operation_id: str
    mutation: bool = False
    idempotency_required: bool = False
    abuse_action: str | None = None
    cache_control: str = "no-store"


@dataclass(frozen=True, slots=True)
class PreparedApiOperation:
    """Immutable result of the API boundary checks for one operation.

    The raw idempotency key exists only in this request-local value and is
    consumed by the workflow adapter.  It is never serialized or persisted.
    """

    operation_id: str
    idempotency_key: str | None = None
    rate_limit_retry_after: int | None = None


def _admin(operation_id: str) -> ApiOperationSpec:
    return ApiOperationSpec(
        operation_id=operation_id,
        mutation=True,
        idempotency_required=True,
        abuse_action=str(AbuseAction.API_ADMIN_WRITE),
    )


API_OPERATION_SPECS = {
    # Authentication and one-time activation flows retain their own
    # abuse/replay controls and are deliberately not idempotency-wrapped here.
    "auth_login": ApiOperationSpec("auth_login", mutation=True),
    "auth_login_verify": ApiOperationSpec("auth_login_verify", mutation=True),
    "auth_csrf": ApiOperationSpec("auth_csrf"),
    "auth_token_refresh": ApiOperationSpec("auth_token_refresh", mutation=True),
    "auth_logout": ApiOperationSpec("auth_logout", mutation=True),
    "auth_staff_activation": ApiOperationSpec("auth_staff_activation", mutation=True),
    "auth_student_activation": ApiOperationSpec(
        "auth_student_activation",
        mutation=True,
        abuse_action=str(AbuseAction.ACTIVATION),
    ),
    "auth_recovery_request": ApiOperationSpec(
        "auth_recovery_request",
        mutation=True,
        abuse_action=str(AbuseAction.RECOVERY_REQUEST),
    ),
    "auth_recovery_reset": ApiOperationSpec(
        "auth_recovery_reset",
        mutation=True,
        abuse_action=str(AbuseAction.RECOVERY_VERIFY),
    ),
    "auth_login_otp_resend": ApiOperationSpec(
        "auth_login_otp_resend",
        mutation=True,
        abuse_action=str(AbuseAction.RECOVERY_RESEND),
    ),
    "auth_me": ApiOperationSpec("auth_me"),
    "protected_file_download": ApiOperationSpec(
        "protected_file_download",
        abuse_action=str(AbuseAction.API_PROTECTED_DOWNLOAD),
    ),
    "authority_grant_create": _admin("authority_grant_create"),
    "authority_grant_bulk_create": _admin("authority_grant_bulk_create"),
    "authority_grant_revoke": _admin("authority_grant_revoke"),
    "authority_capabilities": ApiOperationSpec("authority_capabilities"),
    "authority_scope_options": ApiOperationSpec("authority_scope_options"),
    "authority_grantees": ApiOperationSpec("authority_grantees"),
    "authority_account_grants": ApiOperationSpec("authority_account_grants"),
    "authority_account_effective": ApiOperationSpec("authority_account_effective"),
    "authority_me": ApiOperationSpec("authority_me"),
    "policies_draft_create": _admin("policies_draft_create"),
    "policies_draft_update": _admin("policies_draft_update"),
    "policies_submit": _admin("policies_submit"),
    "policies_approve": _admin("policies_approve"),
    "policies_reject": _admin("policies_reject"),
    "policies_activate": _admin("policies_activate"),
    "policies_retire": _admin("policies_retire"),
    "policies_catalog": ApiOperationSpec("policies_catalog"),
    "policies_effective": ApiOperationSpec("policies_effective"),
    "policies_view": ApiOperationSpec("policies_view"),
    "staff_accounts_create": _admin("staff_accounts_create"),
    "staff_accounts_reinvite": _admin("staff_accounts_reinvite"),
    "staff_accounts_deactivate": _admin("staff_accounts_deactivate"),
    "staff_accounts_head_guidance_assign": _admin("staff_accounts_head_guidance_assign"),
    "staff_accounts_head_guidance_revoke": _admin("staff_accounts_head_guidance_revoke"),
    "staff_accounts_list": ApiOperationSpec("staff_accounts_list"),
    "staff_accounts_view": ApiOperationSpec("staff_accounts_view"),

    # Content reads are intentionally unthrottled unless a domain-specific
    # abuse policy applies. Content mutations use the same API admin write
    # boundary as the other governed management surfaces.
    "content_public_announcements": ApiOperationSpec("content_public_announcements"),
    "content_public_announcement": ApiOperationSpec("content_public_announcement"),
    "content_public_resources": ApiOperationSpec("content_public_resources"),
    "content_public_resource": ApiOperationSpec("content_public_resource"),
    "content_public_page": ApiOperationSpec("content_public_page"),
    "content_public_service_guide": ApiOperationSpec("content_public_service_guide"),
    "content_visible_announcements": ApiOperationSpec("content_visible_announcements"),
    "content_visible_resources": ApiOperationSpec("content_visible_resources"),
    "content_workspace": ApiOperationSpec("content_workspace"),
    "content_workspace_detail": ApiOperationSpec("content_workspace_detail"),
    "content_contact_create": ApiOperationSpec(
        "content_contact_create", mutation=True, abuse_action=str(AbuseAction.CONTACT),
    ),
    "content_contact_queue": ApiOperationSpec("content_contact_queue"),
    "content_contact_detail": ApiOperationSpec("content_contact_detail"),
    "content_contact_reference_detail": ApiOperationSpec("content_contact_reference_detail"),
    "content_contact_replies": ApiOperationSpec("content_contact_replies"),
    "content_contact_delivery_metadata": ApiOperationSpec("content_contact_delivery_metadata"),
    # Profiles is a read-only vertical: reads are neither idempotency-wrapped
    # nor rate limited, and the no-store cache policy is the default.
    "profiles_me": ApiOperationSpec("profiles_me"),
    "profiles_support_directory": ApiOperationSpec("profiles_support_directory"),
}


def _register_account_security_operations() -> None:
    for operation_id in (
        "me_activity_list",
        "me_sessions_list",
        "me_trusted_devices_list",
    ):
        API_OPERATION_SPECS[operation_id] = ApiOperationSpec(operation_id)
    for operation_id in (
        "me_session_revoke",
        "me_sessions_revoke_others",
        "me_trusted_device_revoke",
        "me_trusted_devices_revoke_all",
        "me_password_change",
        "auth_staff_recovery_request",
    ):
        API_OPERATION_SPECS[operation_id] = _admin(operation_id)


_register_account_security_operations()


def _register_imports_operations() -> None:
    for operation_id in (
        "imports_list",
        "imports_catalog",
        "imports_detail",
        "imports_preview",
        "imports_invitation_list",
        "imports_invitation_detail",
    ):
        API_OPERATION_SPECS[operation_id] = ApiOperationSpec(operation_id)
    for operation_id in (
        "imports_create",
        "imports_replace",
        "imports_validate",
        "imports_row_correct",
        "imports_row_reconcile",
        "imports_row_exclude",
        "imports_row_acknowledge_boundary",
        "imports_approve",
        "imports_execute",
        "imports_invitation_issue",
        "imports_invitation_reissue",
        "imports_invitation_revoke",
    ):
        API_OPERATION_SPECS[operation_id] = _admin(operation_id)


_register_imports_operations()


def _register_content_mutations():
    operation_ids = (
        "announcement_create", "announcement_update", "announcement_submit_review",
        "announcement_publish", "announcement_schedule", "announcement_archive",
        "resource_create", "resource_update", "resource_submit_review",
        "resource_publish", "resource_schedule", "resource_archive",
        "page_create", "page_update", "page_submit_review", "page_publish", "page_archive",
        "service_guide_create", "service_guide_update", "service_guide_submit_review",
        "service_guide_publish", "service_guide_schedule", "service_guide_archive",
        "contact_assign", "contact_status", "contact_no_response",
        "contact_reply_create", "contact_reply_update", "contact_reply_submit",
        "contact_reply_approve", "contact_reply_reject", "contact_reply_cancel",
        "contact_reply_retry",
    )
    for suffix in operation_ids:
        operation_id = f"content_{suffix}"
        API_OPERATION_SPECS[operation_id] = _admin(operation_id)


_register_content_mutations()


def _register_appointments_operations():
    read_operations = (
        "appointments_list",
        "appointments_detail",
        "appointments_available_slots",
        "appointments_office_closures",
    )
    mutation_operations = (
        "appointments_create",
        "appointments_submit",
        "appointments_review_decision",
        "appointments_schedule",
        "appointments_review_and_schedule",
        "appointments_assign_counselor",
        "appointments_reassign_counselor",
        "appointments_cancel",
        "appointments_late_cancellation_request",
        "appointments_late_cancellation_decision",
        "appointments_complete",
        "appointments_no_show",
        "appointments_schedule_change",
        "appointments_availability_create",
        "appointments_availability_update",
        "appointments_availability_deactivate",
        "appointments_office_closure_create",
        "appointments_office_closure_update",
        "appointments_office_closure_deactivate",
    )
    for operation_id in read_operations:
        API_OPERATION_SPECS[operation_id] = ApiOperationSpec(operation_id)
    for operation_id in mutation_operations:
        API_OPERATION_SPECS[operation_id] = _admin(operation_id)


def _register_counseling_operations():
    read_operations = (
        "counseling_sessions_list",
        "counseling_session_detail",
        "counseling_session_summary",
        "counseling_routine_interviews_list",
        "counseling_routine_interview_detail",
        "counseling_cases_list",
        "counseling_case_detail",
        "counseling_urgent_list",
        "counseling_urgent_detail",
        "counseling_ecounseling_detail",
        "counseling_ecounseling_recording_availability",
        "counseling_ecounseling_recording_status",
        "counseling_ecounseling_recording_run_status",
        "counseling_ecounseling_transcription_status",
        "counseling_ecounseling_transcript_metadata",
        "counseling_ecounseling_transcript_download",
        "counseling_ecounseling_recording_download",
        "counseling_ecounseling_provider_webhook",
    )
    mutation_operations = (
        "counseling_session_create",
        "counseling_session_start",
        "counseling_note_save",
        "counseling_session_complete",
        "counseling_session_finalize",
        "counseling_session_lock",
        "counseling_session_cancel",
        "counseling_session_no_show",
        "counseling_session_assign",
        "counseling_session_open_from_appointment",
        "counseling_routine_intake_save",
        "counseling_routine_intake_submit",
        "counseling_routine_evaluation_save",
        "counseling_routine_complete",
        "counseling_routine_finalize",
        "counseling_routine_lock",
        "counseling_routine_reopen",
        "counseling_case_create",
        "counseling_case_assign",
        "counseling_case_transition_monitoring",
        "counseling_case_transition_follow_up",
        "counseling_case_resolve",
        "counseling_case_hold",
        "counseling_case_resume",
        "counseling_case_close",
        "counseling_case_reopen",
        "counseling_case_collaborator_add",
        "counseling_case_collaborator_remove",
        "counseling_case_link_session",
        "counseling_urgent_create",
        "counseling_urgent_triage",
        "counseling_urgent_review",
        "counseling_urgent_close",
        "counseling_urgent_access_grant",
        "counseling_urgent_access_revoke",
        "counseling_ecounseling_consent_request",
        "counseling_ecounseling_consent_decision",
        "counseling_ecounseling_consent_withdraw",
        "counseling_ecounseling_participant_add",
        "counseling_ecounseling_participant_revoke",
        "counseling_ecounseling_end",
        "counseling_ecounseling_cancel",
        "counseling_ecounseling_recording_start",
        "counseling_ecounseling_recording_stop",
    )
    for operation_id in read_operations:
        API_OPERATION_SPECS[operation_id] = ApiOperationSpec(operation_id)
    for operation_id in (
        "counseling_ecounseling_transcript_download",
        "counseling_ecounseling_recording_download",
    ):
        API_OPERATION_SPECS[operation_id] = ApiOperationSpec(
            operation_id,
            abuse_action=str(AbuseAction.API_PROTECTED_DOWNLOAD),
        )
    for operation_id in mutation_operations:
        API_OPERATION_SPECS[operation_id] = _admin(operation_id)
    # The e-counseling join flow keeps its dedicated replay protection and is
    # rate limited only through the central abuse-control engine.
    API_OPERATION_SPECS["counseling_ecounseling_join"] = ApiOperationSpec(
        "counseling_ecounseling_join",
        mutation=True,
        abuse_action=str(AbuseAction.ECOCOUNSELING_JOIN),
    )


_register_appointments_operations()
_register_counseling_operations()


def _register_form_vertical_operations() -> None:
    for operation_id in (
        "form_collections_list",
        "form_collections_detail",
        "form_collection_batches_list",
        "form_collection_invitations_list",
        "form_collection_manual_matches_list",
        "form_collection_access_current",
        "exit_interviews_list",
        "exit_interviews_detail",
        "exit_interviews_sensitive_detail",
        "exit_interviews_status",
        "exit_interviews_assignments_list",
        "graduate_tracer_list",
        "graduate_tracer_detail",
        "graduate_tracer_sensitive_detail",
        "graduate_tracer_status",
    ):
        API_OPERATION_SPECS[operation_id] = ApiOperationSpec(operation_id)
    for operation_id in (
        "form_collections_create",
        "form_collections_configure",
        "form_collections_launch",
        "form_collections_pause",
        "form_collections_close",
        "form_collections_archive",
        "form_collection_batch_create",
        "form_collection_batch_issue",
        "form_collection_invitation_revoke",
        "form_collection_manual_match_link",
        "form_collection_manual_match_reject",
        "exit_interviews_acknowledge",
        "exit_interviews_assignment_create",
        "exit_interviews_assignment_reassign",
        "exit_interviews_reopen",
        "exit_interviews_void",
        "exit_interviews_archive",
        "graduate_tracer_reopen",
        "graduate_tracer_void",
        "graduate_tracer_archive",
    ):
        API_OPERATION_SPECS[operation_id] = _admin(operation_id)
    for operation_id in (
        "exit_interviews_start",
        "exit_interviews_draft_save",
        "exit_interviews_submit",
        "graduate_tracer_start",
        "graduate_tracer_draft_save",
        "graduate_tracer_submit",
    ):
        # Student-owned and verified-invitation response mutations use the
        # shared replay contract without the staff/admin write class.
        API_OPERATION_SPECS[operation_id] = ApiOperationSpec(
            operation_id,
            mutation=True,
            idempotency_required=True,
        )
    API_OPERATION_SPECS["form_collection_invitation_verify"] = ApiOperationSpec(
        "form_collection_invitation_verify",
        mutation=True,
        abuse_action=str(AbuseAction.TOKEN_VERIFY),
    )


_register_form_vertical_operations()


def _register_inventory_operations() -> None:
    # Ordinary owner reads are protected by authentication/session only.
    for operation_id in ("inventory_list", "inventory_detail", "inventory_history"):
        API_OPERATION_SPECS[operation_id] = ApiOperationSpec(operation_id)
    # Student-owned mutations stay idempotent without the staff write class.
    for operation_id in (
        "inventory_draft_create",
        "inventory_draft_save",
        "inventory_draft_save_patch",
        "inventory_submit",
    ):
        API_OPERATION_SPECS[operation_id] = ApiOperationSpec(
            operation_id, mutation=True, idempotency_required=True
        )
    # Counselor/Head reopen is a sensitive staff mutation.
    API_OPERATION_SPECS["inventory_reopen"] = _admin("inventory_reopen")


def _register_support_needs_operations() -> None:
    for operation_id in (
        "support_needs_types",
        "support_needs_list",
        "support_needs_detail",
        "support_needs_review_queue",
    ):
        API_OPERATION_SPECS[operation_id] = ApiOperationSpec(operation_id)
    for operation_id in (
        "support_needs_create",
        "support_needs_update",
        "support_needs_verify",
        "support_needs_mark_review",
        "support_needs_dispute",
        "support_needs_archive",
    ):
        API_OPERATION_SPECS[operation_id] = _admin(operation_id)


_register_inventory_operations()
_register_support_needs_operations()


def _register_referrals_call_slips_operations() -> None:
    """Register the combined referral/Call Slip vertical at the API edge."""
    for operation_id in (
        "referrals_list",
        "referrals_detail",
        "referrals_reassignment_detail",
        "call_slips_list",
        "call_slips_detail",
        "call_slips_student_detail",
        "call_slips_printable",
        "call_slips_reschedule_detail",
    ):
        API_OPERATION_SPECS[operation_id] = ApiOperationSpec(operation_id)

    for operation_id in (
        "referrals_create",
        "referrals_submit",
        "referrals_receive",
        "referrals_review",
        "referrals_action",
        "referrals_action_required",
        "referrals_reassignment_request",
        "referrals_assign",
        "referrals_reassign",
        "referrals_reassignment_decision",
        "referrals_escalate",
        "referrals_close",
        "referrals_cancel",
        "referrals_reopen",
        "call_slips_create",
        "call_slips_from_referral",
        "call_slips_update",
        "call_slips_assign",
        "call_slips_reassign",
        "call_slips_issue",
        "call_slips_reschedule_decision",
        "call_slips_attendance",
        "call_slips_no_show",
        "call_slips_expire",
        "call_slips_cancel",
    ):
        API_OPERATION_SPECS[operation_id] = _admin(operation_id)

    # Student-owned actions are still business mutations, but they do not use
    # the staff/admin abuse class. They use the shared replay engine only.
    for operation_id in (
        "call_slips_acknowledge",
        "call_slips_reschedule_request",
    ):
        API_OPERATION_SPECS[operation_id] = ApiOperationSpec(
            operation_id,
            mutation=True,
            idempotency_required=True,
        )


_register_referrals_call_slips_operations()


def _register_workflow_document_operations() -> None:
    """Register workflow-owned binary document boundaries."""
    read_operations = (
        "call_slips_document_preview", "call_slips_document_download",
        "referrals_document_preview", "referrals_document_download",
        "counseling_routine_interviews_document_preview",
        "counseling_routine_interviews_document_download",
        "inventory_document_preview", "inventory_document_download",
        "exit_interviews_document_preview", "exit_interviews_document_download",
        "graduate_tracer_document_preview", "graduate_tracer_document_download",
    )
    for operation_id in read_operations:
        API_OPERATION_SPECS[operation_id] = ApiOperationSpec(
            operation_id,
            abuse_action=(
                str(AbuseAction.API_PROTECTED_DOWNLOAD)
                if operation_id.endswith("_download")
                else None
            ),
        )
    for operation_id in (
        "call_slips_document_generate", "referrals_document_generate",
        "counseling_routine_interviews_document_generate", "inventory_document_generate",
        "exit_interviews_document_generate", "graduate_tracer_document_generate",
    ):
        API_OPERATION_SPECS[operation_id] = _admin(operation_id)


_register_workflow_document_operations()


def _register_good_moral_operations() -> None:
    for operation_id in (
        "good_moral_list",
        "good_moral_detail",
        "good_moral_document_detail",
    ):
        API_OPERATION_SPECS[operation_id] = ApiOperationSpec(operation_id)
    API_OPERATION_SPECS["good_moral_document_download"] = ApiOperationSpec(
        "good_moral_document_download",
        abuse_action=str(AbuseAction.API_PROTECTED_DOWNLOAD),
    )
    for operation_id in (
        "good_moral_create",
        "good_moral_draft_update",
        "good_moral_submit",
        "good_moral_cancel",
        "good_moral_receipt_encode",
        "good_moral_receipt_verify",
        "good_moral_review_start",
        "good_moral_reviewer_assign",
        "good_moral_ossd_verification",
        "good_moral_hold",
        "good_moral_approve",
        "good_moral_reject",
        "good_moral_generate",
        "good_moral_print",
        "good_moral_release",
        "good_moral_dry_seal_confirm",
        "good_moral_void",
        "good_moral_supersede",
        "good_moral_archive",
    ):
        API_OPERATION_SPECS[operation_id] = _admin(operation_id)


_register_good_moral_operations()


def _register_reports_operations() -> None:
    for operation_id in (
        "reports_definitions",
        "reports_definition_detail",
        "reports_runs",
        "reports_run_detail",
        "reports_exports",
        "reports_export_detail",
    ):
        API_OPERATION_SPECS[operation_id] = ApiOperationSpec(operation_id)
    for operation_id in (
        "reports_run",
        "reports_export_create",
        "reports_export_generate",
        "reports_export_cancel",
        "reports_export_archive",
        "reports_export_expire",
    ):
        API_OPERATION_SPECS[operation_id] = ApiOperationSpec(
            operation_id,
            mutation=True,
            idempotency_required=True,
            abuse_action=str(AbuseAction.API_EXPORT),
        )
    API_OPERATION_SPECS["reports_export_download"] = ApiOperationSpec(
        "reports_export_download",
        abuse_action=str(AbuseAction.API_PROTECTED_DOWNLOAD),
    )


_register_reports_operations()


def _register_governance_privacy_operations() -> None:
    for operation_id in (
        "policies_dpo_appointment_view",
        "privacy_reviewer_authorizations",
        "privacy_notice_revisions",
        "privacy_notice_bindings",
    ):
        API_OPERATION_SPECS[operation_id] = ApiOperationSpec(operation_id)
    for operation_id in (
        "policies_dpo_appointment_create",
        "policies_dpo_appointment_retire",
        "privacy_reviewer_authorization_create",
        "privacy_reviewer_authorization_revoke",
        "privacy_notice_revision_create",
        "privacy_notice_revision_approve",
        "privacy_notice_revision_retire",
        "privacy_notice_binding_set",
    ):
        API_OPERATION_SPECS[operation_id] = _admin(operation_id)


def _register_privacy_operations() -> None:
    for operation_id in (
        "privacy_notice_view",
        "privacy_acceptance_list",
        "privacy_requests_list",
        "privacy_request_detail",
        "privacy_request_sensitive_detail",
        "privacy_incidents_list",
        "privacy_incident_detail",
        "privacy_retention_policies",
        "privacy_retention_evaluations",
        "privacy_legal_holds_list",
        "privacy_legal_hold_detail",
    ):
        API_OPERATION_SPECS[operation_id] = ApiOperationSpec(operation_id)
    # Notice acceptance retains the verified-access replay boundary rather than
    # requiring an Idempotency-Key. Authenticated request mutations and all
    # governance/incident/hold changes use the shared API replay engine.
    API_OPERATION_SPECS["privacy_notice_accept"] = ApiOperationSpec(
        "privacy_notice_accept",
        mutation=True,
        abuse_action=str(AbuseAction.TOKEN_VERIFY),
    )
    for operation_id in (
        "privacy_notice_withdraw",
        "privacy_request_create",
        "privacy_request_withdraw",
        "privacy_request_assign",
        "privacy_request_identity_verify",
        "privacy_request_review",
        "privacy_request_more_information",
        "privacy_request_approve",
        "privacy_request_partial_fulfill",
        "privacy_request_deny",
        "privacy_request_complete",
        "privacy_request_close",
        "privacy_request_fulfill",
        "privacy_retention_evaluate",
        "privacy_legal_hold_create",
        "privacy_legal_hold_release",
        "privacy_incident_create",
        "privacy_incident_investigate",
        "privacy_incident_contain",
        "privacy_incident_notification_assess",
        "privacy_incident_resolve",
        "privacy_incident_dismiss",
    ):
        API_OPERATION_SPECS[operation_id] = _admin(operation_id)


_register_governance_privacy_operations()
_register_privacy_operations()


def _register_notification_operations() -> None:
    for operation_id in (
        "notifications_list",
        "notifications_unread_count",
        "notifications_detail",
        "notifications_preferences_catalog",
        "notifications_preferences_list",
        "notifications_delivery_list",
        "notifications_delivery_detail",
    ):
        API_OPERATION_SPECS[operation_id] = ApiOperationSpec(operation_id)

    for operation_id in (
        "notifications_read",
        "notifications_archive",
        "notifications_preference_update",
    ):
        API_OPERATION_SPECS[operation_id] = ApiOperationSpec(
            operation_id,
            mutation=True,
            idempotency_required=True,
        )

    # Delivery lifecycle operations are sensitive technical actions. They use
    # the existing central abuse decision and API replay boundary; authority
    # remains the fixed IT capability in the notifications domain policy.
    for operation_id in (
        "notifications_delivery_retry",
        "notifications_delivery_dead_letter",
    ):
        API_OPERATION_SPECS[operation_id] = ApiOperationSpec(
            operation_id,
            mutation=True,
            idempotency_required=True,
            abuse_action=str(AbuseAction.API_ADMIN_WRITE),
        )


_register_notification_operations()


def _register_it_operations() -> None:
    """Register the restricted backup and system-console contracts."""
    for operation_id in (
        "backups_dashboard",
        "backups_jobs_list",
        "backups_job_detail",
        "backups_artifacts_list",
        "backups_restores_list",
        "backups_restore_detail",
        "system_health",
        "system_errors_list",
        "system_error_detail",
        "system_maintenance_list",
        "system_maintenance_detail",
        "system_release_metadata",
        "system_environment_summary",
        "system_operations_catalog",
        "system_operations_runs",
    ):
        API_OPERATION_SPECS[operation_id] = ApiOperationSpec(operation_id)

    # Health rerun is a bounded diagnostic probe rather than a business-state
    # mutation.  It is still rate-limited through the central sensitive-action
    # registry and never accepts arbitrary commands.
    API_OPERATION_SPECS["system_health_check"] = ApiOperationSpec(
        "system_health_check",
        abuse_action=str(AbuseAction.API_ADMIN_WRITE),
    )

    for operation_id in (
        "backups_job_request",
        "backups_job_queue",
        "backups_job_verify",
        "backups_job_cancel",
        "backups_restore_request",
        "backups_restore_authorize",
        "backups_restore_dry_run",
        "backups_restore_cancel",
        "system_error_resolve",
        "system_error_reopen",
        "system_maintenance_schedule",
        "system_maintenance_activate",
        "system_maintenance_extend",
        "system_maintenance_complete",
        "system_maintenance_cancel",
    ):
        API_OPERATION_SPECS[operation_id] = _admin(operation_id)


_register_it_operations()


def _register_organizations_operations() -> None:
    for operation_id in (
        "organizations_public_identity",
        "organizations_public_branding",
        "organizations_public_links",
        "organizations_public_academic_term",
        "organizations_public_form_revision",
        "organizations_public_document_templates",
        "organizations_institution_profiles_list",
        "organizations_institution_profile_detail",
        "organizations_offices_list",
        "organizations_office_detail",
        "organizations_brand_assets_list",
        "organizations_brand_asset_detail",
        "organizations_public_links_list",
        "organizations_public_link_detail",
        "organizations_academic_terms_list",
        "organizations_academic_term_detail",
        "organizations_form_families_list",
        "organizations_form_family_detail",
        "organizations_form_revisions_list",
        "organizations_form_revision_detail",
        "organizations_document_templates_list",
        "organizations_document_template_detail",
        "organizations_academic_term_rollover_preview",
        "organizations_form_revision_activation_preflight",
    ):
        API_OPERATION_SPECS[operation_id] = ApiOperationSpec(operation_id)
    for operation_id in (
        "organizations_public_branding_asset",
        "organizations_public_branding_asset_content",
    ):
        API_OPERATION_SPECS[operation_id] = ApiOperationSpec(
            operation_id,
            abuse_action=str(AbuseAction.API_PROTECTED_DOWNLOAD),
        )

    mutation_operations = (
        "organizations_institution_profile_create",
        "organizations_institution_profile_update",
        "organizations_institution_profile_activate",
        "organizations_institution_profile_retire",
        "organizations_institution_profile_archive",
        "organizations_office_create",
        "organizations_office_update",
        "organizations_office_activate",
        "organizations_office_retire",
        "organizations_office_archive",
        "organizations_brand_asset_create",
        "organizations_brand_asset_update",
        "organizations_brand_asset_activate",
        "organizations_brand_asset_retire",
        "organizations_brand_asset_archive",
        "organizations_public_link_create",
        "organizations_public_link_update",
        "organizations_public_link_activate",
        "organizations_public_link_retire",
        "organizations_public_link_archive",
        "organizations_academic_term_create",
        "organizations_academic_term_update",
        "organizations_academic_term_submit",
        "organizations_academic_term_approve",
        "organizations_academic_term_activate",
        "organizations_academic_term_close",
        "organizations_academic_term_archive",
        "organizations_academic_term_rollback",
        "organizations_form_family_create",
        "organizations_form_family_update",
        "organizations_form_family_activate",
        "organizations_form_family_retire",
        "organizations_form_family_archive",
        "organizations_form_revision_create",
        "organizations_form_revision_update",
        "organizations_form_revision_attach_source",
        "organizations_form_revision_submit",
        "organizations_form_revision_approve",
        "organizations_form_revision_activate",
        "organizations_form_revision_retire",
        "organizations_form_revision_archive",
        "organizations_form_revision_clone",
    )
    for operation_id in mutation_operations:
        API_OPERATION_SPECS[operation_id] = _admin(operation_id)


_register_organizations_operations()


def _register_assessments_operations() -> None:
    for operation_id in (
        "assessments_instruments",
        "assessments_list",
        "assessments_detail",
        "assessments_interpretation",
        "assessments_file_metadata",
        "assessments_student_summaries",
        "assessments_student_summary_detail",
    ):
        API_OPERATION_SPECS[operation_id] = ApiOperationSpec(operation_id)

    for operation_id in (
        "assessments_create",
        "assessments_update",
        "assessments_record",
        "assessments_submit_review",
        "assessments_review",
        "assessments_release",
        "assessments_void",
        "assessments_supersede",
        "assessments_archive",
        "assessments_file_attach",
    ):
        API_OPERATION_SPECS[operation_id] = _admin(operation_id)

    API_OPERATION_SPECS["assessments_file_download"] = ApiOperationSpec(
        "assessments_file_download",
        abuse_action=str(AbuseAction.API_PROTECTED_DOWNLOAD),
    )


_register_assessments_operations()


def _register_audit_operations() -> None:
    for operation_id in (
        "audit_entries_list",
        "audit_entry_detail",
    ):
        API_OPERATION_SPECS[operation_id] = ApiOperationSpec(operation_id)


_register_audit_operations()



def get_operation_spec(operation_id: str) -> ApiOperationSpec:
    try:
        return API_OPERATION_SPECS[str(operation_id)]
    except KeyError as exc:
        raise KeyError(f"API operation is not registered: {operation_id!r}") from exc


def _actor(request):
    auth = getattr(request, "auth", None)
    return getattr(auth, "user", None)


def prepare_api_operation(request, operation_id: str) -> PreparedApiOperation:
    """Apply the declared sensitive-action and idempotency boundary."""

    spec = get_operation_spec(operation_id)
    actor = _actor(request)
    ip_address = get_client_ip_from_headers(getattr(request, "META", {}) or {})
    session = getattr(request, "session", None)
    session_key = getattr(session, "session_key", None)
    retry_after = None
    if spec.abuse_action:
        subject = getattr(actor, "pk", None)
        decision = evaluate(
            spec.abuse_action,
            subject=subject,
            ip=ip_address,
            session=session_key,
        )
        if not decision.allowed:
            raise RateLimitError(retry_after=decision.retry_after or 60)
        counted = record_volume(
            spec.abuse_action,
            subject=subject,
            ip=ip_address,
            session=session_key,
            reason_code=f"API_{operation_id.upper()}_VOLUME",
        )
        if not counted.allowed:
            raise RateLimitError(retry_after=counted.retry_after or 60)
        retry_after = counted.retry_after
    idempotency_key = None
    if spec.idempotency_required:
        idempotency_key = require_idempotency_key(request)
    return PreparedApiOperation(
        operation_id=spec.operation_id,
        idempotency_key=idempotency_key,
        rate_limit_retry_after=retry_after,
    )


def validate_operation_registry() -> list[str]:
    errors = []
    for operation_id, spec in API_OPERATION_SPECS.items():
        if operation_id != spec.operation_id:
            errors.append(f"operation id mismatch: {operation_id}")
        if spec.idempotency_required and not spec.mutation:
            errors.append(f"read operation requires idempotency: {operation_id}")
        if spec.cache_control != "no-store":
            errors.append(f"unapproved cache policy: {operation_id}")
    return errors
