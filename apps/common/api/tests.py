"""Focused contract tests for the shared API boundary."""

import datetime
import json
from unittest import mock

from django.http import JsonResponse
from django.test import RequestFactory, SimpleTestCase

from apps.common.api.constants import (
    API_MAX_CAPTCHA_RESPONSE_LENGTH,
    API_MAX_IDEMPOTENCY_KEY_LENGTH,
    API_MAX_JSON_BODY_BYTES,
    IDEMPOTENCY_KEY_HEADER,
)
from apps.common.api.correlation import attach_request_correlation, trace_id
from apps.common.api.errors import render_error_response, status_for_code
from apps.common.api.idempotency import require_idempotency_key
from apps.common.api.middleware import ApiBoundaryMiddleware
from apps.common.api.operations import API_OPERATION_SPECS, validate_operation_registry
from apps.common.api.operations import prepare_api_operation
from apps.account_security.abuse_controls import AbuseDecision
from apps.common.api.pagination import page_request_from_query, page_request_from_values
from apps.common.contracts import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    ContractValidationError,
    PageRequest,
)
from apps.common.exceptions import (
    ConditionalChallengeError,
    DependencyFailureError,
    ErrorCode,
    RateLimitError,
    ValidationError,
)
from apps.common.rich_text import RichTextProfile, RichTextValidationError, render_rich_text
from apps.workflow.services import build_request_fingerprint


class ApiErrorContractTests(SimpleTestCase):
    def test_all_transport_codes_have_the_locked_status(self):
        expected = {
            "unauthenticated": 401,
            "permission": 403,
            "not_found": 404,
            "method_not_allowed": 405,
            "lifecycle_conflict": 409,
            "stale_state": 409,
            "validation": 422,
            "payload_too_large": 413,
            "rate_limited": 429,
            "dependency_failure": 503,
            "internal_error": 500,
        }
        for code, status in expected.items():
            self.assertEqual(status_for_code(code), status)

    def test_error_envelope_is_safe_and_has_correlation(self):
        request = RequestFactory().post("/api/v1/test/")
        attach_request_correlation(request)
        response = render_error_response(
            request,
            ValidationError("internal validation explanation", field_errors={"name": ["Invalid value."]}),
        )
        payload = json.loads(response.content)
        self.assertEqual(
            set(payload),
            {
                "detail",
                "code",
                "request_id",
                "error_id",
                "field_errors",
                "challenge_required",
                "challenge_action",
            },
        )
        self.assertEqual(payload["detail"], "The submitted data is invalid.")
        self.assertNotIn("internal validation explanation", response.content.decode())
        self.assertFalse(payload["challenge_required"])
        self.assertIsNone(payload["challenge_action"])
        self.assertTrue(response["X-Request-ID"].startswith("REQ-"))
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertEqual(response["X-Robots-Tag"], "noindex, nofollow, noarchive")

    def test_rate_limit_has_retry_after_and_no_store(self):
        request = RequestFactory().post("/api/v1/test/")
        response = render_error_response(request, RateLimitError(retry_after=17))
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response["Retry-After"], "17")
        self.assertEqual(response["Cache-Control"], "no-store")

    def test_conditional_challenge_has_only_safe_action_metadata(self):
        request = RequestFactory().post("/api/v1/test/")
        response = render_error_response(
            request,
            ConditionalChallengeError("contact", retry_after=31),
        )
        payload = json.loads(response.content)
        self.assertEqual(response.status_code, 429)
        self.assertTrue(payload["challenge_required"])
        self.assertEqual(payload["challenge_action"], "contact")
        self.assertNotIn("raw-turnstile-token", response.content.decode())

    def test_invalid_challenge_action_and_unexpected_metadata_fail_closed(self):
        with self.assertRaises(ValueError):
            ConditionalChallengeError("token_verify")

        request = RequestFactory().post("/api/v1/test/")
        error = RateLimitError(retry_after=10)
        error.challenge_required = True
        error.challenge_action = "token_verify"
        payload = json.loads(render_error_response(request, error).content)
        self.assertFalse(payload["challenge_required"])
        self.assertIsNone(payload["challenge_action"])


class RichTextBoundaryTests(SimpleTestCase):
    def test_public_content_and_privacy_profiles_share_bounded_safe_output(self):
        content = render_rich_text(
            "## Start here\n\nRead the [official notice](https://example.com/privacy).",
        )
        self.assertIn("<h2>Start here</h2>", content)
        self.assertIn('href="https://example.com/privacy"', content)

        privacy = render_rich_text(
            "## Privacy and care\n\nInformation is handled carefully.",
            profile=RichTextProfile.PRIVACY_NOTICE,
        )
        self.assertEqual(
            privacy,
            "<h2>Privacy and care</h2>\n<p>Information is handled carefully.</p>",
        )

    def test_public_rich_text_rejects_unsafe_or_unsupported_source(self):
        invalid_sources = (
            "<script>alert(1)</script>",
            "![badge](https://example.com/badge.png)",
            "[unsafe](http://example.com)",
            "[unsafe](javascript:alert(1))",
            "x" * 64_001,
        )
        for source in invalid_sources:
            with self.subTest(source=source[:32]):
                with self.assertRaises(RichTextValidationError):
                    render_rich_text(source)

    def test_privacy_profile_rejects_html_links_images_and_other_markup(self):
        invalid_sources = (
            "<p>not allowed</p>",
            "## [not a heading](https://example.com)",
            "### Unsupported heading\n\nText",
            "- list item",
            "![image](https://example.com/image.png)",
        )
        for source in invalid_sources:
            with self.subTest(source=source):
                with self.assertRaises(RichTextValidationError):
                    render_rich_text(source, profile=RichTextProfile.PRIVACY_NOTICE)


class ApiRequestContractTests(SimpleTestCase):
    def test_server_owns_request_id_but_valid_trace_is_preserved(self):
        request = RequestFactory().get(
            "/api/v1/test/",
            HTTP_X_REQUEST_ID="caller-chosen",
            HTTP_X_TRACE_ID="trace-abc-01",
        )
        attach_request_correlation(request)
        self.assertTrue(request._compass_request_id.startswith("REQ-"))
        self.assertNotEqual(request._compass_request_id, "caller-chosen")
        self.assertEqual(trace_id(request), "trace-abc-01")

    def test_invalid_trace_is_ignored(self):
        request = RequestFactory().get("/api/v1/test/", HTTP_X_TRACE_ID="x" * 101)
        attach_request_correlation(request)
        self.assertIsNone(trace_id(request))

    def test_json_body_limit_is_enforced_at_boundary(self):
        factory = RequestFactory()
        request = factory.post(
            "/api/v1/test/",
            data=b"{}",
            content_type="application/json",
        )
        request.META["CONTENT_LENGTH"] = str(API_MAX_JSON_BODY_BYTES + 1)
        response = ApiBoundaryMiddleware(lambda _request: JsonResponse({"ok": True}))(request)
        self.assertEqual(response.status_code, 413)
        self.assertEqual(json.loads(response.content)["code"], "payload_too_large")

    def test_workflow_api_responses_are_not_stored_or_shared(self):
        for path in (
            "/api/v1/appointments/",
            "/api/v1/counseling/",
            "/api/v1/referrals/",
            "/api/v1/call-slips/",
            "/api/v1/good-moral/",
            "/api/v1/form-collections/",
            "/api/v1/exit-interviews/",
            "/api/v1/graduate-tracer/",
            "/api/v1/notifications/",
            "/api/v1/backups/",
            "/api/v1/system/",
            "/api/v1/counseling/",
            "/api/v1/files/",
        ):
            with self.subTest(path=path):
                request = RequestFactory().get(path)
                response = ApiBoundaryMiddleware(lambda _request: JsonResponse({"ok": True}))(request)
                self.assertEqual(response["Cache-Control"], "no-store")
                self.assertEqual(response["X-Robots-Tag"], "noindex, nofollow, noarchive")

    def test_boundary_marks_non_api_responses_non_indexable(self):
        request = RequestFactory().get("/health/")
        response = ApiBoundaryMiddleware(lambda _request: JsonResponse({"ok": True}))(request)
        self.assertEqual(response["X-Robots-Tag"], "noindex, nofollow, noarchive")

    def test_signed_brand_asset_keeps_cdn_cache_exception_and_noindex(self):
        request = RequestFactory().get(
            "/api/v1/organizations/public/branding/assets/asset-1/content/?token=signed"
        )

        def response_for(_request):
            response = JsonResponse({"asset": "bytes"})
            response["Cache-Control"] = "public, max-age=60, s-maxage=60, must-revalidate"
            return response

        response = ApiBoundaryMiddleware(response_for)(request)
        self.assertTrue(response["Cache-Control"].startswith("public,"))
        self.assertEqual(response["X-Robots-Tag"], "noindex, nofollow, noarchive")

    def test_idempotency_key_is_required_and_bounded(self):
        request = RequestFactory().post("/api/v1/test/")
        with self.assertRaises(ValidationError):
            require_idempotency_key(request)
        request.META["HTTP_IDEMPOTENCY_KEY"] = "x" * 129
        with self.assertRaises(ValidationError):
            require_idempotency_key(request)

    def test_fingerprint_accepts_dates_without_storing_them_raw(self):
        fingerprint = build_request_fingerprint(
            "POST",
            "/api/v1/test/",
            {"effective_from": datetime.date(2026, 8, 23)},
        )
        self.assertEqual(len(fingerprint), 64)

    def test_pagination_rejects_values_above_global_maximum(self):
        request = RequestFactory().get("/api/v1/test/?page_size=101")
        with self.assertRaises(ContractValidationError):
            page_request_from_query(request)

    def test_typed_pagination_boundary_builds_the_immutable_request(self):
        request = page_request_from_values(2, 50)
        self.assertIsInstance(request, PageRequest)
        self.assertEqual((request.page, request.page_size), (2, 50))
        for page, page_size in ((0, DEFAULT_PAGE_SIZE), (1, 0), (1, MAX_PAGE_SIZE + 1)):
            with self.subTest(page=page, page_size=page_size):
                with self.assertRaises(ContractValidationError):
                    page_request_from_values(page, page_size)


class ApiOperationRegistryTests(SimpleTestCase):
    def test_mutation_preparation_parses_idempotency_once_into_immutable_context(self):
        request = RequestFactory().post("/api/v1/authority/grants/")
        with mock.patch(
            "apps.common.api.operations.evaluate",
            return_value=AbuseDecision(allowed=True),
        ), mock.patch(
            "apps.common.api.operations.record_volume",
            return_value=AbuseDecision(allowed=True),
        ), mock.patch(
            "apps.common.api.operations.require_idempotency_key",
            return_value="operation-key",
        ) as require_key:
            prepared = prepare_api_operation(request, "authority_grant_create")
        self.assertEqual(prepared.operation_id, "authority_grant_create")
        self.assertEqual(prepared.idempotency_key, "operation-key")
        require_key.assert_called_once_with(request)

    def test_inline_challenges_are_limited_to_selected_public_actions(self):
        request = RequestFactory().post("/api/v1/contact-submissions/")
        challenge_decision = AbuseDecision(allowed=True, challenge_required=True, retry_after=23)
        with mock.patch(
            "apps.common.api.operations.evaluate",
            return_value=challenge_decision,
        ), mock.patch(
            "apps.common.api.operations.record_volume",
            return_value=challenge_decision,
        ), mock.patch(
            "apps.common.api.operations.enforce_inline_challenge",
        ) as enforce:
            prepare_api_operation(
                request,
                "content_contact_create",
                captcha_response="transient-token",
            )
        enforce.assert_called_once_with(
            "contact",
            "transient-token",
            subject=None,
            ip="127.0.0.1",
            session=None,
            retry_after=23,
        )

        with mock.patch(
            "apps.common.api.operations.evaluate",
            return_value=challenge_decision,
        ), mock.patch(
            "apps.common.api.operations.record_volume",
            return_value=challenge_decision,
        ), mock.patch(
            "apps.common.api.operations.enforce_inline_challenge",
        ) as enforce:
            prepare_api_operation(
                request,
                "form_collection_invitation_verify",
                captcha_response="must-be-ignored",
            )
        enforce.assert_not_called()

    def test_every_current_route_operation_is_registered(self):
        expected = {
            "auth_login", "auth_login_verify", "auth_csrf", "auth_logout", "auth_me", "auth_staff_activation",
            "auth_token_refresh", "auth_student_activation", "authority_account_effective", "authority_account_grants",
            "authority_capabilities", "authority_grant_bulk_create", "authority_grant_create",
            "authority_grant_revoke", "authority_grantees", "authority_me", "authority_scope_options",
            "policies_activate", "policies_approve", "policies_catalog", "policies_draft_create",
            "policies_draft_update", "policies_effective", "policies_reject", "policies_retire",
            "policies_submit", "policies_view", "protected_file_download", "staff_accounts_create",
            "staff_accounts_deactivate", "staff_accounts_head_guidance_assign",
            "staff_accounts_head_guidance_revoke", "staff_accounts_list", "staff_accounts_reinvite",
            "staff_accounts_view",
            "content_announcement_archive", "content_announcement_create",
            "content_announcement_publish", "content_announcement_schedule",
            "content_announcement_submit_review", "content_announcement_update",
            "content_contact_assign", "content_contact_create", "content_contact_detail",
            "content_contact_delivery_metadata", "content_contact_no_response",
            "content_contact_queue", "content_contact_reference_detail",
            "content_contact_replies", "content_contact_reply_approve",
            "content_contact_reply_cancel", "content_contact_reply_create",
            "content_contact_reply_reject", "content_contact_reply_retry",
            "content_contact_reply_submit", "content_contact_reply_update",
            "content_contact_status", "content_page_archive", "content_page_create",
            "content_page_publish", "content_page_submit_review", "content_page_update",
            "content_public_announcement", "content_public_announcements",
            "content_public_page", "content_public_resource", "content_public_resources",
            "content_public_service_guide", "content_resource_archive",
            "content_resource_create", "content_resource_publish", "content_resource_schedule",
            "content_resource_submit_review", "content_resource_update", "content_service_guide_archive",
            "content_service_guide_create", "content_service_guide_publish",
            "content_service_guide_schedule", "content_service_guide_submit_review",
            "content_service_guide_update", "content_visible_announcements",
            "content_visible_resources", "content_workspace", "content_workspace_detail",
            "profiles_me", "profiles_support_directory", "profiles_staff_students",
            "inventory_list", "inventory_detail", "inventory_history",
            "inventory_queue_list", "inventory_queue_detail", "inventory_queue_sensitive_detail",
            "inventory_draft_create", "inventory_draft_save", "inventory_draft_save_patch",
            "inventory_submit",
            "inventory_reopen",
            "support_needs_types", "support_needs_list", "support_needs_detail",
            "support_needs_review_queue", "support_needs_create", "support_needs_update",
            "support_needs_verify", "support_needs_mark_review", "support_needs_dispute",
            "support_needs_archive",
            "appointments_list", "appointments_detail", "appointments_available_slots",
            "appointments_office_closures",
            "appointments_create", "appointments_submit", "appointments_review_decision",
            "appointments_schedule", "appointments_review_and_schedule",
            "appointments_assign_counselor", "appointments_reassign_counselor",
            "appointments_cancel", "appointments_late_cancellation_request",
            "appointments_late_cancellation_decision", "appointments_complete",
            "appointments_no_show", "appointments_schedule_change",
            "appointments_availability_create", "appointments_availability_update",
            "appointments_availability_deactivate", "appointments_office_closure_create",
            "appointments_office_closure_update", "appointments_office_closure_deactivate",
            "counseling_sessions_list", "counseling_session_detail", "counseling_session_workspace",
            "counseling_note_detail",
            "counseling_session_summary", "counseling_routine_interviews_list",
            "counseling_routine_interview_detail", "counseling_routine_interview_sensitive_detail",
            "counseling_cases_list",
            "counseling_case_detail", "counseling_urgent_list", "counseling_urgent_detail",
            "counseling_urgent_counselor_options",
            "counseling_ecounseling_detail",
            "counseling_session_create", "counseling_session_start", "counseling_note_save",
            "counseling_session_complete", "counseling_session_finalize",
            "counseling_session_lock", "counseling_session_cancel",
            "counseling_session_no_show", "counseling_session_assign",
            "counseling_session_open_from_appointment",
            "counseling_routine_intake_save", "counseling_routine_intake_submit",
            "counseling_routine_evaluation_save", "counseling_routine_complete",
            "counseling_routine_finalize", "counseling_routine_lock",
            "counseling_routine_reopen",
            "counseling_case_create", "counseling_case_assign",
            "counseling_case_transition_monitoring", "counseling_case_transition_follow_up",
            "counseling_case_resolve", "counseling_case_hold", "counseling_case_resume",
            "counseling_case_close", "counseling_case_reopen",
            "counseling_case_collaborator_add", "counseling_case_collaborator_remove",
            "counseling_case_link_session",
            "counseling_urgent_create", "counseling_urgent_triage",
            "counseling_urgent_review", "counseling_urgent_close",
            "counseling_urgent_access_grant", "counseling_urgent_access_revoke",
            "counseling_ecounseling_consent_request", "counseling_ecounseling_consent_decision",
            "counseling_ecounseling_consent_withdraw", "counseling_ecounseling_participant_add",
            "counseling_ecounseling_participant_revoke", "counseling_ecounseling_join",
            "counseling_ecounseling_end", "counseling_ecounseling_cancel",
            "counseling_ecounseling_recording_availability", "counseling_ecounseling_recording_status",
            "counseling_ecounseling_recording_start", "counseling_ecounseling_recording_stop",
            "counseling_ecounseling_recording_run_status", "counseling_ecounseling_transcription_status",
            "counseling_ecounseling_transcript_metadata", "counseling_ecounseling_transcript_download",
            "counseling_ecounseling_recording_download",
            "counseling_ecounseling_provider_webhook",
            "referrals_list", "referrals_detail", "referrals_reassignment_detail",
            "referrals_queue_list", "referrals_counselor_options",
            "referrals_create", "referrals_submit", "referrals_receive", "referrals_review",
            "referrals_action", "referrals_action_required", "referrals_reassignment_request",
            "referrals_assign", "referrals_reassign", "referrals_reassignment_decision",
            "referrals_escalate", "referrals_close", "referrals_cancel", "referrals_reopen",
            "call_slips_list", "call_slips_detail", "call_slips_student_detail",
            "call_slips_printable", "call_slips_reschedule_detail", "call_slips_create",
            "call_slips_from_referral", "call_slips_update", "call_slips_assign",
            "call_slips_reassign", "call_slips_issue", "call_slips_acknowledge",
            "call_slips_reschedule_request", "call_slips_reschedule_decision",
            "call_slips_attendance", "call_slips_no_show", "call_slips_expire",
            "call_slips_cancel",
            "call_slips_queue_list", "call_slips_counselor_options",
            "good_moral_list", "good_moral_detail", "good_moral_document_detail",
            "good_moral_document_download", "good_moral_create", "good_moral_draft_update",
            "good_moral_submit", "good_moral_cancel", "good_moral_receipt_encode",
            "good_moral_receipt_verify", "good_moral_review_start", "good_moral_reviewer_assign",
            "good_moral_ossd_verification", "good_moral_hold", "good_moral_approve",
            "good_moral_reject", "good_moral_generate", "good_moral_print",
            "good_moral_release", "good_moral_dry_seal_confirm", "good_moral_void",
            "good_moral_supersede", "good_moral_archive",
            "form_collections_list", "form_collections_detail", "form_collection_batches_list",
            "form_collection_invitations_list", "form_collection_manual_matches_list",
            "form_collection_access_current", "form_collections_create", "form_collections_configure",
            "form_collections_launch", "form_collections_pause", "form_collections_close",
            "form_collections_archive", "form_collection_batch_create", "form_collection_batch_issue",
            "form_collection_invitation_revoke", "form_collection_manual_match_link",
            "form_collection_manual_match_reject", "form_collection_invitation_verify",
            "exit_interviews_list", "exit_interviews_detail", "exit_interviews_sensitive_detail",
            "exit_interviews_queue_list", "exit_interviews_queue_detail", "exit_interviews_queue_sensitive_detail",
            "exit_interviews_status", "exit_interviews_assignments_list", "exit_interviews_start",
            "exit_interviews_draft_save", "exit_interviews_submit", "exit_interviews_acknowledge",
            "exit_interviews_assignment_create", "exit_interviews_reopen", "exit_interviews_void",
            "exit_interviews_assignment_reassign",
            "exit_interviews_archive", "graduate_tracer_list", "graduate_tracer_detail",
            "graduate_tracer_sensitive_detail", "graduate_tracer_status", "graduate_tracer_start",
            "graduate_tracer_draft_save", "graduate_tracer_submit", "graduate_tracer_reopen",
            "graduate_tracer_void", "graduate_tracer_archive",
            "reports_definitions", "reports_definition_detail", "reports_runs", "reports_run",
            "reports_run_detail", "reports_exports", "reports_export_create", "reports_export_detail",
            "reports_export_generate", "reports_export_download", "reports_export_cancel",
            "reports_export_archive", "reports_export_expire",
            "policies_dpo_appointment_view", "policies_dpo_appointment_create",
            "policies_dpo_appointment_retire", "privacy_reviewer_authorizations",
            "privacy_reviewer_authorization_create", "privacy_reviewer_authorization_revoke",
            "privacy_notice_revisions", "privacy_notice_bindings",
            "privacy_notice_revision_create", "privacy_notice_revision_approve",
            "privacy_notice_revision_retire", "privacy_notice_binding_set",
            "privacy_notice_view", "privacy_notice_accept", "privacy_notice_withdraw",
            "privacy_acceptance_list", "privacy_requests_list", "privacy_request_detail",
            "privacy_request_sensitive_detail", "privacy_request_create", "privacy_request_withdraw",
            "privacy_request_assign", "privacy_request_identity_verify", "privacy_request_review",
            "privacy_request_more_information", "privacy_request_approve", "privacy_request_partial_fulfill",
            "privacy_request_deny", "privacy_request_complete", "privacy_request_close",
            "privacy_request_fulfill", "privacy_retention_policies", "privacy_retention_evaluations",
            "privacy_retention_evaluate", "privacy_legal_holds_list", "privacy_legal_hold_detail",
            "privacy_legal_hold_create", "privacy_legal_hold_release", "privacy_incidents_list",
            "privacy_incident_detail", "privacy_incident_create", "privacy_incident_investigate",
            "privacy_incident_contain", "privacy_incident_notification_assess", "privacy_incident_resolve",
            "privacy_incident_dismiss",
            "notifications_list", "notifications_unread_count", "notifications_detail",
            "notifications_preferences_catalog", "notifications_preferences_list",
            "notifications_delivery_list", "notifications_delivery_detail",
            "notifications_read", "notifications_archive", "notifications_archive_bulk",
            "notifications_preference_update",
            "notifications_delivery_retry", "notifications_delivery_dead_letter",
            "imports_list", "imports_catalog", "imports_detail", "imports_preview",
            "imports_invitation_list", "imports_invitation_detail", "imports_create",
            "imports_replace", "imports_validate", "imports_row_correct", "imports_row_reconcile",
            "imports_row_exclude", "imports_row_acknowledge_boundary", "imports_approve",
            "imports_execute", "imports_invitation_issue", "imports_invitation_reissue",
            "imports_invitation_revoke",
            "call_slips_document_preview", "call_slips_document_generate", "call_slips_document_download",
            "referrals_document_preview", "referrals_document_generate", "referrals_document_download",
            "counseling_routine_interviews_document_preview",
            "counseling_routine_interviews_document_generate",
            "counseling_routine_interviews_document_download",
            "inventory_document_preview", "inventory_document_generate", "inventory_document_download",
            "exit_interviews_document_preview", "exit_interviews_document_generate", "exit_interviews_document_download",
            "graduate_tracer_document_preview", "graduate_tracer_document_generate", "graduate_tracer_document_download",
        }
        expected.update({
            "backups_dashboard", "backups_jobs_list", "backups_job_detail",
            "backups_artifacts_list", "backups_job_request", "backups_job_queue",
            "backups_job_verify", "backups_job_cancel", "backups_restores_list",
            "backups_restore_detail", "backups_restore_request", "backups_restore_authorize",
            "backups_restore_dry_run", "backups_restore_cancel",
            "system_health", "system_health_check",
            "system_errors_list", "system_error_detail", "system_error_resolve",
            "system_error_reopen", "system_maintenance_list", "system_maintenance_detail",
            "system_maintenance_schedule", "system_maintenance_activate",
            "system_maintenance_extend", "system_maintenance_complete",
            "system_maintenance_cancel", "system_release_metadata",
            "system_environment_summary", "system_operations_catalog", "system_operations_runs",
        })
        expected.update({
            "organizations_public_identity", "organizations_public_branding",
            "organizations_public_links", "organizations_public_academic_term",
            "organizations_public_form_revision", "organizations_public_document_templates",
            "organizations_institution_profiles_list", "organizations_institution_profile_detail",
            "organizations_offices_list", "organizations_office_detail",
            "organizations_brand_assets_list", "organizations_brand_asset_detail",
            "organizations_public_links_list", "organizations_public_link_detail",
            "organizations_academic_terms_list", "organizations_academic_term_detail",
            "organizations_form_families_list", "organizations_form_family_detail",
            "organizations_form_revisions_list", "organizations_form_revision_detail",
            "organizations_document_templates_list", "organizations_document_template_detail",
            "organizations_public_branding_asset", "organizations_public_branding_asset_content",
            "organizations_academic_term_rollover_preview",
            "organizations_form_revision_activation_preflight",
            "organizations_institution_profile_create", "organizations_institution_profile_update",
            "organizations_institution_profile_activate", "organizations_institution_profile_retire",
            "organizations_institution_profile_archive", "organizations_office_create",
            "organizations_office_update", "organizations_office_activate", "organizations_office_retire",
            "organizations_office_archive", "organizations_brand_asset_create",
            "organizations_brand_asset_update", "organizations_brand_asset_activate",
            "organizations_brand_asset_retire", "organizations_brand_asset_archive",
            "organizations_public_link_create", "organizations_public_link_update",
            "organizations_public_link_activate", "organizations_public_link_retire",
            "organizations_public_link_archive", "organizations_academic_term_create",
            "organizations_academic_term_update", "organizations_academic_term_submit",
            "organizations_academic_term_approve", "organizations_academic_term_activate",
            "organizations_academic_term_close", "organizations_academic_term_archive",
            "organizations_academic_term_rollback", "organizations_form_family_create",
            "organizations_form_family_update", "organizations_form_family_activate",
            "organizations_form_family_retire", "organizations_form_family_archive",
            "organizations_form_revision_create", "organizations_form_revision_update",
            "organizations_form_revision_attach_source", "organizations_form_revision_submit",
            "organizations_form_revision_approve", "organizations_form_revision_activate",
            "organizations_form_revision_retire", "organizations_form_revision_archive",
            "organizations_form_revision_clone",
        })
        expected.update({
            "assessments_instruments", "assessments_list", "assessments_detail",
            "assessments_interpretation", "assessments_file_metadata",
            "assessments_student_summaries", "assessments_student_summary_detail",
            "assessments_create", "assessments_update", "assessments_record",
            "assessments_submit_review", "assessments_review", "assessments_release",
            "assessments_void", "assessments_supersede", "assessments_archive",
            "assessments_file_attach", "assessments_file_download",
        })
        expected.update({
            "audit_entries_list", "audit_entry_detail",
            "me_activity_list", "me_sessions_list", "me_trusted_devices_list",
            "me_two_factor_status", "me_two_factor_change_request",
            "me_two_factor_change_verify", "me_two_factor_change_resend",
            "me_assurance_challenge", "me_assurance_verify", "me_assurance_resend",
            "me_session_revoke", "me_sessions_revoke_others",
            "me_trusted_device_revoke", "me_trusted_devices_revoke_all",
            "me_password_change", "auth_recovery_request", "auth_recovery_reset",
            "auth_login_otp_resend", "auth_staff_recovery_request",
        })
        self.assertEqual(set(API_OPERATION_SPECS), expected)
        self.assertEqual(validate_operation_registry(), [])
        for operation_id, spec in API_OPERATION_SPECS.items():
            if spec.mutation and spec.operation_id not in {
                "auth_login", "auth_login_verify", "auth_csrf", "auth_logout", "auth_staff_activation", "auth_student_activation", "auth_token_refresh",
                # Public recovery and OTP boundaries retain dedicated abuse and replay controls.
                "auth_recovery_request", "auth_recovery_reset", "auth_login_otp_resend",
                "content_contact_create",
                # Public token verification has its own abuse/replay boundary.
                "form_collection_invitation_verify",
                # Verified-token acceptance has its own replay boundary.
                "privacy_notice_accept",
                # The e-counseling join flow has dedicated replay protection.
                "counseling_ecounseling_join",
            }:
                self.assertTrue(spec.idempotency_required, operation_id)


class InlineChallengeTests(SimpleTestCase):
    def test_invalid_challenge_results_require_the_same_safe_retry_signal(self):
        from apps.account_security.abuse_controls import enforce_inline_challenge
        from apps.account_security.captcha import CaptchaVerificationResult

        for reason_code in (
            "CAPTCHA_RESPONSE_MISSING",
            "CAPTCHA_RESPONSE_INVALID",
            "CAPTCHA_ACTION_MISMATCH",
            "CAPTCHA_HOSTNAME_MISMATCH",
        ):
            with self.subTest(reason_code=reason_code), mock.patch(
                "apps.account_security.abuse_controls.verify_challenge",
                return_value=CaptchaVerificationResult("invalid", reason_code),
            ):
                with self.assertRaises(ConditionalChallengeError):
                    enforce_inline_challenge("contact", "raw-turnstile-token")

    def test_provider_failure_is_reduced_to_a_dependency_error(self):
        from apps.account_security.abuse_controls import enforce_inline_challenge
        from apps.account_security.captcha import CaptchaVerificationResult

        with mock.patch(
            "apps.account_security.abuse_controls.verify_challenge",
            return_value=CaptchaVerificationResult("unavailable", "CAPTCHA_PROVIDER_UNAVAILABLE"),
        ):
            with self.assertRaises(DependencyFailureError):
                enforce_inline_challenge("contact", "raw-turnstile-token")

    def test_valid_challenge_is_consumed_without_returning_the_grant(self):
        from apps.account_security.abuse_controls import enforce_inline_challenge
        from apps.account_security.captcha import CaptchaVerificationResult

        result = CaptchaVerificationResult("valid", "CAPTCHA_VERIFIED", grant="opaque-grant")
        with mock.patch(
            "apps.account_security.abuse_controls.verify_challenge",
            return_value=result,
        ), mock.patch(
            "apps.account_security.abuse_controls.consume_captcha_grant",
            return_value=True,
        ) as consume:
            verified = enforce_inline_challenge(
                "contact",
                "raw-turnstile-token",
                subject="subject",
                ip="ip",
                session="session",
            )

        self.assertIs(verified, result)
        consume.assert_called_once_with(
            "contact",
            "opaque-grant",
            subject="subject",
            ip="ip",
            session="session",
        )


class ApiResponseDocumentationTests(SimpleTestCase):
    @staticmethod
    def _operations(document):
        return {
            operation.get("operationId"): operation
            for path_item in document["paths"].values()
            for operation in path_item.values()
            if isinstance(operation, dict) and operation.get("operationId")
        }

    def test_every_operation_exposes_the_shared_error_contract(self):
        from apps.common.api.openapi import API_ERROR_SCHEMA_REF, COMMON_ERROR_STATUS_CODES
        from config.api.v1 import api_v1

        document = api_v1.get_openapi_schema()
        operations = self._operations(document)
        self.assertIn("ApiErrorSchema", document["components"]["schemas"])
        self.assertEqual(
            set(document["components"]["schemas"]["ApiErrorSchema"]["properties"]),
            {
                "detail",
                "code",
                "request_id",
                "error_id",
                "field_errors",
                "challenge_required",
                "challenge_action",
            },
        )
        logout_responses = operations["auth_logout"]["responses"]
        logout_204 = logout_responses.get(204) or logout_responses.get("204")
        self.assertEqual(logout_204, {"description": "No Content"})

        for operation_id, operation in operations.items():
            with self.subTest(operation_id=operation_id):
                responses = operation["responses"]
                for status_code in COMMON_ERROR_STATUS_CODES:
                    response = responses.get(status_code) or responses.get(str(status_code))
                    self.assertIsNotNone(response)
                    self.assertEqual(
                        response["content"]["application/json"]["schema"],
                        {"$ref": API_ERROR_SCHEMA_REF},
                    )

    def test_idempotency_header_matches_the_operation_registry(self):
        from config.api.v1 import api_v1

        document = api_v1.get_openapi_schema()
        operations = self._operations(document)
        parameter = document["components"]["parameters"]["IdempotencyKeyHeader"]
        self.assertEqual(parameter["name"], IDEMPOTENCY_KEY_HEADER)
        self.assertEqual(parameter["in"], "header")
        self.assertTrue(parameter["required"])
        self.assertEqual(
            parameter["schema"],
            {
                "type": "string",
                "maxLength": API_MAX_IDEMPOTENCY_KEY_LENGTH,
            },
        )

        required_operations = {
            operation_id
            for operation_id, spec in API_OPERATION_SPECS.items()
            if spec.idempotency_required
        }
        documented_required_operations = {
            operation_id
            for operation_id in required_operations
            if operation_id in operations
        }
        self.assertEqual(documented_required_operations, required_operations)

        for operation_id, operation in operations.items():
            with self.subTest(operation_id=operation_id):
                references = [
                    parameter
                    for parameter in operation.get("parameters", [])
                    if isinstance(parameter, dict)
                    and parameter.get("$ref") == "#/components/parameters/IdempotencyKeyHeader"
                ]
                if operation_id in required_operations:
                    self.assertEqual(len(references), 1)
                else:
                    self.assertEqual(references, [])

        for operation_id in (
            "auth_login",
            "auth_login_verify",
            "auth_logout",
            "content_contact_create",
        ):
            self.assertNotIn(
                {"$ref": "#/components/parameters/IdempotencyKeyHeader"},
                operations[operation_id].get("parameters", []),
            )

    def test_conditional_challenge_inputs_are_only_on_selected_operations(self):
        from config.api.v1 import api_v1

        document = api_v1.get_openapi_schema()
        operations = self._operations(document)

        def resolve(schema):
            while "$ref" in schema:
                schema = document["components"]["schemas"][schema["$ref"].rsplit("/", 1)[-1]]
            if "anyOf" in schema:
                for branch in schema["anyOf"]:
                    if "$ref" in branch or branch.get("type") == "object":
                        resolved = resolve(branch)
                        if resolved.get("properties") is not None:
                            return resolved
            return schema

        def request_schema(operation_id):
            request_body = operations[operation_id].get("requestBody", {})
            body = request_body.get("content", {}).get("application/json")
            if body is None:
                return {}
            return resolve(body["schema"])

        def property_schema(schema, property_name):
            property_definition = schema["properties"][property_name]
            if "anyOf" not in property_definition:
                return property_definition
            return next(
                branch
                for branch in property_definition["anyOf"]
                if branch.get("type") == "string"
            )

        selected = {
            "auth_login",
            "auth_staff_activation",
            "auth_student_activation",
            "auth_recovery_request",
            "auth_recovery_reset",
            "content_contact_create",
        }
        excluded = {
            "auth_login_verify",
            "auth_login_otp_resend",
            "auth_logout",
            "auth_token_refresh",
            "counseling_ecounseling_join",
            "form_collection_invitation_verify",
            "graduate_tracer_start",
            "graduate_tracer_draft_save",
            "graduate_tracer_submit",
            "exit_interviews_start",
            "exit_interviews_draft_save",
            "exit_interviews_submit",
        }
        for operation_id in selected:
            with self.subTest(operation_id=operation_id):
                schema = request_schema(operation_id)
                self.assertIn("captcha_response", schema.get("properties", {}))
                self.assertNotIn("captcha_response", schema.get("required", []))
                self.assertEqual(
                    property_schema(schema, "captcha_response").get("maxLength"),
                    API_MAX_CAPTCHA_RESPONSE_LENGTH,
                )

        for operation_id in excluded:
            with self.subTest(operation_id=operation_id):
                self.assertNotIn("captcha_response", request_schema(operation_id).get("properties", {}))

    def test_manually_read_query_filters_are_explicit_and_typed(self):
        from config.api.v1 import api_v1

        document = api_v1.get_openapi_schema()
        operations = self._operations(document)
        expected = {
            "assessments_list": {
                "status": ("string", ""),
                "category": ("string", ""),
            },
            "me_activity_list": {"category": ("string", "all")},
            "content_workspace": {"status": ("string", "all")},
            "notifications_list": {"status": ("string", None)},
            "notifications_delivery_list": {
                "status": ("string", None),
                "delivery_state": ("string", None),
                "template_key": ("string", None),
            },
            "system_errors_list": {
                "unresolved_only": ("boolean", False),
                "category": ("string", None),
            },
            "privacy_notice_view": {
                "purpose_workflow": ("string", ""),
                "locale": ("string", "en"),
            },
            "privacy_acceptance_list": {"purpose_workflow": ("string", "")},
            "organizations_academic_term_rollover_preview": {
                "prior_term_id": ("integer", None),
            },
            "imports_preview": {"editor": ("boolean", False)},
        }

        def schema_types(schema):
            if "type" in schema:
                return {schema["type"]}
            return {
                branch.get("type")
                for branch in schema.get("anyOf", [])
                if branch.get("type")
            }

        for operation_id, fields in expected.items():
            with self.subTest(operation_id=operation_id):
                parameters = {
                    parameter["name"]: parameter
                    for parameter in operations[operation_id]["parameters"]
                    if parameter.get("in") == "query"
                }
                for name, (expected_type, expected_default) in fields.items():
                    with self.subTest(parameter=name):
                        parameter = parameters[name]
                        self.assertFalse(parameter["required"])
                        self.assertIn(expected_type, schema_types(parameter["schema"]))
                        self.assertEqual(parameter["schema"].get("default"), expected_default)

    def test_file_upload_operations_are_explicit_multipart_contracts(self):
        from config.api.v1 import api_v1

        document = api_v1.get_openapi_schema()
        operations = self._operations(document)
        expected = {
            "imports_create": {"file", "source_name", "academic_year"},
            "imports_replace": {"file", "source_name", "academic_year"},
            "assessments_file_attach": {"file"},
            "organizations_brand_asset_create": {
                "file", "institution_id", "office_id", "asset_type", "semantic_role",
                "owner_type", "placement", "display_order", "alt_text", "usage_context",
                "background_variant", "version_label", "source_note", "effective_from",
                "effective_until", "expected_updated_at",
            },
            "organizations_brand_asset_update": {
                "file", "institution_id", "office_id", "asset_type", "semantic_role",
                "owner_type", "placement", "display_order", "alt_text", "usage_context",
                "background_variant", "version_label", "source_note", "effective_from",
                "effective_until", "expected_updated_at",
            },
        }

        def resolve(schema):
            while "$ref" in schema:
                schema = document["components"]["schemas"][schema["$ref"].rsplit("/", 1)[-1]]
            return schema

        def binary_schema(schema):
            schema = resolve(schema)
            if schema.get("format") == "binary":
                return schema
            for branch in schema.get("anyOf", []):
                if branch.get("format") == "binary":
                    return branch
            return {}

        for operation_id, expected_fields in expected.items():
            with self.subTest(operation_id=operation_id):
                request_body = operations[operation_id]["requestBody"]
                content = request_body["content"]
                self.assertEqual(set(content), {"multipart/form-data"})
                self.assertNotIn("application/json", content)
                schema = resolve(content["multipart/form-data"]["schema"])
                self.assertTrue(expected_fields.issubset(schema["properties"]))
                file_schema = binary_schema(schema["properties"]["file"])
                self.assertEqual(file_schema.get("type"), "string")
                self.assertEqual(file_schema.get("format"), "binary")
                required = set(schema.get("required", []))
                if operation_id == "organizations_brand_asset_update":
                    self.assertNotIn("file", required)
                else:
                    self.assertIn("file", required)
                if operation_id in {"imports_create", "imports_replace"}:
                    self.assertTrue({"source_name", "academic_year"}.issubset(required))

    def test_all_paginated_operations_expose_the_shared_contract(self):
        from config.api.v1 import api_v1

        expected_paths = {
            "authority_capabilities": ("/api/v1/authority/capabilities/", "get"),
            "authority_scope_options": ("/api/v1/authority/scope-options/", "get"),
            "authority_grantees": ("/api/v1/authority/grantees/", "get"),
            "authority_account_grants": ("/api/v1/authority/accounts/{user_id}/grants/", "get"),
            "authority_me_coverage": ("/api/v1/authority/me/coverage/", "get"),
            "staff_accounts_list": ("/api/v1/staff-accounts/", "get"),
            "appointments_list": ("/api/v1/appointments/", "get"),
            "appointments_available_slots": ("/api/v1/appointments/slots/", "get"),
            "appointments_office_closures": ("/api/v1/appointments/office-closures/", "get"),
            "assessments_instruments": ("/api/v1/assessments/instruments/", "get"),
            "assessments_student_summaries": ("/api/v1/assessments/student/summaries/", "get"),
            "assessments_list": ("/api/v1/assessments/", "get"),
            "audit_entries_list": ("/api/v1/audit/", "get"),
            "backups_jobs_list": ("/api/v1/backups/jobs/", "get"),
            "backups_artifacts_list": ("/api/v1/backups/jobs/{job_id}/artifacts/", "get"),
            "backups_restores_list": ("/api/v1/backups/restores/", "get"),
            "call_slips_list": ("/api/v1/call-slips/", "get"),
            "call_slips_queue_list": ("/api/v1/call-slips/queue/", "get"),
            "call_slips_counselor_options": (
                "/api/v1/call-slips/{reference_code}/counselor-options/",
                "get",
            ),
            "content_visible_announcements": ("/api/v1/content/feed/announcements/", "get"),
            "content_visible_resources": ("/api/v1/content/feed/resources/", "get"),
            "content_workspace": ("/api/v1/content/workspace/", "get"),
            "content_contact_queue": ("/api/v1/content/contact-submissions/", "get"),
            "content_contact_delivery_metadata": ("/api/v1/content/contact-delivery/metadata/", "get"),
            "content_contact_replies": ("/api/v1/content/contact-submissions/{submission_id}/replies/", "get"),
            "content_public_announcements": ("/api/v1/content/announcements/", "get"),
            "content_public_resources": ("/api/v1/content/resources/", "get"),
            "counseling_sessions_list": ("/api/v1/counseling/sessions/", "get"),
            "counseling_routine_interviews_list": ("/api/v1/counseling/routine-interviews/", "get"),
            "counseling_cases_list": ("/api/v1/counseling/cases/", "get"),
            "counseling_urgent_list": ("/api/v1/counseling/urgent-support/", "get"),
            "counseling_urgent_counselor_options": (
                "/api/v1/counseling/urgent-support/{reference_code}/counselor-options/",
                "get",
            ),
            "exit_interviews_list": ("/api/v1/exit-interviews/", "get"),
            "exit_interviews_queue_list": ("/api/v1/exit-interviews/queue/", "get"),
            "exit_interviews_assignments_list": ("/api/v1/exit-interviews/assignments/", "get"),
            "form_collections_list": ("/api/v1/form-collections/", "get"),
            "form_collection_batches_list": ("/api/v1/form-collections/{collection_id}/batches/", "get"),
            "form_collection_invitations_list": ("/api/v1/form-collections/{collection_id}/invitations/", "get"),
            "form_collection_manual_matches_list": ("/api/v1/form-collections/manual-matches/", "get"),
            "good_moral_list": ("/api/v1/good-moral/", "get"),
            "graduate_tracer_list": ("/api/v1/graduate-tracer/", "get"),
            "imports_list": ("/api/v1/imports/", "get"),
            "imports_catalog": ("/api/v1/imports/catalog/", "get"),
            "imports_preview": ("/api/v1/imports/{batch_id}/preview/", "get"),
            "imports_invitation_list": ("/api/v1/imports/{batch_id}/invitations/", "get"),
            "inventory_list": ("/api/v1/inventory/", "get"),
            "inventory_queue_list": ("/api/v1/inventory/queue/", "get"),
            "inventory_history": ("/api/v1/inventory/{snapshot_id}/history/", "get"),
            "me_activity_list": ("/api/v1/me/activity/", "get"),
            "me_sessions_list": ("/api/v1/me/sessions/", "get"),
            "me_trusted_devices_list": ("/api/v1/me/trusted-devices/", "get"),
            "notifications_list": ("/api/v1/notifications/", "get"),
            "notifications_preferences_catalog": ("/api/v1/notifications/preferences/catalog/", "get"),
            "notifications_preferences_list": ("/api/v1/notifications/preferences/", "get"),
            "notifications_delivery_list": ("/api/v1/notifications/delivery/", "get"),
            "organizations_institution_profiles_list": ("/api/v1/organizations/governance/institution-profiles/", "get"),
            "organizations_offices_list": ("/api/v1/organizations/governance/offices/", "get"),
            "organizations_brand_assets_list": ("/api/v1/organizations/governance/brand-assets/", "get"),
            "organizations_public_links_list": ("/api/v1/organizations/governance/public-links/", "get"),
            "organizations_academic_terms_list": ("/api/v1/organizations/governance/academic-terms/", "get"),
            "organizations_form_families_list": ("/api/v1/organizations/governance/form-families/", "get"),
            "organizations_form_revisions_list": ("/api/v1/organizations/governance/form-revisions/", "get"),
            "organizations_document_templates_list": ("/api/v1/organizations/governance/document-templates/", "get"),
            "privacy_acceptance_list": ("/api/v1/privacy/acceptances/", "get"),
            "privacy_requests_list": ("/api/v1/privacy/requests/", "get"),
            "privacy_retention_policies": ("/api/v1/privacy/retention/policies/", "get"),
            "privacy_retention_evaluations": ("/api/v1/privacy/retention/evaluations/", "get"),
            "privacy_legal_holds_list": ("/api/v1/privacy/legal-holds/", "get"),
            "privacy_incidents_list": ("/api/v1/privacy/incidents/", "get"),
            "profiles_support_directory": ("/api/v1/profiles/directory/", "get"),
            "profiles_staff_students": ("/api/v1/profiles/staff-students/", "get"),
            "referrals_list": ("/api/v1/referrals/", "get"),
            "referrals_queue_list": ("/api/v1/referrals/queue/", "get"),
            "referrals_counselor_options": (
                "/api/v1/referrals/{reference_code}/counselor-options/",
                "get",
            ),
            "reports_definitions": ("/api/v1/reports/definitions/", "get"),
            "reports_runs": ("/api/v1/reports/runs/", "get"),
            "reports_exports": ("/api/v1/reports/exports/", "get"),
            "support_needs_types": ("/api/v1/support-needs/types/", "get"),
            "support_needs_review_queue": ("/api/v1/support-needs/review-queue/", "get"),
            "support_needs_list": ("/api/v1/support-needs/", "get"),
            "system_errors_list": ("/api/v1/system/errors/", "get"),
            "system_maintenance_list": ("/api/v1/system/maintenance/", "get"),
            "system_operations_runs": ("/api/v1/system/operations/runs/", "get"),
            "privacy_reviewer_authorizations": (
                "/api/v1/privacy/reviewer-authorizations/", "get",
            ),
            "privacy_notice_revisions": (
                "/api/v1/privacy/notice-revisions/", "get",
            ),
            "privacy_notice_bindings": (
                "/api/v1/privacy/notice-bindings/", "get",
            ),
            "policies_catalog": ("/api/v1/policies/catalog/", "get"),
            "policies_effective": ("/api/v1/policies/effective/", "get"),
        }
        document = api_v1.get_openapi_schema()
        operations = self._operations(document)

        def has_pagination_contract(operation):
            responses = operation.get("responses", {})
            response = responses.get("200") or responses.get(200) or {}
            content = response.get("content", {})
            schema = content.get("application/json", {}).get("schema", {})
            while "$ref" in schema:
                schema = document["components"]["schemas"][schema["$ref"].rsplit("/", 1)[-1]]
            properties = schema.get("properties", {})
            return (
                {"items", "page", "page_size", "total"}.issubset(properties)
                and properties["items"].get("type") == "array"
                and {parameter.get("name") for parameter in operation.get("parameters", [])}
                >= {"page", "page_size"}
            )

        self.assertEqual(len(expected_paths), 88)
        self.assertEqual(
            {
                operation_id
                for operation_id, operation in operations.items()
                if has_pagination_contract(operation)
            },
            set(expected_paths),
        )

        for operation_id, (path, method) in expected_paths.items():
            with self.subTest(operation_id=operation_id):
                self.assertEqual(document["paths"][path][method]["operationId"], operation_id)
                operation = operations[operation_id]
                parameters = {
                    parameter["name"]: parameter["schema"]
                    for parameter in operation.get("parameters", [])
                    if parameter.get("name") in {"page", "page_size"}
                }
                self.assertEqual(set(parameters), {"page", "page_size"})
                self.assertEqual(parameters["page"]["type"], "integer")
                self.assertEqual(parameters["page"]["default"], 1)
                self.assertEqual(parameters["page"]["minimum"], 1)
                self.assertEqual(parameters["page_size"]["type"], "integer")
                self.assertEqual(parameters["page_size"]["default"], DEFAULT_PAGE_SIZE)
                self.assertEqual(parameters["page_size"]["minimum"], 1)
                self.assertEqual(parameters["page_size"]["maximum"], MAX_PAGE_SIZE)

                responses = operation["responses"]
                response = (responses.get("200") or responses.get(200))["content"]["application/json"]["schema"]
                while "$ref" in response:
                    response = document["components"]["schemas"][response["$ref"].rsplit("/", 1)[-1]]
                properties = response["properties"]
                self.assertEqual(properties["items"]["type"], "array")
                self.assertIn("items", properties["items"])
                self.assertNotEqual(properties["items"]["items"], {})
                for field_name in ("page", "page_size", "total"):
                    self.assertEqual(properties[field_name]["type"], "integer")

    def test_id_contract_matrix_preserves_wire_shapes_and_declares_real_types(self):
        """Keep route IDs deterministic at the API boundary.

        Response IDs are intentionally not inferred from database primary-key
        types here: several domain projections have stable string references
        by contract.  Only route parameters and request fields that are
        backed by integer FKs or UUID values are asserted as typed.
        """
        from config.api.v1 import api_v1

        document = api_v1.get_openapi_schema()
        operations = self._operations(document)

        route_matrix = {
            ("organizations_institution_profile_detail", "profile_id"): (
                "/api/v1/organizations/governance/institution-profiles/{profile_id}/",
                "get",
                "integer",
                None,
            ),
            ("organizations_public_branding_asset", "asset_id"): (
                "/api/v1/organizations/public/branding/assets/{asset_id}/",
                "get",
                "integer",
                None,
            ),
            ("imports_preview", "batch_id"): (
                "/api/v1/imports/{batch_id}/preview/",
                "get",
                "integer",
                None,
            ),
            ("inventory_history", "snapshot_id"): (
                "/api/v1/inventory/{snapshot_id}/history/",
                "get",
                "integer",
                None,
            ),
            ("support_needs_detail", "support_need_id"): (
                "/api/v1/support-needs/{support_need_id}/",
                "get",
                "integer",
                None,
            ),
            ("backups_job_detail", "job_id"): (
                "/api/v1/backups/jobs/{job_id}/",
                "get",
                "string",
                "uuid",
            ),
            ("form_collections_detail", "collection_id"): (
                "/api/v1/form-collections/{collection_id}/",
                "get",
                "string",
                "uuid",
            ),
            ("reports_run_detail", "run_id"): (
                "/api/v1/reports/runs/{run_id}/",
                "get",
                "string",
                "uuid",
            ),
            ("reports_export_detail", "export_id"): (
                "/api/v1/reports/exports/{export_id}/",
                "get",
                "string",
                "uuid",
            ),
            ("content_workspace_detail", "object_id"): (
                "/api/v1/content/workspace/{content_type}/{object_id}/",
                "get",
                "string",
                "uuid",
            ),
            ("privacy_legal_hold_detail", "hold_id"): (
                "/api/v1/privacy/legal-holds/{hold_id}/",
                "get",
                "string",
                "uuid",
            ),
        }
        for (operation_id, parameter_name), (path, method, expected_type, expected_format) in route_matrix.items():
            with self.subTest(operation_id=operation_id, parameter=parameter_name):
                operation = operations[operation_id]
                self.assertEqual(document["paths"][path][method]["operationId"], operation_id)
                parameter = next(
                    item for item in operation.get("parameters", [])
                    if item.get("name") == parameter_name and item.get("in") == "path"
                )
                self.assertEqual(parameter["schema"]["type"], expected_type)
                if expected_format is None:
                    self.assertNotIn("format", parameter["schema"])
                else:
                    self.assertEqual(parameter["schema"]["format"], expected_format)

        request_fields = {
            "DPOAppointmentCreateSchema": {"holder_id": ("integer", None)},
            "PrivacyReviewerAuthorizationCreateSchema": {"authorized_user_id": ("integer", None)},
            "RequestAssignmentSchema": {"reviewer_id": ("integer", None)},
            "RequestFulfillmentSchema": {"protected_file_id": ("string", "uuid")},
            "RestoreRequestSchema": {"backup_job_id": ("string", "uuid")},
            "StartSchema": {
                "student_profile_id": ("integer", None),
                "form_revision_id": ("integer", None),
                "form_collection_id": ("string", "uuid"),
                "form_invitation_id": ("string", "uuid"),
            },
        }
        components = document["components"]["schemas"]

        def concrete_schema(value):
            if "$ref" in value:
                return components[value["$ref"].rsplit("/", 1)[-1]]
            branches = value.get("anyOf")
            if branches:
                return next(branch for branch in branches if branch.get("type") != "null")
            return value

        for schema_name, fields in request_fields.items():
            with self.subTest(schema=schema_name):
                properties = components[schema_name]["properties"]
                for field_name, (expected_type, expected_format) in fields.items():
                    schema = concrete_schema(properties[field_name])
                    self.assertEqual(schema["type"], expected_type)
                    if expected_format is None:
                        self.assertNotIn("format", schema)
                    else:
                        self.assertEqual(schema["format"], expected_format)

        # These are stable public/domain wire identifiers and remain strings
        # even when their backing model uses an integer or UUID primary key.
        for schema_name in (
            "PublicContentSchema",
            "FormCollectionSchema",
            "BackupJobProjectionSchema",
            "ExitInterviewResponseSchema",
        ):
            with self.subTest(response_schema=schema_name):
                self.assertEqual(components[schema_name]["properties"]["id"]["type"], "string")

    def test_binary_routes_describe_their_actual_success_content(self):
        from config.api.v1 import api_v1

        document = api_v1.get_openapi_schema()
        operations = self._operations(document)
        protected_types = {
            "application/pdf",
            "image/jpeg",
            "image/png",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/msword",
            "text/csv",
            "text/plain",
            "text/html",
        }
        expected = {
            **{
                operation_id: {"application/pdf", "text/html"}
                for operation_id in (
                    "call_slips_document_preview",
                    "referrals_document_preview",
                    "inventory_document_preview",
                    "exit_interviews_document_preview",
                    "graduate_tracer_document_preview",
                    "counseling_routine_interviews_document_preview",
                )
            },
            **{
                operation_id: protected_types
                for operation_id in (
                    "call_slips_document_download",
                    "referrals_document_download",
                    "inventory_document_download",
                    "exit_interviews_document_download",
                    "graduate_tracer_document_download",
                    "counseling_routine_interviews_document_download",
                    "protected_file_download",
                    "assessments_file_download",
                    "good_moral_document_download",
                    "counseling_ecounseling_transcript_download",
                )
            },
            "counseling_ecounseling_recording_download": {"video/mp4"},
            "reports_export_download": {"application/pdf", "text/csv"},
            "organizations_public_branding_asset_content": {
                "image/png", "image/jpeg", "image/webp",
            },
        }

        self.assertEqual(len(expected), 19)
        for operation_id, media_types in expected.items():
            with self.subTest(operation_id=operation_id):
                responses = operations[operation_id]["responses"]
                response = responses.get("200") or responses.get(200)
                self.assertEqual(set(response["content"]), media_types)
                for media_type in media_types:
                    self.assertEqual(
                        response["content"][media_type]["schema"],
                        {"type": "string", "format": "binary"},
                    )

    def test_appointments_and_inventory_routes_use_explicit_output_schemas(self):
        from config.api.v1 import api_v1

        document = api_v1.get_openapi_schema()
        operations = self._operations(document)
        expected = {
            "appointments_list": "AppointmentPageResultSchema",
            "appointments_detail": "AppointmentProjectionSchema",
            "appointments_available_slots": "AvailableSlotPageResultSchema",
            "appointments_office_closures": "OfficeClosurePageResultSchema",
            **{
                operation_id: "AppointmentMutationResponseSchema"
                for operation_id in (
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
                )
            },
            **{
                operation_id: "ScheduleChangeResponseSchema"
                for operation_id in (
                    "appointments_schedule_change",
                    "appointments_availability_create",
                    "appointments_availability_update",
                    "appointments_availability_deactivate",
                    "appointments_office_closure_create",
                    "appointments_office_closure_update",
                    "appointments_office_closure_deactivate",
                )
            },
            "inventory_list": "InventoryPageResultSchema",
            "inventory_detail": "InventorySnapshotSchema",
            "inventory_history": "InventoryHistoryPageResultSchema",
            "inventory_document_generate": "GeneratedDocumentMetadataSchema",
            **{
                operation_id: "InventoryMutationResponseSchema"
                for operation_id in (
                    "inventory_draft_create",
                    "inventory_draft_save",
                    "inventory_draft_save_patch",
                    "inventory_submit",
                    "inventory_reopen",
                )
            },
        }

        self.assertEqual(len(expected), 32)
        for operation_id, schema_name in expected.items():
            with self.subTest(operation_id=operation_id):
                responses = operations[operation_id]["responses"]
                response = responses.get("200") or responses.get(200)
                schema = response["content"]["application/json"]["schema"]
                self.assertEqual(schema, {"$ref": f"#/components/schemas/{schema_name}"})

        components = document["components"]["schemas"]
        page_item_refs = {
            "AppointmentPageResultSchema": "AppointmentProjectionSchema",
            "AvailableSlotPageResultSchema": "AvailableSlotSchema",
            "OfficeClosurePageResultSchema": "OfficeClosureSchema",
            "InventoryPageResultSchema": "InventorySnapshotSchema",
            "InventoryHistoryPageResultSchema": "InventoryHistoryEventSchema",
        }
        for page_schema_name, item_schema_name in page_item_refs.items():
            with self.subTest(page_schema=page_schema_name):
                self.assertEqual(
                    components[page_schema_name]["properties"]["items"]["items"]["$ref"],
                    f"#/components/schemas/{item_schema_name}",
                )

        for schema_name in set(expected.values()) | set(page_item_refs.values()):
            with self.subTest(schema=schema_name):
                self.assertIsNot(components[schema_name].get("additionalProperties"), True)

        answers_schema = components["InventorySnapshotSchema"]["properties"]["answers"]
        self.assertIn(
            True,
            [
                branch.get("additionalProperties")
                for branch in answers_schema["anyOf"]
                if isinstance(branch, dict)
            ],
        )

    def test_selected_json_routes_and_nested_pages_use_explicit_schemas(self):
        from config.api.v1 import api_v1

        document = api_v1.get_openapi_schema()
        operations = self._operations(document)
        expected = {
            "content_public_service_guide": "PublicServiceGuideSchema",
            "organizations_public_identity": "PublicIdentitySchema",
            "organizations_public_branding": "PublicBrandingSchema",
            "organizations_public_branding_asset": "PublicBrandAssetDeliverySchema",
            "organizations_public_links": "PublicLinksSchema",
            "organizations_public_academic_term": "PublicAcademicTermSchema",
            "organizations_public_form_revision": "PublicFormRevisionSchema",
            "organizations_public_document_templates": "PublicDocumentTemplatesSchema",
            "profiles_me": "SelfProfileSchema",
        }
        for operation_id, schema_name in expected.items():
            with self.subTest(operation_id=operation_id):
                responses = operations[operation_id]["responses"]
                response = responses.get("200") or responses.get(200)
                schema = response["content"]["application/json"]["schema"]
                self.assertEqual(schema["$ref"], f"#/components/schemas/{schema_name}")

        page_schema = document["components"]["schemas"]["ContentPageResultSchema"]
        self.assertEqual(
            page_schema["properties"]["items"]["items"]["$ref"],
            "#/components/schemas/PublicContentSchema",
        )

        public_schema_names = {
            "PublicServiceGuideSchema",
            "ServiceGuideReadinessSchema",
            "ServiceGuideEntrySchema",
            "ServiceGuideFieldsSchema",
            "ServiceGuideConfirmationFieldSchema",
            "ServiceGuideStepSchema",
            "ServiceGuideMissingFieldSchema",
            "PublicIdentitySchema",
            "PublicBrandingSchema",
            "PublicBrandingAssetMetadataSchema",
            "PublicBrandAssetDeliverySchema",
            "PublicLinksSchema",
            "PublicLinkItemSchema",
            "PublicAcademicTermSchema",
            "PublicFormRevisionSchema",
            "PublicFormFieldSchema",
            "PublicFormOptionSchema",
            "PublicDocumentTemplatesSchema",
            "PublicDocumentTemplateSchema",
            "PublicDocumentTemplateVersionSchema",
            "SelfProfileSchema",
        }
        forbidden = {"expected_updated_at", "source_note", "schema_summary", "is_used"}
        for schema_name in public_schema_names:
            properties = document["components"]["schemas"][schema_name].get("properties", {})
            self.assertTrue(forbidden.isdisjoint(properties), schema_name)

    def test_organizations_use_resource_specific_output_schemas(self):
        from config.api.v1 import api_v1

        document = api_v1.get_openapi_schema()
        operations = self._operations(document)
        expected = {
            "organizations_institution_profiles_list": "InstitutionProfilePageSchema",
            "organizations_institution_profile_detail": "InstitutionProfileProjectionSchema",
            "organizations_offices_list": "OfficeProfilePageSchema",
            "organizations_office_detail": "OfficeProfileProjectionSchema",
            "organizations_brand_assets_list": "BrandAssetPageSchema",
            "organizations_brand_asset_detail": "BrandAssetProjectionSchema",
            "organizations_public_links_list": "PublicLinkPageSchema",
            "organizations_public_link_detail": "PublicLinkProjectionSchema",
            "organizations_academic_terms_list": "AcademicTermPageSchema",
            "organizations_academic_term_detail": "AcademicTermProjectionSchema",
            "organizations_form_families_list": "FormFamilyPageSchema",
            "organizations_form_family_detail": "FormFamilyProjectionSchema",
            "organizations_form_revisions_list": "FormRevisionPageSchema",
            "organizations_form_revision_detail": "FormRevisionProjectionSchema",
            "organizations_document_templates_list": "DocumentTemplatePageSchema",
            "organizations_document_template_detail": "DocumentTemplateProjectionSchema",
            "organizations_academic_term_rollover_preview": "AcademicTermRolloverPreviewSchema",
            "organizations_form_revision_activation_preflight": "FormRevisionActivationPreflightSchema",
            **{
                operation_id: "InstitutionProfileProjectionSchema"
                for operation_id in (
                    "organizations_institution_profile_create",
                    "organizations_institution_profile_update",
                    "organizations_institution_profile_activate",
                    "organizations_institution_profile_retire",
                    "organizations_institution_profile_archive",
                )
            },
            **{
                operation_id: "OfficeProfileProjectionSchema"
                for operation_id in (
                    "organizations_office_create",
                    "organizations_office_update",
                    "organizations_office_activate",
                    "organizations_office_retire",
                    "organizations_office_archive",
                )
            },
            **{
                operation_id: "BrandAssetProjectionSchema"
                for operation_id in (
                    "organizations_brand_asset_create",
                    "organizations_brand_asset_update",
                    "organizations_brand_asset_activate",
                    "organizations_brand_asset_retire",
                    "organizations_brand_asset_archive",
                )
            },
            **{
                operation_id: "PublicLinkProjectionSchema"
                for operation_id in (
                    "organizations_public_link_create",
                    "organizations_public_link_update",
                    "organizations_public_link_activate",
                    "organizations_public_link_retire",
                    "organizations_public_link_archive",
                )
            },
            **{
                operation_id: "AcademicTermProjectionSchema"
                for operation_id in (
                    "organizations_academic_term_create",
                    "organizations_academic_term_update",
                    "organizations_academic_term_submit",
                    "organizations_academic_term_approve",
                    "organizations_academic_term_activate",
                    "organizations_academic_term_close",
                    "organizations_academic_term_archive",
                    "organizations_academic_term_rollback",
                )
            },
            **{
                operation_id: "FormFamilyProjectionSchema"
                for operation_id in (
                    "organizations_form_family_create",
                    "organizations_form_family_update",
                    "organizations_form_family_activate",
                    "organizations_form_family_retire",
                    "organizations_form_family_archive",
                )
            },
            **{
                operation_id: "FormRevisionProjectionSchema"
                for operation_id in (
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
            },
        }
        self.assertEqual(len(expected), 60)

        expected_paths = {
            "organizations_institution_profiles_list": ("/api/v1/organizations/governance/institution-profiles/", "get"),
            "organizations_institution_profile_detail": ("/api/v1/organizations/governance/institution-profiles/{profile_id}/", "get"),
            "organizations_offices_list": ("/api/v1/organizations/governance/offices/", "get"),
            "organizations_office_detail": ("/api/v1/organizations/governance/offices/{office_id}/", "get"),
            "organizations_brand_assets_list": ("/api/v1/organizations/governance/brand-assets/", "get"),
            "organizations_brand_asset_detail": ("/api/v1/organizations/governance/brand-assets/{asset_id}/", "get"),
            "organizations_public_links_list": ("/api/v1/organizations/governance/public-links/", "get"),
            "organizations_public_link_detail": ("/api/v1/organizations/governance/public-links/{link_id}/", "get"),
            "organizations_academic_terms_list": ("/api/v1/organizations/governance/academic-terms/", "get"),
            "organizations_academic_term_detail": ("/api/v1/organizations/governance/academic-terms/{term_id}/", "get"),
            "organizations_form_families_list": ("/api/v1/organizations/governance/form-families/", "get"),
            "organizations_form_family_detail": ("/api/v1/organizations/governance/form-families/{family_id}/", "get"),
            "organizations_form_revisions_list": ("/api/v1/organizations/governance/form-revisions/", "get"),
            "organizations_form_revision_detail": ("/api/v1/organizations/governance/form-revisions/{revision_id}/", "get"),
            "organizations_document_templates_list": ("/api/v1/organizations/governance/document-templates/", "get"),
            "organizations_document_template_detail": ("/api/v1/organizations/governance/document-templates/{template_id}/", "get"),
            "organizations_academic_term_rollover_preview": ("/api/v1/organizations/governance/academic-terms/{term_id}/rollover-preview/", "get"),
            "organizations_form_revision_activation_preflight": ("/api/v1/organizations/governance/form-revisions/{revision_id}/activation-preflight/", "get"),
        }
        mutation_paths = {
            "organizations_institution_profile_create": ("/api/v1/organizations/governance/institution-profiles/", "post"),
            "organizations_institution_profile_update": ("/api/v1/organizations/governance/institution-profiles/{profile_id}/update/", "post"),
            "organizations_institution_profile_activate": ("/api/v1/organizations/governance/institution-profiles/{profile_id}/activate/", "post"),
            "organizations_institution_profile_retire": ("/api/v1/organizations/governance/institution-profiles/{profile_id}/retire/", "post"),
            "organizations_institution_profile_archive": ("/api/v1/organizations/governance/institution-profiles/{profile_id}/archive/", "post"),
            "organizations_office_create": ("/api/v1/organizations/governance/offices/", "post"),
            "organizations_office_update": ("/api/v1/organizations/governance/offices/{office_id}/update/", "post"),
            "organizations_office_activate": ("/api/v1/organizations/governance/offices/{office_id}/activate/", "post"),
            "organizations_office_retire": ("/api/v1/organizations/governance/offices/{office_id}/retire/", "post"),
            "organizations_office_archive": ("/api/v1/organizations/governance/offices/{office_id}/archive/", "post"),
            "organizations_brand_asset_create": ("/api/v1/organizations/governance/brand-assets/", "post"),
            "organizations_brand_asset_update": ("/api/v1/organizations/governance/brand-assets/{asset_id}/update/", "post"),
            "organizations_brand_asset_activate": ("/api/v1/organizations/governance/brand-assets/{asset_id}/activate/", "post"),
            "organizations_brand_asset_retire": ("/api/v1/organizations/governance/brand-assets/{asset_id}/retire/", "post"),
            "organizations_brand_asset_archive": ("/api/v1/organizations/governance/brand-assets/{asset_id}/archive/", "post"),
            "organizations_public_link_create": ("/api/v1/organizations/governance/public-links/", "post"),
            "organizations_public_link_update": ("/api/v1/organizations/governance/public-links/{link_id}/update/", "post"),
            "organizations_public_link_activate": ("/api/v1/organizations/governance/public-links/{link_id}/activate/", "post"),
            "organizations_public_link_retire": ("/api/v1/organizations/governance/public-links/{link_id}/retire/", "post"),
            "organizations_public_link_archive": ("/api/v1/organizations/governance/public-links/{link_id}/archive/", "post"),
            "organizations_academic_term_create": ("/api/v1/organizations/governance/academic-terms/", "post"),
            "organizations_academic_term_update": ("/api/v1/organizations/governance/academic-terms/{term_id}/update/", "post"),
            "organizations_academic_term_submit": ("/api/v1/organizations/governance/academic-terms/{term_id}/submit/", "post"),
            "organizations_academic_term_approve": ("/api/v1/organizations/governance/academic-terms/{term_id}/approve/", "post"),
            "organizations_academic_term_activate": ("/api/v1/organizations/governance/academic-terms/{term_id}/activate/", "post"),
            "organizations_academic_term_close": ("/api/v1/organizations/governance/academic-terms/{term_id}/close/", "post"),
            "organizations_academic_term_archive": ("/api/v1/organizations/governance/academic-terms/{term_id}/archive/", "post"),
            "organizations_academic_term_rollback": ("/api/v1/organizations/governance/academic-terms/{term_id}/rollback/", "post"),
            "organizations_form_family_create": ("/api/v1/organizations/governance/form-families/", "post"),
            "organizations_form_family_update": ("/api/v1/organizations/governance/form-families/{family_id}/update/", "post"),
            "organizations_form_family_activate": ("/api/v1/organizations/governance/form-families/{family_id}/activate/", "post"),
            "organizations_form_family_retire": ("/api/v1/organizations/governance/form-families/{family_id}/retire/", "post"),
            "organizations_form_family_archive": ("/api/v1/organizations/governance/form-families/{family_id}/archive/", "post"),
            "organizations_form_revision_create": ("/api/v1/organizations/governance/form-revisions/", "post"),
            "organizations_form_revision_update": ("/api/v1/organizations/governance/form-revisions/{revision_id}/update/", "post"),
            "organizations_form_revision_attach_source": ("/api/v1/organizations/governance/form-revisions/{revision_id}/attach-source/", "post"),
            "organizations_form_revision_submit": ("/api/v1/organizations/governance/form-revisions/{revision_id}/submit/", "post"),
            "organizations_form_revision_approve": ("/api/v1/organizations/governance/form-revisions/{revision_id}/approve/", "post"),
            "organizations_form_revision_activate": ("/api/v1/organizations/governance/form-revisions/{revision_id}/activate/", "post"),
            "organizations_form_revision_retire": ("/api/v1/organizations/governance/form-revisions/{revision_id}/retire/", "post"),
            "organizations_form_revision_archive": ("/api/v1/organizations/governance/form-revisions/{revision_id}/archive/", "post"),
            "organizations_form_revision_clone": ("/api/v1/organizations/governance/form-revisions/{revision_id}/clone/", "post"),
        }
        expected_paths.update(mutation_paths)

        for operation_id, schema_name in expected.items():
            with self.subTest(operation_id=operation_id):
                response = operations[operation_id]["responses"].get("200") or operations[operation_id]["responses"].get(200)
                self.assertEqual(
                    response["content"]["application/json"]["schema"],
                    {"$ref": f"#/components/schemas/{schema_name}"},
                )
                path, method = expected_paths[operation_id]
                self.assertEqual(document["paths"][path][method]["operationId"], operation_id)

        components = document["components"]["schemas"]
        page_item_refs = {
            "InstitutionProfilePageSchema": "InstitutionProfileProjectionSchema",
            "OfficeProfilePageSchema": "OfficeProfileProjectionSchema",
            "BrandAssetPageSchema": "BrandAssetProjectionSchema",
            "PublicLinkPageSchema": "PublicLinkProjectionSchema",
            "AcademicTermPageSchema": "AcademicTermProjectionSchema",
            "FormFamilyPageSchema": "FormFamilyProjectionSchema",
            "FormRevisionPageSchema": "FormRevisionProjectionSchema",
            "DocumentTemplatePageSchema": "DocumentTemplateProjectionSchema",
        }
        for page_schema_name, item_schema_name in page_item_refs.items():
            with self.subTest(page_schema=page_schema_name):
                self.assertEqual(
                    components[page_schema_name]["properties"]["items"]["items"]["$ref"],
                    f"#/components/schemas/{item_schema_name}",
                )

        self.assertEqual(
            components["AcademicTermRolloverPreviewSchema"]["properties"]["providers"]["items"]["$ref"],
            "#/components/schemas/AcademicTermRolloverProviderSchema",
        )
        self.assertEqual(
            components["AcademicTermRolloverPreviewSchema"]["properties"]["rollback"]["$ref"],
            "#/components/schemas/AcademicTermRolloverRollbackSchema",
        )
        activation_preflight = components["FormRevisionProjectionSchema"]["properties"]["activation_preflight"]
        self.assertIn(
            "#/components/schemas/FormRevisionActivationPreflightSchema",
            [activation_preflight.get("$ref"), *[branch.get("$ref") for branch in activation_preflight.get("anyOf", [])]],
        )

        response_schema_names = set(expected.values()) | set(page_item_refs.values()) | {
            "AcademicTermRolloverProviderSchema",
            "AcademicTermRolloverRollbackSchema",
            "FormRevisionActivationPreflightSchema",
        }
        self.assertNotIn("OrganizationPageSchema", components)
        for schema_name in response_schema_names:
            with self.subTest(schema=schema_name):
                self.assertIsNot(components[schema_name].get("additionalProperties"), True)

        forbidden = {
            "expected_updated_at",
            "reason_code",
            "source_document_reference",
            "source_notes",
            "printable_template_path",
            "source_checksum",
            "original_filename",
            "credential_reference",
            "file",
            "approved_by_id",
            "activated_by_id",
            "retired_by_id",
            "uploaded_by_id",
        }
        for schema_name in response_schema_names - {"AcademicTermRolloverProviderSchema"}:
            with self.subTest(forbidden=schema_name):
                self.assertTrue(
                    forbidden.isdisjoint(components[schema_name].get("properties", {})),
                    schema_name,
                )

    def test_call_slips_and_referrals_use_explicit_output_schemas(self):
        from config.api.v1 import api_v1

        document = api_v1.get_openapi_schema()
        operations = self._operations(document)
        expected = {
            "call_slips_list": "CallSlipPageResultSchema",
            "call_slips_detail": "CallSlipDetailSchema",
            "call_slips_student_detail": "StudentCallSlipDetailSchema",
            "call_slips_printable": "PrintableCallSlipSchema",
            "call_slips_reschedule_detail": "CallSlipRescheduleRequestDetailSchema",
            "call_slips_document_generate": "GeneratedDocumentMetadataSchema",
            **{
                operation_id: "CallSlipMutationResponseSchema"
                for operation_id in (
                    "call_slips_create",
                    "call_slips_from_referral",
                    "call_slips_assign",
                    "call_slips_reassign",
                    "call_slips_update",
                    "call_slips_issue",
                    "call_slips_acknowledge",
                    "call_slips_reschedule_request",
                    "call_slips_reschedule_decision",
                    "call_slips_attendance",
                    "call_slips_no_show",
                    "call_slips_expire",
                    "call_slips_cancel",
                )
            },
            "referrals_list": "ReferralPageResultSchema",
            "referrals_detail": "ReferralDetailSchema",
            "referrals_reassignment_detail": "ReferralReassignmentDetailSchema",
            "referrals_document_generate": "GeneratedDocumentMetadataSchema",
            **{
                operation_id: "ReferralMutationResponseSchema"
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
                )
            },
        }

        self.assertEqual(len(expected), 37)
        for operation_id, schema_name in expected.items():
            with self.subTest(operation_id=operation_id):
                response = operations[operation_id]["responses"].get("200") or operations[operation_id]["responses"].get(200)
                self.assertEqual(
                    response["content"]["application/json"]["schema"],
                    {"$ref": f"#/components/schemas/{schema_name}"},
                )

        components = document["components"]["schemas"]
        page_item_refs = {
            "CallSlipPageResultSchema": "CallSlipQueueItemSchema",
            "ReferralPageResultSchema": "ReferralQueueItemSchema",
        }
        for page_schema_name, item_schema_name in page_item_refs.items():
            with self.subTest(page_schema=page_schema_name):
                self.assertEqual(
                    components[page_schema_name]["properties"]["items"]["items"]["$ref"],
                    f"#/components/schemas/{item_schema_name}",
                )

        nested_refs = {
            ("ReferralDetailSchema", "actions", "items"): "#/components/schemas/ReferralActionOutputSchema",
            ("ReferralDetailSchema", "linked_call_slips", "items"): "#/components/schemas/ReferralLinkedCallSlipSchema",
            ("ReferralLinkedCallSlipSchema", "permissions"): "#/components/schemas/ReferralLinkedCallSlipPermissionSchema",
        }
        for (schema_name, property_name, *nested), expected_ref in nested_refs.items():
            with self.subTest(schema=schema_name, property=property_name):
                schema = components[schema_name]["properties"][property_name]
                for key in nested:
                    schema = schema[key]
                self.assertEqual(schema["$ref"], expected_ref)

        response_schema_names = set(expected.values()) | set(page_item_refs.values()) | {
            "CallSlipDetailSchema",
            "StudentCallSlipDetailSchema",
            "PrintableCallSlipSchema",
            "CallSlipRescheduleRequestDetailSchema",
            "ReferralActionOutputSchema",
            "ReferralLinkedCallSlipPermissionSchema",
            "ReferralLinkedCallSlipSchema",
            "ReferralDetailSchema",
            "ReferralReassignmentDetailSchema",
        }
        for schema_name in response_schema_names:
            with self.subTest(schema=schema_name):
                self.assertIsNot(components[schema_name].get("additionalProperties"), True)

    def test_reports_use_explicit_output_schemas(self):
        from config.api.v1 import api_v1

        document = api_v1.get_openapi_schema()
        operations = self._operations(document)
        expected = {
            "reports_definitions": "ReportDefinitionPageSchema",
            "reports_definition_detail": "ReportDefinitionSchema",
            "reports_runs": "ReportRunPageSchema",
            "reports_run": "ReportRunResponseSchema",
            "reports_run_detail": "ReportRunProjectionSchema",
            "reports_exports": "ReportExportPageSchema",
            "reports_export_create": "ReportExportProjectionSchema",
            "reports_export_detail": "ReportExportProjectionSchema",
            "reports_export_generate": "ReportExportProjectionSchema",
            "reports_export_cancel": "ReportExportProjectionSchema",
            "reports_export_archive": "ReportExportProjectionSchema",
            "reports_export_expire": "ReportExportProjectionSchema",
        }
        self.assertEqual(len(expected), 12)

        expected_paths = {
            "reports_definitions": ("/api/v1/reports/definitions/", "get"),
            "reports_definition_detail": ("/api/v1/reports/definitions/{key}/", "get"),
            "reports_runs": ("/api/v1/reports/runs/", "get"),
            "reports_run": ("/api/v1/reports/runs/", "post"),
            "reports_run_detail": ("/api/v1/reports/runs/{run_id}/", "get"),
            "reports_exports": ("/api/v1/reports/exports/", "get"),
            "reports_export_create": ("/api/v1/reports/exports/", "post"),
            "reports_export_detail": ("/api/v1/reports/exports/{export_id}/", "get"),
            "reports_export_generate": ("/api/v1/reports/exports/{export_id}/generate/", "post"),
            "reports_export_cancel": ("/api/v1/reports/exports/{export_id}/cancel/", "post"),
            "reports_export_archive": ("/api/v1/reports/exports/{export_id}/archive/", "post"),
            "reports_export_expire": ("/api/v1/reports/exports/{export_id}/expire/", "post"),
        }
        for operation_id, schema_name in expected.items():
            with self.subTest(operation_id=operation_id):
                response = operations[operation_id]["responses"].get("200") or operations[operation_id]["responses"].get(200)
                self.assertEqual(
                    response["content"]["application/json"]["schema"],
                    {"$ref": f"#/components/schemas/{schema_name}"},
                )
                path, method = expected_paths[operation_id]
                self.assertEqual(document["paths"][path][method]["operationId"], operation_id)

        components = document["components"]["schemas"]
        page_item_refs = {
            "ReportDefinitionPageSchema": "ReportDefinitionSchema",
            "ReportRunPageSchema": "ReportRunProjectionSchema",
            "ReportExportPageSchema": "ReportExportProjectionSchema",
        }
        for page_schema_name, item_schema_name in page_item_refs.items():
            with self.subTest(page_schema=page_schema_name):
                self.assertEqual(
                    components[page_schema_name]["properties"]["items"]["items"]["$ref"],
                    f"#/components/schemas/{item_schema_name}",
                )

        self.assertEqual(
            components["ReportRunProjectionSchema"]["properties"]["filter_summary"]["$ref"],
            "#/components/schemas/ReportFilterSummarySchema",
        )
        result_schema = components["ReportRunResponseSchema"]["properties"]["result"]
        self.assertIn(
            True,
            [
                branch.get("additionalProperties")
                for branch in result_schema["anyOf"]
                if isinstance(branch, dict)
            ],
        )

        response_schema_names = set(expected.values()) | set(page_item_refs.values()) | {
            "ReportFilterSummarySchema",
            "ReportRunResponseSchema",
            "ReportExportProjectionSchema",
        }
        for schema_name in response_schema_names:
            with self.subTest(schema=schema_name):
                self.assertIsNot(components[schema_name].get("additionalProperties"), True)

        forbidden = {
            "expected_definition_updated_at",
            "purpose",
            "expected_status",
            "reason",
            "allowed_scope_metadata_json",
            "metadata_json",
            "generation_metadata_json",
            "scope_summary_json",
        }
        for schema_name in response_schema_names:
            with self.subTest(forbidden=schema_name):
                self.assertTrue(
                    forbidden.isdisjoint(components[schema_name].get("properties", {})),
                    schema_name,
                )


class CounselingResponseDocumentationTests(SimpleTestCase):
    """Counseling responses stay explicit while preserving binary routes."""

    @staticmethod
    def _operations(document):
        return {
            operation.get("operationId"): operation
            for path_item in document["paths"].values()
            for operation in path_item.values()
            if isinstance(operation, dict) and operation.get("operationId")
        }

    def test_all_json_operations_reference_bounded_response_schemas(self):
        from config.api.v1 import api_v1

        document = api_v1.get_openapi_schema()
        operations = self._operations(document)
        binary_ids = {
            "counseling_routine_interviews_document_preview",
            "counseling_routine_interviews_document_download",
            "counseling_ecounseling_transcript_download",
            "counseling_ecounseling_recording_download",
        }
        counseling_ids = {
            operation_id
            for operation_id in operations
            if operation_id.startswith("counseling_")
        }
        json_ids = counseling_ids - binary_ids
        self.assertEqual(len(counseling_ids), 70)
        self.assertEqual(len(json_ids), 66)

        explicit = {
            "counseling_sessions_list": "CounselingSessionPageSchema",
            "counseling_session_detail": "CounselingSessionProjectionSchema",
            "counseling_session_workspace": "CounselingSessionWorkspaceContextSchema",
            "counseling_note_detail": "CounselingNoteProjectionSchema",
            "counseling_session_summary": "CounselingStudentSummarySchema",
            "counseling_routine_interviews_list": "RoutineInterviewPageSchema",
            "counseling_routine_interview_detail": "RoutineInterviewProjectionSchema",
            "counseling_routine_interview_sensitive_detail": "RoutineInterviewSensitiveDetailSchema",
            "counseling_routine_interviews_document_generate": "GeneratedDocumentMetadataSchema",
            "counseling_cases_list": "CounselingCaseQueuePageSchema",
            "counseling_case_detail": "CounselingCaseProjectionSchema",
            "counseling_urgent_list": "UrgentSupportPageSchema",
            "counseling_urgent_counselor_options": "UrgentSupportCounselorOptionPageSchema",
            "counseling_urgent_detail": "UrgentSupportProjectionSchema",
            "counseling_ecounseling_recording_availability": "RecordingAvailabilitySchema",
            "counseling_ecounseling_recording_status": "RecordingStatusSchema",
            "counseling_ecounseling_recording_start": "RecordingMutationResponseSchema",
            "counseling_ecounseling_recording_stop": "RecordingMutationResponseSchema",
            "counseling_ecounseling_recording_run_status": "RecordingRunProjectionSchema",
            "counseling_ecounseling_transcription_status": "TranscriptionStatusSchema",
            "counseling_ecounseling_transcript_metadata": "TranscriptMetadataSchema",
            "counseling_ecounseling_provider_webhook": "ProviderWebhookResponseSchema",
            "counseling_ecounseling_detail": "ECounselingJoinStateSchema",
            "counseling_ecounseling_join": "ECounselingJoinContextSchema",
        }
        mutation_ids = json_ids - set(explicit)
        self.assertEqual(len(mutation_ids), 42)
        expected = {
            **explicit,
            **{operation_id: "CounselingMutationResponseSchema" for operation_id in mutation_ids},
        }
        for operation_id, schema_name in expected.items():
            with self.subTest(operation_id=operation_id):
                responses = operations[operation_id]["responses"]
                response = responses.get("200") or responses.get(200)
                self.assertEqual(
                    response["content"]["application/json"]["schema"],
                    {"$ref": f"#/components/schemas/{schema_name}"},
                )

    def test_pages_nested_outputs_and_sensitive_fields_are_bounded(self):
        from config.api.v1 import api_v1

        document = api_v1.get_openapi_schema()
        components = document["components"]["schemas"]
        page_items = {
            "CounselingSessionPageSchema": "CounselingSessionProjectionSchema",
            "RoutineInterviewPageSchema": "RoutineInterviewQueueProjectionSchema",
            "CounselingCaseQueuePageSchema": "CounselingCaseQueueProjectionSchema",
            "UrgentSupportPageSchema": "UrgentSupportQueueProjectionSchema",
        }
        for page_schema, item_schema in page_items.items():
            with self.subTest(page_schema=page_schema):
                self.assertEqual(
                    components[page_schema]["properties"]["items"]["items"]["$ref"],
                    f"#/components/schemas/{item_schema}",
                )

        self.assertEqual(
            components["RecordingStatusSchema"]["properties"]["run"]["anyOf"][0]["$ref"],
            "#/components/schemas/RecordingRunProjectionSchema",
        )
        self.assertEqual(
            components["RecordingMutationResponseSchema"]["properties"]["run"]["anyOf"][0]["$ref"],
            "#/components/schemas/RecordingRunProjectionSchema",
        )

        response_schema_names = {
            *page_items,
            *page_items.values(),
            "CounselingStudentSummarySchema",
            "CounselingMutationResponseSchema",
            "RecordingAvailabilitySchema",
            "RecordingStatusSchema",
            "RecordingMutationResponseSchema",
            "RecordingRunProjectionSchema",
            "TranscriptionStatusSchema",
            "TranscriptMetadataSchema",
            "ProviderWebhookResponseSchema",
            "ECounselingJoinStateSchema",
            "ECounselingJoinContextSchema",
            "GeneratedDocumentMetadataSchema",
        }
        forbidden = {
            "expected_updated_at",
            "reason",
            "captcha_response",
            "provider_instance_id",
            "provider_recording_id",
            "provider_transcript_id",
            "provider_transcription_instance_id",
            "protected_file_id",
            "transcript_protected_file_id",
            "checksum_sha256",
            "ip_hash",
            "user_agent_hash",
            "raw_provider_payload",
        }
        for schema_name in response_schema_names:
            with self.subTest(schema=schema_name):
                schema = components[schema_name]
                self.assertIsNot(schema.get("additionalProperties"), True)
                self.assertTrue(
                    forbidden.isdisjoint(schema.get("properties", {})),
                    schema_name,
                )

        for schema_name in response_schema_names - {"ECounselingJoinContextSchema"}:
            self.assertNotIn("meeting_token", components[schema_name].get("properties", {}))

        binary_ids = {
            "counseling_routine_interviews_document_preview",
            "counseling_routine_interviews_document_download",
            "counseling_ecounseling_transcript_download",
            "counseling_ecounseling_recording_download",
        }
        operations = self._operations(document)
        for operation_id in binary_ids:
            with self.subTest(operation_id=operation_id):
                responses = operations[operation_id]["responses"]
                response = responses.get("200") or responses.get(200)
                for media_type, media in response["content"].items():
                    self.assertEqual(media["schema"], {"type": "string", "format": "binary"})

    def test_content_uses_explicit_output_schemas_and_typed_pages(self):
        from config.api.v1 import api_v1

        document = api_v1.get_openapi_schema()
        operations = self._operations(document)
        expected = {
            "content_public_announcements": "ContentPageResultSchema",
            "content_public_announcement": "PublicContentSchema",
            "content_public_resources": "ContentPageResultSchema",
            "content_public_resource": "PublicContentSchema",
            "content_public_page": "PublicPageSchema",
            "content_public_service_guide": "PublicServiceGuideSchema",
            "content_visible_announcements": "ContentPageResultSchema",
            "content_visible_resources": "ContentPageResultSchema",
            "content_workspace": "ContentWorkspacePageSchema",
            "content_workspace_detail": "ContentWorkspaceProjectionSchema",
            **{
                operation_id: "ContentWorkspaceReplaySchema"
                for operation_id in (
                    "content_announcement_create",
                    "content_announcement_update",
                    "content_announcement_submit_review",
                    "content_announcement_publish",
                    "content_announcement_schedule",
                    "content_announcement_archive",
                    "content_resource_create",
                    "content_resource_update",
                    "content_resource_submit_review",
                    "content_resource_publish",
                    "content_resource_schedule",
                    "content_resource_archive",
                    "content_page_create",
                    "content_page_update",
                    "content_page_submit_review",
                    "content_page_publish",
                    "content_page_archive",
                    "content_service_guide_create",
                    "content_service_guide_update",
                    "content_service_guide_submit_review",
                    "content_service_guide_publish",
                    "content_service_guide_schedule",
                    "content_service_guide_archive",
                )
            },
            "content_contact_create": "ContactSubmissionSchema",
            "content_contact_queue": "ContactMetadataPageSchema",
            "content_contact_reference_detail": "ContactDetailSchema",
            "content_contact_detail": "ContactDetailSchema",
            "content_contact_delivery_metadata": "ContactDeliveryMetadataResultSchema",
            "content_contact_assign": "ContactSubmissionSchema",
            "content_contact_status": "ContactSubmissionSchema",
            "content_contact_no_response": "ContactNoResponseProjectionSchema",
            "content_contact_replies": "ContactReplyPageSchema",
            "content_contact_reply_create": "ContactReplySchema",
            "content_contact_reply_update": "ContactReplySchema",
            "content_contact_reply_submit": "ContactReplySchema",
            "content_contact_reply_approve": "ContactReplySchema",
            "content_contact_reply_reject": "ContactReplySchema",
            "content_contact_reply_cancel": "ContactReplySchema",
            "content_contact_reply_retry": "ContactReplySchema",
        }
        self.assertEqual(len(expected), 49)

        for operation_id, schema_name in expected.items():
            with self.subTest(operation_id=operation_id):
                response = operations[operation_id]["responses"].get("200") or operations[operation_id]["responses"].get(200)
                self.assertEqual(
                    response["content"]["application/json"]["schema"],
                    {"$ref": f"#/components/schemas/{schema_name}"},
                )

        components = document["components"]["schemas"]
        page_item_refs = {
            "ContentPageResultSchema": "PublicContentSchema",
            "ContentWorkspacePageSchema": "ContentWorkspaceProjectionSchema",
            "ContactMetadataPageSchema": "ContactMetadataSchema",
            "ContactReplyPageSchema": "ContactReplySchema",
        }
        for page_schema_name, item_schema_name in page_item_refs.items():
            with self.subTest(page_schema=page_schema_name):
                self.assertEqual(
                    components[page_schema_name]["properties"]["items"]["items"]["$ref"],
                    f"#/components/schemas/{item_schema_name}",
                )

        workspace = components["ContentWorkspaceProjectionSchema"]["properties"]
        self.assertEqual(
            workspace["target"]["anyOf"][0]["$ref"],
            "#/components/schemas/ContentWorkspaceTargetSchema",
        )
        self.assertEqual(
            workspace["latest_review"]["anyOf"][0]["$ref"],
            "#/components/schemas/ContentRevisionProjectionSchema",
        )
        self.assertEqual(
            workspace["entries_json"]["items"]["$ref"],
            "#/components/schemas/ContentEditorEntrySchema",
        )
        self.assertEqual(
            components["ContentEditorEntrySchema"]["properties"]["fields"]["anyOf"][0]["$ref"],
            "#/components/schemas/ContentEditorFieldsSchema",
        )
        self.assertEqual(
            components["ContentEditorEntrySchema"]["properties"]["steps"]["items"]["$ref"],
            "#/components/schemas/ContentEditorStepSchema",
        )
        self.assertEqual(
            components["ServiceGuideCreateSchema"]["properties"]["entries_json"]["items"]["$ref"],
            "#/components/schemas/ContentEditorEntrySchema",
        )
        self.assertEqual(
            components["ServiceGuideUpdateSchema"]["properties"]["entries_json"]["anyOf"][0]["items"]["$ref"],
            "#/components/schemas/ContentEditorEntrySchema",
        )
        self.assertEqual(
            components["ContactDeliveryMetadataResultSchema"]["properties"]["counts"]["$ref"],
            "#/components/schemas/ContactDeliveryCountsSchema",
        )
        self.assertEqual(
            components["ContactDeliveryMetadataResultSchema"]["properties"]["items"]["items"]["$ref"],
            "#/components/schemas/ContactDeliveryMetadataItemSchema",
        )

        response_schema_names = set(expected.values()) | set(page_item_refs.values()) | {
            "ContentWorkspaceTargetSchema",
            "ContentRevisionProjectionSchema",
            "ContentEditorEntrySchema",
            "ContentEditorFieldsSchema",
            "ContentEditorFieldSchema",
            "ContentEditorStepSchema",
            "ContentWorkspaceReplaySchema",
            "ContactMetadataSchema",
            "ContactDetailSchema",
            "ContactReplySchema",
            "ContactNoResponseProjectionSchema",
            "ContactDeliveryMetadataResultSchema",
            "ContactDeliveryMetadataItemSchema",
            "ContactDeliveryCountsSchema",
        }
        for schema_name in response_schema_names:
            with self.subTest(schema=schema_name):
                self.assertIsNot(components[schema_name].get("additionalProperties"), True)

        forbidden = {
            "expected_updated_at",
            "reason",
            "metadata_json",
            "message_body_encrypted",
            "source_ip_hash",
            "user_agent_hash",
            "duplicate_fingerprint",
            "idempotency_key_hash",
            "recipient_channel_hash",
            "approval_evidence_json",
            "detail_encrypted",
            "author_id",
            "approved_by_id",
            "recorded_by_id",
        }
        for schema_name in response_schema_names:
            with self.subTest(forbidden=schema_name):
                self.assertTrue(
                    forbidden.isdisjoint(components[schema_name].get("properties", {})),
                    schema_name,
                )

    def test_privacy_uses_explicit_output_schemas(self):
        from config.api.v1 import api_v1

        document = api_v1.get_openapi_schema()
        operations = self._operations(document)
        expected = {
            "privacy_notice_view": "PrivacyNoticeSchema",
            "privacy_notice_accept": "PrivacyAcceptanceProjectionSchema",
            "privacy_notice_withdraw": "PrivacyAcceptanceProjectionSchema",
            "privacy_acceptance_list": "PrivacyAcceptancePageSchema",
            "privacy_requests_list": "PrivacyRequestPageSchema",
            "privacy_request_create": "PrivacyRequestProjectionSchema",
            "privacy_request_sensitive_detail": "PrivacyRequestSensitiveSchema",
            "privacy_request_detail": "PrivacyRequestProjectionSchema",
            "privacy_request_withdraw": "PrivacyRequestProjectionSchema",
            "privacy_request_assign": "PrivacyRequestProjectionSchema",
            "privacy_request_identity_verify": "PrivacyRequestProjectionSchema",
            "privacy_request_review": "PrivacyRequestProjectionSchema",
            "privacy_request_more_information": "PrivacyRequestProjectionSchema",
            "privacy_request_approve": "PrivacyRequestProjectionSchema",
            "privacy_request_partial_fulfill": "PrivacyRequestProjectionSchema",
            "privacy_request_deny": "PrivacyRequestProjectionSchema",
            "privacy_request_complete": "PrivacyRequestProjectionSchema",
            "privacy_request_close": "PrivacyRequestProjectionSchema",
            "privacy_request_fulfill": "PrivacyRequestProjectionSchema",
            "privacy_retention_policies": "PrivacyRetentionPolicyPageSchema",
            "privacy_retention_evaluations": "PrivacyRetentionEvaluationPageSchema",
            "privacy_retention_evaluate": "PrivacyRetentionEvaluationResultSchema",
            "privacy_legal_holds_list": "PrivacyLegalHoldPageSchema",
            "privacy_legal_hold_detail": "PrivacyLegalHoldSchema",
            "privacy_legal_hold_create": "PrivacyLegalHoldSchema",
            "privacy_legal_hold_release": "PrivacyLegalHoldSchema",
            "privacy_incidents_list": "PrivacyIncidentPageSchema",
            "privacy_incident_detail": "PrivacyIncidentProjectionSchema",
            "privacy_incident_create": "PrivacyIncidentProjectionSchema",
            "privacy_incident_investigate": "PrivacyIncidentProjectionSchema",
            "privacy_incident_contain": "PrivacyIncidentProjectionSchema",
            "privacy_incident_notification_assess": "PrivacyIncidentProjectionSchema",
            "privacy_incident_resolve": "PrivacyIncidentProjectionSchema",
            "privacy_incident_dismiss": "PrivacyIncidentProjectionSchema",
        }
        self.assertEqual(len(expected), 34)

        expected_paths = {
            "privacy_notice_view": ("/api/v1/privacy/notices/{notice_identifier}/", "get"),
            "privacy_notice_accept": ("/api/v1/privacy/notices/{notice_identifier}/accept/", "post"),
            "privacy_notice_withdraw": ("/api/v1/privacy/notices/{notice_identifier}/withdraw/", "post"),
            "privacy_acceptance_list": ("/api/v1/privacy/acceptances/", "get"),
            "privacy_requests_list": ("/api/v1/privacy/requests/", "get"),
            "privacy_request_create": ("/api/v1/privacy/requests/", "post"),
            "privacy_request_sensitive_detail": ("/api/v1/privacy/requests/{reference_code}/sensitive/", "get"),
            "privacy_request_detail": ("/api/v1/privacy/requests/{reference_code}/", "get"),
            "privacy_request_withdraw": ("/api/v1/privacy/requests/{reference_code}/withdraw/", "post"),
            "privacy_request_assign": ("/api/v1/privacy/requests/{reference_code}/assign/", "post"),
            "privacy_request_identity_verify": ("/api/v1/privacy/requests/{reference_code}/identity-verify/", "post"),
            "privacy_request_review": ("/api/v1/privacy/requests/{reference_code}/review/", "post"),
            "privacy_request_more_information": ("/api/v1/privacy/requests/{reference_code}/more-information/", "post"),
            "privacy_request_approve": ("/api/v1/privacy/requests/{reference_code}/approve/", "post"),
            "privacy_request_partial_fulfill": ("/api/v1/privacy/requests/{reference_code}/partial/", "post"),
            "privacy_request_deny": ("/api/v1/privacy/requests/{reference_code}/deny/", "post"),
            "privacy_request_complete": ("/api/v1/privacy/requests/{reference_code}/complete/", "post"),
            "privacy_request_close": ("/api/v1/privacy/requests/{reference_code}/close/", "post"),
            "privacy_request_fulfill": ("/api/v1/privacy/requests/{reference_code}/fulfill/", "post"),
            "privacy_retention_policies": ("/api/v1/privacy/retention/policies/", "get"),
            "privacy_retention_evaluations": ("/api/v1/privacy/retention/evaluations/", "get"),
            "privacy_retention_evaluate": ("/api/v1/privacy/retention/evaluate/", "post"),
            "privacy_legal_holds_list": ("/api/v1/privacy/legal-holds/", "get"),
            "privacy_legal_hold_detail": ("/api/v1/privacy/legal-holds/{hold_id}/", "get"),
            "privacy_legal_hold_create": ("/api/v1/privacy/legal-holds/", "post"),
            "privacy_legal_hold_release": ("/api/v1/privacy/legal-holds/{hold_id}/release/", "post"),
            "privacy_incidents_list": ("/api/v1/privacy/incidents/", "get"),
            "privacy_incident_detail": ("/api/v1/privacy/incidents/{incident_code}/", "get"),
            "privacy_incident_create": ("/api/v1/privacy/incidents/", "post"),
            "privacy_incident_investigate": ("/api/v1/privacy/incidents/{incident_code}/investigate/", "post"),
            "privacy_incident_contain": ("/api/v1/privacy/incidents/{incident_code}/contain/", "post"),
            "privacy_incident_notification_assess": ("/api/v1/privacy/incidents/{incident_code}/notification-assess/", "post"),
            "privacy_incident_resolve": ("/api/v1/privacy/incidents/{incident_code}/resolve/", "post"),
            "privacy_incident_dismiss": ("/api/v1/privacy/incidents/{incident_code}/dismiss/", "post"),
        }
        for operation_id, schema_name in expected.items():
            with self.subTest(operation_id=operation_id):
                self.assertIn(operation_id, operations)
                response = operations[operation_id]["responses"].get("200") or operations[operation_id]["responses"].get(200)
                self.assertEqual(
                    response["content"]["application/json"]["schema"],
                    {"$ref": f"#/components/schemas/{schema_name}"},
                )
                path, method = expected_paths[operation_id]
                self.assertEqual(document["paths"][path][method]["operationId"], operation_id)

        components = document["components"]["schemas"]
        self.assertEqual(
            set(components["PrivacyNoticeSchema"]["properties"]),
            {"version", "effective_at", "body_html"},
        )
        self.assertNotIn("body_markdown", components["PrivacyNoticeSchema"]["properties"])
        self.assertNotIn("revision_hash", components["PrivacyNoticeSchema"]["properties"])
        page_item_refs = {
            "PrivacyAcceptancePageSchema": "PrivacyAcceptanceProjectionSchema",
            "PrivacyRequestPageSchema": "PrivacyRequestProjectionSchema",
            "PrivacyRetentionPolicyPageSchema": "PrivacyRetentionPolicySchema",
            "PrivacyRetentionEvaluationPageSchema": "PrivacyRetentionEvaluationSchema",
            "PrivacyLegalHoldPageSchema": "PrivacyLegalHoldSchema",
            "PrivacyIncidentPageSchema": "PrivacyIncidentProjectionSchema",
            "PrivacyRetentionEvaluationResultSchema": "PrivacyRetentionEvaluationSchema",
        }
        for page_schema_name, item_schema_name in page_item_refs.items():
            with self.subTest(page_schema=page_schema_name):
                self.assertEqual(
                    components[page_schema_name]["properties"]["items"]["items"]["$ref"],
                    f"#/components/schemas/{item_schema_name}",
                )

        def refs(value):
            if isinstance(value, list):
                found = set()
                for item in value:
                    found.update(refs(item))
                return found
            if not isinstance(value, dict):
                return set()
            found = {value["$ref"]} if "$ref" in value else set()
            for child in value.values():
                found.update(refs(child))
            return found

        self.assertIn(
            "#/components/schemas/PrivacyIncidentTransitionSchema",
            refs(components["PrivacyIncidentProjectionSchema"]["properties"]["timeline"]),
        )
        self.assertIn(
            "#/components/schemas/PrivacyIncidentSafeEvidenceSchema",
            refs(components["PrivacyIncidentTransitionSchema"]["properties"]["safe_evidence"]),
        )

        response_schema_names = set(expected.values()) | set(page_item_refs.values()) | {
            "PrivacyIncidentTransitionSchema",
            "PrivacyIncidentSafeEvidenceSchema",
        }
        for schema_name in response_schema_names:
            with self.subTest(schema=schema_name):
                self.assertIsNot(components[schema_name].get("additionalProperties"), True)

        forbidden = {
            "expected_updated_at",
            "reason",
            "metadata_json",
            "source_route",
            "actor_user_id",
            "requester_id",
            "subject_reference_hash",
            "target_record_reference_hash",
            "token",
            "token_hash",
            "related_event_ids",
            "action_metadata",
            "reporter_id",
            "owner_id",
            "record_reference_hash",
            "safe_reference",
        }
        for schema_name in response_schema_names:
            with self.subTest(forbidden=schema_name):
                self.assertTrue(
                    forbidden.isdisjoint(components[schema_name].get("properties", {})),
                    schema_name,
                )

    def test_good_moral_uses_explicit_output_schemas(self):
        from config.api.v1 import api_v1

        document = api_v1.get_openapi_schema()
        operations = self._operations(document)
        expected = {
            "good_moral_list": (
                "GoodMoralPageResultSchema",
                "/api/v1/good-moral/",
                "get",
            ),
            "good_moral_create": (
                "GoodMoralMutationResponseSchema",
                "/api/v1/good-moral/",
                "post",
            ),
            "good_moral_detail": (
                "GoodMoralRequestSchema",
                "/api/v1/good-moral/{reference_code}/",
                "get",
            ),
            "good_moral_draft_update": (
                "GoodMoralMutationResponseSchema",
                "/api/v1/good-moral/{reference_code}/",
                "put",
            ),
            "good_moral_document_detail": (
                "GeneratedDocumentMetadataSchema",
                "/api/v1/good-moral/{reference_code}/document/",
                "get",
            ),
            "good_moral_submit": (
                "GoodMoralMutationResponseSchema",
                "/api/v1/good-moral/{reference_code}/submit/",
                "post",
            ),
            "good_moral_cancel": (
                "GoodMoralMutationResponseSchema",
                "/api/v1/good-moral/{reference_code}/cancel/",
                "post",
            ),
            "good_moral_receipt_encode": (
                "GoodMoralMutationResponseSchema",
                "/api/v1/good-moral/{reference_code}/receipt/encode/",
                "post",
            ),
            "good_moral_receipt_verify": (
                "GoodMoralMutationResponseSchema",
                "/api/v1/good-moral/{reference_code}/receipt/verify/",
                "post",
            ),
            "good_moral_review_start": (
                "GoodMoralMutationResponseSchema",
                "/api/v1/good-moral/{reference_code}/review/start/",
                "post",
            ),
            "good_moral_reviewer_assign": (
                "GoodMoralMutationResponseSchema",
                "/api/v1/good-moral/{reference_code}/reviewer/",
                "post",
            ),
            "good_moral_ossd_verification": (
                "GoodMoralMutationResponseSchema",
                "/api/v1/good-moral/{reference_code}/ossd/",
                "post",
            ),
            "good_moral_hold": (
                "GoodMoralMutationResponseSchema",
                "/api/v1/good-moral/{reference_code}/hold/",
                "post",
            ),
            "good_moral_approve": (
                "GoodMoralMutationResponseSchema",
                "/api/v1/good-moral/{reference_code}/approve/",
                "post",
            ),
            "good_moral_reject": (
                "GoodMoralMutationResponseSchema",
                "/api/v1/good-moral/{reference_code}/reject/",
                "post",
            ),
            "good_moral_generate": (
                "GoodMoralMutationResponseSchema",
                "/api/v1/good-moral/{reference_code}/generate/",
                "post",
            ),
            "good_moral_print": (
                "GoodMoralMutationResponseSchema",
                "/api/v1/good-moral/{reference_code}/print/",
                "post",
            ),
            "good_moral_release": (
                "GoodMoralMutationResponseSchema",
                "/api/v1/good-moral/{reference_code}/release/",
                "post",
            ),
            "good_moral_dry_seal_confirm": (
                "GoodMoralMutationResponseSchema",
                "/api/v1/good-moral/{reference_code}/dry-seal/confirm/",
                "post",
            ),
            "good_moral_void": (
                "GoodMoralMutationResponseSchema",
                "/api/v1/good-moral/{reference_code}/void/",
                "post",
            ),
            "good_moral_supersede": (
                "GoodMoralMutationResponseSchema",
                "/api/v1/good-moral/{reference_code}/supersede/",
                "post",
            ),
            "good_moral_archive": (
                "GoodMoralMutationResponseSchema",
                "/api/v1/good-moral/{reference_code}/archive/",
                "post",
            ),
        }
        self.assertEqual(len(expected), 22)

        for operation_id, (schema_name, path, method) in expected.items():
            with self.subTest(operation_id=operation_id):
                self.assertIn(operation_id, operations)
                response = operations[operation_id]["responses"].get("200") or operations[operation_id]["responses"].get(200)
                self.assertEqual(
                    response["content"]["application/json"]["schema"],
                    {"$ref": f"#/components/schemas/{schema_name}"},
                )
                self.assertEqual(document["paths"][path][method]["operationId"], operation_id)

        components = document["components"]["schemas"]
        self.assertEqual(
            components["GoodMoralPageResultSchema"]["properties"]["items"]["items"]["$ref"],
            "#/components/schemas/GoodMoralRequestSchema",
        )
        self.assertEqual(
            components["GoodMoralRequestSchema"]["properties"]["generated_document"]["anyOf"][0]["$ref"],
            "#/components/schemas/GeneratedDocumentMetadataSchema",
        )

        response_schema_names = {
            "GoodMoralRequestSchema",
            "GoodMoralPageResultSchema",
            "GoodMoralMutationResponseSchema",
            "GeneratedDocumentMetadataSchema",
        }
        for schema_name in response_schema_names:
            with self.subTest(schema=schema_name):
                self.assertIsNot(components[schema_name].get("additionalProperties"), True)

        forbidden = {
            "official_receipt_number",
            "official_receipt_date",
            "official_receipt_amount",
            "receipt_encoded_by",
            "receipt_verified_by",
            "receipt_rejection_code",
            "assigned_reviewer",
            "reviewed_by",
            "approved_by",
            "approval_signatory_name",
            "approval_signatory_title",
            "generated_by",
            "generation_failure_code",
            "printed_by",
            "released_by",
            "dry_seal_confirmed_by",
            "office_only_note",
            "hold_rejection_reason_code",
            "metadata_json",
            "reason_code",
            "note",
            "expected_updated_at",
            "requester_user_id",
            "student_profile_id",
        }
        for schema_name in response_schema_names:
            with self.subTest(forbidden=schema_name):
                self.assertTrue(
                    forbidden.isdisjoint(components[schema_name].get("properties", {})),
                    schema_name,
                )

        binary_response = operations["good_moral_document_download"]["responses"]["200"]
        for media in binary_response["content"].values():
            self.assertEqual(media["schema"], {"type": "string", "format": "binary"})

    def test_graduate_tracer_uses_explicit_output_schemas(self):
        from config.api.v1 import api_v1

        document = api_v1.get_openapi_schema()
        operations = self._operations(document)
        expected = {
            "graduate_tracer_list": (
                "GraduateTracerResponsePageSchema",
                "/api/v1/graduate-tracer/",
                "get",
            ),
            "graduate_tracer_start": (
                "GraduateTracerResponseSchema",
                "/api/v1/graduate-tracer/",
                "post",
            ),
            "graduate_tracer_status": (
                "GraduateTracerStatusSchema",
                "/api/v1/graduate-tracer/status/",
                "get",
            ),
            "graduate_tracer_detail": (
                "GraduateTracerDetailSchema",
                "/api/v1/graduate-tracer/{reference_code}/",
                "get",
            ),
            "graduate_tracer_document_generate": (
                "GeneratedDocumentMetadataSchema",
                "/api/v1/graduate-tracer/{reference_code}/document/generate/",
                "post",
            ),
            "graduate_tracer_sensitive_detail": (
                "GraduateTracerDetailSchema",
                "/api/v1/graduate-tracer/{reference_code}/sensitive/",
                "get",
            ),
            "graduate_tracer_draft_save": (
                "GraduateTracerResponseSchema",
                "/api/v1/graduate-tracer/{reference_code}/draft/",
                "put",
            ),
            "graduate_tracer_submit": (
                "GraduateTracerResponseSchema",
                "/api/v1/graduate-tracer/{reference_code}/submit/",
                "post",
            ),
            "graduate_tracer_reopen": (
                "GraduateTracerResponseSchema",
                "/api/v1/graduate-tracer/{reference_code}/reopen/",
                "post",
            ),
            "graduate_tracer_void": (
                "GraduateTracerResponseSchema",
                "/api/v1/graduate-tracer/{reference_code}/void/",
                "post",
            ),
            "graduate_tracer_archive": (
                "GraduateTracerResponseSchema",
                "/api/v1/graduate-tracer/{reference_code}/archive/",
                "post",
            ),
        }
        self.assertEqual(len(expected), 11)

        for operation_id, (schema_name, path, method) in expected.items():
            with self.subTest(operation_id=operation_id):
                self.assertIn(operation_id, operations)
                response = operations[operation_id]["responses"].get("200") or operations[operation_id]["responses"].get(200)
                self.assertEqual(
                    response["content"]["application/json"]["schema"],
                    {"$ref": f"#/components/schemas/{schema_name}"},
                )
                self.assertEqual(document["paths"][path][method]["operationId"], operation_id)

        components = document["components"]["schemas"]
        self.assertEqual(
            components["GraduateTracerResponsePageSchema"]["properties"]["items"]["items"]["$ref"],
            "#/components/schemas/GraduateTracerResponseSchema",
        )

        response_schema_names = {
            "GraduateTracerResponseSchema",
            "GraduateTracerDetailSchema",
            "GraduateTracerResponsePageSchema",
            "GraduateTracerStatusSchema",
            "GeneratedDocumentMetadataSchema",
        }
        for schema_name in response_schema_names:
            with self.subTest(schema=schema_name):
                self.assertIsNot(components[schema_name].get("additionalProperties"), True)

        answers_schema = components["GraduateTracerDetailSchema"]["properties"]["answers"]
        self.assertIn(
            True,
            [
                branch.get("additionalProperties")
                for branch in answers_schema.get("anyOf", [])
                if isinstance(branch, dict)
            ],
        )

        forbidden = {
            "expected_updated_at",
            "reason",
            "response_json",
            "metadata_json",
            "form_invitation_id",
            "invitation_token",
            "token_hash",
            "telephone_number",
            "place_of_work",
            "initial_gross_earnings",
            "business_line",
            "first_job_level",
            "current_job_level",
            "reopen_reason",
            "void_reason",
            "is_paper_transcription",
            "transcribed_by",
            "actor_user_id",
        }
        for schema_name in response_schema_names:
            with self.subTest(forbidden=schema_name):
                self.assertTrue(
                    forbidden.isdisjoint(components[schema_name].get("properties", {})),
                    schema_name,
                )

    def test_exit_interviews_use_explicit_output_schemas(self):
        from config.api.v1 import api_v1

        document = api_v1.get_openapi_schema()
        operations = self._operations(document)
        expected = {
            "exit_interviews_list": "ExitInterviewResponsePageSchema",
            "exit_interviews_status": "ExitInterviewStatusSchema",
            "exit_interviews_assignments_list": "ExitInterviewAssignmentPageSchema",
            "exit_interviews_assignment_create": "ExitInterviewAssignmentSchema",
            "exit_interviews_assignment_reassign": "ExitInterviewAssignmentSchema",
            "exit_interviews_start": "ExitInterviewResponseSchema",
            "exit_interviews_detail": "ExitInterviewDetailSchema",
            "exit_interviews_document_generate": "GeneratedDocumentMetadataSchema",
            "exit_interviews_sensitive_detail": "ExitInterviewDetailSchema",
            "exit_interviews_draft_save": "ExitInterviewResponseSchema",
            "exit_interviews_submit": "ExitInterviewResponseSchema",
            "exit_interviews_acknowledge": "ExitInterviewResponseSchema",
            "exit_interviews_reopen": "ExitInterviewResponseSchema",
            "exit_interviews_void": "ExitInterviewResponseSchema",
            "exit_interviews_archive": "ExitInterviewResponseSchema",
        }
        expected_paths = {
            "exit_interviews_list": ("/api/v1/exit-interviews/", "get"),
            "exit_interviews_status": ("/api/v1/exit-interviews/status/", "get"),
            "exit_interviews_assignments_list": ("/api/v1/exit-interviews/assignments/", "get"),
            "exit_interviews_assignment_create": ("/api/v1/exit-interviews/assignments/", "post"),
            "exit_interviews_assignment_reassign": ("/api/v1/exit-interviews/assignments/reassign/", "post"),
            "exit_interviews_start": ("/api/v1/exit-interviews/", "post"),
            "exit_interviews_detail": ("/api/v1/exit-interviews/{reference_code}/", "get"),
            "exit_interviews_document_generate": (
                "/api/v1/exit-interviews/{reference_code}/document/generate/",
                "post",
            ),
            "exit_interviews_sensitive_detail": (
                "/api/v1/exit-interviews/{reference_code}/sensitive/",
                "get",
            ),
            "exit_interviews_draft_save": ("/api/v1/exit-interviews/{reference_code}/draft/", "put"),
            "exit_interviews_submit": ("/api/v1/exit-interviews/{reference_code}/submit/", "post"),
            "exit_interviews_acknowledge": (
                "/api/v1/exit-interviews/{reference_code}/acknowledge/",
                "post",
            ),
            "exit_interviews_reopen": ("/api/v1/exit-interviews/{reference_code}/reopen/", "post"),
            "exit_interviews_void": ("/api/v1/exit-interviews/{reference_code}/void/", "post"),
            "exit_interviews_archive": ("/api/v1/exit-interviews/{reference_code}/archive/", "post"),
        }

        self.assertEqual(len(expected), 15)
        for operation_id, schema_name in expected.items():
            with self.subTest(operation_id=operation_id):
                self.assertIn(operation_id, operations)
                response = operations[operation_id]["responses"].get("200") or operations[operation_id]["responses"].get(200)
                self.assertEqual(
                    response["content"]["application/json"]["schema"],
                    {"$ref": f"#/components/schemas/{schema_name}"},
                )
                path, method = expected_paths[operation_id]
                self.assertEqual(document["paths"][path][method]["operationId"], operation_id)

        components = document["components"]["schemas"]
        self.assertEqual(
            components["ExitInterviewResponsePageSchema"]["properties"]["items"]["items"]["$ref"],
            "#/components/schemas/ExitInterviewResponseSchema",
        )
        self.assertEqual(
            components["ExitInterviewAssignmentPageSchema"]["properties"]["items"]["items"]["$ref"],
            "#/components/schemas/ExitInterviewAssignmentSchema",
        )

        answers_schema = components["ExitInterviewDetailSchema"]["properties"]["answers"]
        answer_branches = answers_schema.get("anyOf", [answers_schema])
        self.assertTrue(
            any(
                branch.get("type") == "object" and branch.get("additionalProperties") is not False
                for branch in answer_branches
                if isinstance(branch, dict)
            )
        )

        response_schema_names = set(expected.values()) | {
            "ExitInterviewResponseSchema",
            "ExitInterviewDetailSchema",
            "ExitInterviewAssignmentSchema",
            "ExitInterviewStatusSchema",
        }
        for schema_name in response_schema_names:
            with self.subTest(schema=schema_name):
                self.assertIsNot(components[schema_name].get("additionalProperties"), True)

        forbidden = {
            "expected_updated_at",
            "reason",
            "response_json",
            "metadata_json",
            "form_invitation_id",
            "reopen_reason",
            "void_reason",
            "is_paper_transcription",
            "transcribed_by",
            "assigned_by",
            "assigned_by_id",
            "actor_user",
            "actor_id",
        }
        for schema_name in response_schema_names:
            with self.subTest(forbidden=schema_name):
                self.assertTrue(
                    forbidden.isdisjoint(components[schema_name].get("properties", {})),
                    schema_name,
                )

    def test_assessments_use_explicit_output_schemas(self):
        from config.api.v1 import api_v1

        document = api_v1.get_openapi_schema()
        operations = self._operations(document)
        expected = {
            "assessments_instruments": "AssessmentInstrumentPageSchema",
            "assessments_student_summaries": "AssessmentStudentSummaryPageSchema",
            "assessments_student_summary_detail": "AssessmentStudentSummarySchema",
            "assessments_list": "AssessmentPageSchema",
            "assessments_detail": "AssessmentStaffProjectionSchema",
            "assessments_interpretation": "AssessmentSensitiveProjectionSchema",
            "assessments_file_metadata": "AssessmentFileMetadataSchema",
            **{
                operation_id: "AssessmentStaffProjectionSchema"
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
                )
            },
        }
        self.assertEqual(len(expected), 17)

        expected_paths = {
            "assessments_instruments": ("/api/v1/assessments/instruments/", "get"),
            "assessments_student_summaries": (
                "/api/v1/assessments/student/summaries/",
                "get",
            ),
            "assessments_student_summary_detail": (
                "/api/v1/assessments/student/summaries/{record_id}/",
                "get",
            ),
            "assessments_list": ("/api/v1/assessments/", "get"),
            "assessments_detail": ("/api/v1/assessments/{record_id}/", "get"),
            "assessments_interpretation": (
                "/api/v1/assessments/{record_id}/interpretation/",
                "get",
            ),
            "assessments_file_metadata": (
                "/api/v1/assessments/{record_id}/file/metadata/",
                "get",
            ),
            "assessments_create": ("/api/v1/assessments/", "post"),
            "assessments_update": (
                "/api/v1/assessments/{record_id}/update/",
                "post",
            ),
            "assessments_record": (
                "/api/v1/assessments/{record_id}/record/",
                "post",
            ),
            "assessments_submit_review": (
                "/api/v1/assessments/{record_id}/submit-review/",
                "post",
            ),
            "assessments_review": (
                "/api/v1/assessments/{record_id}/review/",
                "post",
            ),
            "assessments_release": (
                "/api/v1/assessments/{record_id}/release/",
                "post",
            ),
            "assessments_void": ("/api/v1/assessments/{record_id}/void/", "post"),
            "assessments_supersede": (
                "/api/v1/assessments/{record_id}/supersede/",
                "post",
            ),
            "assessments_archive": (
                "/api/v1/assessments/{record_id}/archive/",
                "post",
            ),
            "assessments_file_attach": (
                "/api/v1/assessments/{record_id}/file/attach/",
                "post",
            ),
        }
        for operation_id, schema_name in expected.items():
            with self.subTest(operation_id=operation_id):
                response = operations[operation_id]["responses"].get("200") or operations[operation_id]["responses"].get(200)
                self.assertEqual(
                    response["content"]["application/json"]["schema"],
                    {"$ref": f"#/components/schemas/{schema_name}"},
                )
                path, method = expected_paths[operation_id]
                self.assertEqual(document["paths"][path][method]["operationId"], operation_id)

        components = document["components"]["schemas"]
        page_item_refs = {
            "AssessmentInstrumentPageSchema": "AssessmentInstrumentSchema",
            "AssessmentStudentSummaryPageSchema": "AssessmentStudentSummarySchema",
            "AssessmentPageSchema": "AssessmentStaffProjectionSchema",
        }
        for page_schema_name, item_schema_name in page_item_refs.items():
            with self.subTest(page_schema=page_schema_name):
                self.assertEqual(
                    components[page_schema_name]["properties"]["items"]["items"]["$ref"],
                    f"#/components/schemas/{item_schema_name}",
                )

        self.assertEqual(
            components["AssessmentStaffProjectionSchema"]["properties"]["instrument"]["$ref"],
            "#/components/schemas/AssessmentInstrumentSchema",
        )

        response_schema_names = set(expected.values()) | set(page_item_refs.values()) | {
            "AssessmentStudentSummaryInstrumentSchema",
            "AssessmentSensitiveProjectionSchema",
            "AssessmentFileMetadataSchema",
        }
        for schema_name in response_schema_names:
            with self.subTest(schema=schema_name):
                self.assertIsNot(components[schema_name].get("additionalProperties"), True)

        forbidden = {
            "expected_updated_at",
            "expected_instrument_updated_at",
            "reason_code",
            "notes",
            "source_form_reference",
            "interpretation_text",
            "interpretation_text_encrypted",
            "metadata_json",
            "student_profile",
            "administered_by",
            "reviewed_by",
            "released_to_student_by",
        }
        for schema_name in response_schema_names:
            with self.subTest(forbidden=schema_name):
                self.assertTrue(
                    forbidden.isdisjoint(components[schema_name].get("properties", {})),
                    schema_name,
                )

        binary_response = operations["assessments_file_download"]["responses"]["200"]
        for media_type, media in binary_response["content"].items():
            with self.subTest(binary_media_type=media_type):
                self.assertEqual(media["schema"], {"type": "string", "format": "binary"})

    def test_imports_use_explicit_output_schemas(self):
        from config.api.v1 import api_v1

        document = api_v1.get_openapi_schema()
        operations = self._operations(document)
        expected = {
            "imports_list": "ImportBatchPageSchema",
            "imports_catalog": "ImportCatalogPageSchema",
            "imports_detail": "ImportBatchSchema",
            "imports_preview": "ImportRowPageSchema",
            "imports_invitation_list": "ImportInvitationPageSchema",
            "imports_invitation_detail": "ImportInvitationSchema",
            "imports_create": "ImportBatchSchema",
            "imports_replace": "ImportBatchSchema",
            "imports_validate": "ImportBatchSchema",
            "imports_row_correct": "ImportRowSchema",
            "imports_row_reconcile": "ImportRowSchema",
            "imports_row_exclude": "ImportRowSchema",
            "imports_row_acknowledge_boundary": "ImportRowSchema",
            "imports_approve": "ImportBatchSchema",
            "imports_execute": "ImportBatchExecutionResponseSchema",
            "imports_invitation_issue": "ImportInvitationIssueResponseSchema",
            "imports_invitation_reissue": "ImportInvitationSchema",
            "imports_invitation_revoke": "ImportInvitationSchema",
        }
        self.assertEqual(len(expected), 18)

        expected_paths = {
            "imports_list": ("/api/v1/imports/", "get"),
            "imports_catalog": ("/api/v1/imports/catalog/", "get"),
            "imports_detail": ("/api/v1/imports/{batch_id}/", "get"),
            "imports_preview": ("/api/v1/imports/{batch_id}/preview/", "get"),
            "imports_invitation_list": ("/api/v1/imports/{batch_id}/invitations/", "get"),
            "imports_invitation_detail": ("/api/v1/imports/invitations/{invitation_id}/", "get"),
            "imports_create": ("/api/v1/imports/", "post"),
            "imports_replace": ("/api/v1/imports/{batch_id}/replace/", "post"),
            "imports_validate": ("/api/v1/imports/{batch_id}/validate/", "post"),
            "imports_row_correct": ("/api/v1/imports/{batch_id}/rows/{row_id}/correct/", "post"),
            "imports_row_reconcile": ("/api/v1/imports/{batch_id}/rows/{row_id}/reconcile/", "post"),
            "imports_row_exclude": ("/api/v1/imports/{batch_id}/rows/{row_id}/exclude/", "post"),
            "imports_row_acknowledge_boundary": (
                "/api/v1/imports/{batch_id}/rows/{row_id}/acknowledge-boundary/",
                "post",
            ),
            "imports_approve": ("/api/v1/imports/{batch_id}/approve/", "post"),
            "imports_execute": ("/api/v1/imports/{batch_id}/execute/", "post"),
            "imports_invitation_issue": ("/api/v1/imports/{batch_id}/invitations/issue/", "post"),
            "imports_invitation_reissue": (
                "/api/v1/imports/invitations/{invitation_id}/reissue/",
                "post",
            ),
            "imports_invitation_revoke": (
                "/api/v1/imports/invitations/{invitation_id}/revoke/",
                "post",
            ),
        }
        for operation_id, schema_name in expected.items():
            with self.subTest(operation_id=operation_id):
                response = operations[operation_id]["responses"].get("200") or operations[operation_id]["responses"].get(200)
                self.assertEqual(
                    response["content"]["application/json"]["schema"],
                    {"$ref": f"#/components/schemas/{schema_name}"},
                )
                path, method = expected_paths[operation_id]
                self.assertEqual(document["paths"][path][method]["operationId"], operation_id)

        components = document["components"]["schemas"]
        page_item_refs = {
            "ImportBatchPageSchema": "ImportBatchSchema",
            "ImportCatalogPageSchema": "ImportCatalogPlacementSchema",
            "ImportRowPageSchema": "ImportRowSchema",
            "ImportInvitationPageSchema": "ImportInvitationSchema",
        }
        for page_schema_name, item_schema_name in page_item_refs.items():
            with self.subTest(page_schema=page_schema_name):
                self.assertEqual(
                    components[page_schema_name]["properties"]["items"]["items"]["$ref"],
                    f"#/components/schemas/{item_schema_name}",
                )

        self.assertEqual(
            components["ImportBatchSchema"]["properties"]["execution_summary"],
            {"$ref": "#/components/schemas/ImportExecutionSummarySchema"},
        )
        for schema_name, property_name, nested_schema_name in (
            ("ImportBatchExecutionResponseSchema", "execution_result", "ImportExecutionSummarySchema"),
            ("ImportRowSchema", "editable_fields", "ImportRowEditableFieldsSchema"),
        ):
            with self.subTest(schema=schema_name, property=property_name):
                property_schema = components[schema_name]["properties"][property_name]
                self.assertIn(
                    {"$ref": f"#/components/schemas/{nested_schema_name}"},
                    property_schema["anyOf"],
                )

        response_schema_names = set(expected.values()) | set(page_item_refs.values()) | {
            "ImportExecutionSummarySchema",
            "ImportRowEditableFieldsSchema",
            "ImportRowPlacementSchema",
            "ImportInvitationIssueResponseSchema",
        }
        for schema_name in response_schema_names:
            with self.subTest(schema=schema_name):
                self.assertIsNot(components[schema_name].get("additionalProperties"), True)

        forbidden = {
            "expected_updated_at",
            "reason",
            "error_metadata",
            "correction_metadata",
            "filename",
            "content_type",
            "request_key_digest",
            "source_reference",
            "token",
        }
        for schema_name in response_schema_names:
            with self.subTest(forbidden=schema_name):
                self.assertTrue(
                    forbidden.isdisjoint(components[schema_name].get("properties", {})),
                    schema_name,
                )

    def test_form_collection_uses_explicit_output_schemas(self):
        from config.api.v1 import api_v1

        document = api_v1.get_openapi_schema()
        operations = self._operations(document)
        expected = {
            "form_collections_list": "FormCollectionPageSchema",
            "form_collections_create": "FormCollectionSchema",
            "form_collection_access_current": "VerifiedAccessSchema",
            "form_collection_invitation_verify": "VerifiedAccessSchema",
            "form_collections_detail": "FormCollectionSchema",
            "form_collections_configure": "FormCollectionSchema",
            "form_collections_launch": "FormCollectionSchema",
            "form_collections_pause": "FormCollectionSchema",
            "form_collections_close": "FormCollectionSchema",
            "form_collections_archive": "FormCollectionSchema",
            "form_collection_batches_list": "InvitationBatchPageSchema",
            "form_collection_batch_create": "InvitationBatchSchema",
            "form_collection_batch_issue": "InvitationBatchIssueReceiptSchema",
            "form_collection_invitations_list": "InvitationMetadataPageSchema",
            "form_collection_invitation_revoke": "InvitationMetadataSchema",
            "form_collection_manual_matches_list": "ManualMatchPageSchema",
            "form_collection_manual_match_link": "ManualMatchSchema",
            "form_collection_manual_match_reject": "ManualMatchSchema",
        }
        self.assertEqual(len(expected), 18)

        expected_paths = {
            "form_collections_list": ("/api/v1/form-collections/", "get"),
            "form_collections_create": ("/api/v1/form-collections/", "post"),
            "form_collection_access_current": (
                "/api/v1/form-collections/access/current/",
                "get",
            ),
            "form_collection_invitation_verify": (
                "/api/v1/form-collections/invitations/verify/",
                "post",
            ),
            "form_collections_detail": (
                "/api/v1/form-collections/{collection_id}/",
                "get",
            ),
            "form_collections_configure": (
                "/api/v1/form-collections/{collection_id}/",
                "patch",
            ),
            "form_collections_launch": (
                "/api/v1/form-collections/{collection_id}/launch/",
                "post",
            ),
            "form_collections_pause": (
                "/api/v1/form-collections/{collection_id}/pause/",
                "post",
            ),
            "form_collections_close": (
                "/api/v1/form-collections/{collection_id}/close/",
                "post",
            ),
            "form_collections_archive": (
                "/api/v1/form-collections/{collection_id}/archive/",
                "post",
            ),
            "form_collection_batches_list": (
                "/api/v1/form-collections/{collection_id}/batches/",
                "get",
            ),
            "form_collection_batch_create": (
                "/api/v1/form-collections/{collection_id}/batches/",
                "post",
            ),
            "form_collection_batch_issue": (
                "/api/v1/form-collections/batches/{batch_id}/issue/",
                "post",
            ),
            "form_collection_invitations_list": (
                "/api/v1/form-collections/{collection_id}/invitations/",
                "get",
            ),
            "form_collection_invitation_revoke": (
                "/api/v1/form-collections/invitations/{invitation_id}/revoke/",
                "post",
            ),
            "form_collection_manual_matches_list": (
                "/api/v1/form-collections/manual-matches/",
                "get",
            ),
            "form_collection_manual_match_link": (
                "/api/v1/form-collections/manual-matches/{record_id}/link/",
                "post",
            ),
            "form_collection_manual_match_reject": (
                "/api/v1/form-collections/manual-matches/{record_id}/reject/",
                "post",
            ),
        }
        for operation_id, schema_name in expected.items():
            with self.subTest(operation_id=operation_id):
                response = operations[operation_id]["responses"].get("200") or operations[operation_id]["responses"].get(200)
                self.assertEqual(
                    response["content"]["application/json"]["schema"],
                    {"$ref": f"#/components/schemas/{schema_name}"},
                )
                path, method = expected_paths[operation_id]
                self.assertEqual(document["paths"][path][method]["operationId"], operation_id)

        components = document["components"]["schemas"]
        page_item_refs = {
            "FormCollectionPageSchema": "FormCollectionSchema",
            "InvitationBatchPageSchema": "InvitationBatchSchema",
            "InvitationMetadataPageSchema": "InvitationMetadataSchema",
            "ManualMatchPageSchema": "ManualMatchSchema",
        }
        for page_schema_name, item_schema_name in page_item_refs.items():
            with self.subTest(page_schema=page_schema_name):
                self.assertEqual(
                    components[page_schema_name]["properties"]["items"]["items"]["$ref"],
                    f"#/components/schemas/{item_schema_name}",
                )

        response_schema_names = set(expected.values()) | set(page_item_refs.values())
        for schema_name in response_schema_names:
            with self.subTest(schema=schema_name):
                self.assertIsNot(components[schema_name].get("additionalProperties"), True)

        forbidden = {
            "token_hash",
            "control_number_hash",
            "student_number_hash",
            "email_hash",
            "verifier",
            "metadata_json",
            "revoke_reason",
            "reason",
            "expected_updated_at",
        }
        for schema_name in response_schema_names:
            with self.subTest(forbidden=schema_name):
                self.assertTrue(
                    forbidden.isdisjoint(components[schema_name].get("properties", {})),
                    schema_name,
                )

    def test_support_needs_use_explicit_output_schemas(self):
        from config.api.v1 import api_v1

        document = api_v1.get_openapi_schema()
        operations = self._operations(document)
        expected = {
            "support_needs_types": "SupportNeedTypePageSchema",
            "support_needs_review_queue": "SupportNeedPageSchema",
            "support_needs_list": "SupportNeedPageSchema",
            "support_needs_detail": "SupportNeedProjectionSchema",
            "support_needs_create": "SupportNeedMutationResponseSchema",
            "support_needs_update": "SupportNeedMutationResponseSchema",
            "support_needs_verify": "SupportNeedMutationResponseSchema",
            "support_needs_mark_review": "SupportNeedMutationResponseSchema",
            "support_needs_dispute": "SupportNeedMutationResponseSchema",
            "support_needs_archive": "SupportNeedMutationResponseSchema",
        }
        self.assertEqual(len(expected), 10)

        expected_paths = {
            "support_needs_types": ("/api/v1/support-needs/types/", "get"),
            "support_needs_review_queue": ("/api/v1/support-needs/review-queue/", "get"),
            "support_needs_list": ("/api/v1/support-needs/", "get"),
            "support_needs_detail": ("/api/v1/support-needs/{support_need_id}/", "get"),
            "support_needs_create": ("/api/v1/support-needs/", "post"),
            "support_needs_update": ("/api/v1/support-needs/{support_need_id}/", "patch"),
            "support_needs_verify": ("/api/v1/support-needs/{support_need_id}/verify/", "post"),
            "support_needs_mark_review": (
                "/api/v1/support-needs/{support_need_id}/needs-review/",
                "post",
            ),
            "support_needs_dispute": ("/api/v1/support-needs/{support_need_id}/dispute/", "post"),
            "support_needs_archive": ("/api/v1/support-needs/{support_need_id}/archive/", "post"),
        }
        for operation_id, schema_name in expected.items():
            with self.subTest(operation_id=operation_id):
                response = operations[operation_id]["responses"].get("200") or operations[operation_id]["responses"].get(200)
                self.assertEqual(
                    response["content"]["application/json"]["schema"],
                    {"$ref": f"#/components/schemas/{schema_name}"},
                )
                path, method = expected_paths[operation_id]
                self.assertEqual(document["paths"][path][method]["operationId"], operation_id)

        components = document["components"]["schemas"]
        page_item_refs = {
            "SupportNeedTypePageSchema": "SupportNeedTypeSchema",
            "SupportNeedPageSchema": "SupportNeedProjectionSchema",
        }
        for page_schema_name, item_schema_name in page_item_refs.items():
            with self.subTest(page_schema=page_schema_name):
                self.assertEqual(
                    components[page_schema_name]["properties"]["items"]["items"]["$ref"],
                    f"#/components/schemas/{item_schema_name}",
                )

        response_schema_names = set(expected.values()) | set(page_item_refs.values())
        for schema_name in response_schema_names:
            with self.subTest(schema=schema_name):
                self.assertIsNot(components[schema_name].get("additionalProperties"), True)

        self.assertTrue(
            {"support_need_id", "type_key", "status"}.issubset(
                set(components["SupportNeedMutationResponseSchema"].get("required", []))
            )
        )
        forbidden = {
            "student_number",
            "control_number",
            "email",
            "phone",
            "actor_user_id",
            "source_app_label",
            "source_model_name",
            "source_object_id",
            "source_inventory_snapshot_id",
            "source_submission_history_id",
            "evidence_summary",
            "evidence_summary_json",
            "metadata_json",
            "reason_code",
            "expected_updated_at",
            "deactivation_reason",
            "archival_reason",
        }
        for schema_name in response_schema_names:
            with self.subTest(forbidden=schema_name):
                self.assertTrue(
                    forbidden.isdisjoint(components[schema_name].get("properties", {})),
                    schema_name,
                )

    def test_accounts_and_audit_use_explicit_output_schemas(self):
        from config.api.v1 import api_v1

        document = api_v1.get_openapi_schema()
        operations = self._operations(document)
        expected = {
            "staff_accounts_head_guidance_assign": "HeadGuidanceProjectionSchema",
            "staff_accounts_head_guidance_revoke": "HeadGuidanceProjectionSchema",
            "audit_entries_list": "AuditPageSchema",
            "audit_entry_detail": "AuditEntryProjectionSchema",
        }
        expected_paths = {
            "staff_accounts_head_guidance_assign": (
                "/api/v1/staff-accounts/head-guidance/assign/",
                "post",
            ),
            "staff_accounts_head_guidance_revoke": (
                "/api/v1/staff-accounts/head-guidance/revoke/",
                "post",
            ),
            "audit_entries_list": ("/api/v1/audit/", "get"),
            "audit_entry_detail": ("/api/v1/audit/{entry_id}/", "get"),
        }

        for operation_id, schema_name in expected.items():
            with self.subTest(operation_id=operation_id):
                response = operations[operation_id]["responses"].get("200") or operations[operation_id]["responses"].get(200)
                self.assertEqual(
                    response["content"]["application/json"]["schema"],
                    {"$ref": f"#/components/schemas/{schema_name}"},
                )
                path, method = expected_paths[operation_id]
                self.assertEqual(document["paths"][path][method]["operationId"], operation_id)

        components = document["components"]["schemas"]
        self.assertEqual(
            components["AuditPageSchema"]["properties"]["items"]["items"]["$ref"],
            "#/components/schemas/AuditEntryProjectionSchema",
        )
        self.assertEqual(
            components["AuditEntryProjectionSchema"]["properties"]["safe_context"]["$ref"],
            "#/components/schemas/AuditSafeContextSchema",
        )
        for schema_name in (
            "HeadGuidanceProjectionSchema",
            "AuditPageSchema",
            "AuditEntryProjectionSchema",
            "AuditSafeContextSchema",
        ):
            with self.subTest(schema=schema_name):
                self.assertIsNot(components[schema_name].get("additionalProperties"), True)

        self.assertEqual(
            set(components["HeadGuidanceProjectionSchema"]["required"]),
            {"user_id", "is_head_guidance"},
        )
        forbidden = {
            "target_object_id",
            "safe_metadata",
            "actor_user",
            "actor_ip_hash",
            "user_agent_hash",
            "source_view",
            "token",
            "token_hash",
            "password",
            "expected_updated_at",
        }
        for schema_name in (
            "HeadGuidanceProjectionSchema",
            "AuditPageSchema",
            "AuditEntryProjectionSchema",
            "AuditSafeContextSchema",
        ):
            with self.subTest(forbidden=schema_name):
                self.assertTrue(
                    forbidden.isdisjoint(components[schema_name].get("properties", {})),
                    schema_name,
                )

    def test_account_security_pages_use_explicit_output_schemas(self):
        from config.api.v1 import api_v1

        document = api_v1.get_openapi_schema()
        operations = self._operations(document)
        expected = {
            "me_activity_list": "ActivityPageSchema",
            "me_sessions_list": "SessionPageSchema",
            "me_trusted_devices_list": "TrustedDevicePageSchema",
        }
        expected_paths = {
            "me_activity_list": ("/api/v1/me/activity/", "get"),
            "me_sessions_list": ("/api/v1/me/sessions/", "get"),
            "me_trusted_devices_list": ("/api/v1/me/trusted-devices/", "get"),
        }

        for operation_id, schema_name in expected.items():
            with self.subTest(operation_id=operation_id):
                self.assertIn(operation_id, operations)
                response = operations[operation_id]["responses"].get("200") or operations[operation_id]["responses"].get(200)
                self.assertEqual(
                    response["content"]["application/json"]["schema"],
                    {"$ref": f"#/components/schemas/{schema_name}"},
                )
                path, method = expected_paths[operation_id]
                self.assertEqual(document["paths"][path][method]["operationId"], operation_id)

        components = document["components"]["schemas"]
        self.assertEqual(
            components["ActivityPageSchema"]["properties"]["items"]["items"]["$ref"],
            "#/components/schemas/ActivityEntrySchema",
        )
        self.assertEqual(
            components["SessionPageSchema"]["properties"]["items"]["items"]["$ref"],
            "#/components/schemas/ActiveSessionProjectionSchema",
        )
        self.assertNotIn("decode", components["SessionPageSchema"]["properties"])
        self.assertEqual(
            components["TrustedDevicePageSchema"]["properties"]["items"]["items"]["$ref"],
            "#/components/schemas/TrustedDeviceProjectionSchema",
        )
        self.assertEqual(
            components["ActivityEntrySchema"]["properties"]["device"]["anyOf"][0]["$ref"],
            "#/components/schemas/AccountSecurityDisplayStateSchema",
        )

        response_schema_names = {
            "ActivityPageSchema",
            "ActivityEntrySchema",
            "SessionPageSchema",
            "ActiveSessionProjectionSchema",
            "TrustedDevicePageSchema",
            "TrustedDeviceProjectionSchema",
            "AccountSecurityDisplayStateSchema",
        }
        for schema_name in response_schema_names:
            with self.subTest(schema=schema_name):
                self.assertIsNot(components[schema_name].get("additionalProperties"), True)

        forbidden = {
            "session_key",
            "_auth_user_id",
            "device_hash",
            "ip_address",
            "user_agent",
            "target_object_id",
            "safe_metadata",
            "actor_user",
        }
        for schema_name in response_schema_names:
            with self.subTest(forbidden=schema_name):
                self.assertTrue(
                    forbidden.isdisjoint(components[schema_name].get("properties", {})),
                    schema_name,
                )

    def test_governance_uses_explicit_output_schemas(self):
        from config.api.v1 import api_v1

        document = api_v1.get_openapi_schema()
        operations = self._operations(document)
        expected = {
            "policies_dpo_appointment_view": "DPOAppointmentSchema",
            "policies_dpo_appointment_create": "DPOAppointmentSchema",
            "policies_dpo_appointment_retire": "DPOAppointmentSchema",
            "privacy_reviewer_authorizations": "PrivacyReviewerAuthorizationPageSchema",
            "privacy_reviewer_authorization_create": "PrivacyReviewerAuthorizationSchema",
            "privacy_reviewer_authorization_revoke": "PrivacyReviewerAuthorizationSchema",
        }
        expected_paths = {
            "policies_dpo_appointment_view": ("/api/v1/policies/dpo-appointment/", "get"),
            "policies_dpo_appointment_create": ("/api/v1/policies/dpo-appointment/", "post"),
            "policies_dpo_appointment_retire": (
                "/api/v1/policies/dpo-appointment/{appointment_id}/retire/",
                "post",
            ),
            "privacy_reviewer_authorizations": (
                "/api/v1/privacy/reviewer-authorizations/",
                "get",
            ),
            "privacy_reviewer_authorization_create": (
                "/api/v1/privacy/reviewer-authorizations/",
                "post",
            ),
            "privacy_reviewer_authorization_revoke": (
                "/api/v1/privacy/reviewer-authorizations/{authorization_id}/revoke/",
                "post",
            ),
        }

        for operation_id, schema_name in expected.items():
            with self.subTest(operation_id=operation_id):
                self.assertIn(operation_id, operations)
                response = operations[operation_id]["responses"].get("200") or operations[operation_id]["responses"].get(200)
                self.assertEqual(
                    response["content"]["application/json"]["schema"],
                    {"$ref": f"#/components/schemas/{schema_name}"},
                )
                path, method = expected_paths[operation_id]
                self.assertEqual(document["paths"][path][method]["operationId"], operation_id)

        components = document["components"]["schemas"]
        self.assertEqual(
            components["PrivacyReviewerAuthorizationPageSchema"]["properties"]["items"]["items"]["$ref"],
            "#/components/schemas/PrivacyReviewerAuthorizationSchema",
        )
        self.assertEqual(
            components["DPOAppointmentSchema"]["properties"]["holder_id"]["type"],
            "integer",
        )
        self.assertEqual(
            components["PrivacyReviewerAuthorizationSchema"]["properties"]["authorized_user_id"]["type"],
            "integer",
        )
        self.assertEqual(
            components["DPOAppointmentCreateSchema"]["properties"]["holder_id"]["type"],
            "integer",
        )
        self.assertEqual(
            components["PrivacyReviewerAuthorizationCreateSchema"]["properties"]["authorized_user_id"]["type"],
            "integer",
        )

        output_schema_names = {
            "DPOAppointmentSchema",
            "PrivacyReviewerAuthorizationSchema",
            "PrivacyReviewerAuthorizationPageSchema",
        }
        for schema_name in output_schema_names:
            with self.subTest(schema=schema_name):
                self.assertIsNot(components[schema_name].get("additionalProperties"), True)

        forbidden = {
            "reason_code",
            "expected_updated_at",
            "appointed_by",
            "retired_by",
            "authorized_by",
            "revoked_by",
            "actor_user_id",
            "metadata_json",
            "token",
            "token_hash",
            "source_view",
        }
        for schema_name in output_schema_names:
            with self.subTest(forbidden=schema_name):
                self.assertTrue(
                    forbidden.isdisjoint(components[schema_name].get("properties", {})),
                    schema_name,
                )

    def test_backups_and_system_use_explicit_output_schemas(self):
        from config.api.v1 import api_v1

        document = api_v1.get_openapi_schema()
        operations = self._operations(document)
        expected = {
            "backups_dashboard": "BackupDashboardSchema",
            "backups_jobs_list": "BackupJobPageSchema",
            "backups_job_detail": "BackupJobProjectionSchema",
            "backups_artifacts_list": "BackupArtifactPageSchema",
            "backups_job_request": "BackupJobProjectionSchema",
            "backups_job_queue": "BackupJobProjectionSchema",
            "backups_job_verify": "BackupJobProjectionSchema",
            "backups_job_cancel": "BackupJobProjectionSchema",
            "backups_restores_list": "RestoreRequestPageSchema",
            "backups_restore_detail": "RestoreRequestProjectionSchema",
            "backups_restore_request": "RestoreRequestProjectionSchema",
            "backups_restore_authorize": "RestoreRequestProjectionSchema",
            "backups_restore_dry_run": "RestoreRequestProjectionSchema",
            "backups_restore_cancel": "RestoreRequestProjectionSchema",
            "system_health": "HealthProjectionSchema",
            "system_health_check": "HealthProjectionSchema",
            "system_errors_list": "SystemErrorPageSchema",
            "system_error_detail": "ApplicationErrorProjectionSchema",
            "system_error_resolve": "ApplicationErrorProjectionSchema",
            "system_error_reopen": "ApplicationErrorProjectionSchema",
            "system_maintenance_list": "MaintenancePageSchema",
            "system_maintenance_detail": "MaintenanceProjectionSchema",
            "system_maintenance_schedule": "MaintenanceProjectionSchema",
            "system_maintenance_activate": "MaintenanceProjectionSchema",
            "system_maintenance_extend": "MaintenanceProjectionSchema",
            "system_maintenance_complete": "MaintenanceProjectionSchema",
            "system_maintenance_cancel": "MaintenanceProjectionSchema",
            "system_release_metadata": "ReleaseMetadataSchema",
            "system_environment_summary": "EnvironmentSummarySchema",
            "system_operations_catalog": "OperationalCommandCatalogSchema",
            "system_operations_runs": "OperationalRunPageSchema",
        }
        expected_paths = {
            "backups_dashboard": ("/api/v1/backups/", "get"),
            "backups_jobs_list": ("/api/v1/backups/jobs/", "get"),
            "backups_job_detail": ("/api/v1/backups/jobs/{job_id}/", "get"),
            "backups_artifacts_list": ("/api/v1/backups/jobs/{job_id}/artifacts/", "get"),
            "backups_job_request": ("/api/v1/backups/jobs/", "post"),
            "backups_job_queue": ("/api/v1/backups/jobs/{job_id}/queue/", "post"),
            "backups_job_verify": ("/api/v1/backups/jobs/{job_id}/verify/", "post"),
            "backups_job_cancel": ("/api/v1/backups/jobs/{job_id}/cancel/", "post"),
            "backups_restores_list": ("/api/v1/backups/restores/", "get"),
            "backups_restore_detail": ("/api/v1/backups/restores/{request_id}/", "get"),
            "backups_restore_request": ("/api/v1/backups/restores/", "post"),
            "backups_restore_authorize": ("/api/v1/backups/restores/{request_id}/authorize/", "post"),
            "backups_restore_dry_run": ("/api/v1/backups/restores/{request_id}/dry-run/", "post"),
            "backups_restore_cancel": ("/api/v1/backups/restores/{request_id}/cancel/", "post"),
            "system_health": ("/api/v1/system/health/", "get"),
            "system_health_check": ("/api/v1/system/health/check/", "post"),
            "system_errors_list": ("/api/v1/system/errors/", "get"),
            "system_error_detail": ("/api/v1/system/errors/{error_id}/", "get"),
            "system_error_resolve": ("/api/v1/system/errors/{error_id}/resolve/", "post"),
            "system_error_reopen": ("/api/v1/system/errors/{error_id}/reopen/", "post"),
            "system_maintenance_list": ("/api/v1/system/maintenance/", "get"),
            "system_maintenance_detail": ("/api/v1/system/maintenance/{window_id}/", "get"),
            "system_maintenance_schedule": ("/api/v1/system/maintenance/", "post"),
            "system_maintenance_activate": ("/api/v1/system/maintenance/{window_id}/activate/", "post"),
            "system_maintenance_extend": ("/api/v1/system/maintenance/{window_id}/extend/", "post"),
            "system_maintenance_complete": ("/api/v1/system/maintenance/{window_id}/complete/", "post"),
            "system_maintenance_cancel": ("/api/v1/system/maintenance/{window_id}/cancel/", "post"),
            "system_release_metadata": ("/api/v1/system/release/", "get"),
            "system_environment_summary": ("/api/v1/system/environment/", "get"),
            "system_operations_catalog": ("/api/v1/system/operations/", "get"),
            "system_operations_runs": ("/api/v1/system/operations/runs/", "get"),
        }

        for operation_id, schema_name in expected.items():
            with self.subTest(operation_id=operation_id):
                self.assertIn(operation_id, operations)
                response = operations[operation_id]["responses"].get("200") or operations[operation_id]["responses"].get(200)
                self.assertEqual(
                    response["content"]["application/json"]["schema"],
                    {"$ref": f"#/components/schemas/{schema_name}"},
                )
                path, method = expected_paths[operation_id]
                self.assertEqual(document["paths"][path][method]["operationId"], operation_id)

        components = document["components"]["schemas"]
        self.assertEqual(
            components["BackupJobPageSchema"]["properties"]["items"]["items"]["$ref"],
            "#/components/schemas/BackupJobProjectionSchema",
        )
        self.assertEqual(
            components["BackupArtifactPageSchema"]["properties"]["items"]["items"]["$ref"],
            "#/components/schemas/BackupArtifactProjectionSchema",
        )
        self.assertEqual(
            components["RestoreRequestPageSchema"]["properties"]["items"]["items"]["$ref"],
            "#/components/schemas/RestoreRequestProjectionSchema",
        )
        self.assertEqual(
            components["RestoreRequestProjectionSchema"]["properties"]["checklist"]["items"]["$ref"],
            "#/components/schemas/RestoreChecklistProjectionSchema",
        )
        self.assertEqual(
            components["BackupDashboardSchema"]["properties"]["backups"]["$ref"],
            "#/components/schemas/BackupDashboardSummarySchema",
        )
        restores_schema = components["BackupDashboardSchema"]["properties"]["restores"]
        self.assertIn(
            "#/components/schemas/RestoreDashboardSummarySchema",
            [restores_schema.get("$ref"), *[item.get("$ref") for item in restores_schema.get("anyOf", [])]],
        )
        self.assertEqual(
            components["SystemErrorPageSchema"]["properties"]["items"]["items"]["$ref"],
            "#/components/schemas/ApplicationErrorProjectionSchema",
        )
        self.assertEqual(
            components["ApplicationErrorProjectionSchema"]["properties"]["diagnostic_context"]["$ref"],
            "#/components/schemas/DiagnosticContextSchema",
        )
        self.assertEqual(
            components["DiagnosticContextSchema"]["properties"]["values"]["$ref"],
            "#/components/schemas/DiagnosticContextValuesSchema",
        )
        self.assertEqual(
            components["HealthProjectionSchema"]["properties"]["components"]["items"]["$ref"],
            "#/components/schemas/HealthComponentSchema",
        )
        self.assertEqual(
            components["MaintenancePageSchema"]["properties"]["items"]["items"]["$ref"],
            "#/components/schemas/MaintenanceProjectionSchema",
        )
        self.assertEqual(
            components["OperationalRunPageSchema"]["properties"]["items"]["items"]["$ref"],
            "#/components/schemas/OperationalCommandRunProjectionSchema",
        )
        self.assertEqual(
            components["OperationalCommandCatalogSchema"]["properties"]["items"]["items"]["$ref"],
            "#/components/schemas/OperationalCommandSchema",
        )
        self.assertEqual(
            components["EnvironmentSummarySchema"]["properties"]["components"]["$ref"],
            "#/components/schemas/EnvironmentComponentsSchema",
        )

        response_schema_names = set(expected.values()) | {
            "BackupArtifactProjectionSchema",
            "BackupJobProjectionSchema",
            "RestoreChecklistProjectionSchema",
            "RestoreRequestProjectionSchema",
            "BackupDashboardSummarySchema",
            "RestoreDashboardSummarySchema",
            "HealthComponentSchema",
            "DiagnosticContextSchema",
            "DiagnosticContextValuesSchema",
            "DiagnosticRemediationSchema",
            "MaintenanceProjectionSchema",
            "OperationalCommandRunProjectionSchema",
            "ReleaseIdentitySchema",
            "EnvironmentComponentsSchema",
            "EnvironmentMaintenanceSchema",
            "OperationalCommandSchema",
        }
        for schema_name in response_schema_names:
            with self.subTest(schema=schema_name):
                self.assertIsNot(components[schema_name].get("additionalProperties"), True)

        forbidden = {
            "expected_updated_at",
            "reason",
            "metadata_json",
            "manifest_hash_sha256",
            "storage_reference",
            "checksum_sha256",
            "key_version_reference",
            "institutional_authorization_reference",
            "actor_user",
            "actor_role",
            "actor_ip_hash",
            "user_agent_hash",
            "redacted_stack_trace",
            "related_object_id",
        }
        for schema_name in response_schema_names:
            with self.subTest(forbidden=schema_name):
                self.assertTrue(
                    forbidden.isdisjoint(components[schema_name].get("properties", {})),
                    schema_name,
                )
