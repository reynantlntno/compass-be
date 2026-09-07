# Project: COMPASS
# File: apps/counseling/tests.py
# Module: apps.counseling
# Purpose: Focused authorization and output-boundary tests for contract boundary.
# Notes:
#   - Slice A hardens counseling authorization so inactive accounts and
#     legacy superusers are denied.
#   - Slice B adds only explicit session metadata/student-summary projections;
#     it does not change authorization, models, migrations, or API routes.
#   - Slice C adds coverage-based case read visibility and safe case metadata;
#     case mutations remain separately governed.
#   - Slice C makes case metadata visibility coverage-scoped while keeping
#     mutation and note/evaluation/urgent-support decisions separate.

import json
import os
from datetime import time, timedelta
from unittest import mock

from cryptography.fernet import Fernet
from django.contrib.auth.models import AnonymousUser
from django.db import models
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from apps.accounts.models import RoleChoices, User
from apps.access_control.models import CounselorCoverage
from apps.profiles.models import CounselorProfile, StudentProfile
from apps.counseling.models import (
    CounselingCaseConcernCategory,
    CounselingCasePriority,
    CounselingCase,
    CounselingCaseCollaborator,
    CounselingCaseSession,
    CounselingCaseStatus,
    CounselingSession,
    ECounselingProviderChoices,
    ECounselingProviderModeChoices,
    ECounselingParticipant,
    ECounselingParticipantRoleChoices,
    ECounselingPurposeCodeChoices,
    ECounselingRecordingRunStatusChoices,
    ECounselingSession,
    ECounselingStatusChoices,
    TemporarySupportAccessGrant,
    UrgentSupportRequest,
    TemporarySupportAccessStatus,
    TemporarySupportAccessType,
    TemporarySupportAccessPurpose,
    UrgentSupportSourceType,
    UrgentSupportStatus,
    UrgentSupportUrgencyLevel,
    RoutineInterviewRecord,
    RoutineInterviewStatusChoices,
    SessionModeChoices,
    SessionSourceChoices,
    SessionStatusChoices,
    SessionTypeChoices,
)
from apps.counseling.commands import (
    CounselingNoteCommand,
    ECounselingParticipantAddCommand,
    ECounselingParticipantRevokeCommand,
    StudentVisibleSummaryCommand,
)
from apps.counseling.policies import (
    can_add_ecounseling_participant,
    can_cancel_ecounseling_session,
    can_assign_case_to,
    can_assign_session_to,
    can_cancel_session,
    can_close_counseling_case,
    can_create_counseling_case,
    can_create_session_for,
    can_create_urgent_support_triage_session,
    can_decide_recording_consent,
    can_edit_counseling_notes,
    can_edit_counseling_case,
    can_edit_routine_interview_evaluation,
    can_edit_session,
    can_finalize_routine_interview,
    can_finalize_session,
    can_grant_temporary_support_access,
    can_join_ecounseling_session,
    can_lock_session,
    can_manage_ecounseling_participants,
    can_mark_session_no_show,
    can_moderate_ecounseling_session,
    can_end_ecounseling_session,
    can_reopen_routine_interview,
    can_request_recording_consent,
    can_link_session_to_counseling_case,
    can_resolve_counseling_case,
    can_transition_case,
    can_review_urgent_support_request,
    can_use_temporary_support_access_grant,
    can_view_counseling_case,
    can_view_counseling_notes,
    can_view_ecounseling_session,
    can_view_urgent_support_request,
    can_view_routine_interview_evaluation,
    can_view_routine_interview_intake,
    can_view_routine_interview_metadata,
    can_view_session,
)
from apps.counseling.encryption import (
    CounselingEncryptionError,
    NOTE_CONFIDENTIAL_FIELDS,
    GROUPS,
    ROUTINE_EVALUATION,
    ROUTINE_INTAKE,
    SESSION_CONFIDENTIAL_FIELDS,
    prepare_group_write,
    read_counselor_note,
    read_routine_evaluation,
    read_routine_correction,
    read_routine_intake,
    read_student_visible_summary,
)
from apps.counseling.recording_services import recording_file_policy
from apps.counseling.ecounseling_services import (
    ECounselingPermissionError,
    ECounselingValidationError,
    add_ecounseling_participant,
    revoke_ecounseling_participant,
)
from apps.counseling.selectors import (
    get_counseling_cases_visible_to,
    get_counseling_case_metadata_by_reference_code,
    get_counseling_case_metadata_visible_to,
    get_counselor_note_by_reference_code,
    get_counselor_notes_visible_to,
    get_counselor_assigned_sessions,
    get_urgent_support_requests_for_head_review,
    get_urgent_support_requests_visible_to,
    get_sessions_visible_to,
    get_session_metadata_by_reference_code,
    get_session_metadata_visible_to,
    get_routine_interview_metadata_by_session_reference,
    get_routine_interview_metadata_visible_to,
    get_routine_interview_sensitive_detail_by_session_reference,
)
from apps.counseling.projections import (
    CASE_METADATA_FIELDS,
    STUDENT_CASE_METADATA_FIELDS,
    COUNSELOR_NOTE_FIELDS,
    STAFF_SESSION_METADATA_FIELDS,
    STUDENT_SESSION_METADATA_FIELDS,
    STUDENT_SESSION_SUMMARY_FIELDS,
    project_staff_session_metadata,
    project_student_session_metadata,
    project_student_session_summary,
    project_case_metadata,
    project_student_case_metadata,
    project_counselor_note,
    ROUTINE_SENSITIVE_DETAIL_FIELDS,
    ROUTINE_STAFF_METADATA_FIELDS,
    ROUTINE_STUDENT_INTAKE_FIELDS,
    project_routine_interview_metadata,
    project_routine_interview_sensitive_detail,
    project_student_routine_interview,
)
from apps.counseling.services import (
    _actor_category,
    SessionPermissionError,
    save_counselor_private_note,
    save_session_note,
    save_shared_summary,
)
from apps.security.models import FileStatusChoices
from apps.security.models import EncryptionKeyVersion, KeyPurposeChoices, KeyStatusChoices


def _build_user(email, role, *, is_active=True):
    return User.objects.create_user(
        email=email,
        password="correct-horse-battery-staple",
        first_name="Test",
        last_name="User",
        role=role,
        is_active=is_active,
    )


def _make_legacy_superuser(actor):
    actor.is_superuser = True
    actor.save(update_fields=["is_superuser"])
    return actor


def _counselor(email, *, is_active=True, is_head=False):
    actor = _build_user(email, RoleChoices.COUNSELOR, is_active=is_active)
    CounselorProfile.objects.create(user=actor, is_head_guidance=is_head)
    return actor


def _student(email, *, is_active=True):
    actor = _build_user(email, RoleChoices.STUDENT, is_active=is_active)
    StudentProfile.objects.create(user=actor, campus="Main Campus", college="CCMS")
    return actor

def _active_recording_file(session):
    """Return a mocked ACTIVE protected file bound to an AVAILABLE recording run.

    Used to exercise ``recording_file_policy`` while the server-authoritative
    recording gate is lifted for the test (see the individual tests).
    """
    session_proxy = mock.Mock()
    session_proxy.assigned_counselor_id = session.assigned_counselor_id
    child = mock.Mock()
    child.counseling_session = session_proxy
    run = mock.Mock()
    run.status = ECounselingRecordingRunStatusChoices.AVAILABLE
    run.expires_at = timezone.now() + timedelta(hours=1)
    run.ecounseling_session = child
    protected_file = mock.Mock()
    protected_file.status = FileStatusChoices.ACTIVE
    protected_file.ecounseling_recording_run = run
    return protected_file



class SliceAFailClosedTests(TestCase):
    """Inactive and legacy-superuser actors are denied on every counseling branch.

    The deny cases pass ``None`` as the resource deliberately: Slice A guards
    fail closed at the authorization boundary before any record attribute is
    dereferenced, and the positive controls below prove the same functions
    still return True for legitimate active actors.
    """

    def setUp(self):
        self.student = _student("student@example.test")
        self.student_inactive = _student("student-inactive@example.test", is_active=False)
        self.student_legacy = _make_legacy_superuser(_student("student-legacy@example.test"))

        self.counselor = _counselor("counselor@example.test")
        CounselorCoverage.objects.create(
            counselor=self.counselor,
            campus="Main Campus",
            college="CCMS",
            starts_at=timezone.localdate(),
        )
        self.counselor_inactive = _counselor("counselor-inactive@example.test", is_active=False)
        self.counselor_legacy = _make_legacy_superuser(_counselor("counselor-legacy@example.test"))
        self.gco_staff = _build_user("gco@example.test", RoleChoices.GCO_STAFF)

        self.head = _counselor("head@example.test", is_head=True)
        # The database allows exactly one active Head Guidance designation.
        # Inactive/legacy variants still exercise fail-closed behavior without
        # creating a second designated Head.
        self.head_inactive = _counselor("head-inactive@example.test", is_active=False)
        self.head_legacy = _make_legacy_superuser(_counselor("head-legacy@example.test"))

        self.session = CounselingSession.objects.create(
            reference_code="SES-TEST-000001",
            student=self.student,
            assigned_counselor=self.counselor,
            session_type=SessionTypeChoices.COUNSELING,
            session_mode=SessionModeChoices.ONSITE,
            session_source=SessionSourceChoices.COUNSELOR_INITIATED,
            status=SessionStatusChoices.COMPLETED,
        )
        self.session_scheduled = CounselingSession.objects.create(
            reference_code="SES-TEST-000002",
            student=self.student,
            assigned_counselor=self.counselor,
            session_type=SessionTypeChoices.COUNSELING,
            session_mode=SessionModeChoices.ONSITE,
            session_source=SessionSourceChoices.COUNSELOR_INITIATED,
            status=SessionStatusChoices.SCHEDULED,
        )
        self.session_finalized = CounselingSession.objects.create(
            reference_code="SES-TEST-000003",
            student=self.student,
            assigned_counselor=self.counselor,
            session_type=SessionTypeChoices.COUNSELING,
            session_mode=SessionModeChoices.ONSITE,
            session_source=SessionSourceChoices.COUNSELOR_INITIATED,
            status=SessionStatusChoices.FINALIZED,
        )
        self.routine_session = CounselingSession.objects.create(
            reference_code="SES-ROUTINE-000001",
            student=self.student,
            assigned_counselor=self.counselor,
            session_type=SessionTypeChoices.ROUTINE_INTERVIEW,
            session_mode=SessionModeChoices.ONSITE,
            session_source=SessionSourceChoices.ROUTINE_COLLECTION,
            status=SessionStatusChoices.SCHEDULED,
        )
        self.routine_record = RoutineInterviewRecord.objects.create(
            session=self.routine_session,
            status=RoutineInterviewStatusChoices.INTAKE_SUBMITTED,
        )

        self.counseling_case = CounselingCase.objects.create(
            reference_code="CAS-TEST-000001",
            student=self.student,
            assigned_counselor=self.counselor,
            concern_category=CounselingCaseConcernCategory.ACADEMIC,
            priority=CounselingCasePriority.MEDIUM,
            status=CounselingCaseStatus.OPEN,
            opened_by=self.counselor,
        )

        self.online_session = CounselingSession.objects.create(
            reference_code="SES-ECO-000001",
            student=self.student,
            assigned_counselor=self.counselor,
            session_type=SessionTypeChoices.COUNSELING,
            session_mode=SessionModeChoices.ONLINE,
            session_source=SessionSourceChoices.ECOUNSELING,
            status=SessionStatusChoices.SCHEDULED,
        )
        now = timezone.now()
        self.ecounseling_session = ECounselingSession.objects.create(
            reference_code="ECO-TEST-000001",
            counseling_session=self.online_session,
            provider=ECounselingProviderChoices.DAILY,
            provider_mode=ECounselingProviderModeChoices.DAILY_CLOUD,
            room_slug="room-slice-a-test-000001",
            scheduled_start_at=now,
            scheduled_end_at=now + timedelta(hours=1),
            join_window_start_at=now - timedelta(minutes=5),
            join_window_end_at=now + timedelta(hours=1),
            status=ECounselingStatusChoices.SCHEDULED,
        )

        self.urgent_support = UrgentSupportRequest.objects.create(
            reference_code="URG-TEST-000001",
            student=self.student,
            source_type=UrgentSupportSourceType.COUNSELOR_MANUAL,
            urgency_level=UrgentSupportUrgencyLevel.PROMPT_REVIEW,
            status=UrgentSupportStatus.OPEN,
            initiated_by=self.counselor,
        )

    def test_inactive_counselor_denied_session_policies(self):
        self.assertFalse(can_view_session(self.counselor_inactive, None))
        self.assertFalse(can_edit_session(self.counselor_inactive, None))
        self.assertFalse(can_finalize_session(self.counselor_inactive, None))
        self.assertFalse(can_cancel_session(self.counselor_inactive, None))
        self.assertFalse(can_mark_session_no_show(self.counselor_inactive, None))
        self.assertFalse(can_view_counseling_notes(self.counselor_inactive, None))

    def test_gco_staff_cannot_create_general_counseling_session(self):
        self.assertFalse(
            can_create_session_for(
                self.gco_staff,
                self.student,
                source=SessionSourceChoices.COUNSELOR_INITIATED,
            )
        )

    def test_inactive_counselor_denied_routine_policies(self):
        self.assertFalse(can_view_routine_interview_evaluation(self.counselor_inactive, None))
        self.assertFalse(can_edit_routine_interview_evaluation(self.counselor_inactive, None))
        self.assertFalse(can_finalize_routine_interview(self.counselor_inactive, None))

    def test_inactive_counselor_denied_case_and_urgent_support_policies(self):
        self.assertFalse(can_view_counseling_case(self.counselor_inactive, None))
        self.assertFalse(can_edit_counseling_case(self.counselor_inactive, None))
        self.assertFalse(can_close_counseling_case(self.counselor_inactive, None))
        self.assertFalse(can_view_urgent_support_request(self.counselor_inactive, None))
        self.assertFalse(can_use_temporary_support_access_grant(self.counselor_inactive, None))
        self.assertFalse(can_create_urgent_support_triage_session(self.counselor_inactive, None))

    def test_inactive_counselor_denied_ecounseling_and_recording_policies(self):
        self.assertFalse(can_view_ecounseling_session(self.counselor_inactive, None))
        self.assertFalse(can_moderate_ecounseling_session(self.counselor_inactive, None))
        self.assertFalse(can_request_recording_consent(self.counselor_inactive, None))
        self.assertFalse(can_manage_ecounseling_participants(self.counselor_inactive, None))

    def test_inactive_student_denied_recording_consent_decision(self):
        self.assertFalse(can_decide_recording_consent(self.student_inactive, None))


    def test_inactive_and_legacy_head_denied_office_wide_policies(self):
        self.assertFalse(can_view_session(self.head_inactive, None))
        self.assertFalse(can_lock_session(self.head_inactive, None))
        self.assertFalse(can_reopen_routine_interview(self.head_inactive, None))
        self.assertFalse(can_view_urgent_support_request(self.head_inactive, None))
        self.assertFalse(can_review_urgent_support_request(self.head_inactive, None))
        self.assertFalse(can_view_session(self.head_legacy, None))
        self.assertFalse(can_lock_session(self.head_legacy, None))
        self.assertFalse(can_close_counseling_case(self.head_legacy, None))
        self.assertFalse(can_manage_ecounseling_participants(self.head_legacy, None))

    def test_legacy_superuser_counselor_denied_scoped_policies(self):
        self.assertFalse(can_view_session(self.counselor_legacy, None))
        self.assertFalse(can_edit_session(self.counselor_legacy, None))
        self.assertFalse(can_view_counseling_case(self.counselor_legacy, None))
        self.assertFalse(can_view_routine_interview_evaluation(self.counselor_legacy, None))
        self.assertFalse(can_use_temporary_support_access_grant(self.counselor_legacy, None))

    def test_legacy_superuser_student_denied(self):
        self.assertFalse(can_view_session(self.student_legacy, None))
        self.assertFalse(can_decide_recording_consent(self.student_legacy, None))

    def test_legacy_superuser_targets_rejected_in_target_authorization_paths(self):
        self.assertFalse(can_assign_session_to(self.head, self.session_scheduled, self.counselor_legacy))
        self.assertFalse(can_assign_case_to(self.head, self.counseling_case, self.counselor_legacy))
        self.assertFalse(can_grant_temporary_support_access(self.head, self.urgent_support, self.counselor_legacy))
        self.assertFalse(can_add_ecounseling_participant(self.head, self.ecounseling_session, self.counselor_legacy))

    def test_inactive_targets_rejected_in_target_authorization_paths(self):
        self.assertFalse(can_assign_session_to(self.head, self.session_scheduled, self.counselor_inactive))
        self.assertFalse(can_assign_case_to(self.head, self.counseling_case, self.counselor_inactive))
        self.assertFalse(can_grant_temporary_support_access(self.head, self.urgent_support, self.counselor_inactive))

    def test_active_valid_actors_preserved(self):
        # Positive controls: Slice A must not reduce legitimate access.
        self.assertTrue(can_view_session(self.student, self.session))
        self.assertTrue(can_view_session(self.counselor, self.session))
        self.assertTrue(can_view_counseling_notes(self.counselor, self.session))
        self.assertTrue(can_edit_session(self.counselor, self.session))
        self.assertTrue(can_finalize_session(self.counselor, self.session))
        self.assertTrue(can_view_counseling_case(self.counselor, self.counseling_case))
        self.assertTrue(can_edit_counseling_case(self.counselor, self.counseling_case))
        self.assertTrue(can_view_routine_interview_evaluation(self.counselor, self.routine_record))
        self.assertTrue(can_edit_routine_interview_evaluation(self.counselor, self.routine_record))

    def test_active_head_office_wide_authority_preserved(self):
        self.assertTrue(can_view_session(self.head, self.session))
        self.assertTrue(can_view_counseling_case(self.head, self.counseling_case))
        self.assertTrue(can_lock_session(self.head, self.session_finalized))
        self.assertTrue(can_close_counseling_case(self.head, self.counseling_case))
        self.assertTrue(can_assign_session_to(self.head, self.session_scheduled, self.counselor))
        self.assertTrue(can_assign_case_to(self.head, self.counseling_case, self.counselor))

    def test_active_recording_consent_guards_preserved(self):
        self.assertTrue(can_request_recording_consent(self.counselor, self.ecounseling_session))
        self.assertTrue(can_decide_recording_consent(self.student, self.ecounseling_session))
        self.assertFalse(can_request_recording_consent(self.student, self.ecounseling_session))
        self.assertFalse(can_decide_recording_consent(self.counselor, self.ecounseling_session))
    def test_encryption_readers_reject_inactive_and_legacy(self):
        with self.assertRaises(CounselingEncryptionError):
            read_student_visible_summary(self.student_legacy, None)
        with self.assertRaises(CounselingEncryptionError):
            read_student_visible_summary(self.student_inactive, None)
        with self.assertRaises(CounselingEncryptionError):
            read_counselor_note(self.counselor_legacy, None)
        with self.assertRaises(CounselingEncryptionError):
            read_counselor_note(self.counselor_inactive, None)

    def test_routine_correction_guard_runs_before_any_db_read(self):
        # The fail-closed guard must raise before touching ``record.pk``, so a
        # None record (which would otherwise fail on attribute access) is proof
        # the legacy/inactive rejection is not a database-lookup artifact.
        with self.assertRaises(CounselingEncryptionError):
            read_routine_correction(self.head_legacy, None)
        with self.assertRaises(CounselingEncryptionError):
            read_routine_correction(self.head_inactive, None)
        with self.assertRaises(CounselingEncryptionError):
            read_routine_correction(self.counselor, None)

    def test_active_encryption_reader_positive_controls(self):
        # No note exists for the session in the fixture; the active allow paths
        # still succeed (returning empty/None) rather than raising.
        self.assertEqual(read_student_visible_summary(self.student, self.session), "")
        self.assertIsNone(read_counselor_note(self.counselor, self.session))

    def test_recording_file_policy_rejects_inactive_and_legacy(self):
        file = _active_recording_file(self.online_session)
        with mock.patch(
            "apps.counseling.recording_services.recording_is_blocked",
            return_value=False,
        ):
            # Legacy and inactive actors are denied by the fail-closed guard,
            # not by the (now lifted) server recording gate.
            self.assertFalse(recording_file_policy(self.head_legacy, file, "read_content"))
            self.assertFalse(recording_file_policy(self.counselor_inactive, file, "read_content"))

    def test_recording_file_policy_allows_active_actors(self):
        file = _active_recording_file(self.online_session)
        with mock.patch(
            "apps.counseling.recording_services.recording_is_blocked",
            return_value=False,
        ):
            # Recording content remains assigned-counselor only.
            self.assertFalse(recording_file_policy(self.head, file, "read_content"))
            self.assertTrue(recording_file_policy(self.counselor, file, "read_content"))

    def test_actor_category_classifies_inactive_and_legacy_as_other(self):
        # Intentional audit-projection change: only active, non-legacy actors
        # are classified by role/designation; inactive/legacy become "other".
        self.assertEqual(_actor_category(self.counselor), "counselor")
        self.assertEqual(_actor_category(self.head), "head_guidance")
        self.assertEqual(_actor_category(self.student), "student")
        self.assertEqual(_actor_category(self.counselor_inactive), "other")
        self.assertEqual(_actor_category(self.counselor_legacy), "other")
        self.assertEqual(_actor_category(self.head_legacy), "other")



class SliceASelectorFailClosedTests(TestCase):
    """List selectors return empty streams for inactive and legacy actors."""

    def setUp(self):
        self.counselor = _counselor("counselor@example.test")
        self.counselor_inactive = _counselor("counselor-inactive@example.test", is_active=False)
        self.counselor_legacy = _make_legacy_superuser(_counselor("counselor-legacy@example.test"))
        self.head = _counselor("head@example.test", is_head=True)
        self.head_inactive = _counselor("head-inactive@example.test", is_active=False)
        self.student = _student("student@example.test")

        self.session = CounselingSession.objects.create(
            reference_code="SES-SEL-000001",
            student=self.student,
            assigned_counselor=self.counselor,
            session_type=SessionTypeChoices.COUNSELING,
            session_mode=SessionModeChoices.ONSITE,
            session_source=SessionSourceChoices.COUNSELOR_INITIATED,
            status=SessionStatusChoices.SCHEDULED,
        )
        self.counseling_case = CounselingCase.objects.create(
            reference_code="CAS-SEL-000001",
            student=self.student,
            assigned_counselor=self.counselor,
            concern_category=CounselingCaseConcernCategory.ACADEMIC,
            priority=CounselingCasePriority.MEDIUM,
            status=CounselingCaseStatus.OPEN,
            opened_by=self.counselor,
        )
        self.urgent_support = UrgentSupportRequest.objects.create(
            reference_code="URG-SEL-000001",
            student=self.student,
            source_type=UrgentSupportSourceType.COUNSELOR_MANUAL,
            urgency_level=UrgentSupportUrgencyLevel.PROMPT_REVIEW,
            status=UrgentSupportStatus.OPEN,
            initiated_by=self.counselor,
        )

    def test_inactive_and_legacy_counselor_get_empty_streams(self):
        self.assertFalse(get_sessions_visible_to(self.counselor_inactive).exists())
        self.assertFalse(get_sessions_visible_to(self.counselor_legacy).exists())
        self.assertFalse(get_counselor_assigned_sessions(self.counselor_inactive).exists())
        self.assertFalse(get_counselor_assigned_sessions(self.counselor_legacy).exists())
        self.assertFalse(get_counseling_cases_visible_to(self.counselor_inactive).exists())
        self.assertFalse(get_counseling_cases_visible_to(self.counselor_legacy).exists())

    def test_inactive_head_denied_office_wide_streams(self):
        self.assertFalse(get_sessions_visible_to(self.head_inactive).exists())
        self.assertFalse(get_urgent_support_requests_for_head_review(self.head_inactive).exists())

    def test_active_streams_preserved(self):
        self.assertTrue(get_sessions_visible_to(self.counselor).filter(pk=self.session.pk).exists())
        self.assertTrue(get_counselor_assigned_sessions(self.counselor).filter(pk=self.session.pk).exists())
        self.assertTrue(get_counseling_cases_visible_to(self.counselor).filter(pk=self.counseling_case.pk).exists())
        self.assertTrue(get_sessions_visible_to(self.head).filter(pk=self.session.pk).exists())
        self.assertTrue(
            get_urgent_support_requests_for_head_review(self.head).filter(pk=self.urgent_support.pk).exists()
        )


class SessionProjectionTests(TestCase):
    """Verify the Slice B session metadata and student-summary boundaries."""

    def setUp(self):
        self.now = timezone.now().replace(microsecond=0)
        self.student = _student("projection-student@example.test")
        self.out_of_scope_student = _student("projection-out@example.test")
        self.out_of_scope_student.student_profile.college = "ENG"
        self.out_of_scope_student.student_profile.save(update_fields=["college"])

        self.assigned_counselor = _counselor("projection-assigned@example.test")
        self.coverage_counselor = _counselor("projection-coverage@example.test")
        CounselorCoverage.objects.create(
            counselor=self.coverage_counselor,
            campus="Main Campus",
            college="CCMS",
            starts_at=self.now.date(),
        )
        self.grant_counselor = _counselor("projection-grant@example.test")
        self.head = _counselor("projection-head@example.test", is_head=True)
        self.out_of_scope_counselor = _counselor("projection-out-counselor@example.test")
        self.inactive_counselor = _counselor(
            "projection-inactive@example.test", is_active=False
        )
        self.legacy_counselor = _make_legacy_superuser(
            _counselor("projection-legacy@example.test")
        )
        self.gco_staff = _build_user(
            "projection-gco@example.test", RoleChoices.GCO_STAFF
        )
        self.it_admin = _build_user(
            "projection-it@example.test", RoleChoices.IT_ADMIN
        )

        self.assigned_session = self._session(
            "SES-PROJ-000001", self.student, self.assigned_counselor
        )
        self.coverage_session = self._session(
            "SES-PROJ-000002", self.student, self.assigned_counselor
        )
        self.out_of_scope_session = self._session(
            "SES-PROJ-000003", self.out_of_scope_student, self.assigned_counselor
        )
        self.grant_session = self._session(
            "SES-PROJ-000004", self.out_of_scope_student, self.assigned_counselor
        )

        self.urgent_support = UrgentSupportRequest.objects.create(
            reference_code="URG-PROJ-000001",
            student=self.out_of_scope_student,
            source_type=UrgentSupportSourceType.COUNSELOR_MANUAL,
            urgency_level=UrgentSupportUrgencyLevel.PROMPT_REVIEW,
            status=UrgentSupportStatus.OPEN,
            initiated_by=self.assigned_counselor,
            originating_session=self.grant_session,
        )
        TemporarySupportAccessGrant.objects.create(
            urgent_support=self.urgent_support,
            grantee=self.grant_counselor,
            granted_by=self.head,
            grant_type=TemporarySupportAccessType.SESSION_REVIEW,
            purpose_code=TemporarySupportAccessPurpose.URGENT_TRIAGE,
            starts_at=self.now - timedelta(minutes=5),
            expires_at=self.now + timedelta(hours=1),
            status=TemporarySupportAccessStatus.ACTIVE,
        )

    def _session(self, reference_code, student, assigned_counselor):
        scheduled_start = self.now
        scheduled_end = self.now + timedelta(minutes=60)
        actual_start = self.now + timedelta(minutes=5)
        actual_end = self.now + timedelta(minutes=55)
        return CounselingSession.objects.create(
            reference_code=reference_code,
            student=student,
            assigned_counselor=assigned_counselor,
            session_type=SessionTypeChoices.COUNSELING,
            session_mode=SessionModeChoices.ONSITE,
            session_source=SessionSourceChoices.COUNSELOR_INITIATED,
            status=SessionStatusChoices.LOCKED,
            concern_summary="confidential concern summary",
            scheduled_start_at=scheduled_start,
            scheduled_end_at=scheduled_end,
            actual_started_at=actual_start,
            actual_ended_at=actual_end,
            actual_duration_minutes=50,
            ended_early_flag=True,
            ended_early_reason="confidential early-end reason",
            cancellation_reason="confidential cancellation reason",
            completed_at=actual_end,
            finalized_at=actual_end,
            locked_at=actual_end,
        )

    def _assert_plain_safe_projection(self, projection, expected_fields):
        self.assertEqual(set(projection), set(expected_fields))
        self.assertTrue(
            set(SESSION_CONFIDENTIAL_FIELDS).isdisjoint(projection)
        )
        self.assertTrue(
            all(not isinstance(value, models.Model) for value in projection.values())
        )

    def test_staff_metadata_exact_keys_for_assignment_coverage_head_and_grant(self):
        cases = (
            (self.assigned_counselor, self.assigned_session),
            (self.coverage_counselor, self.coverage_session),
            (self.head, self.out_of_scope_session),
            (self.grant_counselor, self.grant_session),
        )
        for actor, session in cases:
            with self.subTest(actor=actor.email, reference_code=session.reference_code):
                projection = project_staff_session_metadata(actor, session)
                self.assertIsNotNone(projection)
                self._assert_plain_safe_projection(
                    projection, STAFF_SESSION_METADATA_FIELDS
                )

    def test_staff_metadata_never_contains_confidential_or_model_values(self):
        projection = project_staff_session_metadata(
            self.assigned_counselor, self.assigned_session
        )
        self.assertNotIn("concern_summary", projection)
        self.assertNotIn("ended_early_reason", projection)
        self.assertNotIn("cancellation_reason", projection)
        for field in SESSION_CONFIDENTIAL_FIELDS:
            self.assertNotIn(field, projection)

    def test_student_metadata_is_owner_only_and_excludes_staff_identifiers(self):
        projection = project_student_session_metadata(
            self.student, self.assigned_session
        )
        self.assertIsNotNone(projection)
        self._assert_plain_safe_projection(
            projection, STUDENT_SESSION_METADATA_FIELDS
        )
        self.assertNotIn("student_id", projection)
        self.assertNotIn("appointment_id", projection)
        self.assertNotIn("assigned_counselor_id", projection)
        self.assertNotIn("session_source", projection)
        self.assertIsNone(
            project_student_session_metadata(
                self.out_of_scope_student, self.assigned_session
            )
        )
        self.assertIsNone(
            project_student_session_metadata(
                self.assigned_counselor, self.assigned_session
            )
        )

    def test_student_summary_uses_only_the_student_safe_reader(self):
        with mock.patch(
            "apps.counseling.projections.read_student_visible_summary",
            return_value="student-safe summary",
        ) as reader:
            projection = project_student_session_summary(
                self.student, self.assigned_session
            )
        reader.assert_called_once_with(self.student, self.assigned_session)
        self.assertEqual(set(projection), set(STUDENT_SESSION_SUMMARY_FIELDS))
        self.assertTrue(
            set(SESSION_CONFIDENTIAL_FIELDS).isdisjoint(projection)
        )
        self.assertEqual(projection["student_visible_summary"], "student-safe summary")
        self.assertNotIn("counselor_narrative", projection)
        self.assertNotIn("recommendations", projection)
        self.assertNotIn("special_concerns", projection)
        self.assertNotIn("follow_up_notes", projection)
        for field in NOTE_CONFIDENTIAL_FIELDS:
            if field != "student_visible_summary":
                self.assertNotIn(field, projection)
        self.assertIsNone(
            project_student_session_summary(
                self.assigned_counselor, self.assigned_session
            )
        )
        self.assertIsNone(
            project_student_session_summary(self.out_of_scope_student, self.assigned_session)
        )

    def test_unauthorized_actors_receive_no_projection_or_list_rows(self):
        actors = (
            AnonymousUser(),
            self.inactive_counselor,
            self.legacy_counselor,
            self.gco_staff,
            self.it_admin,
            self.out_of_scope_counselor,
        )
        for actor in actors:
            with self.subTest(actor=repr(actor)):
                self.assertIsNone(
                    project_staff_session_metadata(actor, self.assigned_session)
                )
                self.assertIsNone(
                    project_student_session_metadata(actor, self.assigned_session)
                )
                self.assertIsNone(
                    project_student_session_summary(actor, self.assigned_session)
                )
                self.assertEqual(get_session_metadata_visible_to(actor), [])

    def test_metadata_list_and_reference_selector_preserve_row_visibility_scope(self):
        coverage_rows = get_session_metadata_visible_to(self.coverage_counselor)
        coverage_codes = {row["reference_code"] for row in coverage_rows}
        self.assertIn(self.assigned_session.reference_code, coverage_codes)
        self.assertIn(self.coverage_session.reference_code, coverage_codes)
        self.assertNotIn(self.out_of_scope_session.reference_code, coverage_codes)
        self.assertNotIn(self.grant_session.reference_code, coverage_codes)
        self.assertTrue(all(isinstance(row, dict) for row in coverage_rows))

        self.assertIsNotNone(
            get_session_metadata_by_reference_code(
                self.coverage_counselor, self.assigned_session.reference_code
            )
        )
        self.assertIsNone(
            get_session_metadata_by_reference_code(
                self.coverage_counselor, self.out_of_scope_session.reference_code
            )
        )
        self.assertIsNotNone(
            get_session_metadata_by_reference_code(
                self.head, self.out_of_scope_session.reference_code
            )
        )

        student_rows = get_session_metadata_visible_to(self.student)
        student_codes = {row["reference_code"] for row in student_rows}
        self.assertEqual(
            student_codes,
            {self.assigned_session.reference_code, self.coverage_session.reference_code},
        )
        self.assertIsNone(
            get_session_metadata_by_reference_code(
                self.student, self.out_of_scope_session.reference_code
            )
        )

    def test_head_outside_assignment_or_coverage_receives_safe_metadata_only(self):
        projection = project_staff_session_metadata(
            self.head, self.out_of_scope_session
        )
        self.assertIsNotNone(projection)
        self._assert_plain_safe_projection(projection, STAFF_SESSION_METADATA_FIELDS)
        self.assertNotIn("concern_summary", projection)
        self.assertNotIn("internal_notes", projection)


class CaseVisibilityTests(TestCase):
    """Verify coverage-based case reads and the safe case metadata boundary."""

    def setUp(self):
        self.today = timezone.localdate()
        self.student = _student("case-scope-student@example.test")
        self.out_of_scope_student = _student("case-scope-out@example.test")
        self.out_of_scope_student.student_profile.college = "ENG"
        self.out_of_scope_student.student_profile.save(update_fields=["college"])

        self.assigned_counselor = _counselor("case-assigned@example.test")
        self.coverage_counselor = _counselor("case-coverage@example.test")
        CounselorCoverage.objects.create(
            counselor=self.coverage_counselor,
            campus="Main Campus",
            college="CCMS",
            starts_at=self.today,
        )
        self.expired_coverage_counselor = _counselor(
            "case-expired-coverage@example.test"
        )
        CounselorCoverage.objects.create(
            counselor=self.expired_coverage_counselor,
            campus="Main Campus",
            college="CCMS",
            starts_at=self.today - timedelta(days=10),
            ends_at=self.today - timedelta(days=1),
        )
        self.inactive_coverage_counselor = _counselor(
            "case-inactive-coverage@example.test"
        )
        CounselorCoverage.objects.create(
            counselor=self.inactive_coverage_counselor,
            campus="Main Campus",
            college="CCMS",
            starts_at=self.today,
            is_active=False,
        )
        self.case_collaborator = _counselor("case-co@example.test")
        self.grant_counselor = _counselor("case-grant@example.test")
        self.head = _counselor("case-head@example.test", is_head=True)
        self.out_of_scope_counselor = _counselor(
            "case-out-counselor@example.test"
        )
        self.inactive_counselor = _counselor(
            "case-inactive@example.test", is_active=False
        )
        self.legacy_counselor = _make_legacy_superuser(
            _counselor("case-legacy@example.test")
        )
        self.gco_staff = _build_user("case-gco@example.test", RoleChoices.GCO_STAFF)
        self.it_admin = _build_user("case-it@example.test", RoleChoices.IT_ADMIN)

        self.covered_case = self._case(
            "CAS-SCOPE-000001", self.student, self.assigned_counselor
        )
        self.out_of_scope_case = self._case(
            "CAS-SCOPE-000002",
            self.out_of_scope_student,
            self.assigned_counselor,
        )
        self.co_case = self._case(
            "CAS-SCOPE-000003",
            self.out_of_scope_student,
            self.assigned_counselor,
        )
        CounselingCaseCollaborator.objects.create(
            counseling_case=self.co_case,
            counselor=self.case_collaborator,
            is_active=True,
            added_by=self.head,
        )
        self.grant_case = self._case(
            "CAS-SCOPE-000004",
            self.out_of_scope_student,
            self.assigned_counselor,
        )
        self.urgent_support = UrgentSupportRequest.objects.create(
            reference_code="URG-SCOPE-000001",
            student=self.out_of_scope_student,
            source_type=UrgentSupportSourceType.COUNSELOR_MANUAL,
            urgency_level=UrgentSupportUrgencyLevel.PROMPT_REVIEW,
            status=UrgentSupportStatus.OPEN,
            initiated_by=self.assigned_counselor,
            counseling_case=self.grant_case,
        )
        TemporarySupportAccessGrant.objects.create(
            urgent_support=self.urgent_support,
            grantee=self.grant_counselor,
            granted_by=self.head,
            grant_type=TemporarySupportAccessType.CASE_REVIEW,
            purpose_code=TemporarySupportAccessPurpose.URGENT_TRIAGE,
            starts_at=timezone.now() - timedelta(minutes=5),
            expires_at=timezone.now() + timedelta(hours=1),
            status=TemporarySupportAccessStatus.ACTIVE,
        )
        self.session = CounselingSession.objects.create(
            reference_code="SES-CASE-SCOPE-000001",
            student=self.student,
            assigned_counselor=self.assigned_counselor,
            session_type=SessionTypeChoices.COUNSELING,
            session_mode=SessionModeChoices.ONSITE,
            session_source=SessionSourceChoices.COUNSELOR_INITIATED,
            status=SessionStatusChoices.SCHEDULED,
        )

    def _case(self, reference_code, student, assigned_counselor):
        now = timezone.now().replace(microsecond=0)
        return CounselingCase.objects.create(
            reference_code=reference_code,
            student=student,
            assigned_counselor=assigned_counselor,
            concern_category=CounselingCaseConcernCategory.ACADEMIC,
            priority=CounselingCasePriority.MEDIUM,
            status=CounselingCaseStatus.OPEN,
            opened_by=self.head,
            resolved_at=None,
            closed_at=None,
            reopened_at=None,
            updated_at=now,
        )

    def test_coverage_grants_case_read_visibility_but_not_mutations(self):
        self.assertTrue(can_view_counseling_case(self.coverage_counselor, self.covered_case))
        self.assertFalse(
            can_view_counseling_case(self.coverage_counselor, self.out_of_scope_case)
        )
        self.assertTrue(
            can_create_counseling_case(
                self.coverage_counselor,
                self.student,
                self.coverage_counselor,
            )
        )
        self.assertFalse(can_edit_counseling_case(self.coverage_counselor, self.covered_case))
        self.assertFalse(
            can_transition_case(self.coverage_counselor, self.covered_case)
        )
        self.assertFalse(can_resolve_counseling_case(self.coverage_counselor, self.covered_case))
        self.assertFalse(
            can_link_session_to_counseling_case(
                self.coverage_counselor, self.covered_case, self.session
            )
        )
        self.assertFalse(
            can_assign_case_to(
                self.coverage_counselor,
                self.covered_case,
                self.assigned_counselor,
            )
        )

    def test_assignment_collaboration_grant_and_head_visibility_remain(self):
        self.assertTrue(
            can_view_counseling_case(self.assigned_counselor, self.out_of_scope_case)
        )
        self.assertTrue(can_view_counseling_case(self.case_collaborator, self.co_case))
        self.assertTrue(can_view_counseling_case(self.grant_counselor, self.grant_case))
        self.assertTrue(can_view_counseling_case(self.head, self.out_of_scope_case))

    def test_expired_or_inactive_coverage_does_not_grant_case_visibility(self):
        self.assertFalse(
            can_view_counseling_case(
                self.expired_coverage_counselor, self.covered_case
            )
        )
        self.assertFalse(
            can_view_counseling_case(
                self.inactive_coverage_counselor, self.covered_case
            )
        )
        self.assertFalse(
            get_counseling_cases_visible_to(self.expired_coverage_counselor).exists()
        )
        self.assertFalse(
            get_counseling_cases_visible_to(self.inactive_coverage_counselor).exists()
        )

    def test_student_owner_receives_only_safe_case_status_projection(self):
        self.assertTrue(can_view_counseling_case(self.student, self.covered_case))
        self.assertTrue(get_counseling_cases_visible_to(self.student).filter(pk=self.covered_case.pk).exists())
        projection = project_student_case_metadata(self.student, self.covered_case)
        self.assertEqual(set(projection), set(STUDENT_CASE_METADATA_FIELDS))
        self.assertNotIn("student_id", projection)
        self.assertNotIn("assigned_counselor_id", projection)

    def test_student_owner_receives_urgent_support_status_only(self):
        self.assertTrue(
            can_view_urgent_support_request(self.out_of_scope_student, self.urgent_support)
        )
        self.assertTrue(
            get_urgent_support_requests_visible_to(self.out_of_scope_student)
            .filter(pk=self.urgent_support.pk)
            .exists()
        )

    def test_non_business_or_fail_closed_actors_are_denied(self):
        actors = (
            AnonymousUser(),
            self.gco_staff,
            self.it_admin,
            self.inactive_counselor,
            self.legacy_counselor,
            self.out_of_scope_counselor,
        )
        for actor in actors:
            with self.subTest(actor=repr(actor)):
                self.assertFalse(can_view_counseling_case(actor, self.covered_case))
                self.assertFalse(get_counseling_cases_visible_to(actor).exists())
                self.assertIsNone(
                    project_case_metadata(actor, self.covered_case)
                )

    def test_case_metadata_projection_has_exact_safe_keys(self):
        cases = (
            (self.coverage_counselor, self.covered_case),
            (self.assigned_counselor, self.covered_case),
            (self.case_collaborator, self.co_case),
            (self.grant_counselor, self.grant_case),
            (self.head, self.out_of_scope_case),
        )
        forbidden = {
            "opened_by_id",
            "resolved_by_id",
            "closed_by_id",
            "reopened_by_id",
            "close_reason_code",
            "reopen_reason_code",
            "case_collaborators",
            "email",
        }
        for actor, counseling_case in cases:
            with self.subTest(actor=actor.email, reference_code=counseling_case.reference_code):
                projection = project_case_metadata(actor, counseling_case)
                self.assertIsNotNone(projection)
                self.assertEqual(set(projection), set(CASE_METADATA_FIELDS))
                self.assertTrue(
                    all(
                        not isinstance(value, models.Model)
                        for value in projection.values()
                    )
                )
                self.assertTrue(forbidden.isdisjoint(projection))

    def test_case_metadata_selectors_preserve_coverage_and_reference_scope(self):
        coverage_rows = get_counseling_case_metadata_visible_to(self.coverage_counselor)
        coverage_codes = {row["reference_code"] for row in coverage_rows}
        self.assertEqual(coverage_codes, {self.covered_case.reference_code})
        self.assertTrue(all(isinstance(row, dict) for row in coverage_rows))

        self.assertIsNotNone(
            get_counseling_case_metadata_by_reference_code(
                self.coverage_counselor,
                self.covered_case.reference_code,
            )
        )
        self.assertIsNone(
            get_counseling_case_metadata_by_reference_code(
                self.coverage_counselor,
                self.out_of_scope_case.reference_code,
            )
        )

        head_codes = {
            row["reference_code"]
            for row in get_counseling_case_metadata_visible_to(self.head)
        }
        self.assertEqual(
            head_codes,
            {
                self.covered_case.reference_code,
                self.out_of_scope_case.reference_code,
                self.co_case.reference_code,
                self.grant_case.reference_code,
            },
        )


class CounselingNoteBoundaryTests(TestCase):
    """Verify raw-note read scope is narrower than session visibility/write scope."""

    def setUp(self):
        self.now = timezone.now().replace(microsecond=0)
        self._encryption_key_patcher = mock.patch.dict(
            os.environ,
            {"COMPASS_TEST_FIELD_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii")},
        )
        self._encryption_key_patcher.start()
        self.addCleanup(self._encryption_key_patcher.stop)
        self.student = _student("notes-student@example.test")
        self.student_legacy = _make_legacy_superuser(
            _student("notes-student-legacy@example.test")
        )
        self.assigned_counselor = _counselor("notes-assigned@example.test")
        self.coverage_counselor = _counselor("notes-coverage@example.test")
        CounselorCoverage.objects.create(
            counselor=self.coverage_counselor,
            campus="Main Campus",
            college="CCMS",
            starts_at=self.now.date(),
        )
        self.case_collaborator = _counselor("notes-co@example.test")
        self.grant_counselor = _counselor("notes-grant@example.test")
        self.case_grant_counselor = _counselor("notes-case-grant@example.test")
        self.head_assigned = _counselor("notes-head-assigned@example.test", is_head=True)
        # One Head can be assigned to one session and outside the scope of
        # another; do not create a second active Head profile.
        self.head_outside = self.head_assigned
        self.out_of_scope_counselor = _counselor("notes-outside@example.test")
        self.inactive_counselor = _counselor(
            "notes-inactive@example.test", is_active=False
        )
        self.legacy_counselor = _make_legacy_superuser(
            _counselor("notes-legacy@example.test")
        )
        self.gco_staff = _build_user("notes-gco@example.test", RoleChoices.GCO_STAFF)
        self.it_admin = _build_user("notes-it@example.test", RoleChoices.IT_ADMIN)
        EncryptionKeyVersion.objects.create(
            key_version="test-notes-v1",
            key_purpose=KeyPurposeChoices.FIELD_ENCRYPTION,
            status=KeyStatusChoices.ACTIVE,
            source_alias="env",
            secret_reference="COMPASS_TEST_FIELD_ENCRYPTION_KEY",
            algorithm="Fernet",
        )

        self.assigned_session = self._session("SES-NOTE-000001", self.assigned_counselor)
        self.coverage_session = self._session("SES-NOTE-000002", self.assigned_counselor)
        self.head_assigned_session = self._session("SES-NOTE-000003", self.head_assigned)
        self.head_outside_session = self._session("SES-NOTE-000004", self.assigned_counselor)
        self.co_session = self._session("SES-NOTE-000005", self.assigned_counselor)
        self.grant_session = self._session("SES-NOTE-000006", self.assigned_counselor)
        self.case_grant_session = self._session("SES-NOTE-000007", self.assigned_counselor)

        self.co_case = self._case("CAS-NOTE-000001")
        CounselingCaseSession.objects.create(
            counseling_case=self.co_case,
            session=self.co_session,
            linked_by=self.head_assigned,
            link_type="RELATED",
        )
        CounselingCaseCollaborator.objects.create(
            counseling_case=self.co_case,
            counselor=self.case_collaborator,
            is_active=True,
            added_by=self.head_assigned,
        )

        self.grant_case = self._case("CAS-NOTE-000002")
        CounselingCaseSession.objects.create(
            counseling_case=self.grant_case,
            session=self.case_grant_session,
            linked_by=self.head_assigned,
            link_type="RELATED",
        )

        self.direct_grant = self._grant(
            self.grant_counselor,
            originating_session=self.grant_session,
            grant_type=TemporarySupportAccessType.SESSION_REVIEW,
            purpose_code=TemporarySupportAccessPurpose.URGENT_TRIAGE,
        )
        self.case_grant = self._grant(
            self.case_grant_counselor,
            counseling_case=self.grant_case,
            grant_type=TemporarySupportAccessType.CASE_REVIEW,
            purpose_code=TemporarySupportAccessPurpose.POST_ACTION_DOCUMENTATION,
        )
        self.invalid_purpose_grant = self._grant(
            self.out_of_scope_counselor,
            originating_session=self.grant_session,
            grant_type=TemporarySupportAccessType.SESSION_REVIEW,
            purpose_code=TemporarySupportAccessPurpose.ASSIGNMENT_DECISION,
        )
        self.invalid_type_counselor = _counselor("notes-invalid-type@example.test")
        self.invalid_type_grant = self._grant(
            self.invalid_type_counselor,
            originating_session=self.grant_session,
            grant_type=TemporarySupportAccessType.TRIAGE_SESSION,
            purpose_code=TemporarySupportAccessPurpose.URGENT_TRIAGE,
        )
        self.expired_counselor = _counselor("notes-expired@example.test")
        self.expired_grant = self._grant(
            self.expired_counselor,
            originating_session=self.grant_session,
            starts_at=self.now - timedelta(hours=2),
            expires_at=self.now - timedelta(hours=1),
        )
        self.revoked_counselor = _counselor("notes-revoked@example.test")
        self.revoked_grant = self._grant(
            self.revoked_counselor,
            originating_session=self.grant_session,
            status=TemporarySupportAccessStatus.REVOKED,
        )

        for session in (
            self.assigned_session,
            self.coverage_session,
            self.head_assigned_session,
            self.head_outside_session,
            self.co_session,
            self.grant_session,
            self.case_grant_session,
        ):
            author = (
                self.head_assigned
                if session == self.head_assigned_session
                else self.assigned_counselor
            )
            save_session_note(
                author,
                session.reference_code,
                CounselingNoteCommand(
                    student_visible_summary="student-safe summary",
                    counselor_narrative="private counselor narrative",
                    recommendations="private recommendations",
                    special_concerns="private special concerns",
                    follow_up_needed=True,
                    follow_up_notes="private follow-up notes",
                ),
            )

    def _session(self, reference_code, assigned_counselor):
        return CounselingSession.objects.create(
            reference_code=reference_code,
            student=self.student,
            assigned_counselor=assigned_counselor,
            session_type=SessionTypeChoices.COUNSELING,
            session_mode=SessionModeChoices.ONSITE,
            session_source=SessionSourceChoices.COUNSELOR_INITIATED,
            status=SessionStatusChoices.COMPLETED,
        )

    def _case(self, reference_code):
        return CounselingCase.objects.create(
            reference_code=reference_code,
            student=self.student,
            assigned_counselor=self.assigned_counselor,
            concern_category=CounselingCaseConcernCategory.ACADEMIC,
            priority=CounselingCasePriority.MEDIUM,
            status=CounselingCaseStatus.OPEN,
            opened_by=self.assigned_counselor,
        )

    def _grant(
        self,
        grantee,
        *,
        originating_session=None,
        counseling_case=None,
        grant_type=TemporarySupportAccessType.SESSION_REVIEW,
        purpose_code=TemporarySupportAccessPurpose.HEAD_GUIDANCE_REVIEW,
        starts_at=None,
        expires_at=None,
        status=TemporarySupportAccessStatus.ACTIVE,
    ):
        urgent_support = UrgentSupportRequest.objects.create(
            reference_code=f"URG-NOTE-{UrgentSupportRequest.objects.count() + 1:06d}",
            student=self.student,
            source_type=UrgentSupportSourceType.COUNSELOR_MANUAL,
            urgency_level=UrgentSupportUrgencyLevel.PROMPT_REVIEW,
            status=UrgentSupportStatus.OPEN,
            initiated_by=self.assigned_counselor,
            originating_session=originating_session,
            counseling_case=counseling_case,
        )
        if starts_at is None:
            starts_at = self.now - timedelta(minutes=5)
        if expires_at is None:
            expires_at = self.now + timedelta(hours=1)
        revoked_at = self.now if status == TemporarySupportAccessStatus.REVOKED else None
        return TemporarySupportAccessGrant.objects.create(
            urgent_support=urgent_support,
            grantee=grantee,
            granted_by=self.head_assigned,
            grant_type=grant_type,
            purpose_code=purpose_code,
            starts_at=starts_at,
            expires_at=expires_at,
            revoked_at=revoked_at,
            revoked_by=self.head_assigned if revoked_at else None,
            status=status,
        )

    def test_assigned_counselor_and_assigned_head_can_read_raw_notes(self):
        self.assertTrue(
            can_view_counseling_notes(self.assigned_counselor, self.assigned_session)
        )
        self.assertTrue(
            can_view_counseling_notes(self.head_assigned, self.head_assigned_session)
        )
        self.assertIsNotNone(
            project_counselor_note(self.assigned_counselor, self.assigned_session)
        )

    def test_head_outside_scope_and_coverage_only_counselor_are_denied(self):
        self.assertTrue(
            can_view_session(self.head_outside, self.head_outside_session)
        )
        self.assertTrue(
            can_view_session(self.coverage_counselor, self.coverage_session)
        )
        self.assertFalse(
            can_view_counseling_notes(self.head_outside, self.head_outside_session)
        )
        self.assertFalse(
            can_view_counseling_notes(self.coverage_counselor, self.coverage_session)
        )
        self.assertIsNone(
            project_counselor_note(self.head_outside, self.head_outside_session)
        )

    def test_active_case_collaborator_requires_linked_active_case_collaboration(self):
        self.assertTrue(can_view_counseling_notes(self.case_collaborator, self.co_session))
        entry = self.co_case.case_collaborator_entries.get(counselor=self.case_collaborator)
        entry.is_active = False
        entry.save(update_fields=["is_active", "updated_at"])
        self.assertFalse(can_view_counseling_notes(self.case_collaborator, self.co_session))

    def test_valid_direct_and_case_grants_allow_raw_notes(self):
        self.assertTrue(
            can_view_counseling_notes(self.grant_counselor, self.grant_session)
        )
        self.assertTrue(
            can_view_counseling_notes(self.case_grant_counselor, self.case_grant_session)
        )

    def test_invalid_expired_and_revoked_grants_do_not_allow_raw_notes(self):
        cases = (
            (self.out_of_scope_counselor, self.grant_session),
            (self.invalid_type_counselor, self.grant_session),
            (self.expired_counselor, self.grant_session),
            (self.revoked_counselor, self.grant_session),
        )
        for actor, session in cases:
            with self.subTest(actor=actor.email):
                self.assertFalse(can_view_counseling_notes(actor, session))

    def test_head_outside_scope_cannot_use_legacy_raw_note_capability_hook(self):
        self.assertFalse(
            can_view_counseling_notes(self.head_outside, self.head_outside_session)
        )
        # Raw notes remain a fixed clinical boundary.  There is deliberately
        # no runtime grant hook for the removed legacy note capability.
        with mock.patch("apps.counseling.policies.has_capability", return_value=True):
            self.assertFalse(
                can_view_counseling_notes(
                    self.head_outside, self.head_outside_session
                )
            )
            self.assertIsNone(
                project_counselor_note(
                    self.head_outside, self.head_outside_session
                )
            )
        self.assertFalse(
            can_edit_counseling_notes(self.head_outside, self.head_outside_session)
        )

    def test_raw_note_projection_has_exact_plain_safe_keys(self):
        projection = project_counselor_note(
            self.assigned_counselor, self.assigned_session
        )
        self.assertIsNotNone(projection)
        self.assertEqual(set(projection), set(COUNSELOR_NOTE_FIELDS))
        self.assertTrue(all(isinstance(value, (str, bool)) for value in projection.values()))
        json.dumps(projection)
        self.assertTrue(all(not isinstance(value, models.Model) for value in projection.values()))
        self.assertTrue(all(not field.endswith("_encrypted") for field in projection))
        self.assertNotIn("authored_by", projection)
        self.assertNotIn("session_id", projection)
        self.assertEqual(
            projection["counselor_narrative"], "private counselor narrative"
        )

    def test_student_gets_only_student_safe_summary(self):
        summary = project_student_session_summary(self.student, self.assigned_session)
        self.assertEqual(summary, {"student_visible_summary": "student-safe summary"})
        self.assertIsNone(project_counselor_note(self.student, self.assigned_session))
        with self.assertRaises(CounselingEncryptionError):
            read_counselor_note(self.student, self.assigned_session)

    def test_non_counselor_and_fail_closed_actors_are_denied(self):
        actors = (
            AnonymousUser(),
            self.student,
            self.student_legacy,
            self.gco_staff,
            self.it_admin,
            self.inactive_counselor,
            self.legacy_counselor,
        )
        for actor in actors:
            with self.subTest(actor=repr(actor)):
                self.assertFalse(
                    can_view_counseling_notes(actor, self.assigned_session)
                )
                self.assertIsNone(project_counselor_note(actor, self.assigned_session))
                self.assertEqual(get_counselor_notes_visible_to(actor), [])

    def test_note_selectors_return_only_authorized_projected_rows(self):
        assigned_codes = {
            row["student_visible_summary"]
            for row in get_counselor_notes_visible_to(self.assigned_counselor)
        }
        self.assertEqual(assigned_codes, {"student-safe summary"})
        head_codes = {
            row["student_visible_summary"]
            for row in get_counselor_notes_visible_to(self.head_outside)
        }
        # The same designated Head is assigned to ``head_assigned_session``;
        # the list may therefore contain that in-scope note, but it must not
        # include the separately assigned session outside the Head's scope.
        self.assertEqual(head_codes, {"student-safe summary"})
        self.assertIsNone(
            get_counselor_note_by_reference_code(
                self.head_outside,
                self.head_outside_session.reference_code,
            )
        )
        self.assertIsNotNone(
            get_counselor_note_by_reference_code(
                self.case_collaborator, self.co_session.reference_code
            )
        )
        self.assertIsNone(
            get_counselor_note_by_reference_code(
                self.coverage_counselor, self.coverage_session.reference_code
            )
        )
        self.assertIsNone(
            get_counselor_note_by_reference_code(
                self.student, self.assigned_session.reference_code
            )
        )

    def test_note_read_access_never_authorizes_note_mutation(self):
        read_only_actors = (
            self.case_collaborator,
            self.grant_counselor,
            self.case_grant_counselor,
            self.head_outside,
        )
        for actor in read_only_actors:
            with self.subTest(actor=actor.email):
                self.assertFalse(
                    can_edit_counseling_notes(actor, self.assigned_session)
                )
                with self.assertRaises(SessionPermissionError):
                    save_session_note(
                        actor,
                        self.assigned_session.reference_code,
                        CounselingNoteCommand(counselor_narrative="must not write"),
                    )
                with self.assertRaises(SessionPermissionError):
                    save_counselor_private_note(
                        actor,
                        self.assigned_session.reference_code,
                        CounselingNoteCommand(counselor_narrative="must not write"),
                    )
                with self.assertRaises(SessionPermissionError):
                    save_shared_summary(
                        actor,
                        self.assigned_session.reference_code,
                        StudentVisibleSummaryCommand(student_visible_summary="must not write"),
                    )

        self.assertTrue(
            can_edit_counseling_notes(
                self.assigned_counselor, self.assigned_session
            )
        )
        save_counselor_private_note(
            self.assigned_counselor,
            self.assigned_session.reference_code,
            CounselingNoteCommand(counselor_narrative="updated private narrative"),
        )
        save_shared_summary(
            self.assigned_counselor,
            self.assigned_session.reference_code,
            StudentVisibleSummaryCommand(student_visible_summary="updated student summary"),
        )
        self.assertEqual(
            read_counselor_note(
                self.assigned_counselor, self.assigned_session
            )["counselor_narrative"],
            "updated private narrative",
        )


class RoutineEvaluationReadBoundaryTests(TestCase):
    """Verify structured routine visibility is broader than raw-text access."""

    def setUp(self):
        self.now = timezone.now().replace(microsecond=0)
        self._encryption_key_patcher = mock.patch.dict(
            os.environ,
            {"COMPASS_TEST_FIELD_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii")},
        )
        self._encryption_key_patcher.start()
        self.addCleanup(self._encryption_key_patcher.stop)

        self.student = _student("routine-student@example.test")
        self.out_of_scope_student = _student("routine-out@example.test")
        self.out_of_scope_student.student_profile.college = "ENG"
        self.out_of_scope_student.student_profile.save(update_fields=["college"])

        self.assigned_counselor = _counselor("routine-assigned@example.test")
        self.coverage_counselor = _counselor("routine-coverage@example.test")
        self.coverage = CounselorCoverage.objects.create(
            counselor=self.coverage_counselor,
            campus="Main Campus",
            college="CCMS",
            starts_at=self.now.date(),
        )
        self.head_assigned = _counselor("routine-head-assigned@example.test", is_head=True)
        self.head_covered = self.head_assigned
        self.head_coverage = CounselorCoverage.objects.create(
            counselor=self.head_covered,
            campus="Main Campus",
            college="CCMS",
            starts_at=self.now.date(),
        )
        self.head_outside = self.head_assigned
        self.out_of_scope_counselor = _counselor("routine-out-counselor@example.test")
        self.expired_counselor = _counselor("routine-expired@example.test")
        CounselorCoverage.objects.create(
            counselor=self.expired_counselor,
            campus="Main Campus",
            college="CCMS",
            starts_at=self.now.date() - timedelta(days=4),
            ends_at=self.now.date() - timedelta(days=1),
        )
        self.inactive_counselor = _counselor(
            "routine-inactive@example.test", is_active=False
        )
        self.legacy_counselor = _make_legacy_superuser(
            _counselor("routine-legacy@example.test")
        )
        self.gco_staff = _build_user("routine-gco@example.test", RoleChoices.GCO_STAFF)
        self.it_admin = _build_user("routine-it@example.test", RoleChoices.IT_ADMIN)

        EncryptionKeyVersion.objects.create(
            key_version="test-routine-v1",
            key_purpose=KeyPurposeChoices.FIELD_ENCRYPTION,
            status=KeyStatusChoices.ACTIVE,
            source_alias="env",
            secret_reference="COMPASS_TEST_FIELD_ENCRYPTION_KEY",
            algorithm="Fernet",
        )

        self.assigned_record = self._record(
            "SES-ROUTINE-READ-000001", self.student, self.assigned_counselor
        )
        self.head_assigned_record = self._record(
            "SES-ROUTINE-READ-000002", self.student, self.head_assigned
        )
        self.covered_record = self._record(
            "SES-ROUTINE-READ-000003", self.student, self.assigned_counselor
        )
        self.outside_record = self._record(
            "SES-ROUTINE-READ-000004",
            self.out_of_scope_student,
            self.assigned_counselor,
        )

    def _record(self, reference_code, student, assigned_counselor):
        record = RoutineInterviewRecord.objects.create(
            session=CounselingSession.objects.create(
                reference_code=reference_code,
                student=student,
                assigned_counselor=assigned_counselor,
                session_type=SessionTypeChoices.ROUTINE_INTERVIEW,
                session_mode=SessionModeChoices.ONSITE,
                session_source=SessionSourceChoices.ROUTINE_COLLECTION,
                status=SessionStatusChoices.SCHEDULED,
            ),
            visit_date=self.now.date(),
            visit_time=time(9, 30),
            duration_minutes=30,
            concern_academic=True,
            concern_financial=True,
            rating_emotionally=7,
            rating_academically=8,
            rating_physically=6,
            rating_socially=7,
            rating_spiritually=5,
            rating_financially=4,
            rating_others=3,
            evaluation_date=self.now.date(),
            submitted_at=self.now,
            evaluated_at=self.now,
            status=RoutineInterviewStatusChoices.EVALUATION_DRAFT,
        )
        prepare_group_write(
            record,
            ROUTINE_INTAKE,
            {
                field: f"private {field}"
                for field in GROUPS[ROUTINE_INTAKE].source_fields
            },
        )
        prepare_group_write(
            record,
            ROUTINE_EVALUATION,
            {
                "rating_others_label": "other rating",
                "special_concern": "private special concern",
                "recommendations": "private recommendation",
            },
        )
        record.save()
        return record

    def _assert_json_plain(self, payload, expected_fields):
        self.assertEqual(set(payload), set(expected_fields))
        json.dumps(payload)
        self.assertTrue(all(not isinstance(value, models.Model) for value in payload.values()))
        self.assertTrue(all(not field.endswith("_encrypted") for field in payload))

    def test_policy_matrix_preserves_scope_and_separates_raw_fields(self):
        self.assertTrue(can_view_routine_interview_metadata(self.coverage_counselor, self.covered_record))
        self.assertTrue(can_view_routine_interview_metadata(self.head_outside, self.outside_record))
        self.assertTrue(can_view_routine_interview_intake(self.student, self.assigned_record))
        self.assertTrue(can_view_routine_interview_intake(self.assigned_counselor, self.assigned_record))
        self.assertTrue(can_view_routine_interview_intake(self.head_covered, self.covered_record))
        self.assertTrue(can_view_routine_interview_evaluation(self.assigned_counselor, self.assigned_record))
        self.assertTrue(can_view_routine_interview_evaluation(self.head_covered, self.covered_record))

        self.assertFalse(can_view_routine_interview_intake(self.coverage_counselor, self.covered_record))
        self.assertFalse(can_view_routine_interview_evaluation(self.coverage_counselor, self.covered_record))
        self.assertFalse(can_view_routine_interview_intake(self.head_outside, self.outside_record))
        self.assertFalse(can_view_routine_interview_evaluation(self.head_outside, self.outside_record))
        self.assertFalse(can_view_routine_interview_evaluation(self.student, self.assigned_record))
        self.assertFalse(can_view_routine_interview_metadata(self.out_of_scope_counselor, self.covered_record))

    def test_expired_coverage_does_not_grant_routine_visibility(self):
        self.assertTrue(
            can_view_routine_interview_metadata(self.expired_counselor, self.covered_record)
            is False
        )
        self.assertNotIn(
            self.covered_record.session.reference_code,
            {row["session_reference_code"] for row in get_routine_interview_metadata_visible_to(self.expired_counselor)},
        )

    def test_raw_readers_reject_unauthorized_actors_before_lookup(self):
        actors = (
            self.coverage_counselor,
            self.head_outside,
            self.gco_staff,
            self.it_admin,
            self.inactive_counselor,
            self.legacy_counselor,
        )
        for reader in (read_routine_intake, read_routine_evaluation):
            for actor in actors:
                with self.subTest(reader=reader.__name__, actor=repr(actor)):
                    with mock.patch("apps.counseling.encryption._record_metadata") as lookup:
                        with self.assertRaises(CounselingEncryptionError):
                            reader(actor, None)
                        lookup.assert_not_called()

    def test_staff_metadata_projection_is_structured_and_json_safe(self):
        for actor, record in (
            (self.assigned_counselor, self.assigned_record),
            (self.coverage_counselor, self.covered_record),
            (self.head_covered, self.covered_record),
            (self.head_outside, self.outside_record),
        ):
            with self.subTest(actor=actor.email):
                payload = project_routine_interview_metadata(actor, record)
                self.assertIsNotNone(payload)
                self._assert_json_plain(payload, ROUTINE_STAFF_METADATA_FIELDS)
                self.assertNotIn("coping_challenges", payload)
                self.assertNotIn("special_concern", payload)
                self.assertNotIn("recommendations", payload)
                self.assertEqual(payload["rating_emotionally"], 7)

    def test_student_projection_contains_intake_only(self):
        payload = project_student_routine_interview(self.student, self.assigned_record)
        self.assertIsNotNone(payload)
        self._assert_json_plain(payload, ROUTINE_STUDENT_INTAKE_FIELDS)
        self.assertEqual(payload["coping_challenges"], "private coping_challenges")
        self.assertNotIn("rating_emotionally", payload)
        self.assertNotIn("special_concern", payload)
        self.assertNotIn("recommendations", payload)
        self.assertNotIn("assigned_counselor_id", payload)
        self.assertIsNone(project_student_routine_interview(self.out_of_scope_student, self.assigned_record))

    def test_sensitive_detail_is_limited_to_assigned_or_in_scope_head(self):
        for actor, record in (
            (self.assigned_counselor, self.assigned_record),
            (self.head_assigned, self.head_assigned_record),
            (self.head_covered, self.covered_record),
        ):
            with self.subTest(actor=actor.email):
                payload = project_routine_interview_sensitive_detail(actor, record)
                self.assertIsNotNone(payload)
                self._assert_json_plain(payload, ROUTINE_SENSITIVE_DETAIL_FIELDS)
                self.assertEqual(payload["special_concern"], "private special concern")
                self.assertEqual(payload["recommendations"], "private recommendation")

        for actor, record in (
            (self.coverage_counselor, self.covered_record),
            (self.head_outside, self.outside_record),
            (self.student, self.assigned_record),
        ):
            with self.subTest(actor=repr(actor)):
                self.assertIsNone(project_routine_interview_sensitive_detail(actor, record))

    def test_routine_projection_selectors_preserve_scope(self):
        coverage_codes = {
            row["session_reference_code"]
            for row in get_routine_interview_metadata_visible_to(self.coverage_counselor)
        }
        self.assertIn(self.covered_record.session.reference_code, coverage_codes)
        self.assertNotIn(self.outside_record.session.reference_code, coverage_codes)
        self.assertIsNotNone(
            get_routine_interview_metadata_by_session_reference(
                self.coverage_counselor,
                self.covered_record.session.reference_code,
            )
        )
        self.assertIsNone(
            get_routine_interview_sensitive_detail_by_session_reference(
                self.coverage_counselor,
                self.covered_record.session.reference_code,
            )
        )
        head_codes = {
            row["session_reference_code"]
            for row in get_routine_interview_metadata_visible_to(self.head_outside)
        }
        self.assertIn(self.outside_record.session.reference_code, head_codes)

    def test_non_counselors_and_fail_closed_actors_get_no_routine_output(self):
        actors = (
            AnonymousUser(),
            self.gco_staff,
            self.it_admin,
            self.inactive_counselor,
            self.legacy_counselor,
        )
        for actor in actors:
            with self.subTest(actor=repr(actor)):
                self.assertEqual(get_routine_interview_metadata_visible_to(actor), [])
                self.assertIsNone(project_routine_interview_metadata(actor, self.covered_record))
                self.assertIsNone(project_student_routine_interview(actor, self.covered_record))

    def test_routine_mutation_policies_remain_separate_from_read_scope(self):
        self.assertFalse(can_edit_routine_interview_evaluation(self.coverage_counselor, self.covered_record))
        self.assertTrue(can_edit_routine_interview_evaluation(self.assigned_counselor, self.assigned_record))
        # Head supervision outside assignment/coverage does not become
        # ordinary clinical mutation authority.
        self.assertFalse(can_edit_routine_interview_evaluation(self.head_outside, self.outside_record))


class ECounselingAuthorizationTests(TestCase):
    """Keep private-room membership, moderation, and grants separate."""

    def setUp(self):
        self.now = timezone.now().replace(microsecond=0)
        self.student = _student("ecounsel-student@example.test")
        self.assigned_counselor = _counselor("ecounsel-assigned@example.test")
        self.head = _counselor("ecounsel-head@example.test", is_head=True)
        self.head_outside = self.head
        self.case_collaborator = _counselor("ecounsel-co@example.test")
        self.unrelated_counselor = _counselor("ecounsel-unrelated@example.test")
        self.inactive_counselor = _counselor(
            "ecounsel-inactive@example.test", is_active=False
        )
        self.legacy_counselor = _make_legacy_superuser(
            _counselor("ecounsel-legacy@example.test")
        )
        self.gco_staff = _build_user("ecounsel-gco@example.test", RoleChoices.GCO_STAFF)
        self.it_admin = _build_user("ecounsel-it@example.test", RoleChoices.IT_ADMIN)

        self.case = CounselingCase.objects.create(
            reference_code="CAS-ECOUNSEL-000001",
            student=self.student,
            assigned_counselor=self.assigned_counselor,
            concern_category=CounselingCaseConcernCategory.ACADEMIC,
            priority=CounselingCasePriority.MEDIUM,
            status=CounselingCaseStatus.OPEN,
            opened_by=self.assigned_counselor,
        )
        CounselingCaseCollaborator.objects.create(
            counseling_case=self.case,
            counselor=self.case_collaborator,
            is_active=True,
            added_by=self.head,
        )

        self.counseling_session = self._session(
            "SES-ECOUNSEL-000001", self.assigned_counselor
        )
        CounselingCaseSession.objects.create(
            counseling_case=self.case,
            session=self.counseling_session,
            linked_by=self.head,
            link_type="RELATED",
        )
        self.ecounseling_session = self._ecounseling(
            "ECS-ECOUNSEL-000001", self.counseling_session
        )
        self._derived_participant(
            self.student,
            ECounselingParticipantRoleChoices.STUDENT,
        )
        self._derived_participant(
            self.assigned_counselor,
            ECounselingParticipantRoleChoices.COUNSELOR,
        )

        self.head_counseling_session = self._session(
            "SES-ECOUNSEL-000002", self.head
        )
        self.head_ecounseling_session = self._ecounseling(
            "ECS-ECOUNSEL-000002", self.head_counseling_session
        )
        self._derived_participant(
            self.student,
            ECounselingParticipantRoleChoices.STUDENT,
            ecounseling_session=self.head_ecounseling_session,
        )
        self._derived_participant(
            self.head,
            ECounselingParticipantRoleChoices.COUNSELOR,
            ecounseling_session=self.head_ecounseling_session,
        )

    def _session(self, reference_code, assigned_counselor):
        return CounselingSession.objects.create(
            reference_code=reference_code,
            student=self.student,
            assigned_counselor=assigned_counselor,
            session_type=SessionTypeChoices.COUNSELING,
            session_mode=SessionModeChoices.ONLINE,
            session_source=SessionSourceChoices.ECOUNSELING,
            status=SessionStatusChoices.SCHEDULED,
            scheduled_start_at=self.now,
            scheduled_end_at=self.now + timedelta(hours=1),
        )

    def _ecounseling(self, reference_code, counseling_session):
        return ECounselingSession.objects.create(
            reference_code=reference_code,
            counseling_session=counseling_session,
            provider=ECounselingProviderChoices.DAILY,
            provider_mode=ECounselingProviderModeChoices.DAILY_CLOUD,
            room_slug=f"compass-room-{reference_code.lower()}",
            room_name_hash="safe-room-hash",
            room_display_name="",
            scheduled_start_at=self.now,
            scheduled_end_at=self.now + timedelta(hours=1),
            join_window_start_at=self.now - timedelta(minutes=1),
            join_window_end_at=self.now + timedelta(hours=1),
            status=ECounselingStatusChoices.SCHEDULED,
            moderator_user=counseling_session.assigned_counselor,
        )

    def _derived_participant(
        self,
        user,
        role,
        *,
        ecounseling_session=None,
    ):
        return ECounselingParticipant.objects.create(
            ecounseling_session=ecounseling_session or self.ecounseling_session,
            user=user,
            role=role,
            approved_by=self.head,
            approved_at=self.now,
            purpose_code=ECounselingPurposeCodeChoices.COUNSELING_DELIVERY,
        )

    def test_owner_assigned_counselor_and_assigned_head_retain_room_access(self):
        self.assertTrue(can_view_ecounseling_session(self.student, self.ecounseling_session))
        self.assertTrue(
            can_view_ecounseling_session(
                self.assigned_counselor, self.ecounseling_session
            )
        )
        self.assertTrue(
            can_join_ecounseling_session(
                self.assigned_counselor, self.ecounseling_session, now=self.now
            )
        )
        self.assertTrue(
            can_moderate_ecounseling_session(
                self.assigned_counselor, self.ecounseling_session
            )
        )
        self.assertTrue(
            can_view_ecounseling_session(
                self.head, self.head_ecounseling_session
            )
        )
        self.assertTrue(
            can_moderate_ecounseling_session(
                self.head, self.head_ecounseling_session
            )
        )

    def test_head_supervision_does_not_imply_private_room_access_or_moderation(self):
        self.assertTrue(
            can_manage_ecounseling_participants(self.head, self.ecounseling_session)
        )
        self.assertFalse(
            can_view_ecounseling_session(self.head_outside, self.ecounseling_session)
        )
        self.assertFalse(
            can_join_ecounseling_session(
                self.head_outside, self.ecounseling_session, now=self.now
            )
        )
        self.assertFalse(
            can_moderate_ecounseling_session(
                self.head_outside, self.ecounseling_session
            )
        )
        self.assertFalse(
            can_end_ecounseling_session(
                self.head_outside, self.ecounseling_session
            )
        )
        self.assertFalse(
            can_cancel_ecounseling_session(
                self.head_outside, self.ecounseling_session
            )
        )

    def test_explicit_head_supervision_grant_allows_room_entry_not_moderation(self):
        grant = add_ecounseling_participant(
            self.head,
            self.ecounseling_session.reference_code,
            ECounselingParticipantAddCommand(
                user_id=str(self.head_outside.pk),
                role=ECounselingParticipantRoleChoices.APPROVED_PARTICIPANT,
                purpose_code=ECounselingPurposeCodeChoices.SUPERVISION,
            ),
        )
        self.assertTrue(grant.is_active)
        self.assertTrue(
            can_view_ecounseling_session(
                self.head_outside, self.ecounseling_session
            )
        )
        self.assertTrue(
            can_join_ecounseling_session(
                self.head_outside, self.ecounseling_session, now=self.now
            )
        )
        self.assertFalse(
            can_moderate_ecounseling_session(
                self.head_outside, self.ecounseling_session
            )
        )

    def test_case_collaborator_requires_relationship_and_matching_purpose(self):
        self.assertTrue(
            can_add_ecounseling_participant(
                self.head,
                self.ecounseling_session,
                self.case_collaborator,
                ECounselingParticipantRoleChoices.APPROVED_PARTICIPANT,
                ECounselingPurposeCodeChoices.COUNSELING_DELIVERY,
            )
        )
        self.assertFalse(
            can_add_ecounseling_participant(
                self.head,
                self.ecounseling_session,
                self.case_collaborator,
                ECounselingParticipantRoleChoices.APPROVED_PARTICIPANT,
                ECounselingPurposeCodeChoices.SUPERVISION,
            )
        )
        self.assertFalse(
            can_add_ecounseling_participant(
                self.head,
                self.ecounseling_session,
                self.unrelated_counselor,
                ECounselingParticipantRoleChoices.APPROVED_PARTICIPANT,
                ECounselingPurposeCodeChoices.COUNSELING_DELIVERY,
            )
        )
        participant = add_ecounseling_participant(
            self.head,
            self.ecounseling_session.reference_code,
            ECounselingParticipantAddCommand(
                user_id=str(self.case_collaborator.pk),
                role=ECounselingParticipantRoleChoices.APPROVED_PARTICIPANT,
                purpose_code=ECounselingPurposeCodeChoices.COUNSELING_DELIVERY,
            ),
        )
        self.assertTrue(can_view_ecounseling_session(self.case_collaborator, self.ecounseling_session))
        self.assertTrue(can_join_ecounseling_session(self.case_collaborator, self.ecounseling_session, now=self.now))
        self.assertTrue(participant.is_active)

    def test_target_allowlist_rejects_students_staff_and_inactive_or_legacy_users(self):
        targets = (
            self.student,
            self.gco_staff,
            self.it_admin,
            self.inactive_counselor,
            self.legacy_counselor,
        )
        for target in targets:
            with self.subTest(target=repr(target)):
                self.assertFalse(
                    can_add_ecounseling_participant(
                        self.head,
                        self.ecounseling_session,
                        target,
                        ECounselingParticipantRoleChoices.APPROVED_PARTICIPANT,
                        ECounselingPurposeCodeChoices.COUNSELING_DELIVERY,
                    )
                )

    def test_regrant_creates_a_new_audited_grant_instead_of_reactivating(self):
        participant = add_ecounseling_participant(
            self.head,
            self.ecounseling_session.reference_code,
            ECounselingParticipantAddCommand(
                user_id=str(self.case_collaborator.pk),
                role=ECounselingParticipantRoleChoices.APPROVED_PARTICIPANT,
                purpose_code=ECounselingPurposeCodeChoices.COUNSELING_DELIVERY,
            ),
        )
        with self.assertRaises(ECounselingValidationError):
            add_ecounseling_participant(
                self.head,
                self.ecounseling_session.reference_code,
                ECounselingParticipantAddCommand(
                    user_id=str(self.case_collaborator.pk),
                    role=ECounselingParticipantRoleChoices.APPROVED_PARTICIPANT,
                    purpose_code=ECounselingPurposeCodeChoices.COUNSELING_DELIVERY,
                ),
            )
        revoke_ecounseling_participant(
            self.head,
            self.ecounseling_session.reference_code,
            ECounselingParticipantRevokeCommand(participant_id=str(participant.pk)),
        )
        replacement = add_ecounseling_participant(
            self.head,
            self.ecounseling_session.reference_code,
            ECounselingParticipantAddCommand(
                user_id=str(self.case_collaborator.pk),
                role=ECounselingParticipantRoleChoices.APPROVED_PARTICIPANT,
                purpose_code=ECounselingPurposeCodeChoices.COUNSELING_DELIVERY,
            ),
        )
        rows = ECounselingParticipant.objects.filter(
            ecounseling_session=self.ecounseling_session,
            user=self.case_collaborator,
        )
        self.assertEqual(rows.count(), 2)
        self.assertFalse(rows.get(pk=participant.pk).is_active)
        self.assertTrue(rows.get(pk=replacement.pk).is_active)
        self.assertNotEqual(participant.pk, replacement.pk)

    def test_terminal_sessions_do_not_accept_participant_management(self):
        self.ecounseling_session.status = ECounselingStatusChoices.COMPLETED
        self.ecounseling_session.save(update_fields=["status", "updated_at"])
        self.assertFalse(
            can_manage_ecounseling_participants(self.head, self.ecounseling_session)
        )
        self.assertFalse(
            can_add_ecounseling_participant(
                self.head,
                self.ecounseling_session,
                self.case_collaborator,
                ECounselingParticipantRoleChoices.APPROVED_PARTICIPANT,
                ECounselingPurposeCodeChoices.COUNSELING_DELIVERY,
            )
        )

    def test_direct_service_call_denies_unrelated_participant(self):
        with self.assertRaises(ECounselingPermissionError):
            add_ecounseling_participant(
                self.head,
                self.ecounseling_session.reference_code,
                ECounselingParticipantAddCommand(
                    user_id=str(self.unrelated_counselor.pk),
                    role=ECounselingParticipantRoleChoices.APPROVED_PARTICIPANT,
                    purpose_code=ECounselingPurposeCodeChoices.COUNSELING_DELIVERY,
                ),
            )


class CounselingCommandBoundaryTests(SimpleTestCase):
    """Counseling commands are frozen value objects with bounded fields."""

    def test_note_command_is_immutable(self):
        command = CounselingNoteCommand(counselor_narrative="private")
        with self.assertRaises(Exception):
            command.counselor_narrative = "mutated"

    def test_session_create_command_rejects_unbounded_student_id(self):
        from apps.counseling.commands import SessionCreateCommand
        from apps.common.exceptions import ValidationError

        with self.assertRaises(ValidationError):
            SessionCreateCommand(student_id="x" * 200)

    def test_commands_carry_no_model_or_mapping_fields(self):
        import inspect

        from apps.counseling import commands as counseling_commands

        forbidden = {"Appointment", "CounselingSession", "QuerySet", "HttpRequest"}
        source = inspect.getsource(counseling_commands)
        for name in forbidden:
            self.assertNotIn(name, source)
