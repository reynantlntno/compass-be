# Project: COMPASS
# File: apps/appointments/tests.py
# Module: apps.appointments
# Purpose: Focused read-visibility and field-projection tests (contract boundary).
# Notes:
#   - Heads Guidance: assigned -> full detail; within live coverage -> coverage
#     detail (reason yes, internal_notes no); outside assignment/coverage ->
#     metadata-only. Each is tested separately (confirmed policy).
#   - get_appointments_visible_to() uses defer() only as a performance hint; the
#     output boundary is appointment_view_projection().

from datetime import timedelta

from django.contrib.auth.models import AnonymousUser
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from apps.access_control.capabilities import Capability
from apps.access_control.choices import GrantReasonCode, ScopeMode
from apps.access_control.models import CounselorCoverage, WorkflowAuthorityGrant
from apps.accounts.models import RoleChoices, User
from apps.appointments.models import Appointment, AppointmentModeChoices, AppointmentStatusChoices
from apps.appointments.commands import (
    AppointmentCancellationCommand,
    AppointmentRequestCommand,
)
from apps.appointments.policies import (
    can_assign_appointment,
    can_assign_appointment_to,
    can_cancel_appointment,
    can_complete_appointment,
    can_mark_no_show,
    can_review_appointment,
    can_review_late_cancellation,
    can_schedule_appointment,
    can_submit_appointment,
    can_view_appointment,
    can_view_appointment_queue,
    can_view_appointment_private_detail,
)
from apps.appointments.selectors import (
    assert_fields_visible,
    appointment_view_projection,
    get_appointments_visible_to,
    get_counselor_appointment_queue,
    get_pending_review_appointments,
    get_student_appointments,
)
from apps.appointments.services import (
    AppointmentPermissionError,
    complete_appointment,
    mark_no_show,
    submit_appointment_request,
)
from apps.profiles.models import CounselorProfile, StudentProfile


def _build_user(email, role, *, is_active=True):
    return User.objects.create_user(
        email=email,
        password="correct-horse-battery-staple",
        first_name="Test",
        last_name="User",
        role=role,
        is_active=is_active,
    )


def _head(email="head@example.test"):
    actor = _build_user(email=email, role=RoleChoices.COUNSELOR)
    CounselorProfile.objects.create(user=actor, is_head_guidance=True)
    return actor


def _appointment(*, student, assigned=None, reference_code=None, status=AppointmentStatusChoices.SCHEDULED):
    return Appointment.objects.create(
        student=student,
        appointment_type="COUNSELING",
        appointment_mode=AppointmentModeChoices.ONSITE,
        status=status,
        reason="test reason",
        internal_notes="confidential internal note",
        assigned_counselor=assigned,
        reference_code=reference_code or f"APT-TEST-{Appointment.objects.count() + 1}",
    )


def _grant_staff(staff, *capabilities, **scope):
    return [WorkflowAuthorityGrant.objects.create(
        grantee=staff, capability=capability.value, scope_mode=ScopeMode.EXPLICIT_ORGANIZATION.value,
        valid_from=timezone.localdate(), valid_until=timezone.localdate() + timedelta(days=365), granted_by=staff,
        grant_reason_code=GrantReasonCode.LOCAL_WORKFLOW.value, **scope,
    ) for capability in capabilities]


class StudentReadTests(TestCase):
    def setUp(self):
        self.student = _build_user(email="student@example.test", role=RoleChoices.STUDENT)
        self.sprofile = StudentProfile.objects.create(
            user=self.student, campus="Main Campus", college="CCMS"
        )
        self.appt = _appointment(student=self.student)

    def test_student_sees_own_row_but_never_private_detail(self):
        self.assertTrue(can_view_appointment(self.student, self.appt))
        self.assertFalse(can_view_appointment_private_detail(self.student, self.appt))

    def test_student_projection_excludes_sensitive_fields(self):
        projection = appointment_view_projection(self.student, self.appt)
        self.assertNotIn("reason", projection)
        self.assertNotIn("internal_notes", projection)
        self.assertNotIn("decline_reason", projection)
        self.assertNotIn("cancellation_reason", projection)

    def test_assert_fields_visible_raises_for_disallowed_field(self):
        projection = appointment_view_projection(self.student, self.appt)
        with self.assertRaises(KeyError):
            assert_fields_visible(projection, "internal_notes")

    def test_student_queryset_only_own_rows(self):
        other = _build_user(email="other@example.test", role=RoleChoices.STUDENT)
        StudentProfile.objects.create(user=other, campus="Main Campus", college="CCMS")
        _appointment(student=other)
        qs = get_appointments_visible_to(self.student)
        self.assertEqual(list(qs.values_list("student_id", flat=True)), [self.student.pk])


class CounselReadTests(TestCase):
    """Non-Head counselors: assigned -> full detail; coverage -> field-limited."""

    def setUp(self):
        self.student = _build_user(email="student@example.test", role=RoleChoices.STUDENT)
        self.sprofile = StudentProfile.objects.create(
            user=self.student, campus="Main Campus", college="CCMS", department="Nursing", program="BSN"
        )
        self.assigned = _build_user(email="assigned-counselor@example.test", role=RoleChoices.COUNSELOR)
        self.covered = _build_user(email="covered-counselor@example.test", role=RoleChoices.COUNSELOR)
        CounselorCoverage.objects.create(
            counselor=self.covered,
            campus="Main Campus",
            college="CCMS",
            department="Nursing",
            program="BSN",
            starts_at=timezone.localdate(),
        )
        self.appt = _appointment(student=self.student, assigned=self.assigned)

    def test_assigned_counselor_gets_full_detail(self):
        self.assertTrue(can_view_appointment_private_detail(self.assigned, self.appt))
        projection = appointment_view_projection(self.assigned, self.appt)
        self.assertIn("reason", projection)
        self.assertIn("internal_notes", projection)

    def test_coverage_counselor_gets_reason_but_not_internal_notes(self):
        self.assertTrue(can_view_appointment_private_detail(self.covered, self.appt))
        projection = appointment_view_projection(self.covered, self.appt)
        self.assertIn("reason", projection)
        self.assertNotIn("internal_notes", projection)
        self.assertNotIn("decline_reason", projection)

    def test_coverage_counselor_out_of_scope_denied(self):
        out_of_scope = _build_user(email="out@example.test", role=RoleChoices.COUNSELOR)
        CounselorCoverage.objects.create(
            counselor=out_of_scope, college="Biology", starts_at=timezone.localdate()
        )
        self.assertFalse(can_view_appointment(out_of_scope, self.appt))
        self.assertFalse(can_view_appointment_private_detail(out_of_scope, self.appt))
        self.assertNotIn(out_of_scope.pk, list(get_appointments_visible_to(out_of_scope).values_list("pk", flat=True)))

    def test_covered_counselor_queryset_contains_in_scope_row(self):
        self.assertIn(
            self.appt.pk,
            list(get_appointments_visible_to(self.covered).values_list("pk", flat=True)),
        )


class HeadGuidanceReadTests(TestCase):
    """Confirmed policy: Head is a COUNSELOR; assigned/coverage vs outside."""

    def setUp(self):
        self.student = _build_user(email="student@example.test", role=RoleChoices.STUDENT)
        self.sprofile = StudentProfile.objects.create(
            user=self.student, campus="Main Campus", college="CCMS", department="Nursing", program="BSN"
        )

    def test_head_assigned_gets_full_assigned_detail(self):
        head = _head(email="head-assigned@example.test")
        appt = _appointment(student=self.student, assigned=head)
        self.assertTrue(can_view_appointment_private_detail(head, appt))
        projection = appointment_view_projection(head, appt)
        self.assertIn("reason", projection)
        self.assertIn("internal_notes", projection)

    def test_head_in_coverage_gets_reason_but_not_internal_notes(self):
        head = _head(email="head-covered@example.test")
        CounselorCoverage.objects.create(
            counselor=head,
            campus="Main Campus",
            college="CCMS",
            department="Nursing",
            program="BSN",
            starts_at=timezone.localdate(),
        )
        appt = _appointment(student=self.student)
        self.assertTrue(can_view_appointment_private_detail(head, appt))
        projection = appointment_view_projection(head, appt)
        self.assertIn("reason", projection)
        self.assertNotIn("internal_notes", projection)

    def test_head_outside_assignment_and_coverage_is_metadata_only(self):
        head = _head(email="head-outside@example.test")
        appt = _appointment(student=self.student)
        self.assertTrue(can_view_appointment(head, appt))
        self.assertFalse(can_view_appointment_private_detail(head, appt))
        projection = appointment_view_projection(head, appt)
        self.assertNotIn("reason", projection)
        self.assertNotIn("internal_notes", projection)
        self.assertNotIn("decline_reason", projection)

    def test_head_metadata_projection_contains_only_json_safe_relation_ids(self):
        head = _head(email="head-json-safe@example.test")
        appt = _appointment(student=self.student, assigned=head)
        projection = appointment_view_projection(head, appt)
        self.assertEqual(projection["assigned_counselor_id"], head.pk)
        self.assertNotIn("assigned_counselor", projection)
        self.assertNotIn("preferred_counselor", projection)
        self.assertNotIn("reviewed_by", projection)
        self.assertTrue(all(not hasattr(value, "_meta") for value in projection.values()))

    def test_projection_contains_no_invented_metadata_fields(self):
        head = _head(email="head-meta@example.test")
        appt = _appointment(student=self.student)
        projection = appointment_view_projection(head, appt)
        for invented in ("urgent_support", "queue_position", "unassigned_flag"):
            self.assertNotIn(invented, projection)


class GCOStaffReadTests(TestCase):
    def setUp(self):
        self.student = _build_user(email="student@example.test", role=RoleChoices.STUDENT)
        self.sprofile = StudentProfile.objects.create(
            user=self.student, campus="Main Campus", college="CCMS"
        )
        self.staff = _build_user(email="staff@example.test", role=RoleChoices.GCO_STAFF)
        self.no_scope_staff = _build_user(email="unscoped-staff@example.test", role=RoleChoices.GCO_STAFF)
        self.appt = _appointment(student=self.student)

    def test_scoped_staff_sees_row_and_reason_not_notes(self):
        _grant_staff(self.staff, Capability.APPOINTMENTS_REVIEW, campus="Main Campus", college="CCMS")
        self.assertTrue(can_view_appointment(self.staff, self.appt))
        self.assertTrue(can_view_appointment_private_detail(self.staff, self.appt))
        projection = appointment_view_projection(self.staff, self.appt)
        self.assertIn("reason", projection)
        self.assertNotIn("internal_notes", projection)

    def test_unscoped_staff_denied(self):
        self.assertFalse(can_view_appointment(self.no_scope_staff, self.appt))
        self.assertFalse(can_view_appointment_private_detail(self.no_scope_staff, self.appt))

    def test_staff_queryset_respects_grant_scope(self):
        _grant_staff(self.staff, Capability.APPOINTMENTS_REVIEW, campus="Main Campus", college="CCMS")
        outside_student = _build_user(email="outside-scope-student@example.test", role=RoleChoices.STUDENT)
        StudentProfile.objects.create(user=outside_student, campus="Main Campus", college="Biology")
        outside = _appointment(student=outside_student)

        visible_ids = set(get_appointments_visible_to(self.staff).values_list("pk", flat=True))
        self.assertIn(self.appt.pk, visible_ids)
        self.assertNotIn(outside.pk, visible_ids)
class SubmitAppointmentTests(TestCase):
    """Dedicated owner-only can_submit_appointment (contract boundary)."""

    def setUp(self):
        self.student = _build_user(email="student@example.test", role=RoleChoices.STUDENT)
        self.sprofile = StudentProfile.objects.create(
            user=self.student, campus="Main Campus", college="CCMS"
        )
        self.draft = _appointment(student=self.student, status=AppointmentStatusChoices.DRAFT)

    def test_owner_student_draft_allowed(self):
        self.assertTrue(can_submit_appointment(self.student, self.draft))

    def test_owner_student_submit_transitions_to_submitted(self):
        result = submit_appointment_request(self.student, self.draft.reference_code)
        self.assertEqual(result.status, AppointmentStatusChoices.SUBMITTED)
        self.assertIsNotNone(result.submitted_at)

    def test_owner_student_non_draft_denied(self):
        self.draft.status = AppointmentStatusChoices.SUBMITTED
        self.draft.save(update_fields=["status"])
        self.assertFalse(can_submit_appointment(self.student, self.draft))

    def test_non_owner_student_denied(self):
        other = _build_user(email="other@example.test", role=RoleChoices.STUDENT)
        self.assertFalse(can_submit_appointment(other, self.draft))

    def test_superuser_student_own_draft_denied(self):
        su = _build_user(email="su-student@example.test", role=RoleChoices.STUDENT)
        su.is_superuser = True
        su.save(update_fields=["is_superuser"])
        own = _appointment(student=su, status=AppointmentStatusChoices.DRAFT)
        self.assertFalse(can_submit_appointment(su, own))

    def test_assigned_and_coverage_counselor_denied(self):
        counselor = _build_user(email="counselor@example.test", role=RoleChoices.COUNSELOR)
        CounselorCoverage.objects.create(
            counselor=counselor,
            campus="Main Campus",
            college="CCMS",
            starts_at=timezone.localdate(),
        )
        self.assertFalse(can_submit_appointment(counselor, self.draft))

    def test_head_guidance_denied(self):
        head = _head(email="head-submit@example.test")
        self.assertFalse(can_submit_appointment(head, self.draft))

    def test_scoped_staff_denied(self):
        staff = _build_user(email="staff@example.test", role=RoleChoices.GCO_STAFF)
        self.assertFalse(can_submit_appointment(staff, self.draft))

    def test_inactive_owner_denied(self):
        inactive = _build_user(email="inactive@example.test", role=RoleChoices.STUDENT, is_active=False)
        own = _appointment(student=inactive, status=AppointmentStatusChoices.DRAFT)
        self.assertFalse(can_submit_appointment(inactive, own))

    def test_submit_decoupled_from_view(self):
        # Head can view the row but is NOT an owner, so submit is denied.
        head = _head(email="head-view-submit@example.test")
        self.assertTrue(can_view_appointment(head, self.draft))
        self.assertFalse(can_submit_appointment(head, self.draft))


class AppointmentMutationAuthorizationTests(TestCase):
    """Mutation scope is narrower than appointment record visibility."""

    def setUp(self):
        self.student = _build_user(email="mutation-student@example.test", role=RoleChoices.STUDENT)
        StudentProfile.objects.create(
            user=self.student,
            campus="Main Campus",
            college="CCMS",
            department="Nursing",
            program="BSN",
        )
        self.unassigned_student = _build_user(
            email="unassigned-student@example.test", role=RoleChoices.STUDENT
        )
        StudentProfile.objects.create(
            user=self.unassigned_student,
            campus="Main Campus",
            college="CCMS",
            department="Nursing",
            program="BSN",
        )
        self.other_student = _build_user(
            email="other-student@example.test", role=RoleChoices.STUDENT
        )
        StudentProfile.objects.create(
            user=self.other_student,
            campus="Main Campus",
            college="Biology",
            department="Science",
            program="BSBIO",
        )
        self.head_student = _build_user(
            email="head-student@example.test", role=RoleChoices.STUDENT
        )
        StudentProfile.objects.create(
            user=self.head_student,
            campus="Main Campus",
            college="CCMS",
            department="Nursing",
            program="BSN",
        )
        self.head_covered_student = _build_user(
            email="head-covered-student@example.test", role=RoleChoices.STUDENT
        )
        StudentProfile.objects.create(
            user=self.head_covered_student,
            campus="Main Campus",
            college="CCMS",
            department="Nursing",
            program="BSN",
        )

        self.assigned_counselor = _build_user(
            email="mutation-assigned@example.test", role=RoleChoices.COUNSELOR
        )
        self.other_counselor = _build_user(
            email="mutation-other@example.test", role=RoleChoices.COUNSELOR
        )
        self.covered_counselor = _build_user(
            email="mutation-covered@example.test", role=RoleChoices.COUNSELOR
        )
        CounselorCoverage.objects.create(
            counselor=self.covered_counselor,
            campus="Main Campus",
            college="CCMS",
            starts_at=timezone.localdate(),
        )

        self.assigned_appointment = _appointment(
            student=self.student,
            assigned=self.assigned_counselor,
            status=AppointmentStatusChoices.SCHEDULED,
        )
        self.unassigned_appointment = _appointment(
            student=self.unassigned_student,
            status=AppointmentStatusChoices.PENDING_REVIEW,
        )
        self.other_assigned_appointment = _appointment(
            student=self.other_student,
            assigned=self.other_counselor,
            status=AppointmentStatusChoices.SCHEDULED,
        )

    def test_assigned_counselor_keeps_mutation_authority(self):
        actor = self.assigned_counselor
        appointment = self.assigned_appointment
        self.assertTrue(can_review_appointment(actor, appointment))
        self.assertTrue(can_assign_appointment(actor, appointment))
        self.assertTrue(can_assign_appointment_to(actor, appointment, actor))
        self.assertTrue(can_schedule_appointment(actor, appointment))
        self.assertTrue(can_cancel_appointment(actor, appointment))
        self.assertTrue(can_complete_appointment(actor, appointment))

    def test_coverage_counselor_can_process_unassigned_in_scope_item(self):
        actor = self.covered_counselor
        appointment = self.unassigned_appointment
        self.assertTrue(can_view_appointment(actor, appointment))
        self.assertTrue(can_review_appointment(actor, appointment))
        self.assertTrue(can_assign_appointment(actor, appointment))
        self.assertTrue(can_assign_appointment_to(actor, appointment, actor))
        self.assertFalse(can_cancel_appointment(actor, appointment))
        self.assertFalse(can_complete_appointment(actor, appointment))

    def test_coverage_counselor_cannot_mutate_another_counselors_appointment(self):
        actor = self.covered_counselor
        appointment = self.assigned_appointment
        self.assertTrue(can_view_appointment(actor, appointment))
        self.assertFalse(can_review_appointment(actor, appointment))
        self.assertFalse(can_assign_appointment(actor, appointment))
        self.assertFalse(can_assign_appointment_to(actor, appointment, actor))
        self.assertFalse(can_cancel_appointment(actor, appointment))
        self.assertFalse(can_complete_appointment(actor, appointment))

    def test_head_assigned_or_covered_uses_normal_counselor_scope(self):
        assigned_head = _head(email="mutation-head-assigned@example.test")
        assigned_appointment = _appointment(
            student=self.head_student,
            assigned=assigned_head,
            status=AppointmentStatusChoices.SCHEDULED,
        )
        self.assertTrue(can_review_appointment(assigned_head, assigned_appointment))
        self.assertTrue(can_assign_appointment(assigned_head, assigned_appointment))
        self.assertTrue(can_cancel_appointment(assigned_head, assigned_appointment))
        self.assertTrue(can_complete_appointment(assigned_head, assigned_appointment))

        CounselorCoverage.objects.create(
            counselor=assigned_head,
            campus="Main Campus",
            college="CCMS",
            starts_at=timezone.localdate(),
        )
        covered_appointment = _appointment(
            student=self.head_covered_student,
            status=AppointmentStatusChoices.PENDING_REVIEW,
        )
        self.assertTrue(can_review_appointment(assigned_head, covered_appointment))
        self.assertTrue(can_assign_appointment(assigned_head, covered_appointment))
        self.assertFalse(can_cancel_appointment(assigned_head, covered_appointment))
        self.assertFalse(can_complete_appointment(assigned_head, covered_appointment))

    def test_head_fixed_named_authority_can_supervise_outside_counselor_scope(self):
        head = _head(email="mutation-head-outside@example.test")
        appointment = self.other_assigned_appointment
        self.assertTrue(can_view_appointment(head, appointment))
        self.assertTrue(can_review_appointment(head, appointment))
        self.assertTrue(can_assign_appointment(head, appointment))
        self.assertTrue(can_assign_appointment_to(head, appointment, head))
        self.assertTrue(can_schedule_appointment(head, appointment))
        self.assertTrue(can_cancel_appointment(head, appointment))
        self.assertTrue(can_complete_appointment(head, appointment))

    def test_late_cancellation_review_uses_mutation_scope(self):
        head = _head(email="mutation-head-late@example.test")
        self.assertTrue(can_review_late_cancellation(head, self.other_assigned_appointment))
        self.assertTrue(
            can_review_late_cancellation(
                self.assigned_counselor,
                self.assigned_appointment,
            )
        )

    def test_gco_staff_assignment_behavior_is_preserved(self):
        staff = _build_user(email="mutation-staff@example.test", role=RoleChoices.GCO_STAFF)
        _grant_staff(
            staff,
            Capability.APPOINTMENTS_REVIEW, Capability.APPOINTMENTS_SCHEDULE,
            Capability.APPOINTMENTS_CANCEL, Capability.APPOINTMENTS_OUTCOME_MANAGE,
            campus="Main Campus", college="Biology",
        )
        appointment = self.other_assigned_appointment
        self.assertTrue(can_review_appointment(staff, appointment))
        self.assertTrue(can_schedule_appointment(staff, appointment))
        self.assertTrue(can_cancel_appointment(staff, appointment))

    def test_ineligible_roles_and_accounts_fail_closed(self):
        inactive = _build_user(
            email="mutation-inactive@example.test",
            role=RoleChoices.COUNSELOR,
            is_active=False,
        )
        legacy = _build_user(email="mutation-legacy@example.test", role=RoleChoices.COUNSELOR)
        legacy.is_superuser = True
        legacy.save(update_fields=["is_superuser"])
        actors = (
            AnonymousUser(),
            self.student,
            _build_user(email="mutation-it@example.test", role=RoleChoices.IT_ADMIN),
            inactive,
            legacy,
        )
        for actor in actors:
            self.assertFalse(can_review_appointment(actor, self.other_assigned_appointment))
            self.assertFalse(can_cancel_appointment(actor, self.other_assigned_appointment))
            self.assertFalse(can_complete_appointment(actor, self.other_assigned_appointment))

    def test_direct_service_uses_named_head_mutation_authority(self):
        head = _head(email="mutation-head-service@example.test")
        appointment = self.other_assigned_appointment
        self.assertTrue(can_view_appointment(head, appointment))
        complete_appointment(head, appointment.reference_code)
        appointment.refresh_from_db()
        self.assertEqual(appointment.status, AppointmentStatusChoices.COMPLETED)

    def test_direct_no_show_service_authorizes_before_idempotent_return(self):
        head = _head(email="mutation-head-no-show@example.test")
        appointment = self.other_assigned_appointment
        appointment.status = AppointmentStatusChoices.NO_SHOW
        appointment.save(update_fields=["status"])
        with self.assertRaises(AppointmentPermissionError):
            mark_no_show(head, appointment.reference_code)


class AppointmentReadHardeningTests(TestCase):
    """Read policies, selectors, and projections fail closed for bad actors."""

    def setUp(self):
        self.student = _build_user(
            email="read-hardening-student@example.test",
            role=RoleChoices.STUDENT,
        )
        self._create_student_profile(self.student)
        self.appointment = _appointment(
            student=self.student,
            status=AppointmentStatusChoices.PENDING_REVIEW,
        )

    @staticmethod
    def _create_student_profile(student):
        StudentProfile.objects.create(
            user=student,
            campus="Main Campus",
            college="CCMS",
            department="Nursing",
            program="BSN",
        )

    def _new_student(self, email):
        student = _build_user(email=email, role=RoleChoices.STUDENT)
        self._create_student_profile(student)
        return student

    def _assert_read_denied(self, actor, appointment=None, *, assert_queue=True):
        appointment = appointment or self.appointment
        self.assertFalse(can_view_appointment(actor, appointment))
        self.assertFalse(can_view_appointment_private_detail(actor, appointment))
        if assert_queue:
            self.assertFalse(can_view_appointment_queue(actor))
        self.assertIsNone(appointment_view_projection(actor, appointment))
        for selector in (
            get_appointments_visible_to,
            get_student_appointments,
            get_counselor_appointment_queue,
            get_pending_review_appointments,
        ):
            self.assertFalse(selector(actor).exists(), selector.__name__)

    def test_inactive_and_legacy_student_cannot_read_own_appointment(self):
        inactive = _build_user(
            email="read-hardening-inactive-student@example.test",
            role=RoleChoices.STUDENT,
            is_active=False,
        )
        inactive_appointment = _appointment(
            student=inactive,
            status=AppointmentStatusChoices.PENDING_REVIEW,
        )

        legacy = _build_user(
            email="read-hardening-legacy-student@example.test",
            role=RoleChoices.STUDENT,
        )
        legacy.is_superuser = True
        legacy.save(update_fields=["is_superuser"])
        legacy_appointment = _appointment(
            student=legacy,
            status=AppointmentStatusChoices.PENDING_REVIEW,
        )

        self._assert_read_denied(inactive, inactive_appointment)
        self._assert_read_denied(legacy, legacy_appointment)

    def test_inactive_counselor_cannot_read_assigned_appointment(self):
        inactive = _build_user(
            email="read-hardening-inactive-counselor@example.test",
            role=RoleChoices.COUNSELOR,
            is_active=False,
        )
        student = self._new_student("read-hardening-inactive-counselor-student@example.test")
        appointment = _appointment(student=student, assigned=inactive)
        self._assert_read_denied(inactive, appointment)

    def test_inactive_and_legacy_head_cannot_read_office_visible_rows(self):
        inactive_head = _head(email="read-hardening-inactive-head@example.test")
        inactive_head.is_active = False
        inactive_head.save(update_fields=["is_active"])
        inactive_student = self._new_student("read-hardening-inactive-head-student@example.test")
        inactive_appointment = _appointment(student=inactive_student, assigned=inactive_head)
        self._assert_read_denied(inactive_head, inactive_appointment)

        # Only one active Head Guidance designation is allowed. Reuse this
        # designated account for the legacy-superuser boundary.
        inactive_head.is_active = True
        inactive_head.is_superuser = True
        inactive_head.save(update_fields=["is_active", "is_superuser"])
        legacy_student = self._new_student("read-hardening-legacy-head-student@example.test")
        legacy_appointment = _appointment(student=legacy_student, assigned=inactive_head)

        self._assert_read_denied(inactive_head, legacy_appointment)

    def test_anonymous_and_active_out_of_scope_projection_cannot_read_metadata(self):
        out_of_scope = _build_user(
            email="read-hardening-out-of-scope@example.test",
            role=RoleChoices.COUNSELOR,
        )
        CounselorCoverage.objects.create(
            counselor=out_of_scope,
            college="Biology",
            starts_at=timezone.localdate(),
        )

        self._assert_read_denied(AnonymousUser())
        self._assert_read_denied(out_of_scope, assert_queue=False)
        self.assertTrue(can_view_appointment_queue(out_of_scope))

    def test_active_read_and_mutation_controls_remain_available(self):
        counselor = _build_user(
            email="read-hardening-active-counselor@example.test",
            role=RoleChoices.COUNSELOR,
        )
        student = self._new_student("read-hardening-active-counselor-student@example.test")
        appointment = _appointment(student=student, assigned=counselor)
        self.assertTrue(can_view_appointment(counselor, appointment))
        self.assertIsNotNone(appointment_view_projection(counselor, appointment))
        self.assertTrue(can_review_appointment(counselor, appointment))


class TypedCommandAndBoundaryTests(TestCase):
    """Commands are frozen/validated and are the only mutation input."""

    def _student(self, email):
        actor = _build_user(email=email, role=RoleChoices.STUDENT)
        StudentProfile.objects.create(user=actor, campus="Main", college="CCMS")
        return actor

    def test_commands_are_immutable(self):
        command = AppointmentRequestCommand(
            appointment_type="COUNSELING",
            appointment_mode="ONSITE",
            reason="test reason",
        )
        with self.assertRaises(Exception):
            command.reason = "mutated"

    def test_commands_reject_unbounded_text(self):
        from apps.common.exceptions import ValidationError

        with self.assertRaises(ValidationError):
            AppointmentCancellationCommand(reason="x" * 2000)

    def test_services_reject_arbitrary_dictionaries(self):
        actor = self._student("boundary-dict@example.test")
        appointment = _appointment(student=actor, status=AppointmentStatusChoices.DRAFT)
        from apps.common.exceptions import ValidationError

        with self.assertRaises(ValidationError):
            submit_appointment_request(actor, {"reference_code": appointment.reference_code})

    def test_unknown_reference_fails_closed(self):
        from apps.common.exceptions import NotFoundError

        actor = self._student("boundary-missing@example.test")
        with self.assertRaises(NotFoundError):
            submit_appointment_request(actor, "APT-DOES-NOT-EXIST")

    def test_stale_expected_timestamp_is_rejected(self):
        from apps.common.exceptions import StaleStateError

        actor = self._student("boundary-stale@example.test")
        appointment = _appointment(student=actor, status=AppointmentStatusChoices.DRAFT)
        with self.assertRaises(StaleStateError):
            submit_appointment_request(
                actor,
                appointment.reference_code,
                expected_updated_at=timezone.now() - timedelta(days=1),
            )


class ArchitectureBoundaryTests(SimpleTestCase):
    """Static boundary guarantees for the appointments/counseling vertical."""

    def _source(self, dotted_module: str) -> str:
        import importlib
        import inspect

        return inspect.getsource(importlib.import_module(dotted_module))

    def test_appointments_services_do_not_import_counseling_mutations(self):
        source = self._source("apps.appointments.services")
        self.assertNotIn("apps.counseling.services", source)

    def test_counseling_services_do_not_import_appointments_mutations(self):
        source = self._source("apps.counseling.services")
        self.assertNotIn("apps.appointments.services", source)

    def test_removed_cross_domain_mutation_boundary_stays_removed(self):
        import importlib

        with self.assertRaises(ModuleNotFoundError):
            importlib.import_module("apps.counseling.appointment_services")

    def test_domain_services_accept_no_raw_data_dictionaries(self):
        import ast
        import importlib
        import inspect

        for dotted in ("apps.counseling.services", "apps.appointments.services"):
            module = importlib.import_module(dotted)
            tree = ast.parse(inspect.getsource(module))
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    for argument in node.args.args:
                        self.assertNotEqual(
                            argument.arg,
                            "data",
                            f"{dotted}.{node.name} still takes a raw data dictionary",
                        )

    def test_domain_services_and_commands_do_not_import_http_layers(self):
        for dotted in (
            "apps.appointments.services",
            "apps.counseling.services",
            "apps.appointments.commands",
            "apps.counseling.commands",
        ):
            source = self._source(dotted)
            self.assertNotIn("django.http", source)
            self.assertNotIn("from ninja", source)

    def test_openapi_operation_ids_are_stable(self):
        from config.api.v1 import api_v1

        schema = api_v1.get_openapi_schema()
        operation_ids = set()
        for path_operations in schema["paths"].values():
            for method_def in path_operations.values():
                if isinstance(method_def, dict) and method_def.get("operationId"):
                    operation_ids.add(method_def["operationId"])
        required = {
            "appointments_list", "appointments_detail", "appointments_create",
            "appointments_submit", "appointments_review_decision", "appointments_schedule",
            "appointments_assign_counselor", "appointments_cancel",
            "appointments_late_cancellation_request", "appointments_late_cancellation_decision",
            "appointments_complete", "appointments_no_show", "appointments_available_slots",
            "counseling_sessions_list", "counseling_session_detail", "counseling_session_summary",
            "counseling_session_create", "counseling_session_start", "counseling_note_save",
            "counseling_session_complete", "counseling_session_finalize",
            "counseling_session_lock", "counseling_session_cancel",
            "counseling_session_no_show", "counseling_session_assign",
            "counseling_routine_interviews_list", "counseling_routine_intake_save",
            "counseling_routine_intake_submit", "counseling_routine_evaluation_save",
            "counseling_cases_list", "counseling_case_create", "counseling_case_close",
            "counseling_case_reopen", "counseling_case_collaborator_add",
            "counseling_case_collaborator_remove", "counseling_case_link_session",
            "counseling_urgent_list", "counseling_urgent_create", "counseling_urgent_review",
            "counseling_urgent_close", "counseling_urgent_access_grant",
            "counseling_ecounseling_join", "counseling_ecounseling_end",
            "counseling_ecounseling_cancel",
        }
        self.assertEqual(required - operation_ids, set())
