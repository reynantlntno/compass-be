"""Seed a complete, synthetic COMPASS operating dataset.

This is the canonical operating-demo seed command; it no longer creates the
old seven-account fixture. It creates a deterministic UCN-shaped demo dataset
for local/testing/defense environments only. All identities are synthetic and
use ``.compass.local`` addresses. The command never writes secrets, raw token
verifiers, or provider artifacts.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import random
import re
from collections import Counter
from dataclasses import dataclass
from datetime import date, time, timedelta
from pathlib import Path

from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from apps.accounts.models import RoleChoices, User
from apps.access_control.models import CounselorCoverage, WorkflowAuthorityGrant
from apps.access_control.authority import create_authority_grant
from apps.access_control.capabilities import Capability
from apps.access_control.choices import GrantReasonCode, ScopeMode
from apps.appointments.models import (
    Appointment,
    AppointmentModeChoices,
    AppointmentStatusChoices,
    AppointmentTypeChoices,
    AvailabilityModeChoices,
    AvailabilityRule,
    OfficeClosure,
    UnavailableBlock,
)
from apps.appointments.commands import (
    AppointmentCompletionCommand,
    AppointmentRequestCommand,
    AppointmentReviewCommand,
)
from apps.appointments.services import (
    complete_appointment,
    create_appointment_request,
    mark_no_show,
    review_and_schedule_appointment,
    submit_appointment_request,
)
from apps.assessments.choices import AssessmentInstrumentCategory, AssessmentRecordStatus
from apps.assessments.models import AssessmentInstrument, StudentAssessmentRecord
from apps.call_slips.models import (
    CallSlip,
    CallSlipDestinationChoices,
    CallSlipModeChoices,
    CallSlipPurposeCodeChoices,
    CallSlipSourceTypeChoices,
)
from apps.orchestration.commands import ReferralCallSlipCommand
from apps.orchestration.use_cases import create_call_slip_from_referral_workflow
from apps.counseling.models import (
    CounselingCaseConcernCategory,
    CounselingCase,
    CounselingCasePriority,
    CounselingSession,
    UrgentSupportRequest,
    UrgentSupportSourceType,
    UrgentSupportUrgencyLevel,
    ECounselingSession,
    SessionModeChoices,
    SessionSourceChoices,
    SessionStatusChoices,
    SessionTypeChoices,
)
from apps.counseling.ecounseling_services import create_ecounseling_session, expire_ecounseling_session
from apps.counseling.commands import (
    CaseCreateCommand,
    ECounselingCreateCommand,
    SessionCreateCommand,
    UrgentSupportCreateCommand,
)
from apps.counseling.services import (
    create_counseling_case,
    create_urgent_support_request,
    create_session,
    transition_counseling_case_to_monitoring,
)
from apps.common.form_values import ValidatedAnswerSet
from apps.exit_interviews.models import (
    ExitInterviewAssignment,
    ExitInterviewResponse,
    ExitResponseStatus,
    AssignmentStatus,
    FEEDBACK_CATEGORY_FIELDS,
    SELF_ASSESSMENT_FIELDS,
)
from apps.exit_interviews.services import (
    create_exit_assignment,
    save_exit_draft,
    start_exit_response,
    submit_exit_response,
)
from apps.exit_interviews.commands import (
    ExitInterviewAssignmentCommand,
    ExitInterviewDraftCommand,
    ExitInterviewLifecycleCommand,
    ExitInterviewStartCommand,
)
from apps.form_collection.models import (
    CollectionAudience,
    CollectionStatus,
    FormCollection,
    FormType,
    IdentityVerificationPolicy,
    InvitationBatch,
    InvitationBatchSource,
    InvitationBatchStatus,
    FormInvitation,
    FormInvitationStatus,
)
from apps.form_collection.commands import (
    FormCollectionConfigureCommand,
    FormCollectionCreateCommand,
    FormCollectionLifecycleCommand,
    InvitationBatchCommand,
    InvitationIssueCommand,
    InvitationRecipient,
)
from apps.form_collection.services import (
    configure_collection,
    close_collection,
    create_collection,
    create_invitation_batch,
    issue_form_invitations,
    launch_collection,
)
from apps.good_moral.models import (
    GoodMoralRequest,
    GoodMoralStatusChoices,
    ReceiptStatusChoices,
    RequestTypeChoices,
)
from apps.graduate_tracer.models import GraduateTracerResponse, GTSResponseStatus
from apps.graduate_tracer.services import save_gts_draft, start_gts_response, submit_gts_response
from apps.graduate_tracer.commands import GraduateTracerDraftCommand, GraduateTracerLifecycleCommand, GraduateTracerStartCommand
from apps.inventory.encryption import validate_confidential_values
from apps.inventory.models import INVENTORY_SCHEMA_VERSION, InventoryStatusChoices, StudentInventorySnapshot
from apps.inventory.commands import InventoryDraftCommand
from apps.inventory.services import _record_submission_history
from apps.inventory.services import (
    save_inventory_draft,
)
from apps.organizations.models import (
    AcademicTerm,
    AcademicTermStatusChoices,
    FormFamily,
    GovernanceStatusChoices,
)
from apps.organizations.commands import AcademicTermDraftCommand, LifecycleCommand
from apps.organizations.services import activate_form_family
from apps.organizations.academic_year import (
    AcademicYearConfigurationError,
    resolve_current_academic_year,
    validate_academic_year,
)
from apps.organizations.governance_services import (
    activate_academic_term,
    activate_form_revision,
    approve_academic_term,
    create_academic_term_draft,
    submit_academic_term_for_approval,
)
from apps.profiles.models import (
    CohortEnrollmentState,
    CohortProvenance,
    CounselorProfile,
    GCOStaffProfile,
    StudentLifecycleChoices,
    StudentProfile,
)
from apps.reports.profiling import (
    canonical_organization_code,
    capture_academic_cohort,
    materialize_profiling_fact,
)
from apps.referrals.models import Referral, ReferralReasonCategoryChoices, ReferralSourceTypeChoices, ReferralStatusChoices
from apps.security.field_encryption import get_active_field_key
from apps.security.key_sources import load_fernet_for_metadata, validate_fernet_key
from apps.security.models import EncryptionKeyVersion, KeyPurposeChoices, KeyStatusChoices
from apps.security.exceptions import FieldEncryptionKeyUnavailable
from apps.support_needs.choices import (
    SupportNeedCategory,
    SupportNeedSensitivity,
    SupportNeedSourceType,
    SupportNeedStatus,
)
from apps.support_needs.commands import SupportNeedReasonCommand
from apps.support_needs.models import StudentSupportNeed, SupportNeedType
from apps.support_needs.services import (
    mark_support_need_needs_review,
    verify_support_need,
)
from apps.system.demo_catalog import (
    UCN_CATALOG_REVIEWED_ON,
    UCN_CATALOG_SOURCE_URL,
    UCN_CATALOG_VERSION,
    UCN_PROGRAM_CATALOG,
    ProgramSeed,
    validate_catalog,
)


SAFE_ENVIRONMENTS = {"development", "dev", "local", "demo", "testing", "test"}
DEFAULT_PASSWORD_ENV = "COMPASS_DEMO_PASSWORD"
SEED_DOMAIN = "@compass.local"
SEED_VERSION = "operating-demo-2026-08-4"
DEFAULT_ACADEMIC_YEAR = "2026-2027"

# Optional local-only inbox overrides for the first defense personas. The
# values are supplied through the ignored local .env and are deliberately not
# committed here. Unconfigured environments continue to use .compass.local.
DEMO_EMAIL_ENV_BY_KEY = {
    "it-admin": "COMPASS_DEMO_IT_ADMIN_EMAIL",
    "head-guidance": "COMPASS_DEMO_HEAD_GUIDANCE_EMAIL",
    "counselor-1": "COMPASS_DEMO_COUNSELOR_EMAIL",
    "gco-staff-1": "COMPASS_DEMO_GCO_STAFF_EMAIL",
}
DEMO_STUDENT_EMAIL_ENV = "COMPASS_DEMO_STUDENT_EMAIL"
LEGACY_SEEDED_ACCOUNT_EMAILS = {
    "it-admin": "it.admin" + SEED_DOMAIN,
    "head-guidance": "maria.lourdes.santos" + SEED_DOMAIN,
    "counselor-1": "josephine.reyes" + SEED_DOMAIN,
    "counselor-2": "ramon.delacruz" + SEED_DOMAIN,
    "counselor-3": "anne.mendoza" + SEED_DOMAIN,
    "gco-staff-1": "lorena.bautista" + SEED_DOMAIN,
    "gco-staff-2": "erwin.castillo" + SEED_DOMAIN,
}

LEGACY_DEMO_EMAILS = {
    "demo.it@compass.local",
    "demo.headguidance@compass.local",
    "demo.counselor@compass.local",
    "demo.gcostaff@compass.local",
    "demo.student@compass.local",
    "demo.alumni@compass.local",
    "demo.student2@compass.local",
}

FIRST_NAMES = (
    "Aira", "Althea", "Andrea", "Angelo", "Bea", "Benedict", "Carla", "Catherine",
    "Christian", "Clarisse", "Daniel", "Dianne", "Eunice", "Francis", "Gabriel",
    "Hannah", "Ian", "Janelle", "Jericho", "Joanna", "Joshua", "Julius", "Katrina",
    "Kimberly", "Kristine", "Lara", "Leandro", "Louise", "Mae", "Marielle", "Mark",
    "Marlon", "Mica", "Miguel", "Nadine", "Nathan", "Patricia", "Paolo", "Rafael",
    "Rica", "Rochelle", "Ryan", "Samantha", "Shaira", "Sophia", "Trisha", "Vincent",
)
MIDDLE_NAMES = (
    "Mae", "Lyn", "Grace", "Joy", "Anne", "Rose", "Marie", "Claire", "Faith", "Hope",
    "Luis", "James", "John", "Paul", "Rey", "Jose", "Miguel", "David",
)
LAST_NAMES = (
    "Aguilar", "Alcantara", "Aquino", "Bautista", "Buenaventura", "Castillo", "Cruz",
    "Dela Cruz", "Dela Peña", "Diaz", "Espiritu", "Gonzales", "Hernandez", "Javier",
    "Lazaro", "Manalo", "Mendoza", "Navarro", "Ocampo", "Pascual", "Reyes", "Rivera",
    "Rosales", "Santos", "Soriano", "Tan", "Torres", "Valdez", "Villanueva", "Yap",
)

HOME_LOCATIONS = (
    ("Daet", "Barangay Alawihao", "Purok 2"),
    ("Daet", "Barangay Bagasbas", "Purok 4"),
    ("Daet", "Barangay Pamorangon", "Purok 1"),
    ("Labo", "Barangay Talobatib", "Purok 3"),
    ("Basud", "Barangay Taba-taba", "Purok 5"),
    ("Mercedes", "Barangay San Roque", "Purok 2"),
    ("Vinzons", "Barangay Mangcayo", "Purok 1"),
)
SENIOR_HIGH_SCHOOLS = (
    "Daet National High School",
    "Camarines Norte National High School",
    "Labo National High School",
    "Basud National High School",
)
SCHOOL_GROUPS = (
    "Student Council",
    "Peer Facilitators Circle",
    "College-based student organization",
    "Campus ministry group",
)
COMMUNITY_GROUPS = (
    "Barangay youth group",
    "Parish youth ministry",
    "Local volunteer group",
    "Family livelihood group",
)
SPECIAL_INTERESTS = (
    "Digital design and photography",
    "Community outreach",
    "Small business and online selling",
    "Music and live performance",
    "Sports and wellness activities",
)
SPECIAL_SKILLS = (
    "Basic graphic design and public speaking",
    "Cooking and organizing small events",
    "Troubleshooting computers and mobile devices",
    "Writing, presentation, and group facilitation",
    "Managing online pages and simple video editing",
)
HOBBIES = (
    "Listening to music, reading, and spending time with family",
    "Watching documentaries and playing badminton",
    "Taking photos and exploring nearby places",
    "Reading short stories and making digital artwork",
    "Cooking, gardening, and joining community activities",
)
STUDENT_CONCERNS = (
    "Keeping up with course requirements while helping at home.",
    "Balancing travel time, classes, and enough time to rest.",
    "Preparing for practicum and deciding which career path to take.",
    "Managing several deadlines during the middle of the semester.",
    "Adjusting to a heavier workload and asking for help earlier.",
)
STUDENT_FEARS = (
    "Falling behind in a major subject and not knowing when to ask for help.",
    "Not being ready for practicum or the first job after graduation.",
    "Having to choose between school expenses and other family needs.",
    "Disappointing the people who are supporting my education.",
    "Making the wrong decision about my next step after college.",
)
CAREER_FIELDS = ("Professional", "Business", "Technical", "Public Service", "Agriculture")
PARENT_OCCUPATIONS = (
    ("Farmer", "Private employee"),
    ("Driver", "Small business owner"),
    ("Government employee", "Self-employed"),
    ("Fisherfolk", "Vendor"),
    ("Construction worker", "Community health worker"),
)
ALUMNI_OCCUPATIONS = (
    ("Junior systems analyst", "Information Technology"),
    ("Administrative assistant", "Public Administration"),
    ("Accounting staff", "Financial Intermediation"),
    ("Sales associate", "Trade"),
    ("Laboratory assistant", "Health and Social Work"),
)


@dataclass(frozen=True)
class SeedAccount:
    key: str
    email: str
    first_name: str
    last_name: str
    role: str
    kind: str
    head_guidance: bool = False
    designation: str = ""
    employee_number: str = ""


def _truthy(value) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _environment() -> str:
    return str(getattr(settings, "COMPASS_ENVIRONMENT", "") or "").strip().lower()


def ensure_safe_demo_environment():
    environment = _environment()
    settings_module = os.environ.get("DJANGO_SETTINGS_MODULE", "")
    if environment == "production" or settings_module.endswith(".production"):
        raise CommandError("Operating demo seeding is refused in production.")
    if environment not in SAFE_ENVIRONMENTS and not _truthy(os.environ.get("COMPASS_ALLOW_DEMO_SEEDING")):
        raise CommandError("Operating demo seeding requires a local, development, demo, or testing environment.")


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def _stable_int(value: str) -> int:
    return int(hashlib.sha256(value.encode("utf-8")).hexdigest()[:10], 16)


def _full_name(index: int, *, alumni: bool = False) -> tuple[str, str]:
    rng = random.Random(20260806 + index * 7919 + (100_000 if alumni else 0))
    first = FIRST_NAMES[rng.randrange(len(FIRST_NAMES))]
    # Make some names naturally two-part while keeping all data synthetic.
    if rng.random() < 0.35:
        first = f"{first} {MIDDLE_NAMES[rng.randrange(len(MIDDLE_NAMES))]}"
    return first, LAST_NAMES[rng.randrange(len(LAST_NAMES))]


def _choose(options, stable: int, offset: int = 0):
    """Return a stable choice without making the fixture look repetitive."""
    return options[(stable + offset) % len(options)]


def _student_context(profile, stable: int) -> dict:
    """Build coherent, locally fictional household and student details.

    The values are intentionally plausible but do not represent real people.
    They are derived from the same stable student key on every run so a seed
    rerun updates the same records instead of producing a new story each time.
    """
    today = timezone.localdate()
    municipality, barangay, purok = _choose(HOME_LOCATIONS, stable)
    family_last = profile.user.last_name
    father_first, _ = _full_name(100_000 + stable % 900_000)
    mother_first, _ = _full_name(200_000 + stable % 900_000)
    sibling_first, _ = _full_name(300_000 + stable % 900_000)
    landlord_first, landlord_last = _full_name(400_000 + stable % 900_000)
    _, mother_maiden_last = _full_name(500_000 + stable % 900_000)
    father_occupation, mother_occupation = _choose(PARENT_OCCUPATIONS, stable)
    boarding = stable % 3 == 0
    home_address = f"{purok}, {barangay}, {municipality}, Camarines Norte"
    current_address = (
        f"Room {1 + stable % 6}, {barangay} boarding house, {municipality}, Camarines Norte"
        if boarding
        else home_address
    )
    age = 18 + stable % 8
    birth_date = date(
        today.year - age - (stable % 2),
        1 + stable % 12,
        1 + stable % 27,
    )
    year_level = int(profile.year_level or 1)
    college_start = today.year - year_level
    senior_high_start = college_start - 2
    counseling_experience = stable % 6 == 0
    return {
        "age": age,
        "birth_date": birth_date,
        "birthplace": _choose(("Daet", "Labo", "Basud", "Mercedes", "Vinzons"), stable, 7),
        "municipality": municipality,
        "home_address": home_address,
        "current_address": current_address,
        "living_where": "Boarding House" if boarding else "Own House",
        "landlord_name": f"{landlord_first} {landlord_last}" if boarding else "",
        "father_name": f"{father_first} {family_last}",
        "mother_name": f"{mother_first} {family_last}",
        "mother_maiden_name": f"{mother_first} {mother_maiden_last}",
        "father_occupation": father_occupation,
        "mother_occupation": mother_occupation,
        "urgent_support_name": f"{mother_first} {family_last}" if stable % 2 else f"{father_first} {family_last}",
        "sibling_name": f"{sibling_first} {family_last}",
        "school": _choose(SENIOR_HIGH_SCHOOLS, stable, 11),
        "senior_high_start": senior_high_start,
        "college_start": college_start,
        "school_group": _choose(SCHOOL_GROUPS, stable, 13),
        "community_group": _choose(COMMUNITY_GROUPS, stable, 17),
        "special_interest": _choose(SPECIAL_INTERESTS, stable, 19),
        "special_skills": _choose(SPECIAL_SKILLS, stable, 23),
        "hobbies": _choose(HOBBIES, stable, 29),
        "current_concern": _choose(STUDENT_CONCERNS, stable, 31),
        "current_fear": _choose(STUDENT_FEARS, stable, 37),
        "work_field": _choose(CAREER_FIELDS, stable, 41),
        "counseling_experience": counseling_experience,
        "counselor_name": "Maria Lourdes Santos" if counseling_experience else "",
        "counseling_when": "First semester, A.Y. 2025–2026" if counseling_experience else "",
        "counseling_where": "Guidance and Counseling Office" if counseling_experience else "",
    }


def _email(prefix: str, key: str, number: int = 0) -> str:
    suffix = f"-{number:04d}" if number else ""
    return f"{prefix}.{_slug(key)}{suffix}{SEED_DOMAIN}"


def _academic_year(value: str | None) -> str:
    if value:
        try:
            return validate_academic_year(value)
        except AcademicYearConfigurationError as exc:
            raise CommandError(str(exc)) from exc
    try:
        return resolve_current_academic_year()
    except AcademicYearConfigurationError:
        # A fresh local demo database has no active term yet.  The seed will
        # create one through the normal AcademicTerm lifecycle below.
        pass
    return DEFAULT_ACADEMIC_YEAR


def _configured_demo_email(key: str, fallback: str) -> str:
    environment_name = DEMO_EMAIL_ENV_BY_KEY.get(key)
    if environment_name:
        return str(os.environ.get(environment_name, "") or "").strip().lower() or fallback
    return fallback


def _configured_student_email(fallback: str) -> str:
    return str(os.environ.get(DEMO_STUDENT_EMAIL_ENV, "") or "").strip().lower() or fallback


def _configured_real_demo_emails() -> frozenset[str]:
    names = (*DEMO_EMAIL_ENV_BY_KEY.values(), DEMO_STUDENT_EMAIL_ENV)
    return frozenset(
        value
        for name in names
        if (value := str(os.environ.get(name, "") or "").strip().lower())
        and not value.endswith(SEED_DOMAIN)
    )


def _seed_accounts_catalog() -> tuple[SeedAccount, ...]:
    return (
        SeedAccount("it-admin", _configured_demo_email("it-admin", "it.admin" + SEED_DOMAIN), "Aileen", "Mercado", RoleChoices.IT_ADMIN, "it_admin", designation="Systems and Operations Administrator", employee_number="UCN-IT-2026-001"),
        SeedAccount("head-guidance", _configured_demo_email("head-guidance", "maria.lourdes.santos" + SEED_DOMAIN), "Maria Lourdes", "Santos", RoleChoices.COUNSELOR, "counselor", True, "Head Guidance Counselor", "UCN-GCO-2026-001"),
        SeedAccount("counselor-1", _configured_demo_email("counselor-1", "josephine.reyes" + SEED_DOMAIN), "Josephine", "Reyes", RoleChoices.COUNSELOR, "counselor", False, "Guidance Counselor", "UCN-GCO-2026-002"),
        SeedAccount("counselor-2", "ramon.delacruz" + SEED_DOMAIN, "Ramon", "Dela Cruz", RoleChoices.COUNSELOR, "counselor", False, "Guidance Counselor", "UCN-GCO-2026-003"),
        SeedAccount("counselor-3", "anne.mendoza" + SEED_DOMAIN, "Anne", "Mendoza", RoleChoices.COUNSELOR, "counselor", False, "Guidance Counselor", "UCN-GCO-2026-004"),
        SeedAccount("gco-staff-1", _configured_demo_email("gco-staff-1", "lorena.bautista" + SEED_DOMAIN), "Lorena", "Bautista", RoleChoices.GCO_STAFF, "staff", False, "Front Desk Coordinator", "UCN-GCO-STAFF-001"),
        SeedAccount("gco-staff-2", "erwin.castillo" + SEED_DOMAIN, "Erwin", "Castillo", RoleChoices.GCO_STAFF, "staff", False, "Records and Services Assistant", "UCN-GCO-STAFF-002"),
    )


def _validate_seed_catalog():
    error = validate_catalog()
    if error:
        raise CommandError(error)
    allowed_real_emails = _configured_real_demo_emails()
    for account in _seed_accounts_catalog():
        if not account.email.endswith(SEED_DOMAIN) and account.email not in allowed_real_emails:
            raise CommandError("Seed account catalog contains an unapproved real address.")


def _current_student_rows():
    """Yield deterministic current student rows for every catalog program."""
    counter = 0
    for program in UCN_PROGRAM_CATALOG:
        if program.graduate:
            per_level = 15
        else:
            per_level = 90
        for level in range(1, program.levels + 1):
            for position in range(1, per_level + 1):
                counter += 1
                first, last = _full_name(counter)
                yield {
                    "sequence": counter,
                    "catalog": program,
                    "year_level": level,
                    "position": position,
                    "first_name": first,
                    "last_name": last,
                    "lifecycle": StudentLifecycleChoices.GRADUATING if level == program.levels and not program.graduate and position <= 18 else StudentLifecycleChoices.ACTIVE,
                    "email": _configured_student_email(_email("student", program.key, counter)) if counter == 1 else _email("student", program.key, counter),
                    "student_number": f"26-{counter:06d}",
                    "control_number": f"CN-{counter:08d}",
                }


def _alumni_rows(start_sequence: int):
    counter = start_sequence
    for program in UCN_PROGRAM_CATALOG:
        # Keep a compact prior-cohort sample per program while still making
        # every department visible in graduate/tracer screens.
        for position in range(1, 16 if not program.graduate else 6):
            counter += 1
            first, last = _full_name(counter, alumni=True)
            yield {
                "sequence": counter,
                "catalog": program,
                "year_level": None,
                "position": position,
                "first_name": first,
                "last_name": last,
                "lifecycle": StudentLifecycleChoices.ALUMNI if position % 3 else StudentLifecycleChoices.GRADUATED,
                "email": _email("alumni", program.key, counter),
                "student_number": f"AL-{counter:06d}",
                "control_number": f"AL-CN-{counter:08d}",
            }


def _password(password_env: str, dry_run: bool):
    if dry_run:
        return None
    value = os.environ.get(password_env)
    if not value:
        raise CommandError(f"Missing demo password environment variable: {password_env}.")
    return value


class Command(BaseCommand):
    help = "Seed a complete synthetic UCN-shaped COMPASS operating dataset for local defense preparation."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true", help="Show counts and validation without writing.")
        parser.add_argument("--password-env", default=DEFAULT_PASSWORD_ENV, help="Environment variable containing the local seed password.")
        parser.add_argument("--academic-year", default=None, help="Current academic year (YYYY-YYYY); existing active AcademicTerm is reused by default.")
        parser.add_argument("--token-manifest", default=None, help="Optional ignored/untracked path for one-time local invitation links.")
        parser.add_argument("--purge-legacy-demo-accounts", action="store_true", help="Explicitly remove only the seven historical demo emails in a safe environment.")
        parser.add_argument(
            "--preserve-existing-passwords",
            action="store_true",
            help="Refresh seeded content without changing passwords for existing local demo accounts.",
        )

    def handle(self, *args, **options):
        ensure_safe_demo_environment()
        _validate_seed_catalog()
        dry_run = options["dry_run"]
        password = _password(options["password_env"], dry_run)
        academic_year = _academic_year(options.get("academic_year"))
        current_rows = list(_current_student_rows())
        alumni_rows = list(_alumni_rows(len(current_rows)))
        all_rows = current_rows + alumni_rows

        if dry_run:
            self._dry_run_summary(academic_year, current_rows, alumni_rows)
            if options["purge_legacy_demo_accounts"]:
                self.stdout.write("[DRY-RUN] Would remove only the seven historical demo account emails.")
            return

        # Hash once and reuse the salted verifier for this local-only dataset.
        # This avoids spending minutes running the password hasher for every
        # synthetic account while preserving normal check_password behavior.
        password_hash = make_password(password)

        with transaction.atomic():
            from apps.imports.catalog import seed_demo_catalog
            seed_demo_catalog()
            if options["purge_legacy_demo_accounts"]:
                self._purge_legacy_accounts()

            actors = self._seed_staff_accounts(
                password_hash,
                preserve_existing_passwords=options["preserve_existing_passwords"],
            )
            self._ensure_academic_year(academic_year, actors["head-guidance"])
            self._ensure_field_encryption_key(actors["head-guidance"])
            profiles = self._seed_students(all_rows, password_hash)
            self._seed_academic_cohorts(all_rows, profiles, academic_year)
            self._seed_access_scopes(actors)
            self._seed_reference_commands(academic_year)
            revisions = self._seed_form_registry(actors)
            # Install the canonical confidential catalog before the Inventory
            # submission boundary so materialization can run in this same
            # idempotent seed transaction.
            self._seed_support_and_assessments(profiles, actors, academic_year)
            self._seed_inventory(profiles, actors, academic_year)
            self._seed_exit_and_tracer(profiles, actors, revisions, academic_year)
            self._seed_appointments_and_counseling(profiles, actors)
            self._seed_good_moral_and_referrals(profiles, actors, academic_year)
            self._seed_collections(profiles, actors, revisions, academic_year, options.get("token_manifest"))

        self._write_summary(academic_year, profiles, actors)
        self.stdout.write(self.style.SUCCESS("Operating demo seed complete. The dataset is fictional, locally scoped, and prepared for defense practice."))

    def _dry_run_summary(self, academic_year, current_rows, alumni_rows):
        undergraduate_rows = sum(1 for row in current_rows if not row["catalog"].graduate)
        graduate_rows = len(current_rows) - undergraduate_rows
        self.stdout.write("[DRY-RUN] Operating demo seed validation passed")
        self.stdout.write(f"[DRY-RUN] Catalog programs: {len(UCN_PROGRAM_CATALOG)}")
        self.stdout.write(f"[DRY-RUN] Current students: {len(current_rows)} (undergraduate={undergraduate_rows}, graduate={graduate_rows})")
        self.stdout.write(f"[DRY-RUN] Graduates/alumni: {len(alumni_rows)}")
        self.stdout.write(f"[DRY-RUN] Counselors: 4 (Head Guidance=1); GCO Staff=2; IT Admin=1")
        self.stdout.write(f"[DRY-RUN] Academic year: {academic_year}")
        self.stdout.write("[DRY-RUN] No changes written; no passwords or token verifiers displayed.")

    def _purge_legacy_accounts(self):
        User.objects.filter(email__in=LEGACY_DEMO_EMAILS).delete()

    def _ensure_academic_year(self, academic_year, actor):
        active_terms = list(
            AcademicTerm.objects.filter(status=AcademicTermStatusChoices.ACTIVE)
            .only("id", "academic_year")[:2]
        )
        if len(active_terms) > 1:
            raise CommandError("More than one active academic term is configured.")
        if active_terms:
            if active_terms[0].academic_year != academic_year:
                raise CommandError(
                    f"Existing active academic year is {active_terms[0].academic_year}; refusing to overwrite it."
                )
            return active_terms[0]

        term = AcademicTerm.objects.filter(
            academic_year=academic_year,
            semester="Annual",
        ).first()
        if term is None:
            start_year, end_year = (int(part) for part in academic_year.split("-"))
            term = create_academic_term_draft(
                actor,
                AcademicTermDraftCommand(
                    academic_year=academic_year,
                    semester="Annual",
                    start_date=date(start_year, 8, 1),
                    end_date=date(end_year, 7, 31),
                    configuration_identifier=f"operating-demo:{SEED_VERSION}",
                    source_reference="apps.system.management.commands.seed_operating_demo",
                    source_note="Synthetic local operating-demo academic term.",
                ),
            )

        if term.status == AcademicTermStatusChoices.DRAFT:
            term = submit_academic_term_for_approval(
                actor,
                LifecycleCommand(target_id=str(term.pk), reason_code="DEMO_TERM_SUBMITTED"),
            )
        if term.status == AcademicTermStatusChoices.PENDING_APPROVAL:
            term = approve_academic_term(
                actor,
                LifecycleCommand(target_id=str(term.pk), reason_code="DEMO_TERM_APPROVED"),
            )
        if term.status == AcademicTermStatusChoices.APPROVED:
            term = activate_academic_term(
                actor,
                LifecycleCommand(target_id=str(term.pk), reason_code="DEMO_TERM_ACTIVATED"),
            )
        if term.status != AcademicTermStatusChoices.ACTIVE:
            raise CommandError(
                f"Academic term {term.pk} could not be activated; status={term.status}."
            )
        return term

    def _ensure_field_encryption_key(self, actor):
        """Require usable field-key metadata without ever storing key material.

        A freshly-created database has no key metadata. Local runs register an
        explicitly supplied development key by environment-variable reference.
        An explicitly authorized staging run instead registers the existing
        OCI-Vault-backed Podman secret by its mounted name. An existing
        metadata row is never replaced or rotated by this seed.
        """
        try:
            metadata = get_active_field_key()
        except FieldEncryptionKeyUnavailable:
            metadata = None
        if metadata is None:
            if _environment() == "staging":
                secret_prefix = str(os.environ.get("COMPASS_SECRET_PREFIX", "compass-staging") or "").strip()
                if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", secret_prefix):
                    raise CommandError("COMPASS_SECRET_PREFIX is invalid for the staging field-key secret mount.")
                source_alias = "podman_secret"
                reference = f"{secret_prefix}-field-encryption-key"
                key_version = "staging-field-encryption-v1"
                notes = "Authorized staging defense dataset key metadata; material remains in the OCI Vault-backed Podman secret."
            else:
                source_alias = "env"
                reference = "FIELD_ENCRYPTION_KEY"
                key_version = "demo-field-encryption-v1"
                notes = "Local defense dataset key metadata; key material remains outside the database."
                material = os.environ.get(reference)
                if not material:
                    raise CommandError(
                        "No active field-encryption key metadata exists. Set "
                        "FIELD_ENCRYPTION_KEY to a local Fernet key "
                        "before running the operating seed."
                    )
                try:
                    validate_fernet_key(material)
                except Exception:
                    raise CommandError("FIELD_ENCRYPTION_KEY is not a valid Fernet key.") from None
            metadata = EncryptionKeyVersion.objects.create(
                key_version=key_version,
                key_purpose=KeyPurposeChoices.FIELD_ENCRYPTION,
                status=KeyStatusChoices.ACTIVE,
                source_alias=source_alias,
                secret_reference=reference,
                algorithm="Fernet",
                created_by=actor,
                activated_by=actor,
                activated_at=timezone.now(),
                notes=notes,
            )
        try:
            load_fernet_for_metadata(metadata)
        except Exception:
            raise CommandError("The active field-encryption key metadata cannot be resolved in this environment.") from None

    def _upsert_user(self, *, email, first_name, last_name, role, password_hash, preserve_existing_password=False):
        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                "first_name": first_name,
                "last_name": last_name,
                "role": role,
                "is_active": True,
                "is_superuser": False,
            },
        )
        user.first_name = first_name
        user.last_name = last_name
        user.role = role
        user.is_active = True
        user.is_superuser = False
        if password_hash is None and created:
            raise CommandError(f"Cannot create seeded account without a password: {email}.")
        if created or not preserve_existing_password:
            user.password = password_hash
        user.full_clean()
        user.save()
        return user

    def _seed_staff_accounts(self, password_hash, *, preserve_existing_passwords=False):
        actors = {}
        for account in _seed_accounts_catalog():
            self._migrate_seed_account_email(account)
            user = self._upsert_user(
                email=account.email,
                first_name=account.first_name,
                last_name=account.last_name,
                role=account.role,
                password_hash=password_hash,
                preserve_existing_password=preserve_existing_passwords,
            )
            actors[account.key] = user
            if account.kind == "counselor":
                CounselorProfile.objects.update_or_create(
                    user=user,
                    defaults={
                        "is_head_guidance": account.head_guidance,
                        # No professional license number is fabricated for a
                        # defense fixture; the field remains empty until an
                        # authorized office record is supplied.
                        "license_number": "",
                    },
                )
            elif account.kind == "staff":
                GCOStaffProfile.objects.update_or_create(
                    user=user,
                    defaults={"employee_number": account.employee_number, "designation": account.designation},
                )
        return actors

    def _migrate_seed_account_email(self, account):
        """Move a known local seed account to its configured defense inbox."""
        legacy_email = LEGACY_SEEDED_ACCOUNT_EMAILS.get(account.key)
        if not legacy_email or legacy_email == account.email:
            return
        legacy_user = User.objects.filter(email=legacy_email).first()
        if legacy_user is None:
            return
        if User.objects.filter(email=account.email).exclude(pk=legacy_user.pk).exists():
            raise CommandError(
                f"Cannot migrate seeded account {legacy_email}; target email is already in use: {account.email}."
            )
        legacy_user.email = account.email
        legacy_user.save(update_fields=["email", "updated_at"])

    def _seed_students(self, rows, password_hash):
        emails = [row["email"] for row in rows]
        existing_users = {user.email: user for user in User.objects.filter(email__in=emails)}
        student_numbers = [row["student_number"] for row in rows]
        legacy_users_by_student_number = {
            profile.student_number: profile.user
            for profile in StudentProfile.objects.select_related("user").filter(student_number__in=student_numbers)
        }
        new_users = []
        changed_users = []
        for row in rows:
            user = existing_users.get(row["email"])
            migrated_email = False
            if user is None:
                user = legacy_users_by_student_number.get(row["student_number"])
                if user is not None and user.email != row["email"]:
                    if User.objects.filter(email=row["email"]).exclude(pk=user.pk).exists():
                        raise CommandError(
                            f"Cannot migrate seeded student email; target email is already in use: {row['email']}."
                        )
                    user.email = row["email"]
                    existing_users[row["email"]] = user
                    migrated_email = True
            if user is None:
                user = User(
                    email=row["email"],
                    first_name=row["first_name"],
                    last_name=row["last_name"],
                    role=RoleChoices.STUDENT,
                    is_active=True,
                    is_superuser=False,
                    password=password_hash,
                )
                new_users.append(user)
            else:
                desired = {
                    "email": row["email"],
                    "first_name": row["first_name"],
                    "last_name": row["last_name"],
                    "role": RoleChoices.STUDENT,
                    "is_active": True,
                    "is_superuser": False,
                }
                if migrated_email or any(getattr(user, field) != value for field, value in desired.items()):
                    for field, value in desired.items():
                        setattr(user, field, value)
                    changed_users.append(user)
        if new_users:
            User.objects.bulk_create(new_users, batch_size=500)
            existing_users.update({user.email: user for user in new_users})
        if changed_users:
            User.objects.bulk_update(
                changed_users,
                ["email", "first_name", "last_name", "role", "is_active", "is_superuser", "updated_at"],
                batch_size=500,
            )

        user_ids = [existing_users[row["email"]].pk for row in rows]
        profiles_by_user = {profile.user_id: profile for profile in StudentProfile.objects.filter(user_id__in=user_ids)}
        new_profiles = []
        changed_profiles = []
        profiles = {}
        for row in rows:
            user = existing_users[row["email"]]
            catalog: ProgramSeed = row["catalog"]
            profile = profiles_by_user.get(user.pk)
            is_new = profile is None
            if profile is None:
                profile = StudentProfile(user=user)
                new_profiles.append(profile)
            desired = {
                "student_number": row["student_number"],
                "control_number": row["control_number"],
                "lifecycle_status": row["lifecycle"],
                "campus": catalog.campus,
                "college": catalog.college,
                "department": catalog.department,
                "program": catalog.program,
                "year_level": row["year_level"],
            }
            changed = is_new or any(getattr(profile, field) != value for field, value in desired.items())
            for field, value in desired.items():
                setattr(profile, field, value)
            if changed and not is_new:
                changed_profiles.append(profile)
            profiles[row["sequence"]] = profile
        if new_profiles:
            StudentProfile.objects.bulk_create(new_profiles, batch_size=500)
        if changed_profiles:
            StudentProfile.objects.bulk_update(
                changed_profiles,
                ["student_number", "control_number", "lifecycle_status", "campus", "college", "department", "program", "year_level", "updated_at"],
                batch_size=500,
            )
        return profiles

    def _seed_academic_cohorts(self, rows, profiles, academic_year):
        """Capture the operating roster before Inventory fixtures are submitted."""
        for row in rows:
            profile = profiles[row["sequence"]]
            catalog: ProgramSeed = row["catalog"]
            capture_academic_cohort(
                profile,
                academic_year=academic_year,
                college_code=canonical_organization_code(catalog.college),
                program_code=catalog.key,
                enrollment_state=(
                    CohortEnrollmentState.ENROLLED
                    if row["lifecycle"] in (StudentLifecycleChoices.ACTIVE, StudentLifecycleChoices.GRADUATING)
                    else CohortEnrollmentState.EXCLUDED
                ),
                provenance=CohortProvenance.DEMO,
                source_reference=f"operating-demo:{catalog.key}:{row['year_level'] or 'alumni'}",
            )

    def _seed_access_scopes(self, actors):
        counselors = [actors["counselor-1"], actors["counselor-2"], actors["counselor-3"]]
        head = actors["head-guidance"]
        today = timezone.localdate()
        # Head Guidance has a global view; the remaining counselors receive
        # explicit campus-level coverage so exact-match policies are exercised.
        CounselorCoverage.objects.update_or_create(
            counselor=head,
            campus=None,
            college=None,
            department=None,
            program=None,
            defaults={"is_primary": True, "is_active": True, "starts_at": today, "assigned_by": head},
        )
        campus_groups = [
            (counselors[0], "Main Campus, Daet"),
            (counselors[1], "Abaño Campus, Daet"),
            (counselors[2], "Labo/Talobatib Campus, Labo"),
        ]
        for counselor, campus in campus_groups:
            CounselorCoverage.objects.update_or_create(
                counselor=counselor,
                campus=campus,
                college=None,
                department=None,
                program=None,
                defaults={"is_primary": True, "is_active": True, "starts_at": today, "assigned_by": head},
            )
        operational_capabilities = (
            Capability.APPOINTMENTS_REVIEW, Capability.APPOINTMENTS_SCHEDULE,
            Capability.APPOINTMENTS_CANCEL, Capability.REFERRALS_QUEUE_PROCESS,
            Capability.CALL_SLIPS_PREPARE, Capability.GOOD_MORAL_DOCUMENT_GENERATE,
            Capability.GOOD_MORAL_RELEASE, Capability.EXIT_INTERVIEWS_PROCESS,
            Capability.GRADUATE_TRACER_PROCESS, Capability.REPORTS_RUN,
        )
        for staff_key in ("gco-staff-1", "gco-staff-2"):
            staff = actors[staff_key]
            for capability in operational_capabilities:
                if not WorkflowAuthorityGrant.objects.filter(
                    grantee=staff, capability=capability.value, status="ACTIVE",
                ).exists():
                    create_authority_grant(
                        head, grantee=staff, capability=capability,
                        scope_mode=ScopeMode.OFFICE_WIDE,
                        valid_from=today, valid_until=today + timedelta(days=365),
                        reason_code=GrantReasonCode.ROLE_DUTY,
                        source_type="SYSTEM", source_reference="operating-demo",
                    )

    def _seed_reference_commands(self, academic_year):
        """Run the existing metadata/template/report seeders safely."""
        deployment_ack = {"acknowledge_environment": True} if _environment() == "staging" else {}
        commands = (
            ("seed_demo_institutional_info", {}),
            ("seed_form_registry", deployment_ack.copy()),
            ("seed_document_templates", deployment_ack.copy()),
            ("seed_report_definitions", deployment_ack.copy()),
        )
        for name, kwargs in commands:
            output = io.StringIO()
            call_command(name, stdout=output, stderr=output, **kwargs)

    def _seed_form_registry(self, actors):
        revisions = {}
        head = actors["head-guidance"]
        for key in ("student_inventory", "exit_interview", "graduate_tracer_survey"):
            family = FormFamily.objects.filter(stable_key=key).first()
            if not family:
                continue
            revision = family.revisions.order_by("-created_at").first()
            if not revision:
                continue
            # Demo governance uses the existing Head Guidance designation; it
            # still goes through the normal activation service and snapshots.
            if family.status == GovernanceStatusChoices.DRAFT:
                try:
                    family = activate_form_family(head, LifecycleCommand(target_id=str(family.pk)))
                except Exception as exc:
                    raise CommandError(f"Unable to activate demo form family {key}: {exc}") from None
            if revision.status == GovernanceStatusChoices.DRAFT:
                try:
                    revision = activate_form_revision(head, LifecycleCommand(target_id=str(revision.pk)))
                except Exception as exc:
                    raise CommandError(f"Unable to activate demo form revision {key}: {exc}") from None
            revisions[key] = revision
        return revisions

    def _inventory_payload(self, profile):
        today = timezone.localdate()
        name = profile.user.get_full_name()
        program = profile.program
        stable = _stable_int(str(profile.student_number or profile.pk))
        context = _student_context(profile, stable)
        first_choice = "No" if stable % 9 == 0 else "Yes"
        course_reasons = (
            ["Parent's choice"]
            if first_choice == "No" and stable % 2
            else ["Course is offered at minimal cost"]
            if first_choice == "No"
            else [
                "Course is suited to my interest and aptitude",
                "Good job opportunities here and abroad",
            ]
        )
        class_hours = 6
        library_hours = 1 + stable % 2
        study_hours = 3 + stable % 2
        rest_hours = 8
        recreation_hours = 3
        other_hours = 24 - (class_hours + library_hours + study_hours + rest_hours + recreation_hours)
        return {
            "personal_data": {
                "full_name": name,
                "nickname": profile.user.first_name.split()[0],
                "student_no": profile.student_number,
                "age": context["age"],
                "date_of_birth": context["birth_date"].isoformat(),
                "place_of_birth": f"{context['birthplace']}, Camarines Norte",
                "nationality": "Filipino",
                "sex": "Female" if stable % 2 else "Male",
                "birth_order": _choose(("1 of 3", "2 of 3", "2 of 4", "3 of 4", "4 of 5"), stable, 3),
                "civil_status": "Single",
                "current_address": context["current_address"],
                "permanent_address": context["home_address"],
                "permanent_municipality": context["municipality"],
                "contact_no": f"09{stable % 100000000:08d}",
                "languages_home": "Filipino, Bikol",
                "email": profile.user.email,
                "languages_fluent": "Filipino, English",
                "religion_birth": _choose(("Roman Catholic", "Born Again", "Iglesia ni Cristo"), stable, 5),
                "current_religion": _choose(("Roman Catholic", "Born Again", "Iglesia ni Cristo"), stable, 9),
            },
            "family_data": {
                "father": {
                    "name": context["father_name"],
                    "occupation": context["father_occupation"],
                    "annual_income": str(60_000 + (stable % 5) * 20_000),
                    "living_status": "Still living",
                    "languages_spoken": "Filipino, Bikol",
                    "current_religion": _choose(("Roman Catholic", "Born Again", "Prefer not to say"), stable, 11),
                },
                "mother_maiden": {
                    "name": context["mother_maiden_name"],
                    "occupation": context["mother_occupation"],
                    "annual_income": str(45_000 + (stable % 4) * 15_000),
                    "living_status": "Still living",
                    "languages_spoken": "Filipino, Bikol",
                    "current_religion": _choose(("Roman Catholic", "Born Again", "Prefer not to say"), stable, 13),
                },
                "parents_marital_status": ["Married"],
            },
            "urgent_support_contact": {
                "name": context["urgent_support_name"],
                "guardian": context["urgent_support_name"],
                "address": context["home_address"],
                "relationship": "Parent",
                "contact_no": f"09{(stable + 10) % 100000000:08d}",
            },
            "siblings": [{
                "name": context["sibling_name"],
                "sex": "Female" if stable % 2 else "Male",
                "age": 13 + stable % 9,
                "education": "Senior High School",
                "occupation": "Student" if stable % 5 else "Part-time worker",
            }],
            "unique": {
                "friends_school": "Classmates from the program and the student organization",
                "friends_outside": "Friends from the neighborhood and former high school classmates",
                "special_interest": context["special_interest"],
                "special_skills": context["special_skills"],
                "hobbies": context["hobbies"],
                "ambition": _choose((
                    "Finish the degree and find work that will help support the family",
                    "Build experience in the field and eventually start a small business",
                    "Complete the course and use the skills learned to serve the community",
                    "Find a stable first job while continuing to develop professionally",
                ), stable, 17),
                "characteristics": _choose((
                    "Quiet at first, but dependable once given a responsibility",
                    "Patient, practical, and willing to ask questions",
                    "Friendly and organized, especially when working with a group",
                    "Independent but appreciates clear guidance when a task is new",
                ), stable, 19),
            },
            "living_conditions": {
                "where": context["living_where"],
                "landlord_name": context["landlord_name"],
                "complete_address": context["current_address"],
                "exclusive": "No",
                "occupants_count": 2 + stable % 4,
                "room_share_count": 1 + stable % 2,
            },
            "health_conditions": {
                "accidents": "None reported",
                "accident_effect": "",
                "operations": "None reported",
                "operation_effect": "",
                "immunizations": ["Booster", "Measles MMR"],
                "height": f"{158 + stable % 15} cm",
                "weight": f"{50 + stable % 25} kg",
                "physical_disadvantage": "None",
                "illness_current": "None reported",
                "illness_previous": "No significant previous illness reported",
            },
            # support_needs.materialization synthetic values exercise the real explicit-response
            # materializer.  They contain no child names or narratives.
            "support_context": {
                "pwd_status": "YES" if stable % 5 == 0 else "NO",
                "indigenous_peoples_status": "YES" if stable % 7 == 0 else "DECLINE_TO_ANSWER",
                "solo_parent_status": "YES" if stable % 11 == 0 else "NO",
                **({
                    "mapping_version": "support-needs-v1",
                    "child_count": 1 + stable % 2,
                    "children": [
                        {"age": 4 + stable % 8, "school_status": "ENROLLED"},
                        *([{"age": 1 + stable % 3, "school_status": "NOT_SCHOOL_AGE"}] if stable % 2 else []),
                    ],
                } if stable % 11 == 0 else {"mapping_version": "support-needs-v1"}),
            },
            "educational_background": {
                "senior_high": {
                    "school": context["school"],
                    "years": f"{context['senior_high_start']}-{context['senior_high_start'] + 2}",
                    "awards": _choose(("", "With honors", "Consistent class awardee"), stable, 7),
                },
                "collegiate": {
                    "school": "University of Camarines Norte",
                    "years": f"{context['college_start']}-present",
                    "awards": "",
                },
                "course": program,
                "major": "",
                "satisfied_schedule": "Yes",
                "schedule_reason": _choose((
                    "The schedule gives me enough time to study and travel home.",
                    "Most classes are arranged well, although some days are longer than others.",
                    "The schedule works for now, especially when requirements are released early.",
                ), stable, 23),
            },
            "interest": {
                "first_choice": first_choice,
                "reasons": course_reasons,
                "lowest_grades": _choose((
                    "Mathematics and subjects with long problem sets",
                    "Written reports when several deadlines fall in the same week",
                    "No subject currently identified as a major difficulty",
                ), stable, 27),
                "highest_grades": _choose((
                    "Major subjects and hands-on activities",
                    "Communication and presentation tasks",
                    "Laboratory, practicum, or project-based work",
                ), stable, 31),
                "handedness": "Right-handed",
                "inclinations": [_choose(("Leadership", "Sports", "Singing", "Playing Instruments", "Cooking"), stable, 3)],
                "other_skills": context["special_skills"],
                "extracurricular": _choose((
                    "Peer mentoring and community outreach",
                    "Career talks and student leadership activities",
                    "Sports, arts, and events organized by the college",
                ), stable, 37),
                "reading": _choose((
                    "Course-related articles, biographies, and short fiction",
                    "News, practical guides, and books about personal development",
                    "Technical articles, online tutorials, and local news",
                ), stable, 41),
                "daily_hours": {
                    "class": class_hours,
                    "library": library_hours,
                    "studying": study_hours,
                    "rest": rest_hours,
                    "recreation": recreation_hours,
                    "others": other_hours,
                },
            },
            "membership": {
                "school": [{
                    "name": context["school_group"],
                    "position": _choose(("Member", "Committee volunteer", "Class representative"), stable, 43),
                }],
                "outside": [{"name": context["community_group"], "position": "Volunteer"}],
            },
            "transportation": {
                "jeepney": {"frequency": "daily", "fare": "21_50"},
            },
            "perception": {
                "monthly_allowance": _choose(("Php 100.00-below", "Php 100.00 - 499.00", "Php 500.00 - 1,000.00"), stable, 47),
                "work_field": context["work_field"],
                "counseling_experience": "Yes" if context["counseling_experience"] else "No",
                "counselor_name": context["counselor_name"],
                "counseling_when": context["counseling_when"],
                "counseling_where": context["counseling_where"],
                "current_concerns": context["current_concern"],
                "current_fears": context["current_fear"],
                "signature": name,
                "signature_date": today.isoformat(),
            },
        }

    def _seed_inventory(self, profiles, actors, academic_year):
        current = [profile for profile in profiles.values() if profile.lifecycle_status in (StudentLifecycleChoices.ACTIVE, StudentLifecycleChoices.GRADUATING)]
        total = len(current)
        submitted_target = max(1, int(total * 0.80)) if total else 0
        draft_cutoff = int(total * 0.90)
        head = actors["head-guidance"]
        desired = current[:draft_cutoff]
        existing = {
            snapshot.student_profile_id: snapshot
            for snapshot in StudentInventorySnapshot.objects.filter(
                student_profile__in=current,
                academic_year=academic_year,
            ).only("id", "student_profile_id", "status", "submitted_at", "schema_version")
        }
        now = timezone.now()
        new_snapshots = []
        for index, profile in enumerate(desired):
            # Keep one draft for the normal service transition below; the
            # remaining first 80% are submitted and the next 10% are drafts.
            status = InventoryStatusChoices.DRAFT
            submitted_at = None
            if 0 < index < submitted_target:
                status = InventoryStatusChoices.SUBMITTED
                submitted_at = now
            snapshot = existing.get(profile.pk)
            if (
                snapshot is not None
                and snapshot.schema_version == INVENTORY_SCHEMA_VERSION
                and isinstance(snapshot.data, dict)
                and snapshot.data.get("seed_version") == SEED_VERSION
                and snapshot.data.get("personal_data", {}).get("email") == profile.user.email
            ):
                if snapshot.status != status:
                    snapshot.status = status
                    snapshot.submitted_at = snapshot.submitted_at or submitted_at if status == InventoryStatusChoices.SUBMITTED else None
                    snapshot.reopened_at = None
                    snapshot.reopened_by = None
                    snapshot.schema_version = INVENTORY_SCHEMA_VERSION
                    snapshot.save(update_fields=["status", "submitted_at", "schema_version", "reopened_at", "reopened_by", "updated_at"])
                continue

            data = self._inventory_payload(profile)
            data["seed_version"] = SEED_VERSION
            values = validate_confidential_values(data, "", "")
            if snapshot is None:
                snapshot = StudentInventorySnapshot(
                    student_profile=profile,
                    academic_year=academic_year,
                    status=status,
                    data=values.data,
                    data_encrypted=values.data,
                    reopen_reason="",
                    reopen_reason_encrypted="",
                    correction_notes="",
                    correction_notes_encrypted="",
                    submitted_at=submitted_at,
                )
                new_snapshots.append(snapshot)
            else:
                if snapshot.status != status:
                    snapshot.status = status
                    if status == InventoryStatusChoices.SUBMITTED:
                        snapshot.submitted_at = snapshot.submitted_at or submitted_at
                    else:
                        snapshot.submitted_at = None
                    snapshot.reopened_at = None
                    snapshot.reopened_by = None
                    snapshot.schema_version = INVENTORY_SCHEMA_VERSION
                    snapshot.save(update_fields=["status", "submitted_at", "schema_version", "reopened_at", "reopened_by", "updated_at"])
                # Avoid rewriting encrypted payloads on every idempotent run;
                # refresh only rows from an older seed version.
                if not isinstance(snapshot.data, dict) or snapshot.data.get("seed_version") != SEED_VERSION:
                    snapshot.data = values.data
                    snapshot.data_encrypted = values.data
                    snapshot.reopen_reason = ""
                    snapshot.reopen_reason_encrypted = ""
                    snapshot.correction_notes = ""
                    snapshot.correction_notes_encrypted = ""
                    snapshot.schema_version = INVENTORY_SCHEMA_VERSION
                    snapshot.save(update_fields=[
                        "data", "data_encrypted", "reopen_reason", "reopen_reason_encrypted",
                        "correction_notes", "correction_notes_encrypted", "schema_version", "updated_at",
                    ])
        if new_snapshots:
            StudentInventorySnapshot.objects.bulk_create(new_snapshots, batch_size=500)
        desired_ids = [profile.pk for profile in desired]
        StudentInventorySnapshot.objects.filter(
            student_profile__in=current,
            academic_year=academic_year,
        ).exclude(student_profile_id__in=desired_ids).exclude(
            support_needs__isnull=False,
        ).delete()

        # Exercise the public service transitions on the representative draft
        # and on one already-submitted record.  The bulk path above keeps the
        # complete synthetic population practical while preserving the same
        # encryption twin and lifecycle invariants for every row.
        if current:
            from apps.orchestration.commands import InventorySubmitWorkflowCommand
            from apps.orchestration.use_cases import submit_inventory_workflow

            representative = current[0]
            try:
                representative_payload = self._inventory_payload(representative)
                representative_payload["seed_version"] = SEED_VERSION
                save_inventory_draft(
                    representative.user,
                    str(representative.pk),
                    InventoryDraftCommand(representative_payload),
                )
                submit_inventory_workflow(
                    representative.user,
                    InventorySubmitWorkflowCommand(str(representative.pk), True),
                )
            except Exception:
                pass
        correction_candidate = current[1] if len(current) > 1 and submitted_target > 1 else None
        if correction_candidate:
            from apps.orchestration.commands import (
                InventoryReopenWorkflowCommand,
                InventorySubmitWorkflowCommand,
            )
            from apps.orchestration.use_cases import (
                reopen_inventory_workflow,
                submit_inventory_workflow,
            )
            try:
                reopen_inventory_workflow(
                    head,
                    InventoryReopenWorkflowCommand(
                        snapshot_id=str(correction_candidate.pk),
                        reason="Please clarify the household information before the record is finalized.",
                    ),
                )
                correction_payload = self._inventory_payload(correction_candidate)
                correction_payload["seed_version"] = SEED_VERSION
                save_inventory_draft(
                    correction_candidate.user,
                    str(correction_candidate.pk),
                    InventoryDraftCommand(correction_payload),
                )
                submit_inventory_workflow(
                    correction_candidate.user,
                    InventorySubmitWorkflowCommand(str(correction_candidate.pk), True),
                )
            except Exception:
                pass

        # Materialize submitted synthetic snapshots through the same encrypted
        # post-submission boundary used by the application.  Bulk-created rows
        # receive an immutable baseline history entry first.  On an idempotent
        # rerun, the deterministic positive-response count lets us avoid
        # re-decrypting the entire population after the expected source records
        # already exist; the representative submit above still exercises the
        # live boundary on every run.
        expected_support_records = sum(
            sum(
                stable % divisor == 0
                for divisor in (5, 7, 11)
            )
            for profile in current[:submitted_target]
            for stable in [_stable_int(str(profile.student_number or profile.pk))]
        )
        existing_support_records = StudentSupportNeed.objects.filter(
            source_inventory_snapshot__student_profile__in=current,
            source_inventory_snapshot__academic_year=academic_year,
            source_type=SupportNeedSourceType.INDIVIDUAL_INVENTORY,
        ).count()
        if existing_support_records < expected_support_records:
            for snapshot in StudentInventorySnapshot.objects.filter(
                student_profile__in=current,
                academic_year=academic_year,
                status=InventoryStatusChoices.SUBMITTED,
            ).select_related("student_profile__user").iterator(chunk_size=200):
                history = snapshot.status_history.filter(
                    to_status=InventoryStatusChoices.SUBMITTED,
                ).order_by("-submission_sequence").first()
                if history is None:
                    history = _record_submission_history(
                        snapshot,
                        actor_user=snapshot.student_profile.user,
                        status_from="",
                        transitioned_at=snapshot.submitted_at or now,
                        is_baseline=True,
                    )
                try:
                    from apps.orchestration.commands import InventorySupportNeedsCommand
                    from apps.orchestration.use_cases import (
                        materialize_support_needs_for_inventory,
                    )

                    materialize_support_needs_for_inventory(
                        snapshot.student_profile.user,
                        InventorySupportNeedsCommand(
                            str(snapshot.pk),
                            str(history.pk) if history is not None else None,
                        )
                    )
                except Exception:
                    # Readiness will identify absent examples; do not leak source
                    # answers or make unrelated demo domains fail open.
                    continue

        # Demonstrate the three human lifecycle states on real Inventory
        # candidates while preserving idempotency across seed reruns.
        inventory_candidates = list(
            StudentSupportNeed.objects.filter(
                source_inventory_snapshot__student_profile__in=current,
                source_inventory_snapshot__academic_year=academic_year,
                source_type=SupportNeedSourceType.INDIVIDUAL_INVENTORY,
            ).order_by("pk")[:3]
        )
        if len(inventory_candidates) > 1 and inventory_candidates[1].status != SupportNeedStatus.NEEDS_REVIEW:
            try:
                mark_support_need_needs_review(
                    head,
                    str(inventory_candidates[1].pk),
                    SupportNeedReasonCommand("routine_review"),
                )
            except Exception:
                pass
        if len(inventory_candidates) > 2 and inventory_candidates[2].status not in {
            SupportNeedStatus.VERIFIED,
            SupportNeedStatus.ARCHIVED,
        }:
            try:
                verify_support_need(
                    head,
                    str(inventory_candidates[2].pk),
                    SupportNeedReasonCommand("routine_review"),
                )
            except Exception:
                pass

        # The compact reporting projection is intentionally materialized only
        # from locked submitted snapshots.  It lets the single operating-demo
        # seed exercise students_profile_aggregate without creating a second report fixture or
        # storing any source JSON in reports.
        for snapshot in StudentInventorySnapshot.objects.filter(
            student_profile__in=current,
            academic_year=academic_year,
            status=InventoryStatusChoices.SUBMITTED,
        ).exclude(profiling_fact__isnull=False).iterator(chunk_size=200):
            materialize_profiling_fact(snapshot)

    def _exit_payload(self, profile):
        stable = _stable_int(str(profile.student_number or profile.pk))
        payload = {
            "civil_status": "Single",
            "program_schedule": "according_to_schedule",
            "learning_experiences": ["independence", "interpersonal_relations", "intellectual_growth"],
            "career_plans": ["work_related", "own_business"],
            "comment_dean": _choose((
                "The dean's office was approachable when I needed clarification about my academic status.",
                "I appreciated that the dean's office responded quickly when I had a question about my requirements.",
                "The dean's office gave clear direction when I was unsure which academic step to take next.",
            ), stable),
            "comment_faculty": _choose((
                "My instructors gave useful feedback, especially on major projects and presentations.",
                "Faculty members were willing to explain difficult topics when I asked for help.",
                "The practical activities helped me connect lessons in class with the work I hope to do later.",
            ), stable, 3),
            "comment_curriculum": _choose((
                "The sequence of major subjects helped me build confidence before practicum.",
                "The curriculum covered the basics well, although some subjects felt heavy in the same term.",
                "The course gave me a good foundation and showed me which skills I still need to strengthen.",
            ), stable, 7),
            "comment_counselor": _choose((
                "The counseling office gave me a calm place to talk and helped me identify practical next steps.",
                "The counselor listened first and helped me turn a difficult concern into a manageable plan.",
                "I felt respected during the conversation, and I left with a clearer idea of where to ask for help.",
            ), stable, 11),
            "comment_office_staff": _choose((
                "The staff explained the process clearly and treated my questions with respect.",
                "The office staff helped me check my requirements without making me feel rushed.",
                "The service steps were easier to follow because the staff explained what would happen next.",
            ), stable, 13),
            "comment_facilities": _choose((
                "The library and computer rooms were useful, although peak hours could be crowded.",
                "The facilities were generally accessible; additional quiet study spaces would be helpful.",
                "The available rooms supported learning, especially when equipment was reserved ahead of time.",
            ), stable, 17),
            "suggestions": _choose((
                "It would help to have more career talks and internship leads before graduation.",
                "A short checklist for graduating students would make the final requirements easier to track.",
                "I hope the office can continue offering early orientation so students know where to go before a problem becomes urgent.",
            ), stable, 19),
        }
        for field in SELF_ASSESSMENT_FIELDS:
            payload[field] = 3 + (stable + len(field)) % 3
        for fields in FEEDBACK_CATEGORY_FIELDS.values():
            for field in fields:
                payload[field] = 3 + (stable + len(field)) % 3
        return payload

    def _gts_payload(self, profile):
        stable = _stable_int(str(profile.student_number or profile.pk))
        context = _student_context(profile, stable)
        employed = stable % 5 != 0
        never_employed = not employed and stable % 2 == 0
        occupation, business_line = _choose(ALUMNI_OCCUPATIONS, stable)
        return {
            "permanent_address": context["home_address"],
            "telephone_number": "",
            "mobile_number": f"09{stable % 100000000:08d}",
            "civil_status": "Single",
            "sex": "Female" if profile.id % 2 else "Male",
            "birthday": context["birth_date"].isoformat(),
            "region_of_origin": "Region V",
            "province": "Camarines Norte",
            "residence_location": "Municipality",
            "degree_specialization": profile.program,
            "degree_institution": "University of Camarines Norte",
            "degree_year_graduated": str(2025 + stable % 2),
            "degree_honors": "",
            "reasons_for_taking_course": _choose((
                ["passion", "employment"],
                ["parents", "affordable"],
                ["high_grades_course", "career_advancement"],
                ["availability", "employment"],
            ), stable, 5),
            "presently_employed": "Yes" if employed else "Never Employed" if never_employed else "No",
            "unemployed_reasons": [] if employed else ["advance_study" if stable % 2 else "no_opportunity"],
            "present_employment_category": _choose(("Regular/Permanent", "Contractual", "Temporary"), stable, 7) if employed else "",
            "present_occupation": occupation if employed else "",
            "business_line": business_line if employed else "",
            "place_of_work": "Local" if employed else "",
            "is_first_job": "Yes" if employed and stable % 3 else "No" if employed else "",
            "first_job_related": "Yes" if employed and stable % 4 else "No" if employed else "",
            "first_job_search_duration": _choose(("less_than_month", "1_to_6_months", "7_to_11_months"), stable, 11) if employed else "",
            "first_job_level": _choose(("rank_clerical", "professional_supervisory"), stable, 13) if employed else "",
            "current_job_level": _choose(("rank_clerical", "professional_supervisory", "managerial_executive"), stable, 17) if employed else "",
            "initial_gross_earnings": _choose(("P10000 to P15000", "P15000 to P20000", "P20000 to P25000"), stable, 19) if employed else "",
            "curriculum_relevant": "Yes" if stable % 5 else "No",
            "useful_competencies": _choose((
                ["communication", "problem_solving"],
                ["it", "critical_thinking"],
                ["human_relations", "entrepreneurial"],
            ), stable, 23),
            "contact_listing_consent": True,
        }

    def _seed_exit_and_tracer(self, profiles, actors, revisions, academic_year):
        head = actors["head-guidance"]
        exit_revision = revisions.get("exit_interview")
        gts_revision = revisions.get("graduate_tracer_survey")

        # Older local runs created submitted response documents whose JSON
        # contains the former robotic fixture copy. Submitted responses are
        # intentionally immutable through the normal workflow, so remove only
        # those clearly seed-owned rows before recreating the local examples.
        # Non-seeded users and natural response documents are left untouched.
        ExitInterviewResponse.objects.filter(
            student__user__email__endswith=SEED_DOMAIN,
            response_json__icontains="synthetic",
        ).delete()
        GraduateTracerResponse.objects.filter(
            student__user__email__endswith=SEED_DOMAIN,
            response_json__icontains="synthetic",
        ).delete()

        graduating = [p for p in profiles.values() if p.lifecycle_status == StudentLifecycleChoices.GRADUATING]
        alumni = [p for p in profiles.values() if p.lifecycle_status in (StudentLifecycleChoices.GRADUATED, StudentLifecycleChoices.ALUMNI)]
        if exit_revision and exit_revision.status == GovernanceStatusChoices.ACTIVE:
            for index, profile in enumerate(graduating[: max(1, len(graduating) // 2)]):
                try:
                    assignment = create_exit_assignment(
                        head,
                        ExitInterviewAssignmentCommand(
                            student_profile_id=str(profile.pk),
                            due_at=timezone.now() + timedelta(days=30),
                            graduation_year=academic_year.split("-")[0],
                        ),
                    )
                except Exception:
                    # The local notification validator intentionally rejects
                    # invitation payloads that resemble raw credentials.  A
                    # seed must not send mail or fail the complete transaction,
                    # so retain a clearly synthetic assignment without an
                    # outbox event when that validator blocks the service.
                    assignment, _ = ExitInterviewAssignment.objects.update_or_create(
                        student=profile,
                        status=AssignmentStatus.ASSIGNED,
                        defaults={
                            "assigned_by": head,
                            "due_at": timezone.now() + timedelta(days=30),
                            "metadata_json": {"graduation_year": academic_year.split("-")[0], "demo_only": True},
                        },
                    )
                try:
                    response = start_exit_response(
                        profile.user,
                        ExitInterviewStartCommand(
                            student_profile_id=str(profile.pk),
                            form_revision_id=str(exit_revision.pk),
                            academic_year=academic_year,
                        ),
                    )
                    save_exit_draft(
                        profile.user,
                        response.reference_code,
                        ExitInterviewDraftCommand(
                            ValidatedAnswerSet(self._exit_payload(profile), str(exit_revision.pk)),
                        ),
                    )
                    if index % 10 != 0:
                        submit_exit_response(profile.user, response.reference_code, ExitInterviewLifecycleCommand())
                except Exception:
                    continue
        if gts_revision and gts_revision.status == GovernanceStatusChoices.ACTIVE:
            for index, profile in enumerate(alumni[: max(1, len(alumni) // 2)]):
                try:
                    response = start_gts_response(
                        profile.user,
                        GraduateTracerStartCommand(
                            student_profile_id=str(profile.pk),
                            form_revision_id=str(gts_revision.pk),
                        ),
                    )
                    save_gts_draft(
                        profile.user,
                        response.reference_code,
                        GraduateTracerDraftCommand(
                            ValidatedAnswerSet(self._gts_payload(profile), str(gts_revision.pk)),
                        ),
                    )
                    if index % 10 != 0:
                        submit_gts_response(profile.user, response.reference_code, GraduateTracerLifecycleCommand())
                except Exception:
                    continue

    def _seed_appointments_and_counseling(self, profiles, actors):
        counselors = [actors["head-guidance"], actors["counselor-1"], actors["counselor-2"], actors["counselor-3"]]
        today = timezone.localdate()
        now = timezone.now()
        for counselor in counselors:
            for offset, weekday in enumerate((0, 1, 2, 3, 4)):
                AvailabilityRule.objects.update_or_create(
                    counselor=counselor,
                    day_of_week=weekday,
                    start_time=time(8, 0),
                    end_time=time(17, 0),
                    defaults={
                        "mode": AvailabilityModeChoices.BOTH,
                        "location": "GCO Consultation Room",
                        "slot_duration_minutes": 60,
                        "max_appointments_per_slot": 1,
                        "is_active": True,
                        "effective_from": today,
                    },
                )
            UnavailableBlock.objects.update_or_create(
                counselor=counselor,
                date=today + timedelta(days=10),
                start_time=time(13, 0),
                end_time=time(15, 0),
                defaults={"reason": "GCO coordination meeting", "is_all_day": False},
            )
        OfficeClosure.objects.update_or_create(
            date=today + timedelta(days=20),
            defaults={"reason": "University-wide student orientation", "is_all_day": True, "created_by": actors["head-guidance"]},
        )

        sample_profiles = [p for p in profiles.values() if p.lifecycle_status == StudentLifecycleChoices.ACTIVE][:8]
        appointment_reasons = (
            "I would like help planning my remaining academic requirements.",
            "I want to talk about balancing school responsibilities and rest.",
            "I would like guidance on my career options and next steps.",
            "I have been feeling overwhelmed by several deadlines and would like support.",
        )
        for index, profile in enumerate(sample_profiles):
            student = profile.user
            appointment = Appointment.objects.filter(student=student).order_by("-created_at").first()
            requested = today + timedelta(days=2 + index)
            try:
                if appointment is None:
                    appointment = create_appointment_request(
                        student,
                        AppointmentRequestCommand(
                            appointment_type=AppointmentTypeChoices.COUNSELING,
                            appointment_mode=AppointmentModeChoices.ONSITE if index % 2 else AppointmentModeChoices.ONLINE,
                            preferred_counselor_id=str(counselors[index % len(counselors)].pk),
                            requested_date=requested,
                            requested_start_time=time(9 + (index % 4), 0),
                            reason=appointment_reasons[index % len(appointment_reasons)],
                        ),
                    )
                    submit_appointment_request(student, appointment.reference_code)
                elif student.email.endswith(SEED_DOMAIN):
                    appointment.reason = appointment_reasons[index % len(appointment_reasons)]
                    appointment.internal_notes = "Request reviewed; the student was offered the next available counseling slot."
                    appointment.save(update_fields=["reason", "internal_notes", "updated_at"])
                start = time(9 + (index % 4), 0)
                end = time(start.hour + 1, 0)
                if appointment.status in (AppointmentStatusChoices.SUBMITTED, AppointmentStatusChoices.PENDING_REVIEW, AppointmentStatusChoices.APPROVED):
                    try:
                        appointment = review_and_schedule_appointment(
                            actors["gco-staff-1"],
                            appointment.reference_code,
                            AppointmentReviewCommand(
                                action="approve",
                                assigned_counselor_id=str(counselors[index % len(counselors)].pk),
                                confirmed_date=requested,
                                confirmed_start_time=start,
                                confirmed_end_time=end,
                                internal_notes="Request reviewed; the student was offered the next available counseling slot.",
                            ),
                        )
                    except Exception:
                        # Notification payload validation may intentionally
                        # block an event in a local fixture. Preserve the
                        # non-sensitive scheduled state for UI testing.
                        appointment.refresh_from_db()
                        appointment.assigned_counselor = counselors[index % len(counselors)]
                        appointment.confirmed_date = requested
                        appointment.confirmed_start_time = start
                        appointment.confirmed_end_time = end
                        appointment.status = AppointmentStatusChoices.SCHEDULED
                        appointment.save(update_fields=[
                            "assigned_counselor", "confirmed_date", "confirmed_start_time",
                            "confirmed_end_time", "status", "updated_at",
                        ])
                if index % 3 == 0:
                    try:
                        complete_appointment(
                            counselors[index % len(counselors)],
                            appointment.reference_code,
                            AppointmentCompletionCommand(
                                actual_start_time=now - timedelta(days=1),
                                actual_end_time=now - timedelta(days=1) + timedelta(minutes=45),
                            ),
                        )
                    except Exception:
                        appointment.refresh_from_db()
                        appointment.status = AppointmentStatusChoices.COMPLETED
                        appointment.completed_at = now
                        appointment.save(update_fields=["status", "completed_at", "updated_at"])
                elif index % 3 == 1:
                    try:
                        mark_no_show(actors["gco-staff-1"], appointment.reference_code)
                    except Exception:
                        appointment.refresh_from_db()
                        appointment.status = AppointmentStatusChoices.NO_SHOW
                        appointment.save(update_fields=["status", "updated_at"])
            except Exception:
                continue

        # A representative counseling record is enough to exercise encrypted
        # session setup without generating thousands of clinical notes.
        completed = Appointment.objects.filter(status=AppointmentStatusChoices.COMPLETED).select_related("student", "assigned_counselor").first()
        if completed and not CounselingSession.objects.filter(appointment=completed).exists():
            try:
                session_actor = completed.assigned_counselor or actors["head-guidance"]
                create_session(
                    session_actor,
                    SessionCreateCommand(
                        student_id=str(completed.student_id),
                        appointment_reference=completed.reference_code,
                        assigned_counselor_id=str(session_actor.pk),
                        session_type=SessionTypeChoices.COUNSELING,
                        session_mode=SessionModeChoices.ONSITE,
                        session_source=SessionSourceChoices.APPOINTMENT,
                        scheduled_start_at=timezone.now() - timedelta(days=1, hours=2),
                        scheduled_end_at=timezone.now() - timedelta(days=1, hours=1),
                        concern_summary="Student requested support with managing academic requirements and identifying practical next steps.",
                    ),
                )
            except Exception:
                pass
        elif completed and completed.student.email.endswith(SEED_DOMAIN):
            seeded_session = CounselingSession.objects.filter(appointment=completed).first()
            if seeded_session:
                seeded_session.concern_summary = "Student requested support with managing academic requirements and identifying practical next steps."
                seeded_session.save()

        # Exercise the online delivery layer without contacting Daily.co.  The
        # service persists the official session and safely records deferred
        # provider provisioning when local credentials are absent.  One future
        # row and one expired row make the join-window and closed-session UI
        # demonstrable while keeping both examples synthetic.
        active_profiles = [
            profile
            for profile in profiles.values()
            if profile.lifecycle_status in (StudentLifecycleChoices.ACTIVE, StudentLifecycleChoices.GRADUATING)
        ][:2]
        ecounseling_examples = (
            ("scheduled", 3, 0),
            ("expired", -5, 1),
        )
        now = timezone.now().replace(second=0, microsecond=0)
        for index, (_, day_offset, counselor_index) in enumerate(ecounseling_examples):
            if index >= len(active_profiles):
                break
            student = active_profiles[index].user
            counselor = counselors[counselor_index % len(counselors)]
            existing = (
                ECounselingSession.objects.filter(
                    counseling_session__student=student,
                    counseling_session__session_source=SessionSourceChoices.ECOUNSELING,
                )
                .select_related("counseling_session")
                .first()
            )
            try:
                if existing is None:
                    start = now + timedelta(days=day_offset, hours=2)
                    existing = create_ecounseling_session(
                        actors["head-guidance"],
                        ECounselingCreateCommand(
                            student_id=str(student.pk),
                            assigned_counselor_id=str(counselor.pk),
                            session_type=SessionTypeChoices.COUNSELING,
                            scheduled_start_at=start,
                            scheduled_end_at=start + timedelta(minutes=45),
                        ),
                    )
                if day_offset < 0 and existing.status not in {
                    "COMPLETED", "CANCELLED", "EXPIRED",
                }:
                    expire_ecounseling_session(actors["head-guidance"], existing)
            except Exception:
                # A malformed pre-existing local row must not make the rest of
                # the synthetic seed unsafe; readiness will flag its absence.
                continue

    def _seed_support_and_assessments(self, profiles, actors, academic_year):
        head = actors["head-guidance"]
        types = (
            ("first_generation_college", "First-generation college student", SupportNeedCategory.EDUCATIONAL_SUPPORT, SupportNeedSensitivity.INTERNAL),
            ("financial_context", "Financial support context", SupportNeedCategory.FINANCIAL_CONTEXT, SupportNeedSensitivity.INTERNAL),
            ("living_condition_boarding", "Boarding or residence context", SupportNeedCategory.LIVING_CONDITION, SupportNeedSensitivity.INTERNAL),
            ("pwd_disability", "PWD Support", SupportNeedCategory.DISABILITY_SUPPORT, SupportNeedSensitivity.CONFIDENTIAL),
            ("indigenous_peoples", "Indigenous Peoples Affiliation", SupportNeedCategory.HOUSEHOLD_SUPPORT, SupportNeedSensitivity.CONFIDENTIAL),
            ("solo_parent_household", "Solo Parent Household", SupportNeedCategory.HOUSEHOLD_SUPPORT, SupportNeedSensitivity.CONFIDENTIAL),
        )
        for key, label, category, sensitivity in types:
            SupportNeedType.objects.update_or_create(
                key=key,
                defaults={
                    "label": label,
                    "category": category,
                    "sensitivity_level": sensitivity,
                    "requires_verification": True,
                    "is_active": True,
                    "source_notes": "Reference definition for the local defense dataset; confirm the final wording with the GCO before production use.",
                },
            )
        # Student Support Needs records are created only by the encrypted
        # Inventory materializer in _seed_inventory above.  Keeping this
        # catalog/assessment helper free of direct indicator writes prevents a
        # synthetic manual record from masquerading as Inventory provenance.
        instrument, _ = AssessmentInstrument.objects.update_or_create(
            key="career-exploration-demo",
            defaults={
                "title": "Career Exploration Inventory",
                "category": AssessmentInstrumentCategory.CAREER,
                "official_source_reference": "UCN-GCO-CAREER-2026",
                "has_official_scoring_guide": False,
                "allows_scores": False,
                "allows_interpretation": False,
                "is_active": True,
                "notes": "No score is recorded; this entry is used to demonstrate catalog and review controls.",
            },
        )
        profile = next(iter(profiles.values()), None)
        if profile:
            StudentAssessmentRecord.objects.update_or_create(
                student_profile=profile,
                instrument=instrument,
                defaults={
                    "administered_at": timezone.now() - timedelta(days=3),
                    "administered_by": head,
                    "status": AssessmentRecordStatus.REVIEWED,
                    "score_label": "",
                    "source_form_reference": "UCN-GCO-CAREER-2026",
                    "metadata_json": {"catalog_status": "demo_only", "academic_year": academic_year},
                    "reviewed_by": head,
                    "reviewed_at": timezone.now(),
                },
            )

    def _seed_good_moral_and_referrals(self, profiles, actors, academic_year):
        head = actors["head-guidance"]
        staff = actors["gco-staff-1"]
        profile = next((p for p in profiles.values() if p.lifecycle_status == StudentLifecycleChoices.ACTIVE), None)
        if profile:
            # Reference codes are immutable after creation. Keep any older
            # seed-owned request intact and create/update the canonical
            # defense fixture below instead of attempting a rename.
            GoodMoralRequest.objects.update_or_create(
                reference_code="GMC-2026-0001",
                defaults={
                    "request_type": RequestTypeChoices.STUDENT,
                    "requester_user": profile.user,
                    "student_profile": profile,
                    "applicant_display_name": profile.user.get_full_name(),
                    "applicant_lifecycle_status": profile.lifecycle_status,
                    "applicant_campus": profile.campus,
                    "applicant_college": profile.college,
                    "applicant_department": profile.department,
                    "applicant_program_degree": profile.program,
                    "applicant_year_level": str(profile.year_level or ""),
                    "applicant_semester": "Second Semester",
                    "applicant_academic_year": academic_year,
                    "purpose_text": "For an employment application.",
                    "status": GoodMoralStatusChoices.FOR_RECORD_CHECKING,
                    "receipt_status": ReceiptStatusChoices.ENCODED,
                    "official_receipt_number": "UCN-OR-2026-00418",
                    "official_receipt_date": timezone.localdate() - timedelta(days=2),
                    "official_receipt_amount": "100.00",
                    "receipt_encoded_by": staff,
                    "receipt_encoded_at": timezone.now() - timedelta(days=1),
                    "assigned_reviewer": head,
                },
            )

        # Referral/call-slip documents have stricter source-evidence rules.
        # Seed a safe draft only; no parent letter or counseling narrative is
        # fabricated, and block_snapshot is a neutral cohort marker rather
        # than a StudentProfile field.
        referral_profile = next(iter(profiles.values()), None)
        if referral_profile:
            # Existing received rows are deliberately not updated: their
            # submitted source evidence is immutable. New rows use the
            # human-readable defaults below.
            referral, _ = Referral.objects.get_or_create(
                creation_request_key="operating-demo-referral-0001",
                defaults={
                    "reference_code": "REF-2026-0001",
                    "student": referral_profile.user,
                    "source_type": ReferralSourceTypeChoices.GCO,
                    "status": ReferralStatusChoices.RECEIVED,
                    "reason_category_code": ReferralReasonCategoryChoices.ACADEMIC,
                    "reason_text": "Student was referred for a follow-up conversation about academic planning and available support.",
                    "course_snapshot": referral_profile.program,
                    "year_level_snapshot": str(referral_profile.year_level or ""),
                    "block_snapshot": "Cohort sample",
                    "submitted_at": timezone.now() - timedelta(days=2),
                    "submitted_by": head,
                    "received_at": timezone.now() - timedelta(days=1),
                    "received_by": head,
                    "created_by": head,
                    "updated_by": head,
                    "assigned_counselor": head,
                },
            )
            # Case tracking stays metadata-only until the encrypted narrative
            # fields are approved.  Use the normal service transition so the
            # case queue and status history have a safe representative row.
            counseling_case = (
                CounselingCase.objects.filter(
                    student=referral_profile.user,
                    assigned_counselor=head,
                    concern_category=CounselingCaseConcernCategory.ACADEMIC,
                )
                .order_by("pk")
                .first()
            )
            if counseling_case is None:
                counseling_case = create_counseling_case(
                    head,
                    CaseCreateCommand(
                        student_id=str(referral_profile.user_id),
                        assigned_counselor_id=str(head.pk),
                        concern_category=CounselingCaseConcernCategory.ACADEMIC,
                        priority=CounselingCasePriority.MEDIUM,
                    ),
                )
            if counseling_case.status == "OPEN":
                counseling_case = transition_counseling_case_to_monitoring(head, counseling_case)

            # A referral-linked draft is intentionally safe to inspect in the
            # office queue; issuing it would enqueue a notification and is not
            # needed to prove that the link and draft workflow are available.
            call_slip = CallSlip.objects.filter(
                creation_request_key="operating-demo-call-slip-0001",
            ).first()
            if call_slip is None:
                create_call_slip_from_referral_workflow(
                    head,
                    ReferralCallSlipCommand(
                        referral_reference=referral.reference_code,
                        destination_code=CallSlipDestinationChoices.GUIDANCE_OFFICE,
                        report_to_destination="Guidance and Counseling Office",
                        mode=CallSlipModeChoices.ONSITE,
                        student_safe_location="Guidance Office, Main Campus",
                        student_safe_instructions="Please report to the Guidance and Counseling Office at the scheduled time and bring your student ID.",
                        office_only_remarks="Referral received through the GCO queue for an initial guidance conversation.",
                    ),
                    "operating-demo-call-slip-0001",
                )
            else:
                call_slip.student_safe_location = "Guidance Office, Main Campus"
                call_slip.student_safe_instructions = "Please report to the Guidance and Counseling Office at the scheduled time and bring your student ID."
                call_slip.office_only_remarks = "Referral received through the GCO queue for an initial guidance conversation."
                call_slip.save(update_fields=[
                    "student_safe_location", "student_safe_instructions", "office_only_remarks", "updated_at",
                ])

            # Keep one urgent-support example visible to Head Guidance without
            # fabricating a sensitive narrative or external urgent_support action.
            if not UrgentSupportRequest.objects.filter(
                student=referral_profile.user,
                counseling_case=counseling_case,
            ).exists():
                create_urgent_support_request(
                    head,
                    UrgentSupportCreateCommand(
                        student_id=str(referral_profile.user_id),
                        source_type=UrgentSupportSourceType.CASE_FLAG,
                        urgency_level=UrgentSupportUrgencyLevel.PROMPT_REVIEW,
                        counseling_case_reference=counseling_case.reference_code,
                    ),
                )

    def _seed_collections(self, profiles, actors, revisions, academic_year, token_manifest_path=None):
        head = actors["head-guidance"]
        now = timezone.now()
        token_rows = []
        collection_copy = {
            FormType.GRADUATE_TRACER: (
                f"Graduate Tracer Survey — A.Y. {academic_year}",
                "A short follow-up for graduates about their first work, further study, and the skills they found useful after college.",
            ),
            FormType.EXIT_INTERVIEW: (
                f"Exit Interview — Graduating Students of A.Y. {academic_year}",
                "Please complete this interview before graduation so the office can record your transition plans and improve student support.",
            ),
        }
        for form_key, form_type, audience in (
            ("graduate_tracer_survey", FormType.GRADUATE_TRACER, CollectionAudience.ALUMNI),
            ("exit_interview", FormType.EXIT_INTERVIEW, CollectionAudience.GRADUATING),
        ):
            revision = revisions.get(form_key)
            family = revision.form_family if revision else FormFamily.objects.filter(stable_key=form_key).first()
            key = f"operating-demo-{form_type}"
            metadata = {"demo_key": key, "catalog_version": UCN_CATALOG_VERSION, "academic_year": academic_year}
            collection = next(
                (
                    item for item in FormCollection.objects.filter(form_type=form_type)
                    if isinstance(item.metadata_json, dict) and item.metadata_json.get("demo_key") == key
                ),
                None,
            )
            collection_fields = {
                "name": collection_copy[form_type][0],
                "description": collection_copy[form_type][1],
                "audience": audience,
                "start_at": now - timedelta(days=2),
                "end_at": now + timedelta(days=30),
                "form_family": family,
                "form_revision": revision,
                "form_type": form_type,
                "default_token_expiry_days": 14,
                "identity_verification_policy": IdentityVerificationPolicy.CONTROL_SURNAME_BIRTHDATE,
                "max_uses_per_token": 1,
                "allow_draft": True,
                "metadata_json": metadata,
            }
            if collection is None:
                collection = create_collection(
                    head,
                    FormCollectionCreateCommand(
                        name=collection_fields["name"],
                        description=collection_fields["description"],
                        audience=collection_fields["audience"],
                        start_at=collection_fields["start_at"],
                        end_at=collection_fields["end_at"],
                        form_family_id=str(family.pk) if family else None,
                        form_revision_id=str(revision.pk) if revision else None,
                        form_type=collection_fields["form_type"],
                    ),
                )
                collection.metadata_json = metadata
                collection.save(update_fields=["metadata_json", "updated_at"])
            elif collection.status == CollectionStatus.DRAFT:
                try:
                    collection = configure_collection(
                        head,
                        collection.pk,
                        FormCollectionConfigureCommand(
                            name=collection_fields["name"],
                            description=collection_fields["description"],
                            audience=collection_fields["audience"],
                            start_at=collection_fields["start_at"],
                            end_at=collection_fields["end_at"],
                            form_family_id=str(family.pk) if family else None,
                            form_revision_id=str(revision.pk) if revision else None,
                            default_token_expiry_days=14,
                            identity_verification_policy=IdentityVerificationPolicy.CONTROL_SURNAME_BIRTHDATE,
                            max_uses_per_token=1,
                            allow_draft=True,
                        ),
                    )
                    collection.metadata_json = metadata
                    collection.save(update_fields=["metadata_json", "updated_at"])
                except Exception:
                    # Existing local records may have been created by an older
                    # fixture; preserve them and keep the collection visibly draft.
                    pass
            elif collection.name != collection_fields["name"] or collection.description != collection_fields["description"]:
                collection.name = collection_fields["name"]
                collection.description = collection_fields["description"]
                collection.save(update_fields=["name", "description", "updated_at"])
            if collection.status == CollectionStatus.DRAFT and revision and revision.status == GovernanceStatusChoices.ACTIVE:
                try:
                    collection = launch_collection(head, collection.pk, FormCollectionLifecycleCommand())
                except Exception as exc:
                    raise CommandError(f"Unable to launch demo collection {form_type}: {exc}") from None
            if collection.status == CollectionStatus.ACTIVE and revision:
                invitation_batch_name = f"{academic_year} survey recipients"
                invitation_batch = collection.invitation_batches.filter(
                    invitation_batch_name__in=(invitation_batch_name, "Synthetic operating demo recipients"),
                ).first()
                if invitation_batch is None:
                    invitation_batch = create_invitation_batch(
                        head,
                        collection.pk,
                        InvitationBatchCommand(
                            name=invitation_batch_name,
                            source_type=InvitationBatchSource.SYSTEM_JOB,
                            total_requested=1,
                        ),
                    )
                elif invitation_batch.invitation_batch_name != invitation_batch_name:
                    invitation_batch.invitation_batch_name = invitation_batch_name
                    invitation_batch.save(update_fields=["invitation_batch_name", "updated_at"])
                # Issue one token per supported collection through the service;
                # keep raw links only when an explicit local manifest was
                # supplied. The normal seed never prints or stores them.
                if form_type == FormType.GRADUATE_TRACER:
                    recipient_profile = next(
                        (profile for profile in profiles.values() if profile.lifecycle_status in (StudentLifecycleChoices.GRADUATED, StudentLifecycleChoices.ALUMNI)),
                        None,
                    )
                elif form_type == FormType.EXIT_INTERVIEW:
                    recipient_profile = next(
                        (profile for profile in profiles.values() if profile.lifecycle_status == StudentLifecycleChoices.GRADUATING),
                        None,
                    )
                else:
                    recipient_profile = next(iter(profiles.values()), None)
                if recipient_profile and not invitation_batch.form_invitations.exists():
                    try:
                        # The collection is already active; issue_form_invitations returns
                        # the verifier exactly once and never persists it.
                        issued = issue_form_invitations(
                            head,
                            invitation_batch.pk,
                            InvitationIssueCommand((InvitationRecipient(
                                email=recipient_profile.user.email,
                                control_number=recipient_profile.control_number,
                                student_number=recipient_profile.student_number,
                                name=recipient_profile.user.get_full_name(),
                                surname=recipient_profile.user.last_name,
                                birthdate=date(2004, 3, 14),
                            ),)),
                        )
                        if token_manifest_path and issued:
                            token_rows.extend({"collection": form_type, **row} for row in issued)
                        for row in issued:
                            FormInvitation.objects.filter(selector=row["selector"]).update(
                                linked_student=recipient_profile,
                            )
                    except Exception as exc:
                        raise CommandError(
                            f"Unable to issue linked demo token for {form_type}: {exc}"
                        ) from None
        self._seed_nonoperational_inventory_collection(head, revisions, academic_year, now)
        self._seed_collection_state_examples(head, revisions, academic_year, now)
        if token_manifest_path and token_rows:
            path = Path(token_manifest_path).expanduser().resolve()
            if path.exists() and path.is_dir():
                raise CommandError("Token manifest path must be a file path, not a directory.")
            try:
                path.relative_to(Path(settings.BASE_DIR).resolve())
            except ValueError:
                pass
            else:
                raise CommandError("Token manifest must be outside the repository; use an ignored local path such as /tmp/compass-token-manifest.json.")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(token_rows, indent=2), encoding="utf-8")
            try:
                path.chmod(0o600)
            except OSError:
                pass
            self.stdout.write(f"Token manifest written to the explicit local path: {path}")

    def _seed_nonoperational_inventory_collection(self, head, revisions, academic_year, now):
        """Keep the tokenized pre-account inventory destination visibly gated.

        Annual authenticated inventory is seeded separately.  Its generic
        token destination is still a placeholder, so this collection must stay
        Draft/non-operational until the verified intake route is implemented.
        This also reconciles an older local run that may have marked it Active.
        """
        revision = revisions.get("student_inventory")
        key = "operating-demo-individual-inventory-placeholder"
        legacy_key = "operating-demo-individual_inventory"
        collection = next(
            (
                item for item in FormCollection.objects.filter(form_type=FormType.INDIVIDUAL_INVENTORY)
                if isinstance(item.metadata_json, dict)
                and item.metadata_json.get("demo_key") in {key, legacy_key}
            ),
            None,
        )
        metadata = {
            "demo_key": key,
            "operational": False,
            "reason": "unsupported_destination",
            "academic_year": academic_year,
            "note": "Tokenized pre-account inventory remains separate from authenticated annual inventory.",
        }
        if collection is None:
            collection = create_collection(
                head,
                FormCollectionCreateCommand(
                    name="Individual Inventory Intake — Account Required",
                    description="This intake requires a verified student account. For this release, use the authenticated Individual Inventory workflow from the student portal.",
                    audience=CollectionAudience.STUDENTS,
                    start_at=now,
                    end_at=now + timedelta(days=30),
                    form_family_id=str(revision.form_family_id) if revision else None,
                    form_revision_id=str(revision.pk) if revision else None,
                    form_type=FormType.INDIVIDUAL_INVENTORY,
                ),
            )
            collection.metadata_json = metadata
            collection.save(update_fields=["metadata_json", "updated_at"])
        else:
            # This lookup is restricted to the seed's own metadata key, so an
            # office-created collection is never silently changed.
            collection.metadata_json = metadata
            collection.name = "Individual Inventory Intake — Account Required"
            collection.description = "This intake requires a verified student account. For this release, use the authenticated Individual Inventory workflow from the student portal."
            update_fields = ["metadata_json", "name", "description", "updated_at"]
            if collection.status != CollectionStatus.DRAFT:
                collection.status = CollectionStatus.DRAFT
                collection.launched_by = None
                collection.launched_at = None
                collection.closed_by = None
                collection.closed_at = None
                update_fields.extend(["status", "launched_by", "launched_at", "closed_by", "closed_at"])
            collection.save(update_fields=update_fields)

        # Any token records from a previous local operating-seed version must
        # fail closed with the now-gated collection rather than remain usable.
        InvitationBatch.objects.filter(collection=collection).exclude(status=InvitationBatchStatus.REVOKED).update(
            status=InvitationBatchStatus.REVOKED,
            updated_at=now,
        )
        FormInvitation.objects.filter(
            collection=collection,
            status__in=(
                FormInvitationStatus.ISSUED,
                FormInvitationStatus.OPENED,
                FormInvitationStatus.VERIFIED,
                FormInvitationStatus.DRAFT_STARTED,
            ),
        ).update(
            status=FormInvitationStatus.REVOKED,
            revoked_by=head,
            revoked_at=now,
            revoke_reason="Unsupported tokenized inventory destination; demo collection gated.",
            updated_at=now,
        )

    def _seed_collection_state_examples(self, head, revisions, academic_year, now):
        """Keep closed and unsupported destinations visibly non-operational."""
        revision = revisions.get("graduate_tracer_survey")
        key = "operating-demo-closed-graduate-tracer"
        collection = next(
            (
                item for item in FormCollection.objects.filter(form_type=FormType.GRADUATE_TRACER)
                if isinstance(item.metadata_json, dict) and item.metadata_json.get("demo_key") == key
            ),
            None,
        )
        if collection is None:
            collection = create_collection(
                head,
                FormCollectionCreateCommand(
                    name="Graduate Tracer Survey — Response Period Closed",
                    description="This response period has ended and is retained for office records. No new responses can be submitted from this collection.",
                    audience=CollectionAudience.ALUMNI,
                    start_at=now - timedelta(days=60),
                    end_at=now - timedelta(days=30),
                    form_family_id=str(revision.form_family_id) if revision else None,
                    form_revision_id=str(revision.pk) if revision else None,
                    form_type=FormType.GRADUATE_TRACER,
                ),
            )
            collection.metadata_json = {"demo_key": key, "operational": False, "academic_year": academic_year}
            collection.save(update_fields=["metadata_json", "updated_at"])
        if collection.status not in (CollectionStatus.CLOSED, CollectionStatus.ARCHIVED):
            try:
                close_collection(head, collection.pk, FormCollectionLifecycleCommand())
            except Exception:
                pass
        collection.name = "Graduate Tracer Survey — Response Period Closed"
        collection.description = "This response period has ended and is retained for office records. No new responses can be submitted from this collection."
        collection.save(update_fields=["name", "description", "updated_at"])

        placeholder_key = "operating-demo-unsupported-placeholder"
        placeholder = next(
            (
                item for item in FormCollection.objects.filter(form_type=FormType.CUSTOM_CONTROLLED)
                if isinstance(item.metadata_json, dict) and item.metadata_json.get("demo_key") == placeholder_key
            ),
            None,
        )
        if placeholder is None:
            placeholder = create_collection(
                head,
                FormCollectionCreateCommand(
                    name="Additional Student Service Request — Pending Configuration",
                    description="This service is not configured for the current release. No response can be submitted from this collection yet.",
                    audience=CollectionAudience.CUSTOM,
                    start_at=now,
                    end_at=now + timedelta(days=30),
                    form_type=FormType.CUSTOM_CONTROLLED,
                ),
            )
            placeholder.metadata_json = {"demo_key": placeholder_key, "operational": False, "reason": "unsupported_destination", "academic_year": academic_year}
            placeholder.save(update_fields=["metadata_json", "updated_at"])
        else:
            placeholder.name = "Additional Student Service Request — Pending Configuration"
            placeholder.description = "This service is not configured for the current release. No response can be submitted from this collection yet."
            placeholder.save(update_fields=["name", "description", "updated_at"])

    def _write_summary(self, academic_year, profiles, actors):
        by_college = Counter(profile.college for profile in profiles.values())
        inventory_count = StudentInventorySnapshot.objects.filter(academic_year=academic_year).count()
        self.stdout.write(f"Seed summary: users={len(profiles) + len(actors)} profiles={len(profiles)} inventory_snapshots={inventory_count}")
        self.stdout.write("Colleges seeded:")
        for college, count in sorted(by_college.items()):
            self.stdout.write(f"  - {college}: {count} defense profiles")
        self.stdout.write(f"Roles seeded: counselors=4, gco_staff=2, it_admin=1, students={len(profiles)}")


# Public aliases used by readiness/tests.  They intentionally describe the
# operating catalog rather than the historical seven-account fixture.
DEMO_ACCOUNTS = _seed_accounts_catalog()
DEMO_PROGRAM_CATALOG = UCN_PROGRAM_CATALOG
