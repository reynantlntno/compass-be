"""student_onboarding office-facing student onboarding workflow services."""

from __future__ import annotations

import csv
import datetime
import hashlib
import hmac
import io
import re
import unicodedata
from typing import Any

from django.conf import settings
from django.core.validators import validate_email
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils import timezone

from apps.account_security.tokens import hash_identifier
from apps.accounts.models import RoleChoices, User
from apps.audit.services import audit_log
from apps.common.django_adapters import ModelValidationError
from apps.common.exceptions import (
    NotFoundError,
    PermissionDeniedError as PermissionDenied,
    StaleStateError,
    ValidationError,
    WorkflowError,
)
from apps.common.request_dedup import hash_request_key
from apps.form_collection.models import UnlinkedFormSubmission
from apps.form_collection.tokens import normalize_email, normalize_identifier
from apps.imports.catalog import CatalogPlacement, placement_map
from apps.imports.models import (
    RowValidationStatus,
    StudentImportBatch,
    StudentImportBatchStatus,
    StudentImportRow,
)
from apps.imports.commands import (
    ActivationInvitationIssueCommand,
    ImportBatchCreateCommand,
    ImportBatchExecuteCommand,
    ImportBatchLifecycleCommand,
    ImportBatchReplacementCommand,
    ImportRowCorrectionCommand,
    ImportRowDecisionCommand,
    ImportRowReconciliationCommand,
    StudentAccountProvisionCommand,
)
from apps.profiles.models import (
    CohortEnrollmentState,
    CohortProvenance,
    StudentAcademicCohort,
    StudentLifecycleChoices,
    StudentProfile,
)
from apps.reports.profiling import capture_academic_cohort
from apps.orchestration.commands import StudentActivationInvitationCommand
from apps.orchestration.use_cases import create_student_activation_invitation_for_import
from apps.governance.selectors import resolve_effective_policy


ONBOARDING_TEMPLATE_VERSION = "student_onboarding-v1"
ONBOARDING_HEADERS = (
    "template_version",
    "student_number",
    "control_number",
    "email",
    "first_name",
    "last_name",
    "program_code",
    "campus",
    "college",
    "department",
    "program",
    "year_level",
    "lifecycle_status",
)
FORMULA_PREFIXES = ("=", "+", "-", "@")
ALLOWED_LIFECYCLE_STATES = set(StudentLifecycleChoices.values)
CLEAR_ROW_STATES = {
    RowValidationStatus.VALID,
    RowValidationStatus.RECONCILED_EXISTING,
    RowValidationStatus.EXCLUDED,
}


class OnboardingValidationError(ValidationError):
    """Safe validation failure for office-facing onboarding operations."""


@transaction.atomic
def _provision_student_account(command: StudentAccountProvisionCommand, *, actor_user=None) -> User:
    """Create one inactive STUDENT account from an execution command.

    This is deliberately private to the canonical student_onboarding execution path.  It
    is not a second importer or a general account-creation service.
    """
    if not isinstance(command, StudentAccountProvisionCommand):
        raise ValidationError("Student provisioning requires a typed command.")
    try:
        validate_email(command.email)
    except ModelValidationError as exc:
        raise ValidationError("Invalid email format.") from exc
    if User.objects.filter(email__iexact=command.email).exists():
        raise ValidationError("Email already exists in database.")
    if command.student_number and StudentProfile.objects.filter(student_number__iexact=command.student_number).exists():
        raise ValidationError("Student number already exists in database.")
    if command.control_number and StudentProfile.objects.filter(control_number__iexact=command.control_number).exists():
        raise ValidationError("Control number already exists in database.")
    user = User.objects.create(
        email=command.email,
        first_name=command.first_name,
        last_name=command.last_name,
        role=RoleChoices.STUDENT,
        is_active=False,
    )
    user.set_unusable_password()
    user.save(update_fields=["password"])
    StudentProfile.objects.create(
        user=user,
        student_number=command.student_number,
        control_number=command.control_number,
        campus=command.campus,
        college=command.college,
        department=command.department,
        program=command.program,
        year_level=command.year_level,
        lifecycle_status=command.lifecycle_status,
    )
    audit_log(
        action_type="ACCOUNT_PROVISION",
        event_category="SECURITY",
        target_model="accounts.User",
        target_object_id=user.id,
        actor_user=actor_user,
        source_app="imports",
        source_view="student_onboarding_execute",
        metadata={
            "has_student_number": bool(command.student_number),
            "has_control_number": bool(command.control_number),
            "lifecycle_status": command.lifecycle_status,
            "campus": command.campus,
        },
    )
    return user


def _secret() -> bytes:
    return str(
        getattr(settings, "ACCOUNT_SECURITY_HASH_SECRET", "")
        or getattr(settings, "SECRET_KEY", "compass")
    ).encode("utf-8")


def _digest(value: str) -> str:
    return hmac.new(_secret(), value.encode("utf-8"), hashlib.sha256).hexdigest()


def normalize_cell(value: Any) -> str:
    value = "" if value is None else str(value)
    value = unicodedata.normalize("NFKC", value).replace("\r", " ").replace("\n", " ")
    return " ".join(value.strip().split())


def _formula_injection(value: str) -> bool:
    normalized = normalize_cell(value)
    return bool(normalized and normalized.startswith(FORMULA_PREFIXES))


def _max_upload_bytes() -> int:
    policy = resolve_effective_policy("student_import.controls")
    if policy is None:
        return 2 * 1024 * 1024
    return int((policy.configuration_json or {}).get("max_upload_bytes", 2 * 1024 * 1024))


def _max_upload_rows() -> int:
    policy = resolve_effective_policy("student_import.controls")
    if policy is None:
        return 2000
    return int((policy.configuration_json or {}).get("max_upload_rows", 2000))


def _current_academic_year() -> str:
    from apps.organizations.academic_year import resolve_current_academic_year

    try:
        return resolve_current_academic_year()
    except Exception as exc:
        raise OnboardingValidationError("The current academic year is not configured.") from exc


def _valid_academic_year(value: str) -> bool:
    match = re.fullmatch(r"(\d{4})-(\d{4})", str(value or "").strip())
    return bool(match and int(match.group(2)) == int(match.group(1)) + 1)


def _safe_year_level(value: str) -> int | None:
    value = normalize_cell(value)
    if not re.fullmatch(r"\d{1,2}", value):
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _read_upload(upload: Any, filename: str = "", content_type: str = "") -> tuple[bytes, str, str]:
    if hasattr(upload, "read"):
        raw = upload.read()
        filename = filename or getattr(upload, "name", "")
        content_type = content_type or getattr(upload, "content_type", "")
    else:
        raw = upload
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    if not isinstance(raw, (bytes, bytearray)):
        raise OnboardingValidationError("Upload content is not a CSV file.")
    raw = bytes(raw)
    if len(raw) > _max_upload_bytes():
        raise OnboardingValidationError("Upload exceeds the permitted size.")
    suffix = str(filename or "").lower()
    if suffix and not suffix.endswith(".csv"):
        raise OnboardingValidationError("Only CSV uploads are accepted.")
    if content_type and content_type.lower() not in {
        "text/csv", "application/csv", "application/vnd.ms-excel", "text/plain",
    }:
        raise OnboardingValidationError("Only CSV uploads are accepted.")
    if b"\x00" in raw:
        raise OnboardingValidationError("CSV contains unsupported binary content.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise OnboardingValidationError("CSV must be UTF-8 encoded.") from exc
    return raw, text, suffix


def _header_error(headers: list[str]) -> str | None:
    normalized = list(headers)
    expected = list(ONBOARDING_HEADERS)
    if len(normalized) != len(set(normalized)):
        return "CSV header contains duplicate columns."
    if normalized != expected:
        if set(normalized) != set(expected):
            return "CSV header contains unknown or missing columns."
        return "CSV columns must use the student_onboarding-v1 order."
    return None


def _row_error(row: StudentImportRow, code: str, message: str, *, metadata=None):
    row.validation_status = RowValidationStatus.INVALID
    row.error_code = code
    row.error_message = message
    row.error_metadata = metadata or {}


@transaction.atomic
def _parse_onboarding_upload(
    upload: Any,
    *,
    source_name: str,
    academic_year: str,
    actor_user: Any,
    filename: str = "",
    content_type: str = "",
    replacement_of: StudentImportBatch | None = None,
) -> StudentImportBatch:
    """Stage a strict student_onboarding-v1 upload with no account side effects."""
    if not str(source_name or "").strip():
        raise OnboardingValidationError("Source name is required.")
    clean_academic_year = normalize_cell(academic_year)
    if not _valid_academic_year(clean_academic_year) or clean_academic_year != _current_academic_year():
        raise OnboardingValidationError("Academic year must match the configured current academic year.")
    raw, text, _ = _read_upload(upload, filename, content_type)
    catalog_version, _placements, _demo_only = placement_map()
    content_hmac = _digest(raw.hex())
    existing = StudentImportBatch.objects.filter(
        template_version=ONBOARDING_TEMPLATE_VERSION,
        academic_year=clean_academic_year,
        catalog_version=catalog_version,
        content_hmac=content_hmac,
        status__in=[
            StudentImportBatchStatus.DRAFT,
            StudentImportBatchStatus.VALIDATED,
            StudentImportBatchStatus.NEEDS_REVIEW,
            StudentImportBatchStatus.APPROVED,
            StudentImportBatchStatus.EXECUTED,
        ],
    ).first()
    if existing:
        return existing

    try:
        reader = csv.reader(io.StringIO(text, newline=""), strict=True)
        rows = list(reader)
    except (csv.Error, UnicodeError) as exc:
        raise OnboardingValidationError("CSV could not be parsed safely.") from exc
    if not rows:
        raise OnboardingValidationError("CSV is empty.")
    header_error = _header_error(rows[0])
    if header_error:
        raise OnboardingValidationError(header_error)
    nonblank = [
        (row_number, row)
        for row_number, row in enumerate(rows[1:], start=2)
        if any(normalize_cell(cell) for cell in row)
    ]
    if not nonblank:
        raise OnboardingValidationError("CSV contains no student rows.")
    if len(nonblank) > _max_upload_rows():
        raise OnboardingValidationError("CSV exceeds the permitted row count.")
    if any(_formula_injection(cell) for _row_number, row in nonblank for cell in row):
        raise OnboardingValidationError("Spreadsheet formula input is not allowed.")

    try:
        with transaction.atomic():
            batch = StudentImportBatch.objects.create(
                source_name=normalize_cell(source_name),
                academic_year=clean_academic_year,
                status=StudentImportBatchStatus.DRAFT,
                created_by=actor_user,
                template_version=ONBOARDING_TEMPLATE_VERSION,
                catalog_version=catalog_version,
                content_hmac=content_hmac,
                replacement_of=replacement_of,
            )
    except IntegrityError:
        # The conditional unique constraint closes the concurrent-upload race;
        # resolve the winner without creating a second batch.
        existing = StudentImportBatch.objects.filter(
            template_version=ONBOARDING_TEMPLATE_VERSION,
            academic_year=clean_academic_year,
            catalog_version=catalog_version,
            content_hmac=content_hmac,
        ).first()
        if existing:
            return existing
        raise
    for row_number, raw_row in nonblank:
        cells = [normalize_cell(cell) for cell in raw_row]
        padded = (cells + [""] * len(ONBOARDING_HEADERS))[: len(ONBOARDING_HEADERS)]
        values = dict(zip(ONBOARDING_HEADERS, padded))
        values["student_number"] = normalize_identifier(values["student_number"]) or ""
        values["control_number"] = normalize_identifier(values["control_number"]) or ""
        values["email"] = normalize_email(values["email"]) or ""
        values["program_code"] = values["program_code"].upper()
        field_limits = {
            "student_number": 50,
            "control_number": 50,
            "email": 254,
            "first_name": 150,
            "last_name": 150,
            "program_code": 100,
            "campus": 100,
            "college": 100,
            "department": 100,
            "program": 100,
            "lifecycle_status": 30,
        }
        if any(len(values[field]) > limit for field, limit in field_limits.items()):
            raise OnboardingValidationError("CSV contains a field exceeding the permitted length.")
        row = StudentImportRow.objects.create(
            batch=batch,
            row_number=row_number,
            student_number=values["student_number"] or None,
            control_number=values["control_number"] or None,
            email=values["email"] or None,
            first_name=values["first_name"],
            last_name=values["last_name"],
            program_code=values["program_code"],
            campus=values["campus"],
            college=values["college"],
            department=values["department"],
            program=values["program"],
            year_level=_safe_year_level(values["year_level"]),
            lifecycle_status=values["lifecycle_status"].upper().replace(" ", "_"),
            validation_status=RowValidationStatus.PENDING,
        )
        if len(raw_row) != len(ONBOARDING_HEADERS):
            _row_error(row, "MALFORMED_ROW", "Row has an invalid number of columns.")
        elif values["template_version"] != ONBOARDING_TEMPLATE_VERSION:
            _row_error(row, "TEMPLATE_VERSION", "Row uses an unsupported template version.")
        elif any(_formula_injection(value) for value in cells):
            _row_error(row, "FORMULA_INPUT", "Spreadsheet formula input is not allowed.")
        row.save(update_fields=["validation_status", "error_code", "error_message", "error_metadata"])
    return batch


def _candidate_profiles(row: StudentImportRow) -> set[int]:
    candidates: set[int] = set()
    filters = []
    if row.student_number:
        filters.append(StudentProfile.objects.filter(student_number__iexact=row.student_number))
    if row.control_number:
        filters.append(StudentProfile.objects.filter(control_number__iexact=row.control_number))
    if row.email:
        filters.append(StudentProfile.objects.filter(user__email__iexact=row.email))
    for query in filters:
        candidates.update(query.values_list("pk", flat=True))
    if row.email and User.objects.filter(email__iexact=row.email).exists():
        # An account without a profile is still a collision; it must never be
        # silently linked or duplicated by onboarding.
        candidates.add(-1)
    try:
        hashes = {
            "control_number_hash": hash_identifier(normalize_identifier(row.control_number)) if row.control_number else None,
            "student_number_hash": hash_identifier(normalize_identifier(row.student_number)) if row.student_number else None,
            "email_hash": hash_identifier(normalize_email(row.email)) if row.email else None,
        }
        unlinked_query = Q()
        for field, value in hashes.items():
            if value:
                unlinked_query |= Q(**{field: value})
        unlinked = UnlinkedFormSubmission.objects.filter(unlinked_query)
        candidates.update(unlinked.exclude(linked_student__isnull=True).values_list("linked_student_id", flat=True))
        # An exact hashed match to an unlinked unlinked record is still a
        # reconciliation boundary.  Never silently create a duplicate account.
        if unlinked.filter(linked_student__isnull=True).exists() or unlinked.filter(student_match_status="NEEDS_MANUAL_REVIEW").exists():
            candidates.add(-1)
    except Exception:
        # The collection reconciliation tables are optional during migrations.
        pass
    return candidates


def _canonical_digest(batch: StudentImportBatch) -> str:
    rows = []
    for row in batch.rows.order_by("row_number"):
        rows.append(
            ":".join(
                str(value or "")
                for value in (
                    batch.template_version,
                    batch.catalog_version,
                    batch.academic_year,
                    row.row_number,
                    row.validation_status,
                    row.error_code,
                    row.correction_revision,
                    row.student_number,
                    row.control_number,
                    row.email,
                    row.first_name,
                    row.last_name,
                    row.program_code,
                    row.campus,
                    row.college,
                    row.department,
                    row.program,
                    row.year_level,
                    row.lifecycle_status,
                    row.provisioned_user_id,
                    row.reconciled_profile_id,
                )
            )
        )
    return _digest("|".join(rows))


def _assert_catalog_matches_rows(batch: StudentImportBatch, programs: dict[str, CatalogPlacement]) -> None:
    """Fail closed if an active catalog was edited without a version change."""
    for row in batch.rows.order_by("row_number"):
        if row.validation_status in {RowValidationStatus.EXCLUDED, RowValidationStatus.SUPERSEDED}:
            continue
        placement = programs.get((row.program_code or "").strip().upper())
        if (
            not placement
            or row.year_level is None
            or row.year_level < 1
            or row.year_level > placement.max_year_level
            or (row.campus, row.college, row.department, row.program)
            != (placement.campus, placement.college, placement.department, placement.program)
        ):
            raise WorkflowError("The approved onboarding catalog changed; revalidation is required.")


def _invalidate_approval(batch: StudentImportBatch, reason: str) -> StudentImportBatch:
    """Persist approval invalidation without retaining a stale execution gate."""
    batch.approved_at = None
    batch.approved_by = None
    batch.approved_digest = ""
    batch.approval_revoked_at = timezone.now()
    batch.approval_revocation_reason = reason[:80]
    batch.status = StudentImportBatchStatus.NEEDS_REVIEW
    batch.save(update_fields=[
        "approved_at", "approved_by", "approved_digest", "approval_revoked_at",
        "approval_revocation_reason", "status", "updated_at",
    ])
    return batch


def _validate_onboarding_batch(batch: StudentImportBatch, actor_user: Any = None) -> StudentImportBatch:
    """Validate placement, identity, duplicates, and unlinked boundaries."""
    if batch.template_version != ONBOARDING_TEMPLATE_VERSION:
        raise WorkflowError("This batch is not a supported student onboarding batch.")
    if batch.status in {StudentImportBatchStatus.EXECUTED, StudentImportBatchStatus.EXECUTING}:
        raise WorkflowError("Executed onboarding batches cannot be revalidated.")
    if batch.approved_at:
        _invalidate_approval(batch, "revalidated")

    _catalog_version, programs, _demo_only = placement_map()
    if batch.catalog_version != _catalog_version:
        _invalidate_approval(batch, "catalog_changed")
        raise OnboardingValidationError("The approved catalog changed; upload the batch again.")
    seen: dict[str, dict[str, list[int]]] = {"email": {}, "student": {}, "control": {}}
    rows = list(batch.rows.order_by("row_number"))
    for row in rows:
        for kind, value in (
            ("email", row.email),
            ("student", row.student_number),
            ("control", row.control_number),
        ):
            if value:
                seen[kind].setdefault(value.strip().lower(), []).append(row.row_number)

    for row in rows:
        if row.validation_status in {RowValidationStatus.EXCLUDED, RowValidationStatus.RECONCILED_EXISTING}:
            continue
        # Structural upload failures are durable row-level errors.  Do not
        # let later semantic checks overwrite a malformed-column, template,
        # or formula-input result with VALID.
        if row.error_code in {"MALFORMED_ROW", "TEMPLATE_VERSION", "FORMULA_INPUT"}:
            continue
        errors: list[tuple[str, str]] = []
        if not row.first_name or not row.last_name:
            errors.append(("REQUIRED_NAME", "Required name fields are missing."))
        if not row.email:
            errors.append(("REQUIRED_EMAIL", "Required email is missing."))
        else:
            try:
                validate_email(row.email)
            except ModelValidationError:
                errors.append(("EMAIL_FORMAT", "Email format is invalid."))
        if not row.student_number and not row.control_number:
            errors.append(("REQUIRED_IDENTIFIER", "At least one student or control identifier is required."))
        if row.lifecycle_status not in ALLOWED_LIFECYCLE_STATES:
            errors.append(("LIFECYCLE", "Lifecycle state is not supported."))
        if row.year_level is None:
            errors.append(("YEAR_LEVEL", "Year level is required."))
        placement = programs.get((row.program_code or "").strip().upper())
        if not placement:
            errors.append(("PROGRAM", "Program placement is not in the approved catalog."))
        elif row.year_level and (row.year_level < 1 or row.year_level > placement.max_year_level):
            errors.append(("YEAR_LEVEL", "Year level is not valid for the selected program."))
        elif placement:
            # Store catalog strings as canonical values; input mismatch is a
            # correction signal rather than a second institution vocabulary.
            supplied = (row.campus, row.college, row.department, row.program)
            canonical = (placement.campus, placement.college, placement.department, placement.program)
            if any(value and value != expected for value, expected in zip(supplied, canonical)):
                errors.append(("PLACEMENT", "Academic placement does not match the approved catalog."))
            row.campus, row.college, row.department, row.program = canonical
        for kind, value in (
            ("email", row.email),
            ("student", row.student_number),
            ("control", row.control_number),
        ):
            if value and len(seen[kind].get(value.strip().lower(), [])) > 1:
                errors.append((f"DUPLICATE_{kind.upper()}", "Duplicate identifier found in this batch."))
        if not errors:
            candidates = _candidate_profiles(row)
            if candidates:
                code = "AMBIGUOUS_MATCH" if len(candidates) > 1 or -1 in candidates else "MATCH_REVIEW_REQUIRED"
                _row_error(row, code, "A possible existing or unlinked record requires Head Guidance review.")
                row.validation_status = RowValidationStatus.MANUAL_REVIEW
            else:
                row.validation_status = RowValidationStatus.VALID
                row.error_code = ""
                row.error_message = None
                row.error_metadata = {}
        else:
            code, message = errors[0]
            _row_error(row, code, message)
        row.save()

    batch.validation_revision += 1
    batch.validation_digest = _canonical_digest(batch)
    batch.validated_by = actor_user
    batch.validated_at = timezone.now()
    batch.status = (
        StudentImportBatchStatus.VALIDATED
        if all(row.validation_status == RowValidationStatus.VALID for row in rows)
        else StudentImportBatchStatus.NEEDS_REVIEW
    )
    batch.save()
    audit_log(
        action_type="STUDENT_ONBOARDING_VALIDATED",
        event_category="WORKFLOW",
        target_model="imports.StudentImportBatch",
        target_object_id=batch.id,
        actor_user=actor_user,
        source_app="imports",
        metadata={"row_count": len(rows), "validation_revision": batch.validation_revision},
    )
    return batch


def _require_preparation_or_review(actor):
    from apps.access_control.authority import has_capability
    from apps.access_control.capabilities import Capability

    if not any(
        has_capability(actor, capability)
        for capability in (
            Capability.STUDENT_IMPORTS_PREPARE,
            Capability.STUDENT_IMPORTS_REVIEW,
            Capability.STUDENT_IMPORTS_APPROVE,
        )
    ):
        raise PermissionDenied("Student onboarding preparation or review authority is required.")


def _require_head(actor):
    from apps.access_control.authority import has_capability
    from apps.access_control.capabilities import Capability

    if not has_capability(actor, Capability.STUDENT_IMPORTS_APPROVE):
        raise PermissionDenied("Head Guidance authorization is required for this action.")


def _correct_onboarding_row(row: StudentImportRow, *, actor_user: Any, changes: dict[str, Any]) -> StudentImportRow:
    _require_preparation_or_review(actor_user)
    allowed = {
        "student_number", "control_number", "email", "first_name", "last_name",
        "program_code", "campus", "college", "department", "program", "year_level", "lifecycle_status",
    }
    changed = []
    metadata = list(row.correction_metadata or [])
    for field, value in changes.items():
        if field not in allowed:
            continue
        value = normalize_cell(value)
        if _formula_injection(value):
            raise OnboardingValidationError("Spreadsheet formula input is not allowed.")
        if field == "year_level":
            value = _safe_year_level(value)
        if field in {"student_number", "control_number", "email"}:
            value = (normalize_identifier(value) if field != "email" else normalize_email(value)) or None
        if field == "program_code":
            value = value.upper()
        setattr(row, field, value)
        changed.append(field)
    if not changed:
        raise OnboardingValidationError("No correctable fields were supplied.")
    row.correction_revision += 1
    metadata.append({"revision": row.correction_revision, "changed_fields": sorted(changed), "value_hashes": {field: _digest(str(getattr(row, field) or "")) for field in changed}})
    # Correction metadata is append-only.  It contains changed field names and
    # one-way value hashes only; never retain prior raw values.
    row.correction_metadata = metadata
    row.validation_status = RowValidationStatus.PENDING
    row.error_code = ""
    row.error_message = None
    row.error_metadata = {}
    row.batch.approved_at = None
    row.batch.approved_by = None
    row.batch.approved_digest = ""
    row.batch.approval_revoked_at = timezone.now()
    row.batch.approval_revocation_reason = "row_corrected"
    row.batch.status = StudentImportBatchStatus.DRAFT
    row.batch.save(update_fields=["approved_at", "approved_by", "approved_digest", "approval_revoked_at", "approval_revocation_reason", "status", "updated_at"])
    row.save()
    audit_log(
        action_type="STUDENT_ONBOARDING_ROW_CORRECTED",
        event_category="WORKFLOW",
        target_model="imports.StudentImportRow",
        target_object_id=row.id,
        actor_user=actor_user,
        source_app="imports",
        metadata={"row_number": row.row_number, "correction_revision": row.correction_revision, "changed_fields": sorted(changed)},
    )
    return row


def _reconcile_onboarding_row(row: StudentImportRow, *, actor_user: Any, student_profile: StudentProfile) -> StudentImportRow:
    _require_preparation_or_review(actor_user)
    if not student_profile or not student_profile.user_id:
        raise OnboardingValidationError("A valid existing student profile is required.")
    if student_profile.user.role != RoleChoices.STUDENT:
        raise OnboardingValidationError("A student profile is required for reconciliation.")
    if student_profile.pk not in _candidate_profiles(row):
        raise OnboardingValidationError("The selected profile is not a matched reconciliation candidate.")
    row.reconciled_profile = student_profile
    row.reviewed_by = actor_user
    row.reviewed_at = timezone.now()
    row.validation_status = RowValidationStatus.RECONCILED_EXISTING
    row.error_code = ""
    row.error_message = None
    row.error_metadata = {}
    row.batch.status = StudentImportBatchStatus.NEEDS_REVIEW
    row.batch.approved_at = None
    row.batch.approved_by = None
    row.batch.approved_digest = ""
    row.batch.approval_revoked_at = timezone.now()
    row.batch.approval_revocation_reason = "reconciliation_changed"
    row.batch.save(update_fields=["status", "approved_at", "approved_by", "approved_digest", "approval_revoked_at", "approval_revocation_reason", "updated_at"])
    row.save()
    audit_log(
        action_type="STUDENT_ONBOARDING_ROW_RECONCILED",
        event_category="WORKFLOW",
        target_model="imports.StudentImportRow",
        target_object_id=row.id,
        actor_user=actor_user,
        source_app="imports",
        metadata={"row_number": row.row_number, "profile_id": student_profile.pk},
    )
    return row


def _exclude_onboarding_row(row: StudentImportRow, *, actor_user: Any) -> StudentImportRow:
    _require_preparation_or_review(actor_user)
    row.validation_status = RowValidationStatus.EXCLUDED
    row.reviewed_by = actor_user
    row.reviewed_at = timezone.now()
    row.error_code = "EXCLUDED_BY_HEAD"
    row.error_message = "Row was explicitly excluded by Head Guidance."
    row.error_metadata = {}
    row.batch.status = StudentImportBatchStatus.NEEDS_REVIEW
    row.batch.approved_at = None
    row.batch.approved_by = None
    row.batch.approved_digest = ""
    row.batch.approval_revoked_at = timezone.now()
    row.batch.approval_revocation_reason = "row_excluded"
    row.batch.save(update_fields=["status", "approved_at", "approved_by", "approved_digest", "approval_revoked_at", "approval_revocation_reason", "updated_at"])
    row.save()
    audit_log(
        action_type="STUDENT_ONBOARDING_ROW_EXCLUDED",
        event_category="WORKFLOW",
        target_model="imports.StudentImportRow",
        target_object_id=row.id,
        actor_user=actor_user,
        source_app="imports",
        metadata={"row_number": row.row_number},
    )
    return row


def _acknowledge_unlinked_boundary(row: StudentImportRow, *, actor_user: Any) -> StudentImportRow:
    """Record Head Guidance acknowledgement without linking or clearing review."""
    _require_preparation_or_review(actor_user)
    if row.validation_status != RowValidationStatus.MANUAL_REVIEW:
        raise WorkflowError("Only a row in manual review can acknowledge a unlinked boundary.")
    row.reviewed_by = actor_user
    row.reviewed_at = timezone.now()
    row.error_code = "PROVISIONAL_BOUNDARY_ACKNOWLEDGED"
    row.error_message = "A unlinked-record boundary was acknowledged; explicit reconciliation remains required."
    row.error_metadata = {"boundary_acknowledged": True}
    row.batch.status = StudentImportBatchStatus.NEEDS_REVIEW
    row.batch.approved_at = None
    row.batch.approved_by = None
    row.batch.approved_digest = ""
    row.batch.approval_revoked_at = timezone.now()
    row.batch.approval_revocation_reason = "unlinked_boundary_acknowledged"
    row.batch.save(update_fields=[
        "status", "approved_at", "approved_by", "approved_digest",
        "approval_revoked_at", "approval_revocation_reason", "updated_at",
    ])
    row.save(update_fields=["reviewed_by", "reviewed_at", "error_code", "error_message", "error_metadata", "updated_at"])
    audit_log(
        action_type="STUDENT_ONBOARDING_PROVISIONAL_BOUNDARY_ACKNOWLEDGED",
        event_category="WORKFLOW",
        target_model="imports.StudentImportRow",
        target_object_id=row.id,
        actor_user=actor_user,
        source_app="imports",
        metadata={"row_number": row.row_number},
    )
    return row


@transaction.atomic
def _replace_onboarding_batch(
    batch: StudentImportBatch,
    upload: Any,
    *,
    source_name: str,
    academic_year: str,
    actor_user: Any,
    filename: str = "",
    content_type: str = "",
) -> StudentImportBatch:
    """Stage a replacement and conservatively supersede the prior batch."""
    _require_preparation_or_review(actor_user)
    locked = StudentImportBatch.objects.select_for_update().get(pk=batch.pk)
    if locked.template_version != ONBOARDING_TEMPLATE_VERSION:
        raise WorkflowError("This batch is not a supported student onboarding batch.")
    if locked.status in {StudentImportBatchStatus.EXECUTING, StudentImportBatchStatus.EXECUTED}:
        raise WorkflowError("An executing or executed batch cannot be replaced.")
    replacement = _parse_onboarding_upload(
        upload,
        source_name=source_name,
        academic_year=academic_year,
        actor_user=actor_user,
        filename=filename,
        content_type=content_type,
        replacement_of=locked,
    )
    if replacement.pk == locked.pk:
        return replacement
    locked.rows.update(validation_status=RowValidationStatus.SUPERSEDED)
    locked.status = StudentImportBatchStatus.SUPERSEDED
    locked.approval_revoked_at = timezone.now()
    locked.approval_revocation_reason = "replaced"
    locked.approved_at = None
    locked.approved_by = None
    locked.approved_digest = ""
    locked.save(update_fields=[
        "status", "approval_revoked_at", "approval_revocation_reason",
        "approved_at", "approved_by", "approved_digest", "updated_at",
    ])
    audit_log(
        action_type="STUDENT_ONBOARDING_REPLACED",
        event_category="WORKFLOW",
        target_model="imports.StudentImportBatch",
        target_object_id=locked.id,
        actor_user=actor_user,
        source_app="imports",
        metadata={"replacement_batch_id": replacement.id, "row_count": locked.rows.count()},
    )
    return replacement


@transaction.atomic
def _approve_onboarding_batch(batch: StudentImportBatch, *, actor_user: Any) -> StudentImportBatch:
    _require_head(actor_user)
    original_batch = batch
    batch = StudentImportBatch.objects.select_for_update().prefetch_related("rows").get(pk=batch.pk)
    rows = list(batch.rows.order_by("row_number"))
    if not rows or any(row.validation_status not in CLEAR_ROW_STATES for row in rows):
        raise WorkflowError("Every row must be valid, reconciled, or explicitly excluded before approval.")
    digest = _canonical_digest(batch)
    batch.status = StudentImportBatchStatus.APPROVED
    batch.approved_by = actor_user
    batch.approved_at = timezone.now()
    batch.approved_digest = digest
    batch.approval_revoked_at = None
    batch.approval_revocation_reason = ""
    batch.save()
    for field in ("status", "approved_by_id", "approved_at", "approved_digest", "approval_revoked_at", "approval_revocation_reason"):
        setattr(original_batch, field, getattr(batch, field))
    audit_log(
        action_type="STUDENT_ONBOARDING_APPROVED",
        event_category="WORKFLOW",
        target_model="imports.StudentImportBatch",
        target_object_id=batch.id,
        actor_user=actor_user,
        source_app="imports",
        metadata={"row_count": len(rows)},
    )
    return batch


def _cohort_for(profile: StudentProfile, batch: StudentImportBatch, row: StudentImportRow):
    existing = StudentAcademicCohort.objects.filter(student_profile=profile, academic_year=batch.academic_year).first()
    state = (
        CohortEnrollmentState.ENROLLED
        if row.lifecycle_status in {StudentLifecycleChoices.ACTIVE, StudentLifecycleChoices.GRADUATING}
        else CohortEnrollmentState.EXCLUDED
    )
    if existing:
        if existing.provenance != CohortProvenance.IMPORT or existing.source_reference != f"import:{batch.id}:{row.row_number}":
            raise WorkflowError("An immutable academic-year cohort already exists for this student.")
        return existing
    return capture_academic_cohort(
        profile,
        academic_year=batch.academic_year,
        campus=row.campus,
        college=row.college,
        department=row.department,
        program=row.program,
        program_code=row.program_code,
        year_level=row.year_level,
        enrollment_state=state,
        provenance=CohortProvenance.IMPORT,
        source_reference=f"import:{batch.id}:{row.row_number}",
    )


def _execute_onboarding_batch(batch: StudentImportBatch, *, actor_user: Any, idempotency_key: str = "") -> dict:
    """Preflight catalog authority, then execute the approved batch atomically."""
    current = StudentImportBatch.objects.get(pk=batch.pk)
    if current.status != StudentImportBatchStatus.EXECUTED:
        catalog_version, programs, _demo_only = placement_map()
        if current.catalog_version != catalog_version:
            _invalidate_approval(current, "catalog_changed")
            raise WorkflowError("The onboarding catalog changed; the batch requires revalidation.")
        try:
            _assert_catalog_matches_rows(current, programs)
        except WorkflowError:
            _invalidate_approval(current, "catalog_changed")
            raise
    result = _execute_onboarding_batch_atomic(
        current, actor_user=actor_user, idempotency_key=idempotency_key
    )
    batch.refresh_from_db()
    return result


@transaction.atomic
def _execute_onboarding_batch_atomic(
    batch: StudentImportBatch,
    *,
    actor_user: Any,
    idempotency_key: str = "",
    idempotency_already_hashed: bool = False,
    expected_updated_at: str | None = None,
) -> dict:
    """Provision the complete approved batch atomically and idempotently."""
    from apps.imports.policies import can_execute_student_onboarding

    original_batch = batch
    batch = StudentImportBatch.objects.select_for_update().get(pk=batch.pk)
    _assert_expected_updated_at(batch, expected_updated_at)
    if batch.status == StudentImportBatchStatus.EXECUTED:
        from apps.imports.policies import can_manage_student_imports
        if not can_manage_student_imports(actor_user):
            raise PermissionDenied("You are not authorized to execute this onboarding batch.")
        return batch.execution_summary or {"success": batch.rows.filter(validation_status=RowValidationStatus.PROVISIONED).count(), "reconciled": batch.rows.filter(validation_status=RowValidationStatus.RECONCILED_EXISTING).count(), "excluded": batch.rows.filter(validation_status=RowValidationStatus.EXCLUDED).count()}
    if not can_execute_student_onboarding(actor_user, batch=batch):
        raise PermissionDenied("You are not authorized to execute this onboarding batch.")
    catalog_version, programs, _demo_only = placement_map()
    if batch.catalog_version != catalog_version:
        _invalidate_approval(batch, "catalog_changed")
        raise WorkflowError("The onboarding catalog changed; the batch requires revalidation.")
    _assert_catalog_matches_rows(batch, programs)
    if batch.status != StudentImportBatchStatus.APPROVED or batch.approved_digest != _canonical_digest(batch):
        raise WorkflowError("The batch approval is missing or stale.")
    rows = list(batch.rows.select_for_update().order_by("row_number"))
    if any(row.validation_status not in CLEAR_ROW_STATES for row in rows):
        raise WorkflowError("The batch contains rows that require review.")
    batch.status = StudentImportBatchStatus.EXECUTING
    batch.execution_idempotency_key = (
        idempotency_key.lower()
        if idempotency_already_hashed
        else hash_request_key(idempotency_key or f"batch:{batch.pk}", secret=_secret(), max_length=None)
    )
    batch.save(update_fields=["status", "execution_idempotency_key", "updated_at"])
    success = reconciled = excluded = 0
    for row in rows:
        if row.validation_status == RowValidationStatus.EXCLUDED:
            excluded += 1
            continue
        if row.validation_status == RowValidationStatus.RECONCILED_EXISTING:
            profile = StudentProfile.objects.select_for_update().select_related("user").get(pk=row.reconciled_profile_id)
            if profile.user.role != RoleChoices.STUDENT:
                raise WorkflowError("Reconciled profile is not a student account.")
            row.provisioned_user = profile.user
            row.reconciled_profile = profile
            _cohort_for(profile, batch, row)
            if not profile.user.is_active:
                create_student_activation_invitation_for_import(
                    actor_user,
                    StudentActivationInvitationCommand(
                        user_id=str(profile.user_id),
                    ),
                )
            row.save(update_fields=["provisioned_user", "reconciled_profile", "updated_at"])
            reconciled += 1
            continue

        email = (row.email or "").strip().lower()
        if User.objects.select_for_update().filter(email__iexact=email).exists():
            raise WorkflowError("A live duplicate appeared while executing the batch.")
        if row.student_number and StudentProfile.objects.select_for_update().filter(student_number__iexact=row.student_number).exists():
            raise WorkflowError("A live duplicate appeared while executing the batch.")
        if row.control_number and StudentProfile.objects.select_for_update().filter(control_number__iexact=row.control_number).exists():
            raise WorkflowError("A live duplicate appeared while executing the batch.")
        user = _provision_student_account(
            StudentAccountProvisionCommand(
                email=email,
                first_name=row.first_name,
                last_name=row.last_name,
                student_number=row.student_number,
                control_number=row.control_number,
                campus=row.campus,
                college=row.college,
                department=row.department,
                program=row.program,
                year_level=row.year_level,
                lifecycle_status=row.lifecycle_status,
            ),
            actor_user=actor_user,
        )
        _cohort_for(user.student_profile, batch, row)
        create_student_activation_invitation_for_import(
            actor_user,
            StudentActivationInvitationCommand(
                user_id=str(user.pk),
                source_view="student_onboarding_execute",
            ),
        )
        row.provisioned_user = user
        row.validation_status = RowValidationStatus.PROVISIONED
        row.error_code = ""
        row.error_message = None
        row.save(update_fields=["provisioned_user", "validation_status", "error_code", "error_message", "updated_at"])
        success += 1
    batch.status = StudentImportBatchStatus.EXECUTED
    batch.executed_by = actor_user
    batch.executed_at = timezone.now()
    batch.execution_summary = {"success": success, "reconciled": reconciled, "excluded": excluded, "total": len(rows)}
    batch.save(update_fields=["status", "executed_by", "executed_at", "execution_summary", "updated_at"])
    for field in ("status", "executed_by_id", "executed_at", "execution_summary", "execution_idempotency_key"):
        setattr(original_batch, field, getattr(batch, field))
    audit_log(
        action_type="STUDENT_ONBOARDING_EXECUTED",
        event_category="WORKFLOW",
        target_model="imports.StudentImportBatch",
        target_object_id=batch.id,
        actor_user=actor_user,
        source_app="imports",
        metadata=batch.execution_summary,
    )
    return batch.execution_summary


def _onboarding_preview(batch: StudentImportBatch, *, include_correction: bool = False) -> list[dict[str, Any]]:
    """Return only masked, bounded row data for templates and JSON previews."""
    from apps.notifications.models import EmailDelivery
    from apps.student_activation.models import StudentActivationInvitation

    result = []
    for row in batch.rows.order_by("row_number"):
        email = row.email or ""
        masked_email = ""
        if "@" in email:
            local, domain = email.split("@", 1)
            masked_email = f"{local[:1]}***{local[-1:] if len(local) > 1 else ''}@{domain}"
        item = {
            "row_id": row.pk,
            "row_number": row.row_number,
            "initials": f"{(row.first_name or '')[:1]}{(row.last_name or '')[:1]}".upper(),
            "email": masked_email,
            "identifier": " / ".join(filter(None, ["***" if row.student_number else "", "***" if row.control_number else ""])),
            "placement": ", ".join(filter(None, [row.college, row.program, str(row.year_level or "")])),
            "status": row.get_validation_status_display(),
            "status_code": row.validation_status,
            "error": row.error_message or "",
            "invitation_id": None,
            "invitation_status": "",
            "invitation_delivery_state": "",
            "candidates": [],
            "unlinked_boundary": False,
        }
        if include_correction and row.validation_status == RowValidationStatus.MANUAL_REVIEW:
            candidate_ids = _candidate_profiles(row)
            item["unlinked_boundary"] = -1 in candidate_ids
            profiles = (
                StudentProfile.objects.select_related("user")
                .filter(pk__in=[candidate for candidate in candidate_ids if candidate > 0])
                .order_by("pk")
            )
            for profile in profiles:
                profile_email = profile.user.email or ""
                if "@" in profile_email:
                    local, domain = profile_email.split("@", 1)
                    masked_profile_email = f"{local[:1]}***{local[-1:] if len(local) > 1 else ''}@{domain}"
                else:
                    masked_profile_email = "[masked]"
                item["candidates"].append({
                    "profile_id": profile.pk,
                    "label": f"{(profile.user.first_name or '')[:1]}{(profile.user.last_name or '')[:1]} / {masked_profile_email}",
                })
        if row.provisioned_user_id:
            invitation = (
                StudentActivationInvitation.objects
                .filter(user_id=row.provisioned_user_id)
                .order_by("-created_at", "-pk")
                .first()
            )
            if invitation:
                item["invitation_id"] = invitation.pk
                if invitation.used_at:
                    item["invitation_status"] = "Activated"
                elif invitation.revoked_at:
                    item["invitation_status"] = "Revoked"
                elif invitation.expires_at <= timezone.now():
                    item["invitation_status"] = "Expired"
                elif invitation.reissued_from_id:
                    item["invitation_status"] = "Reissued"
                else:
                    item["invitation_status"] = "Queued"
                delivery = (
                    EmailDelivery.objects
                    .filter(template_key="student_activation", related_object_id=str(invitation.pk))
                    .order_by("-created_at", "-pk")
                    .first()
                )
                if delivery:
                    item["invitation_delivery_state"] = delivery.delivery_state or delivery.status
        if include_correction:
            item["correction"] = {
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
                "year_level": row.year_level or "",
                "lifecycle_status": row.lifecycle_status,
            }
        result.append(item)
    return result


def _assert_expected_updated_at(instance, expected_updated_at: str | None) -> None:
    if not expected_updated_at:
        return
    try:
        expected = datetime.datetime.fromisoformat(expected_updated_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError("expected_updated_at is invalid.") from exc
    actual = instance.updated_at
    if timezone.is_naive(expected):
        expected = timezone.make_aware(expected, timezone.get_current_timezone())
    if timezone.is_naive(actual):
        actual = timezone.make_aware(actual, timezone.get_current_timezone())
    if actual != expected:
        raise StaleStateError()


def _locked_batch(batch_id: str, *, with_rows: bool = False) -> StudentImportBatch:
    query = StudentImportBatch.objects.select_for_update()
    if with_rows:
        query = query.prefetch_related("rows")
    batch = query.filter(pk=batch_id).first()
    if batch is None:
        raise NotFoundError("The import batch was not found.")
    return batch


def _locked_row(row_id: str) -> StudentImportRow:
    row = StudentImportRow.objects.filter(pk=row_id).first()
    if row is None:
        raise NotFoundError("The import row was not found.")
    batch = _locked_batch(str(row.batch_id))
    locked_row = StudentImportRow.objects.select_for_update().filter(pk=row_id, batch_id=batch.pk).first()
    if locked_row is None:
        raise NotFoundError("The import row was not found.")
    locked_row.batch = batch
    return locked_row


def stage_onboarding_batch(
    *,
    actor_user: User,
    command: ImportBatchCreateCommand,
    upload: bytes,
) -> StudentImportBatch:
    """Stable-ID-free upload edge for the canonical student_onboarding staging step."""
    from apps.imports.policies import can_edit_student_onboarding

    if not can_edit_student_onboarding(actor_user):
        raise PermissionDenied("You are not authorized to prepare student imports.")
    if not isinstance(command, ImportBatchCreateCommand):
        raise ValidationError("Batch creation requires a typed command.")
    return _parse_onboarding_upload(
        upload,
        source_name=command.source_name,
        academic_year=command.academic_year,
        actor_user=actor_user,
        filename=command.filename,
        content_type=command.content_type,
    )


@transaction.atomic
def validate_onboarding_batch_by_id(
    *,
    actor_user: User,
    batch_id: str,
    command: ImportBatchLifecycleCommand,
) -> StudentImportBatch:
    from apps.imports.policies import can_review_student_onboarding

    from apps.imports.commands import ImportBatchLifecycleCommand
    if not isinstance(command, ImportBatchLifecycleCommand):
        raise ValidationError("Batch validation requires a typed command.")
    if not can_review_student_onboarding(actor_user):
        raise PermissionDenied()
    batch = _locked_batch(batch_id)
    _assert_expected_updated_at(batch, command.expected_updated_at)
    return _validate_onboarding_batch(batch, actor_user=actor_user)


@transaction.atomic
def replace_onboarding_batch_by_id(
    *,
    actor_user: User,
    batch_id: str,
    command: ImportBatchReplacementCommand,
    upload: bytes,
) -> StudentImportBatch:
    if not isinstance(command, ImportBatchReplacementCommand):
        raise ValidationError("Batch replacement requires a typed command.")
    batch = _locked_batch(batch_id)
    _assert_expected_updated_at(batch, command.expected_updated_at)
    return _replace_onboarding_batch(
        batch,
        upload,
        source_name=command.source_name,
        academic_year=command.academic_year,
        actor_user=actor_user,
        filename=command.filename,
        content_type=command.content_type,
    )


@transaction.atomic
def correct_onboarding_row_by_id(
    *,
    actor_user: User,
    row_id: str,
    command: ImportRowCorrectionCommand,
) -> StudentImportRow:
    from apps.imports.commands import ImportRowCorrectionCommand
    if not isinstance(command, ImportRowCorrectionCommand):
        raise ValidationError("Row correction requires a typed command.")
    row = _locked_row(row_id)
    _assert_expected_updated_at(row, command.expected_updated_at)
    return _correct_onboarding_row(row, actor_user=actor_user, changes=command.updates())


@transaction.atomic
def reconcile_onboarding_row_by_id(
    *,
    actor_user: User,
    row_id: str,
    command: ImportRowReconciliationCommand,
) -> StudentImportRow:
    from apps.imports.commands import ImportRowReconciliationCommand
    if not isinstance(command, ImportRowReconciliationCommand):
        raise ValidationError("Row reconciliation requires a typed command.")
    row = _locked_row(row_id)
    _assert_expected_updated_at(row, command.expected_updated_at)
    profile = (
        StudentProfile.objects.select_for_update()
        .select_related("user")
        .filter(pk=command.student_profile_id)
        .first()
    )
    if profile is None:
        raise NotFoundError("The student profile was not found.")
    return _reconcile_onboarding_row(row, actor_user=actor_user, student_profile=profile)


@transaction.atomic
def exclude_onboarding_row_by_id(
    *,
    actor_user: User,
    row_id: str,
    command: ImportRowDecisionCommand,
) -> StudentImportRow:
    from apps.imports.commands import ImportRowDecisionCommand
    if not isinstance(command, ImportRowDecisionCommand):
        raise ValidationError("Row exclusion requires a typed command.")
    row = _locked_row(row_id)
    _assert_expected_updated_at(row, command.expected_updated_at)
    return _exclude_onboarding_row(row, actor_user=actor_user)


@transaction.atomic
def acknowledge_unlinked_boundary_by_id(
    *,
    actor_user: User,
    row_id: str,
    command: ImportRowDecisionCommand,
) -> StudentImportRow:
    from apps.imports.commands import ImportRowDecisionCommand
    if not isinstance(command, ImportRowDecisionCommand):
        raise ValidationError("Boundary acknowledgement requires a typed command.")
    row = _locked_row(row_id)
    _assert_expected_updated_at(row, command.expected_updated_at)
    return _acknowledge_unlinked_boundary(row, actor_user=actor_user)


@transaction.atomic
def approve_onboarding_batch_by_id(
    *,
    actor_user: User,
    batch_id: str,
    command: ImportBatchLifecycleCommand,
) -> StudentImportBatch:
    from apps.imports.commands import ImportBatchLifecycleCommand
    if not isinstance(command, ImportBatchLifecycleCommand):
        raise ValidationError("Batch approval requires a typed command.")
    batch = _locked_batch(batch_id, with_rows=True)
    _assert_expected_updated_at(batch, command.expected_updated_at)
    return _approve_onboarding_batch(batch, actor_user=actor_user)


def execute_onboarding_batch_by_id(
    *,
    actor_user: User,
    batch_id: str,
    command: ImportBatchExecuteCommand,
) -> dict:
    from apps.imports.commands import ImportBatchExecuteCommand
    if not isinstance(command, ImportBatchExecuteCommand):
        raise ValidationError("Batch execution requires a typed command.")
    batch = StudentImportBatch.objects.filter(pk=batch_id).first()
    if batch is None:
        raise NotFoundError("The import batch was not found.")
    _assert_expected_updated_at(batch, command.expected_updated_at)
    return _execute_onboarding_batch_with_digest(
        batch,
        actor_user=actor_user,
        request_key_digest=command.request_key_digest,
        expected_updated_at=command.expected_updated_at,
    )


def _execute_onboarding_batch_with_digest(batch, *, actor_user, request_key_digest: str, expected_updated_at: str | None = None) -> dict:
    """Execute through the canonical locked implementation with a digest."""
    return _execute_onboarding_batch_atomic(
        batch,
        actor_user=actor_user,
        idempotency_key=request_key_digest,
        idempotency_already_hashed=True,
        expected_updated_at=expected_updated_at,
    )


@transaction.atomic
def issue_onboarding_invitations_by_batch_id(
    *,
    actor_user: User,
    batch_id: str,
    command: ActivationInvitationIssueCommand,
) -> dict:
    from apps.imports.policies import can_operate_activation_delivery

    if not isinstance(command, ActivationInvitationIssueCommand):
        raise ValidationError("Invitation issuance requires a typed command.")
    if not can_operate_activation_delivery(actor_user):
        raise PermissionDenied()
    batch = _locked_batch(batch_id)
    _assert_expected_updated_at(batch, command.expected_updated_at)
    if batch.status != StudentImportBatchStatus.EXECUTED:
        raise WorkflowError("Activation invitations can be issued only after batch execution.")
    rows = list(
        batch.rows.select_for_update()
        .select_related("provisioned_user")
        .filter(validation_status=RowValidationStatus.PROVISIONED)
        .order_by("row_number")
    )
    issued = 0
    skipped = 0
    from apps.orchestration.commands import StudentActivationInvitationCommand
    from apps.orchestration.use_cases import create_student_activation_invitation_for_import
    from apps.student_activation.models import StudentActivationInvitation

    for row in rows:
        if not row.provisioned_user_id or row.provisioned_user.is_active:
            skipped += 1
            continue
        current = StudentActivationInvitation.objects.filter(
            user_id=row.provisioned_user_id,
            used_at__isnull=True,
            revoked_at__isnull=True,
        ).first()
        if current and current.expires_at > timezone.now():
            skipped += 1
            continue
        create_student_activation_invitation_for_import(
            actor_user,
            StudentActivationInvitationCommand(
                user_id=str(row.provisioned_user_id),
                source_view="student_import_invitation_issue",
            ),
        )
        issued += 1
    return {"issued": issued, "skipped": skipped, "eligible": len(rows)}


def template_csv() -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow(ONBOARDING_HEADERS)
    writer.writerow([
        ONBOARDING_TEMPLATE_VERSION, "DEMO-STUDENT-001", "DEMO-CONTROL-001", "student@example.invalid",
        "Synthetic", "Student", "CCMS_BS_INFORMATION_TECHNOLOGY", "Main Campus, Daet",
        "College of Computing and Multimedia Studies", "Information Technology",
        "BS Information Technology", "1", StudentLifecycleChoices.ACTIVE,
    ])
    return ("\ufeff" + output.getvalue()).encode("utf-8")
