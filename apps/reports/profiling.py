"""Normalized Students' Profile aggregate reporting data boundary.

This module is the only reporting-layer reader of confidential Inventory data.
It converts a submitted snapshot into an intentionally narrow, versioned fact;
report construction thereafter reads facts and historical cohort records only.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
import re
from typing import Any, Iterable

from django.db import transaction

from apps.common.exceptions import ValidationError
from apps.inventory.encryption import InventoryEncryptionError, read_confidential_snapshot
from apps.inventory.models import InventoryStatusChoices, StudentInventorySnapshot
from apps.profiles.models import (
    CohortEnrollmentState,
    CohortProvenance,
    StudentAcademicCohort,
)
from apps.reports.models import ProfilingFactStatus, StudentProfilingFact
from apps.security.exceptions import FieldEncryptionError


PROFILING_MAPPING_VERSION = "profiling-v1"
NOT_SPECIFIED = "NOT_SPECIFIED"
WITHOUT_INVENTORY = "WITHOUT_INVENTORY"
DRAFT = "DRAFT"
REOPENED = "REOPENED"
UNREADABLE = "UNREADABLE"
INVALID = "INVALID"
UNPROJECTED = "UNPROJECTED"
SUPPRESSION_LABEL = "Suppressed for privacy"


class ProfilingReconciliationError(ValidationError):
    """Raised before unsafe/inconsistent report data can be rendered."""


@dataclass(frozen=True)
class ProfilingContext:
    academic_year: str
    college: str
    year_level: int
    campus: str = ""
    department: str = ""
    program: str = ""

    @classmethod
    def from_filters(cls, filters: dict[str, Any]) -> "ProfilingContext":
        required = ("academic_year", "college", "year_level")
        missing = [key for key in required if filters.get(key) in (None, "")]
        if missing:
            raise ValidationError("Academic year, college, and year level are required for Students' Profile.")
        try:
            year_level = int(filters["year_level"])
        except (TypeError, ValueError) as exc:
            raise ValidationError("Year level must be a positive whole number.") from exc
        if year_level < 1:
            raise ValidationError("Year level must be a positive whole number.")
        return cls(
            academic_year=str(filters["academic_year"]).strip(),
            college=str(filters["college"]).strip(),
            year_level=year_level,
            campus=str(filters.get("campus") or "").strip(),
            department=str(filters.get("department") or "").strip(),
            program=str(filters.get("program") or "").strip(),
        )

    def as_filters(self) -> dict[str, Any]:
        values = {
            "academic_year": self.academic_year,
            "college": self.college,
            "year_level": self.year_level,
            "campus": self.campus,
            "department": self.department,
            "program": self.program,
        }
        return {key: value for key, value in values.items() if value not in (None, "")}


def canonical_organization_code(value: str) -> str:
    """Produce a deterministic non-display code when an upstream catalog lacks one."""
    return re.sub(r"[^A-Z0-9]+", "_", (value or "").upper()).strip("_")


def capture_academic_cohort(
    student_profile,
    *,
    academic_year: str,
    campus: str | None = None,
    college: str | None = None,
    college_code: str | None = None,
    department: str | None = None,
    program: str | None = None,
    program_code: str | None = None,
    year_level: int | None = None,
    enrollment_state: str = CohortEnrollmentState.ENROLLED,
    provenance: str = CohortProvenance.MANUAL,
    source_reference: str = "",
) -> StudentAcademicCohort:
    """Capture a cohort once and reject any later conflicting historic context."""
    if not academic_year or not academic_year.strip():
        raise ValidationError("Academic year is required for cohort capture.")
    values = {
        "campus": (student_profile.campus if campus is None else campus).strip(),
        "college": (student_profile.college if college is None else college).strip(),
        "department": (student_profile.department if department is None else department).strip(),
        "program": (student_profile.program if program is None else program).strip(),
        "year_level": student_profile.year_level if year_level is None else year_level,
        "enrollment_state": enrollment_state,
        "provenance": provenance,
        "source_reference": (source_reference or "").strip(),
    }
    values["college_code"] = (college_code or canonical_organization_code(values["college"]))[:80]
    values["program_code"] = (program_code or canonical_organization_code(values["program"]))[:100]
    cohort, created = StudentAcademicCohort.objects.get_or_create(
        student_profile=student_profile,
        academic_year=academic_year.strip(),
        defaults=values,
    )
    if created:
        return cohort
    conflicts = [key for key, value in values.items() if getattr(cohort, key) != value]
    if conflicts:
        raise ValidationError("A conflicting historical academic cohort already exists.")
    return cohort


def _text(value: Any) -> str:
    return " ".join(str(value or "").strip().casefold().split())


def _code(value: Any, choices: dict[str, str], *, fallback: str = NOT_SPECIFIED) -> str:
    return choices.get(_text(value), fallback)


def _age_band(value: Any) -> str:
    try:
        age = int(value)
    except (TypeError, ValueError):
        return NOT_SPECIFIED
    if age <= 16:
        return "AGE_16_AND_BELOW"
    if age == 17:
        return "AGE_17"
    if age == 18:
        return "AGE_18"
    if age == 19:
        return "AGE_19"
    return "AGE_20_AND_ABOVE"


def _annual_income_band(family: dict[str, Any]) -> str:
    amounts = []
    # The approved v1 basis is household annual income.  Both parents must
    # supply a strict numeric amount; one-parent/free-text guesses are not a
    # valid household total.
    for member in (family.get("father") or {}, family.get("mother_maiden") or family.get("mother") or {}):
        raw = member.get("annual_income_prior_year", member.get("annual_income"))
        if raw in (None, ""):
            continue
        if isinstance(raw, bool):
            return NOT_SPECIFIED
        if isinstance(raw, (int, Decimal)):
            amount = Decimal(raw)
        elif isinstance(raw, float):
            amount = Decimal(str(raw))
        elif isinstance(raw, str) and re.fullmatch(r"\s*(?:php|₱)?\s*[0-9][0-9,]*(?:\.\d{1,2})?\s*", raw, re.I):
            try:
                amount = Decimal(re.sub(r"(?i)php|₱|,|\s", "", raw))
            except InvalidOperation:
                return NOT_SPECIFIED
        else:
            return NOT_SPECIFIED
        if amount < 0:
            return NOT_SPECIFIED
        amounts.append(amount)
    if len(amounts) != 2:
        return NOT_SPECIFIED
    total = sum(amounts, Decimal("0"))
    if total < Decimal("131484"):
        return "POOR_INCOME"
    if total < Decimal("262968"):
        return "LOW_INCOME"
    if total < Decimal("525936"):
        return "LOWER_MIDDLE_INCOME"
    if total < Decimal("920388"):
        return "MIDDLE_MIDDLE_INCOME"
    if total < Decimal("1577808"):
        return "UPPER_MIDDLE_INCOME"
    if total < Decimal("2626680"):
        return "UPPER_INCOME"
    return "RICH_INCOME"


GENDER_CHOICES = {"male": "MALE", "female": "FEMALE"}
CIVIL_STATUS_CHOICES = {
    "single": "SINGLE", "married": "MARRIED", "solo parent": "SOLO_PARENT",
}
RELIGION_CHOICES = {
    "roman catholic": "ROMAN_CATHOLIC", "born again": "BORN_AGAIN",
    "iglesia ni cristo": "IGLESIA_NI_CRISTO", "mormons": "MORMON",
    "mormon": "MORMON", "jehova's witness": "JEHOVAS_WITNESS",
    "jehovah's witness": "JEHOVAS_WITNESS", "seventh day adventist": "SEVENTH_DAY_ADVENTIST",
    "church of christ": "CHURCH_OF_CHRIST", "evangelical christian": "EVANGELICAL_CHRISTIAN",
    "mcgi": "MCGI", "members church of god international": "MCGI",
    "baptist": "BAPTIST", "pmcc": "PMCC", "none": "NONE",
    "other": "OTHER_DECLARED_RELIGION",
}
PARENT_LIVING_CHOICES = {"still living": "STILL_LIVING", "deceased": "DECEASED"}
PARENTS_MARITAL_CHOICES = {
    "married": "MARRIED", "living together": "LIVING_TOGETHER", "widow": "WIDOW_WIDOWER",
    "widower": "WIDOW_WIDOWER", "mother ofw": "MOTHER_OFW", "father ofw": "FATHER_OFW",
    "permanently separated": "PERMANENTLY_SEPARATED",
    "mother with other partner": "MOTHER_OTHER_PARTNER",
    "father with other partner": "FATHER_OTHER_PARTNER", "legally separated": "LEGALLY_SEPARATED",
    "temporarily separated": "TEMPORARILY_SEPARATED",
}
OCCUPATION_CHOICES = {
    "government employee": "GOVERNMENT_EMPLOYEE", "private employee": "PRIVATE_EMPLOYEE",
    "laborer": "LABORER", "farmer": "FARMER", "self employed": "SELF_EMPLOYED",
    "self-employed": "SELF_EMPLOYED", "small business owner": "SELF_EMPLOYED",
    "ofw": "OFW", "none": "NOT_CURRENTLY_WORKING", "none/not employed": "NOT_CURRENTLY_WORKING", "housewife": "NOT_CURRENTLY_WORKING",
    "househusband": "NOT_CURRENTLY_WORKING", "other": "OTHER_OCCUPATION",
}
LIVING_CHOICES = {
    "own house": "OWN_HOUSE", "with relatives": "WITH_RELATIVES",
    "boarding house": "BOARDING_HOUSE_DORMITORY", "boarding house/dormitory": "BOARDING_HOUSE_DORMITORY",
    "other": "OTHER_LIVING_CONDITION",
}
MUNICIPALITY_CHOICES = {
    name.casefold(): code
    for code, name in (
        ("BASUD", "Basud"), ("CAPALONGA", "Capalonga"), ("DAET", "Daet"),
        ("JOSE_PANGANIBAN", "Jose Panganiban"), ("LABO", "Labo"),
        ("MERCEDES", "Mercedes"), ("PARACALE", "Paracale"),
        ("SAN_LORENZO_RUIZ", "San Lorenzo Ruiz"), ("SAN_VICENTE", "San Vicente"),
        ("SANTA_ELENA", "Sta. Elena"), ("TALISAY", "Talisay"),
        ("VINZONS", "Vinzons"), ("CAMARINES_SUR", "Camarines Sur"),
    )
}
MUNICIPALITY_CHOICES.update({code.casefold(): code for code in MUNICIPALITY_CHOICES.values()})


def normalize_profiling_v1(data: dict[str, Any]) -> dict[str, str]:
    """Return codes only; unknown or ambiguous legacy values stay unspecified."""
    personal = data.get("personal_data") or {}
    family = data.get("family_data") or {}
    health = data.get("health_conditions") or {}
    living = data.get("living_conditions") or {}
    father = family.get("father") or {}
    mother = family.get("mother_maiden") or family.get("mother") or {}
    disability = _text(health.get("physical_disability_status", health.get("physical_disadvantage")))
    disability_code = {
        "none": "NOT_DECLARED",
        "not declared": "NOT_DECLARED",
        "no physical disability": "NOT_DECLARED",
        "no declared physical disability": "NOT_DECLARED",
        "declared physical disability": "DECLARED_PHYSICAL_DISABILITY",
        "with physical disability": "DECLARED_PHYSICAL_DISABILITY",
    }.get(disability, NOT_SPECIFIED)
    religion = _code(personal.get("current_religion"), RELIGION_CHOICES)
    parent_marital = family.get("parents_marital_status_code", family.get("parents_marital_status"))
    if isinstance(parent_marital, list):
        parent_marital = parent_marital[0] if len(parent_marital) == 1 else ""
    return {
        "gender_code": _code(personal.get("sex"), GENDER_CHOICES),
        "age_band_code": _age_band(personal.get("age")),
        "civil_status_code": _code(personal.get("civil_status"), CIVIL_STATUS_CHOICES),
        "physical_disability_code": disability_code,
        "religion_code": religion,
        "mother_living_status_code": _code(mother.get("living_status"), PARENT_LIVING_CHOICES),
        "father_living_status_code": _code(father.get("living_status"), PARENT_LIVING_CHOICES),
        "parents_marital_status_code": _code(parent_marital, PARENTS_MARITAL_CHOICES),
        "municipality_code": _code(personal.get("permanent_municipality"), MUNICIPALITY_CHOICES),
        "parents_annual_income_code": _annual_income_band(family),
        "mother_occupation_code": _code(mother.get("occupation_code", mother.get("occupation")), OCCUPATION_CHOICES),
        "father_occupation_code": _code(father.get("occupation_code", father.get("occupation")), OCCUPATION_CHOICES),
        "living_condition_code": _code(living.get("where"), LIVING_CHOICES),
    }


@transaction.atomic
def materialize_profiling_fact(snapshot: StudentInventorySnapshot) -> StudentProfilingFact:
    """Project a submitted snapshot without leaking failed confidential content."""
    cohort = StudentAcademicCohort.objects.filter(
        student_profile=snapshot.student_profile,
        academic_year=snapshot.academic_year,
    ).first()
    if cohort is None:
        raise ValidationError("A historical academic cohort is required before profiling materialization.")
    defaults = {
        "cohort": cohort,
        "source_schema_key": snapshot.schema_key,
        "source_schema_version": snapshot.schema_version,
        "mapping_version": PROFILING_MAPPING_VERSION,
    }
    if snapshot.status == InventoryStatusChoices.REOPENED_FOR_CORRECTION:
        defaults.update(status=ProfilingFactStatus.REOPENED, data_quality_code=REOPENED)
    elif snapshot.status != InventoryStatusChoices.SUBMITTED:
        raise ValidationError("Only submitted or reopened Inventory snapshots can be materialized.")
    else:
        try:
            normalized = normalize_profiling_v1(read_confidential_snapshot(snapshot).data)
        except InventoryEncryptionError as exc:
            defaults.update(status=ProfilingFactStatus.UNREADABLE, data_quality_code=exc.code)
        except FieldEncryptionError:
            defaults.update(
                status=ProfilingFactStatus.UNREADABLE,
                data_quality_code="inventory_confidential_unreadable",
            )
        except (ValidationError, TypeError, ValueError, AttributeError):
            defaults.update(status=ProfilingFactStatus.INVALID, data_quality_code=INVALID)
        else:
            defaults.update(status=ProfilingFactStatus.READY, data_quality_code="", **normalized)
    fact, _ = StudentProfilingFact.objects.update_or_create(
        inventory_snapshot=snapshot,
        defaults=defaults,
    )
    return fact


def mark_profiling_fact_reopened(snapshot: StudentInventorySnapshot) -> StudentProfilingFact | None:
    """Invalidate an existing fact immediately when its source becomes editable."""
    if snapshot.status != InventoryStatusChoices.REOPENED_FOR_CORRECTION:
        raise ValidationError("Only reopened snapshots can invalidate a profiling fact.")
    if not hasattr(snapshot, "profiling_fact"):
        return None
    fact = snapshot.profiling_fact
    fact.status = ProfilingFactStatus.REOPENED
    fact.data_quality_code = REOPENED
    fact.save(update_fields=["status", "data_quality_code", "updated_at"])
    return fact


SECTION_SPECS = (
    ("gender", "Gender", "gender_code", (("MALE", "Male"), ("FEMALE", "Female"))),
    ("age", "Age", "age_band_code", (("AGE_16_AND_BELOW", "16 and below"), ("AGE_17", "17"), ("AGE_18", "18"), ("AGE_19", "19"), ("AGE_20_AND_ABOVE", "20 and above"))),
    ("civil_status", "Civil status", "civil_status_code", (("SINGLE", "Single"), ("MARRIED", "Married"), ("SOLO_PARENT", "Solo parent"))),
    ("physical_disability", "Physical disability", "physical_disability_code", (("DECLARED_PHYSICAL_DISABILITY", "With physical disability"), ("NOT_DECLARED", "No physical disability"))),
    ("religion", "Religion", "religion_code", tuple((code, label) for code, label in (("ROMAN_CATHOLIC", "Roman Catholic"), ("BORN_AGAIN", "Born Again"), ("IGLESIA_NI_CRISTO", "Iglesia Ni Cristo"), ("MORMON", "Mormon"), ("JEHOVAS_WITNESS", "Jehovah's Witness"), ("SEVENTH_DAY_ADVENTIST", "Seventh Day Adventist"), ("CHURCH_OF_CHRIST", "Church of Christ"), ("EVANGELICAL_CHRISTIAN", "Evangelical Christian"), ("MCGI", "MCGI"), ("BAPTIST", "Baptist"), ("PMCC", "PMCC"), ("NONE", "None"), ("OTHER_DECLARED_RELIGION", "Other declared religion")))),
    ("parents_living", "Parents still living/deceased", "parent_living", (("MOTHER_STILL_LIVING", "Mother - still living"), ("MOTHER_DECEASED", "Mother - deceased"), ("MOTHER_NOT_SPECIFIED", "Mother - not specified"), ("FATHER_STILL_LIVING", "Father - still living"), ("FATHER_DECEASED", "Father - deceased"), ("FATHER_NOT_SPECIFIED", "Father - not specified"))),
    ("parents_marital_status", "Marital status of parents", "parents_marital_status_code", (("MARRIED", "Married"), ("LIVING_TOGETHER", "Living together"), ("WIDOW_WIDOWER", "Widow/Widower"), ("MOTHER_OFW", "Mother OFW"), ("FATHER_OFW", "Father OFW"), ("PERMANENTLY_SEPARATED", "Permanently separated"), ("MOTHER_OTHER_PARTNER", "Mother with other partner"), ("FATHER_OTHER_PARTNER", "Father with other partner"), ("LEGALLY_SEPARATED", "Legally separated"), ("TEMPORARILY_SEPARATED", "Temporarily separated"))),
    ("municipality", "Municipality", "municipality_code", ()),
    ("parents_annual_income", "Parents' annual income", "parents_annual_income_code", (("POOR_INCOME", "Poor income (below 131,484 annual income)"), ("LOW_INCOME", "Low income (131,484 to below 262,968 annual income)"), ("LOWER_MIDDLE_INCOME", "Lower middle income (262,968 to below 525,936 annual income)"), ("MIDDLE_MIDDLE_INCOME", "Middle middle income (525,936 to below 920,388 annual income)"), ("UPPER_MIDDLE_INCOME", "Upper middle income (920,388 to below 1,577,808 annual income)"), ("UPPER_INCOME", "Upper income (1,577,808 to below 2,626,680 annual income)"), ("RICH_INCOME", "Rich income (2,626,680 annual income and above)"))),
    ("mother_occupation", "Mother's occupation", "mother_occupation_code", (("GOVERNMENT_EMPLOYEE", "Government employee"), ("PRIVATE_EMPLOYEE", "Private employee"), ("LABORER", "Laborer"), ("FARMER", "Farmer"), ("SELF_EMPLOYED", "Self-employed"), ("OFW", "OFW"), ("NOT_CURRENTLY_WORKING", "None/not employed"), ("OTHER_OCCUPATION", "Other"))),
    ("father_occupation", "Father's occupation", "father_occupation_code", (("GOVERNMENT_EMPLOYEE", "Government employee"), ("PRIVATE_EMPLOYEE", "Private employee"), ("LABORER", "Laborer"), ("FARMER", "Farmer"), ("SELF_EMPLOYED", "Self-employed"), ("OFW", "OFW"), ("NOT_CURRENTLY_WORKING", "None/not employed"), ("OTHER_OCCUPATION", "Other"))),
    ("living_condition", "Living condition", "living_condition_code", (("OWN_HOUSE", "Own house"), ("WITH_RELATIVES", "With relatives"), ("BOARDING_HOUSE_DORMITORY", "Boarding house/dormitory"), ("OTHER_LIVING_CONDITION", "Other"))),
)


DATA_QUALITY_ROWS = (
    (NOT_SPECIFIED, "Not specified"),
    (DRAFT, "Draft Individual Inventory"),
    (REOPENED, "Reopened for correction"),
    (UNREADABLE, "Unreadable/invalid submitted Inventory"),
    (UNPROJECTED, "Submitted Inventory pending profiling projection"),
    (WITHOUT_INVENTORY, "Without Individual Inventory"),
)


def _percentage(value: int, total: int) -> str:
    if not total:
        return "0.00%"
    return f"{(Decimal(value) * Decimal('100') / Decimal(total)).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)}%"


def _cohort_queryset(context: ProfilingContext):
    filters = context.as_filters()
    return StudentAcademicCohort.objects.filter(
        enrollment_state=CohortEnrollmentState.ENROLLED,
        **filters,
    ).order_by("program", "id")


def _fact_category(fact: StudentProfilingFact | None, snapshot: StudentInventorySnapshot | None, field: str) -> str:
    if snapshot is None:
        return WITHOUT_INVENTORY
    if snapshot.status == InventoryStatusChoices.DRAFT:
        return DRAFT
    if snapshot.status == InventoryStatusChoices.REOPENED_FOR_CORRECTION:
        return REOPENED
    if fact is None:
        return UNPROJECTED
    if fact.status in (ProfilingFactStatus.UNREADABLE, ProfilingFactStatus.INVALID):
        return UNREADABLE
    if fact.status != ProfilingFactStatus.READY:
        return REOPENED
    if field == "parent_living":
        return ""
    return getattr(fact, field) or NOT_SPECIFIED


def _build_matrix(
    metric_key: str,
    title: str,
    field: str,
    categories: tuple[tuple[str, str], ...],
    cohorts: list[StudentAcademicCohort],
    snapshots: dict[int, StudentInventorySnapshot],
    facts: dict[int, StudentProfilingFact],
    programs: list[tuple[str, str]],
) -> dict[str, Any]:
    category_rows = list(categories)
    if field == "municipality_code":
        present = sorted({fact.municipality_code for fact in facts.values() if fact.status == ProfilingFactStatus.READY and fact.municipality_code and fact.municipality_code != NOT_SPECIFIED})
        category_rows.extend((code, code.replace("_", " ").title()) for code in present)
    if field == "parent_living":
        category_rows = [
            (f"MOTHER_{code.split('MOTHER_', 1)[-1]}", label)
            for code, label in category_rows if code.startswith("MOTHER_")
        ] + [
            (f"FATHER_{code.split('FATHER_', 1)[-1]}", label)
            for code, label in categories if code.startswith("FATHER_")
        ]
        category_rows.extend(
            (f"{prefix}{code}", f"{parent} - {label.lower()}")
            for prefix, parent in (("MOTHER_", "Mother"), ("FATHER_", "Father"))
            for code, label in DATA_QUALITY_ROWS
        )
        # NOT_SPECIFIED is a normalized parent response and also appears in
        # the common quality rows. Keep one deterministic row per code so a
        # parent denominator cannot be counted twice.
        seen_codes = set()
        unique_rows = []
        for item in category_rows:
            if item[0] not in seen_codes:
                seen_codes.add(item[0])
                unique_rows.append(item)
        category_rows = unique_rows
    else:
        category_rows.extend(DATA_QUALITY_ROWS)
    program_codes = [code for code, _label in programs]
    counters = {code: Counter() for code, _ in category_rows}
    for cohort in cohorts:
        snapshot = snapshots.get(cohort.student_profile_id)
        fact = facts.get(snapshot.id) if snapshot else None
        if field == "parent_living" and fact and snapshot and snapshot.status == InventoryStatusChoices.SUBMITTED and fact.status == ProfilingFactStatus.READY:
            mother = fact.mother_living_status_code or NOT_SPECIFIED
            father = fact.father_living_status_code or NOT_SPECIFIED
            program_code = cohort.program_code or canonical_organization_code(cohort.program) or "NOT_SPECIFIED"
            counters[f"MOTHER_{mother}"][program_code] += 1
            counters[f"FATHER_{father}"][program_code] += 1
            continue
        code = _fact_category(fact, snapshot, field)
        if field == "parent_living":
            program_code = cohort.program_code or canonical_organization_code(cohort.program) or "NOT_SPECIFIED"
            counters[f"MOTHER_{code}"][program_code] += 1
            counters[f"FATHER_{code}"][program_code] += 1
            continue
        counters.setdefault(code, Counter())
        program_code = cohort.program_code or canonical_organization_code(cohort.program) or "NOT_SPECIFIED"
        counters[code][program_code] += 1
    rows = []
    cohort_total = len(cohorts)
    for code, label in category_rows:
        counts = {program: counters[code][program] for program in program_codes}
        total = sum(counts.values())
        rows.append({"code": code, "label": label, "program_counts": counts, "total": total, "percentage": _percentage(total, cohort_total), "is_total": False})
    if field != "parent_living":
        for program in program_codes:
            if sum(row["program_counts"][program] for row in rows) != sum(1 for row in cohorts if (row.program_code or canonical_organization_code(row.program) or "NOT_SPECIFIED") == program):
                raise ProfilingReconciliationError("Profiling section does not reconcile to the cohort.")
    else:
        for parent_prefix in ("MOTHER_", "FATHER_"):
            for program in program_codes:
                if sum(row["program_counts"][program] for row in rows if row["code"].startswith(parent_prefix)) != sum(1 for row in cohorts if (row.program_code or canonical_organization_code(row.program) or "NOT_SPECIFIED") == program):
                    raise ProfilingReconciliationError("Parent living-status section does not reconcile to the cohort.")
    total_counts = {
        code: sum(1 for cohort in cohorts if (cohort.program_code or canonical_organization_code(cohort.program) or "NOT_SPECIFIED") == code)
        for code in program_codes
    }
    if field == "parent_living":
        rows.extend(
            {"code": f"{prefix}TOTAL", "label": f"{parent} total", "program_counts": dict(total_counts), "total": cohort_total, "percentage": "100.00%", "is_total": True}
            for prefix, parent in (("MOTHER_", "Mother"), ("FATHER_", "Father"))
        )
    else:
        rows.append({"code": "TOTAL", "label": "TOTAL", "program_counts": total_counts, "total": cohort_total, "percentage": "100.00%", "is_total": True})
    columns = [{"key": code, "label": label} for code, label in programs] + [
        {"key": "total", "label": "Total"}, {"key": "percentage", "label": "Percentage (%)"},
    ]
    for row in rows:
        row["values"] = {**row["program_counts"], "total": row["total"], "percentage": row["percentage"]}
    return {"metric_key": metric_key, "title": title, "columns": columns, "program_columns": columns[:-2], "rows": rows, "cohort_total": cohort_total}


def suppress_profiling_sections(sections: Iterable[dict[str, Any]], threshold: int = 5) -> tuple[list[dict[str, Any]], int]:
    """Suppress a complete section disclosure set whenever any positive cell is small."""
    threshold = max(5, int(threshold))
    rendered = []
    suppressed_cells = 0
    for section in sections:
        section = {**section, "rows": [{**row, "program_counts": dict(row["program_counts"]), "values": dict(row["values"])} for row in section["rows"]]}
        values = [value for row in section["rows"] for value in row["program_counts"].values()]
        suppress = any(0 < value < threshold for value in values)
        if suppress:
            for row in section["rows"]:
                for program in row["program_counts"]:
                    row["program_counts"][program] = SUPPRESSION_LABEL
                    row["values"][program] = SUPPRESSION_LABEL
                    suppressed_cells += 1
                row["total"] = SUPPRESSION_LABEL
                row["percentage"] = SUPPRESSION_LABEL
                row["values"]["total"] = SUPPRESSION_LABEL
                row["values"]["percentage"] = SUPPRESSION_LABEL
                suppressed_cells += 2
            section["suppression_notice"] = "Section suppressed for privacy."
        rendered.append(section)
    return rendered, suppressed_cells


def build_students_profile_report(context: ProfilingContext | dict[str, Any], *, suppression_threshold: int = 5) -> dict[str, Any]:
    """Return a deterministic, PII-free, already-suppressed report payload."""
    if isinstance(context, dict):
        context = ProfilingContext.from_filters(context)
    if context.department or context.program:
        raise ValidationError("Department and program filters are not permitted for Students' Profile.")
    unsliced = StudentAcademicCohort.objects.filter(
        enrollment_state=CohortEnrollmentState.ENROLLED,
        academic_year=context.academic_year,
        college=context.college,
        year_level=context.year_level,
    )
    if context.campus and (
        not unsliced.filter(campus=context.campus).exists()
        or unsliced.filter(campus=context.campus).count() != unsliced.count()
    ):
        raise ValidationError("Campus may not narrow the Students' Profile release cohort.")
    cohorts = list(_cohort_queryset(context))
    if not cohorts:
        raise ValidationError("No authoritative cohort matches the selected profiling context.")
    program_labels = {}
    for cohort in cohorts:
        code = cohort.program_code or canonical_organization_code(cohort.program) or "NOT_SPECIFIED"
        label = cohort.program or "Not specified"
        if code in program_labels and program_labels[code] != label:
            raise ProfilingReconciliationError(
                "Historical cohort contains ambiguous program labels for one program code."
            )
        program_labels[code] = label
    programs = sorted(program_labels.items(), key=lambda item: (item[1], item[0]))
    # The aggregate path only needs the snapshot identity and lifecycle state.
    # Deliberately defer every confidential field so constructing a report never
    # decrypts (or materializes) source Inventory JSON, correction notes, or a
    # reopen reason.  Normalized values come exclusively from the bounded
    # StudentProfilingFact projection created at submission time.
    snapshot_qs = StudentInventorySnapshot.objects.filter(
        student_profile_id__in=[cohort.student_profile_id for cohort in cohorts],
        academic_year=context.academic_year,
    ).only("id", "student_profile_id", "status")
    snapshots = {snapshot.student_profile_id: snapshot for snapshot in snapshot_qs}
    facts = {
        fact.inventory_snapshot_id: fact
        for fact in StudentProfilingFact.objects.filter(
            inventory_snapshot__in=snapshot_qs,
            cohort_id__in=[cohort.id for cohort in cohorts],
            mapping_version=PROFILING_MAPPING_VERSION,
        ).select_related("cohort")
    }
    sections = [
        _build_matrix(metric_key, title, field, categories, cohorts, snapshots, facts, programs)
        for metric_key, title, field, categories in SECTION_SPECS
    ]
    sections, _suppressed_cell_count = suppress_profiling_sections(sections, suppression_threshold)
    return {
        "report_context": {
            **context.as_filters(),
            "program_labels": [{"key": code, "label": label} for code, label in programs],
            "cohort_total": len(cohorts),
            "mapping_version": PROFILING_MAPPING_VERSION,
        },
        "sections": sections,
        # Deliberately fixed: no metadata reveals whether a specific section
        # triggered the primary/complementary protection rule.
        "privacy_controls_enforced": True,
    }
