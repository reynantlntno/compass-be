"""Synthetic UCN academic catalog used by the local operating demo seed.

The catalog intentionally stays as versioned Python data instead of introducing
new organization tables.  The application currently stores campus, college,
department, and program values as bounded strings on ``StudentProfile`` and on
the access-control scope records.  Keeping one canonical set of strings here
prevents the exact-match coverage rules from drifting.

The active base groups mirror the UCN public admission/catalog navigation
reviewed for the demo seed.  Majors are expanded into separate synthetic
program rows so that the search, filtering, and report fixtures have useful
coverage.  No real student information or enrolment counts are copied.
"""

from dataclasses import dataclass


UCN_CATALOG_SOURCE_URL = "https://ucn.edu.ph/UCN/main-home-page-copy/admission/"
UCN_CATALOG_REVIEWED_ON = "2026-08-06"
UCN_CATALOG_VERSION = "ucn-public-catalog-2026-08"


@dataclass(frozen=True)
class ProgramSeed:
    key: str
    campus: str
    college: str
    department: str
    program: str
    levels: int = 4
    graduate: bool = False
    major: str = ""
    source_group: str = ""


def _program(
    key,
    campus,
    college,
    department,
    program,
    *,
    levels=4,
    graduate=False,
    major="",
    source_group="",
):
    return ProgramSeed(
        key=key,
        campus=campus,
        college=college,
        department=department,
        program=program,
        levels=levels,
        graduate=graduate,
        major=major,
        source_group=source_group or key,
    )


MAIN = "Main Campus, Daet"
ABANO = "Abaño Campus, Daet"
LABO = "Labo/Talobatib Campus, Labo"
MERCEDES = "Mercedes Campus, San Roque"
PANGANIBAN = "Jose Panganiban Campus"
ENTIENZA = "Ret. Judge Antonio C. Entienza Campus, Santa Elena"


UCN_PROGRAM_CATALOG = (
    # College of Agriculture and Natural Resources — Labo/Talobatib.
    _program("CANR_BS_AGRICULTURE_CROP", LABO, "College of Agriculture and Natural Resources", "Agriculture", "BS Agriculture – Crop Science", major="Crop Science", source_group="BS Agriculture"),
    _program("CANR_BS_AGRICULTURE_ANIMAL", LABO, "College of Agriculture and Natural Resources", "Agriculture", "BS Agriculture – Animal Science", major="Animal Science", source_group="BS Agriculture"),
    _program("CANR_BS_ENVIRONMENTAL_SCIENCE", LABO, "College of Agriculture and Natural Resources", "Environmental Science", "BS Environmental Science"),
    _program("CANR_BS_AGRI_BIOSYSTEMS_ENGINEERING", LABO, "College of Agriculture and Natural Resources", "Agricultural and Biosystems Engineering", "BS Agricultural and Biosystems Engineering", levels=5),

    # College of Arts and Sciences — Main Campus.
    _program("CAS_BS_DEVELOPMENT_COMMUNICATION", MAIN, "College of Arts and Sciences", "Development Communication", "BS Development Communication"),
    _program("CAS_BS_APPLIED_MATHEMATICS", MAIN, "College of Arts and Sciences", "Applied Mathematics", "BS Applied Mathematics"),
    _program("CAS_BS_PSYCHOLOGY", MAIN, "College of Arts and Sciences", "Psychology", "BS Psychology"),
    _program("CAS_BS_BIOLOGY", MAIN, "College of Arts and Sciences", "Biology", "BS Biology"),
    _program("CAS_BA_ENGLISH_LANGUAGE_STUDIES", MAIN, "College of Arts and Sciences", "English Language Studies", "BA English Language Studies"),
    _program("CAS_BA_SOCIOLOGY", MAIN, "College of Arts and Sciences", "Sociology", "BA Sociology"),

    # College of Computing and Multimedia Studies — Main Campus.
    _program("CCMS_BS_INFORMATION_TECHNOLOGY", MAIN, "College of Computing and Multimedia Studies", "Information Technology", "BS Information Technology"),
    _program("CCMS_BS_INFORMATION_SYSTEMS", MAIN, "College of Computing and Multimedia Studies", "Information Systems", "BS Information Systems"),
    _program("CCMS_MASTER_INFORMATION_TECHNOLOGY", MAIN, "College of Computing and Multimedia Studies", "Information Technology", "Master in Information Technology", levels=2, graduate=True),

    # College of Business and Public Administration — Main Campus.
    _program("CBPA_BACHELOR_PUBLIC_ADMINISTRATION", MAIN, "College of Business and Public Administration", "Public Administration", "Bachelor of Public Administration"),
    _program("CBPA_BS_HOSPITALITY_MANAGEMENT", MAIN, "College of Business and Public Administration", "Hospitality Management", "BS Hospitality Management"),
    _program("CBPA_BS_ACCOUNTANCY", MAIN, "College of Business and Public Administration", "Accountancy", "BS Accountancy"),
    _program("CBPA_BS_OFFICE_ADMINISTRATION", MAIN, "College of Business and Public Administration", "Office Administration", "BS Office Administration"),
    _program("CBPA_BS_ENTREPRENEURSHIP", MAIN, "College of Business and Public Administration", "Entrepreneurship", "BS Entrepreneurship"),
    _program("CBPA_BSBA_BUSINESS_ECONOMICS", MAIN, "College of Business and Public Administration", "Business Administration", "BS Business Administration – Business Economics", major="Business Economics", source_group="BS Business Administration"),
    _program("CBPA_BSBA_MARKETING_MANAGEMENT", MAIN, "College of Business and Public Administration", "Business Administration", "BS Business Administration – Marketing Management", major="Marketing Management", source_group="BS Business Administration"),
    _program("CBPA_BSBA_HUMAN_RESOURCE_MANAGEMENT", MAIN, "College of Business and Public Administration", "Business Administration", "BS Business Administration – Human Resource Management", major="Human Resource Management", source_group="BS Business Administration"),
    _program("CBPA_BSBA_FINANCIAL_MANAGEMENT", MAIN, "College of Business and Public Administration", "Business Administration", "BS Business Administration – Financial Management", major="Financial Management", source_group="BS Business Administration"),

    # College of Education — Abaño Campus.
    _program("COED_BSED_ENGLISH", ABANO, "College of Education", "Secondary Education", "BSEd – English", major="English", source_group="BSEd"),
    _program("COED_BSED_FILIPINO", ABANO, "College of Education", "Secondary Education", "BSEd – Filipino", major="Filipino", source_group="BSEd"),
    _program("COED_BSED_MATHEMATICS", ABANO, "College of Education", "Secondary Education", "BSEd – Mathematics", major="Mathematics", source_group="BSEd"),
    _program("COED_BSED_SCIENCE", ABANO, "College of Education", "Secondary Education", "BSEd – Science", major="Science", source_group="BSEd"),
    _program("COED_BSED_SOCIAL_STUDIES", ABANO, "College of Education", "Secondary Education", "BSEd – Social Studies", major="Social Studies", source_group="BSEd"),
    _program("COED_BEED", ABANO, "College of Education", "Elementary Education", "BEEd"),
    _program("COED_BTLED", ABANO, "College of Education", "Technology and Livelihood Education", "BTLEd"),
    _program("COED_BPED", ABANO, "College of Education", "Physical Education", "BPEd"),

    # College of Engineering — Main Campus.
    _program("COENG_BS_CIVIL_ENGINEERING", MAIN, "College of Engineering", "Civil Engineering", "BS Civil Engineering", levels=5),
    _program("COENG_BS_ELECTRICAL_ENGINEERING", MAIN, "College of Engineering", "Electrical Engineering", "BS Electrical Engineering", levels=5),
    _program("COENG_BS_MECHANICAL_ENGINEERING", MAIN, "College of Engineering", "Mechanical Engineering", "BS Mechanical Engineering", levels=5),

    # College of Fisheries, Aquatic Sciences, and Technology — Mercedes.
    _program("CFAST_BS_FISHERIES", MERCEDES, "College of Fisheries, Aquatic Sciences, and Technology", "Fisheries", "BS Fisheries"),

    # College of Trades and Technology — Jose Panganiban Campus.
    _program("COTT_BTVTED_GARMENTS", PANGANIBAN, "College of Trades and Technology", "Technical-Vocational Teacher Education", "BTVTEd – Garments and Fashion Design", major="Garments and Fashion Design", source_group="BTVTEd"),
    _program("COTT_BTVTED_FOOD_SERVICE", PANGANIBAN, "College of Trades and Technology", "Technical-Vocational Teacher Education", "BTVTEd – Food and Service Management", major="Food and Service Management", source_group="BTVTEd"),
    _program("COTT_BTVTED_AUTOMOTIVE", PANGANIBAN, "College of Trades and Technology", "Technical-Vocational Teacher Education", "BTVTEd – Automotive Technology", major="Automotive Technology", source_group="BTVTEd"),
    _program("COTT_BTVTED_ELECTRICAL", PANGANIBAN, "College of Trades and Technology", "Technical-Vocational Teacher Education", "BTVTEd – Electrical Technology", major="Electrical Technology", source_group="BTVTEd"),
    _program("COTT_BS_INDUSTRIAL_TECH_ELECTRICAL", PANGANIBAN, "College of Trades and Technology", "Industrial Technology", "BS Industrial Technology – Electrical Technology", major="Electrical Technology", source_group="BS Industrial Technology"),
    _program("COTT_BS_INDUSTRIAL_TECH_COMPUTER", PANGANIBAN, "College of Trades and Technology", "Industrial Technology", "BS Industrial Technology – Computer Technology", major="Computer Technology", source_group="BS Industrial Technology"),
    _program("COTT_BS_INDUSTRIAL_TECH_ELECTRONICS", PANGANIBAN, "College of Trades and Technology", "Industrial Technology", "BS Industrial Technology – Electronics Technology", major="Electronics Technology", source_group="BS Industrial Technology"),

    # Ret. Judge Antonio C. Entienza Campus — Santa Elena.
    _program("ENTIENZA_BSED_ENGLISH", ENTIENZA, "Ret. Judge Antonio C. Entienza Campus", "Secondary Education", "BSEd – English", major="English", source_group="BSEd"),
    _program("ENTIENZA_BSED_MATHEMATICS", ENTIENZA, "Ret. Judge Antonio C. Entienza Campus", "Secondary Education", "BSEd – Mathematics", major="Mathematics", source_group="BSEd"),
    _program("ENTIENZA_BEED", ENTIENZA, "Ret. Judge Antonio C. Entienza Campus", "Elementary Education", "BEEd"),
    _program("ENTIENZA_BS_ENTREPRENEURSHIP", ENTIENZA, "Ret. Judge Antonio C. Entienza Campus", "Entrepreneurship", "BS Entrepreneurship"),

    # Graduate School — Main Campus.
    _program("GS_DOCTOR_BUSINESS_ADMINISTRATION", MAIN, "Graduate School", "Doctoral Programs", "Doctor in Business Administration", levels=3, graduate=True),
    _program("GS_DOCTOR_PUBLIC_ADMINISTRATION", MAIN, "Graduate School", "Doctoral Programs", "Doctor of Public Administration", levels=3, graduate=True),
    _program("GS_DOCTOR_EDUCATION", MAIN, "Graduate School", "Doctoral Programs", "Doctor in Education", levels=3, graduate=True),
    _program("GS_MASTER_BUSINESS_ADMINISTRATION", MAIN, "Graduate School", "Masteral Programs", "Master in Business Administration", levels=2, graduate=True),
    _program("GS_MASTER_PUBLIC_ADMINISTRATION", MAIN, "Graduate School", "Masteral Programs", "Master in Public Administration", levels=2, graduate=True),
    _program("GS_MASTER_MANAGEMENT_EDUCATIONAL_PLANNING", MAIN, "Graduate School", "Masteral Programs", "Master in Management – Educational Planning and Management", levels=2, graduate=True, major="Educational Planning and Management", source_group="Master in Management"),
    _program("GS_MASTER_MANAGEMENT_HUMAN_RESOURCE", MAIN, "Graduate School", "Masteral Programs", "Master in Management – Human Resource Management", levels=2, graduate=True, major="Human Resource Management", source_group="Master in Management"),
    _program("GS_MASTER_ARTS_EDUCATION_LEADERSHIP", MAIN, "Graduate School", "Masteral Programs", "Master of Arts in Education – Educational Leadership and Management", levels=2, graduate=True, major="Educational Leadership and Management", source_group="Master of Arts in Education"),
    _program("GS_MASTER_ARTS_EDUCATION_FILIPINO", MAIN, "Graduate School", "Masteral Programs", "Master of Arts in Education – Teaching Filipino Language", levels=2, graduate=True, major="Teaching Filipino Language", source_group="Master of Arts in Education"),
)


def validate_catalog():
    """Return a deterministic validation error, or ``None`` when valid."""
    seen = set()
    for row in UCN_PROGRAM_CATALOG:
        if row.key in seen:
            return f"Duplicate catalog key: {row.key}"
        seen.add(row.key)
        for field_name in ("campus", "college", "department", "program"):
            value = getattr(row, field_name)
            if not value or len(value) > 100:
                return f"Catalog {field_name} is empty or exceeds 100 characters: {row.key}"
        if row.levels < 1 or row.levels > 6:
            return f"Catalog levels are invalid: {row.key}"
    return None
