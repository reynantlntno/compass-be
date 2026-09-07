# Project: COMPASS
# File: apps/reports/sensitivity.py
# Module: apps.reports
# Purpose: Field and category sensitivity classifier

from apps.reports.choices import FieldSensitivity

# Sensitive fields that require cell count suppression when below threshold
SENSITIVE_FIELDS = {
    "religion",
    "disability",
    "income",
    "salary",
    "family_status",
    "parent_occupation",
    "living_condition",
    "municipality",
    "barangay",
    "health",
    "employment_details",
    "employer_name",
    "contact_details",
    "service_sensitive_category",
    "referral_reason_category",
    "free_text",
    "narrative",
}

# Forbidden fields that are blocked entirely from report queries and outputs
FORBIDDEN_FIELDS = {
    "counseling_notes",
    "e_counseling_messages",
    "raw_referral_reason",
    "case_details",
    "raw_token",
    "verifier",
    "token_hash",
    "selector",
    "raw_request_body",
    "ip_address",
    "user_agent",
    "session_key",
    "student_number",
    "control_number",
    "email",
    "phone",
    "name",
    "first_name",
    "last_name",
    "surname",
}

# General internal fields (not sensitive but not public)
INTERNAL_FIELDS = {
    "campus",
    "college",
    "department",
    "program",
    "year_level",
    "lifecycle_status",
    "employment_status",
    "first_job_related",
    "job_relevance_summary",
    "overall_satisfaction",
    "sqd_average",
    "client_type",
    "service_category",
}


def classify_field_sensitivity(field_key: str) -> FieldSensitivity:
    """Classifies a given field key or category string into FieldSensitivity level."""
    if not field_key:
        return FieldSensitivity.FORBIDDEN
        
    key_lower = field_key.strip().lower()
    
    # Check forbidden first
    if key_lower in FORBIDDEN_FIELDS or any(f in key_lower for f in ["password", "secret", "token", "notes", "message"]):
        return FieldSensitivity.FORBIDDEN
        
    # Check sensitive
    if key_lower in SENSITIVE_FIELDS or any(s in key_lower for s in ["income", "salary", "disability", "religion", "health", "narrative", "free_text"]):
        return FieldSensitivity.SENSITIVE
        
    # Check internal
    if key_lower in INTERNAL_FIELDS:
        return FieldSensitivity.INTERNAL
        
    # Default: conservative (restricted/forbidden rather than public)
    return FieldSensitivity.RESTRICTED
