"""Stable reason categories for the assured IT Admin recovery route."""

STAFF_RECOVERY_REASON_CHOICES = (
    ("self_service_inaccessible", "Self-service inaccessible"),
    ("internal_role_policy", "Internal-role policy"),
    ("out_of_band_email_ownership", "Out-of-band ownership verified"),
)
STAFF_RECOVERY_REASON_CODES = frozenset(code for code, _label in STAFF_RECOVERY_REASON_CHOICES)
