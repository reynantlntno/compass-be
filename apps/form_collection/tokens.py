# Project: COMPASS
# File: apps/form_collection/tokens.py
# Module: apps.form_collection
# Purpose: Cryptographically secure token helpers and normalization functions
# Domain boundary and service policy.

import secrets
from datetime import date, datetime
from apps.account_security.tokens import hash_identifier, compare_tokens


def generate_selector_and_verifier() -> tuple[str, str]:
    """Generate a unique selector (for db lookup) and a raw verifier token."""
    selector = secrets.token_hex(16)
    verifier = secrets.token_hex(32)
    return selector, verifier


def hash_verifier(verifier: str) -> str:
    """Hash the verifier token using HMAC-SHA256 for secure storage."""
    return hash_identifier(verifier)


def normalize_email(email: str) -> str:
    """Normalize email address by stripping whitespace and lowercasing."""
    if not email:
        return ""
    return str(email).strip().lower()


def normalize_identifier(identifier: str) -> str:
    """Normalize student/control numbers by stripping, uppercasing, and removing dashes/spaces."""
    if not identifier:
        return ""
    val = str(identifier).strip().upper()
    # Remove common delimiters
    val = val.replace("-", "").replace(" ", "")
    return val


def normalize_surname(surname: str) -> str:
    """Normalize surname by stripping whitespace and lowercasing."""
    if not surname:
        return ""
    return str(surname).strip().lower()


def normalize_birthdate(bdate) -> str:
    """Normalize birthdate to standard YYYY-MM-DD format."""
    if not bdate:
        return ""
    if isinstance(bdate, (date, datetime)):
        return bdate.strftime("%Y-%m-%d")
    # If it is a string, strip it
    val = str(bdate).strip()
    # Try parsing to make sure format is clean
    for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%d/%m/%Y", "%Y/%m/%d"):
        try:
            parsed = datetime.strptime(val, fmt).date()
            return parsed.strftime("%Y-%m-%d")
        except ValueError:
            continue
    return val
