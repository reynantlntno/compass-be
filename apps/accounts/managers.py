# Project: COMPASS
# File: apps/accounts/managers.py
# Module: accounts
# Purpose: Custom UserManager for email-based authentication
# Domain boundary and service policy.
# Notes: Email is the USERNAME_FIELD. Student number belongs on StudentProfile.

from django.contrib.auth.models import BaseUserManager


class UserManager(BaseUserManager):
    """Custom user manager using email as the unique identifier."""

    def create_user(self, email, password=None, **extra_fields):
        """Create and return a regular user with the given email and password."""
        if not email:
            raise ValueError("Users must have an email address.")
        if extra_fields.get("is_superuser") is True:
            raise ValueError(
                "Django superuser provisioning is disabled; use the role-scoped API "
                "IT_ADMIN workflow instead."
            )
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """Reject standard Django superuser provisioning for this API service."""

        raise ValueError(
            "Django superuser provisioning is disabled; use the role-scoped API "
            "IT_ADMIN workflow instead."
        )
