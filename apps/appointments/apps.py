# Project: COMPASS
# File: apps/appointments/apps.py
# Module: apps.appointments
# Purpose: Django AppConfig definition for apps.appointments
# Domain boundary and service policy.
# Notes: None

from django.apps import AppConfig


class AppointmentsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.appointments"
    verbose_name = "Appointments"

    def ready(self):
        from apps.appointments.policy import (
            APPOINTMENTS_SCHEDULING_POLICY_DEFINITION,
            OFFICE_CLOSURES_POLICY_DEFINITION,
        )
        from apps.governance.registry import register_policy_definition

        register_policy_definition(OFFICE_CLOSURES_POLICY_DEFINITION)
        register_policy_definition(APPOINTMENTS_SCHEDULING_POLICY_DEFINITION)
