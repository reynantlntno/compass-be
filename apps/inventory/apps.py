# Project: COMPASS
# File: apps/inventory/apps.py
# Module: apps.inventory
# Purpose: Django AppConfig definition for apps.inventory
# Domain boundary and service policy.

from django.apps import AppConfig


class InventoryConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.inventory"
    verbose_name = "Inventory Management"

    def ready(self):
        # Imports register settings checks and temporary Release 1 targets.
        from apps.inventory import checks  # noqa: F401
        from apps.inventory.encryption_targets import register_inventory_encryption_targets

        register_inventory_encryption_targets()
