# Project: COMPASS
# File: apps/audit/models.py
# Module: apps.audit
# Purpose: Audit log entry model for system and user activities
# Domain boundary and service policy.
# Notes: Data here is strictly immutable and redacted for privacy.

from django.db import models
from django.conf import settings

class AuditLogEntry(models.Model):
    """
    Immutable audit log entry for system and user activities.
    Must NOT contain sensitive narratives, raw passwords, or unredacted tokens.
    """
    actor_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_logs",
        help_text="User who performed the action. Null for system background tasks."
    )
    actor_role = models.CharField(
        max_length=50,
        blank=True,
        help_text="Snapshot of the user's role at the time of the action."
    )
    
    action_type = models.CharField(max_length=100, help_text="e.g., STATUS_TRANSITION, SENSITIVE_VIEW")
    event_category = models.CharField(max_length=100, help_text="e.g., SECURITY, DATA_ACCESS")
    severity = models.CharField(max_length=20, default="INFO", help_text="e.g., INFO, WARNING, CRITICAL")
    
    target_model = models.CharField(max_length=100, help_text="Name of the model affected, e.g., Appointment")
    target_object_id = models.CharField(max_length=255, help_text="String representation of the object ID")
    reference_code = models.CharField(max_length=50, null=True, blank=True, help_text="Immutable workflow reference code, e.g. APT-2026-0001")
    
    actor_ip_hash = models.CharField(max_length=64, null=True, blank=True, help_text="Hashed IP address for privacy")
    user_agent_hash = models.CharField(max_length=64, null=True, blank=True, help_text="Hashed User-Agent for privacy")
    
    request_id = models.CharField(max_length=100, null=True, blank=True, help_text="Correlation ID for the HTTP request")
    trace_id = models.CharField(max_length=100, null=True, blank=True, help_text="Correlation ID for distributed tracing/jobs")
    source_app = models.CharField(max_length=100, null=True, blank=True, help_text="The Django app generating the log")
    source_view = models.CharField(max_length=255, null=True, blank=True, help_text="The view or service function generating the log")
    
    safe_metadata = models.JSONField(default=dict, help_text="Sanitized metadata. MUST NOT contain raw secrets or PII narratives.")
    metadata_schema_version = models.IntegerField(default=1, help_text="Version of the metadata structure.")
    
    created_at = models.DateTimeField(auto_now_add=True, help_text="When the event occurred.")

    class Meta:
        verbose_name = "Audit Log Entry"
        verbose_name_plural = "Audit Log Entries"
        indexes = [
            models.Index(fields=["created_at"]),
            models.Index(fields=["actor_user"]),
            models.Index(fields=["action_type"]),
            models.Index(fields=["event_category"]),
            models.Index(fields=["severity"]),
            models.Index(fields=["reference_code"]),
            models.Index(fields=["target_model", "target_object_id"]),
        ]
        ordering = ["-created_at"]

    def __str__(self):
        actor = self.actor_user.email if self.actor_user else "System"
        return f"[{self.created_at.strftime('%Y-%m-%d %H:%M:%S')}] {self.action_type} by {actor} on {self.target_model}"
