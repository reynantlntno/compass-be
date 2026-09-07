from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from apps.audit.services import audit_log
from apps.access_control.authority import resolve_capability
from apps.access_control.capabilities import Capability
from apps.documents.models import DocumentStatusChoices
from apps.reports.choices import ExportStatusChoices, ReportFamilyChoices
from apps.reports.export_services import (
    expire_report_export,
    revoke_csm_export_download_for_retention_hold,
)
from apps.reports.commands import ReportExportLifecycleCommand
from apps.reports.models import ReportExportRequest
from apps.security.models import FileStatusChoices


REASON_CODE = "csm_privacy_remediation"
EXECUTION_CONFIRMATION = "csm_privacy_remediation"
ELIGIBLE_EXPORT_STATUSES = (
    ExportStatusChoices.GENERATED,
    ExportStatusChoices.DOWNLOADED,
)
ELIGIBLE_DOCUMENT_STATUSES = (
    DocumentStatusChoices.GENERATED,
    DocumentStatusChoices.RELEASED,
)


class Command(BaseCommand):
    help = "Dry-run or revoke pre-DATA-001 downloadable CSM export artifacts."

    def add_arguments(self, parser):
        parser.add_argument("--cutoff", required=True, help="DATA-001 deployment cutoff in ISO-8601 form.")
        parser.add_argument("--actor-user-id", help="Authorized actor UUID for lifecycle and audit evidence.")
        parser.add_argument(
            "--system-identity",
            help="Bounded deployment/system identity for a non-mutating dry-run.",
        )
        parser.add_argument("--execute", action="store_true", help="Apply the remediation; omitted means dry-run.")
        parser.add_argument(
            "--confirm",
            default="",
            help=f"Execution confirmation; must equal {EXECUTION_CONFIRMATION!r} with --execute.",
        )

    def handle(self, *args, **options):
        cutoff = parse_datetime(options["cutoff"])
        if cutoff is None:
            raise CommandError("--cutoff must be a valid ISO-8601 datetime.")
        if timezone.is_naive(cutoff):
            raise CommandError("--cutoff must include a timezone offset.")

        execute = bool(options["execute"])
        actor_user_id = options.get("actor_user_id")
        system_identity = (options.get("system_identity") or "").strip()
        if bool(actor_user_id) == bool(system_identity):
            raise CommandError("Provide exactly one of --actor-user-id or --system-identity.")
        if len(system_identity) > 100 or (system_identity and not system_identity.replace("-", "").replace("_", "").isalnum()):
            raise CommandError("--system-identity must be a bounded alphanumeric identifier.")
        if execute and system_identity:
            raise CommandError("Execution requires an authorized --actor-user-id; system identity is dry-run only.")

        actor = None
        if actor_user_id:
            User = get_user_model()
            try:
                actor = User.objects.get(pk=actor_user_id, is_active=True)
            except (User.DoesNotExist, ValueError):
                raise CommandError("--actor-user-id must identify an active authorized user.")
            if not (
                resolve_capability(actor, Capability.REPORTS_EXPORT_OPERATE)
                or resolve_capability(actor, Capability.REPORTS_EXPORT_MAINTAIN)
            ):
                raise CommandError("--actor-user-id is not authorized for export lifecycle remediation.")

        if execute and options["confirm"] != EXECUTION_CONFIRMATION:
            raise CommandError(
                f"Execution requires --confirm {EXECUTION_CONFIRMATION}."
            )

        candidates = self._candidate_queryset(cutoff)
        if not candidates.exists():
            self.stdout.write("No eligible CSM export artifacts; safe no-op.")
            return

        if not execute:
            self.stdout.write("Eligible CSM export artifacts exist; dry-run made no changes.")
            return

        retention_blocked = False
        for export_id in candidates.values_list("id", flat=True).iterator():
            with transaction.atomic():
                export_request = (
                    ReportExportRequest.objects.select_for_update(of=("self",))
                    .select_related("report_definition", "protected_file", "generated_document")
                    .get(id=export_id)
                )
                previous_status = export_request.status
                if export_request.protected_file.retention_hold:
                    export_request = revoke_csm_export_download_for_retention_hold(actor, export_request)
                    cleanup_action = "download_revoked_retention_hold"
                    retention_blocked = True
                else:
                    export_request = expire_report_export(
                        actor,
                        str(export_request.id),
                        ReportExportLifecycleCommand(
                            export_id=str(export_request.id),
                            expected_status=export_request.status,
                        ),
                    )
                    cleanup_action = "expired_delete_marked"

                audit_log(
                    action_type="CSM_EXPORT_PRIVACY_REMEDIATED",
                    event_category="DATA_ACCESS",
                    target_model="reports.ReportExportRequest",
                    target_object_id=str(export_request.id),
                    actor_user=actor,
                    source_app="reports",
                    metadata={
                        "export_object_id": str(export_request.id),
                        "report_definition_key": export_request.report_definition.key,
                        "previous_status": previous_status,
                        "cleanup_action": cleanup_action,
                        "actor_id": str(actor.id),
                        "timestamp": timezone.now().isoformat(),
                        "reason_code": REASON_CODE,
                    },
                )

        if retention_blocked:
            self.stdout.write(
                "CSM export download authorization revoked; retention-hold deletion blockers require authorized follow-up."
            )
        else:
            self.stdout.write("Eligible CSM export artifacts remediated successfully.")

    @staticmethod
    def _candidate_queryset(cutoff):
        now = timezone.now()
        return (
            ReportExportRequest.objects.filter(
                report_definition__family=ReportFamilyChoices.FEEDBACK_CSM,
                status__in=ELIGIBLE_EXPORT_STATUSES,
                generated_at__lt=cutoff,
                expired_at__isnull=True,
                protected_file__isnull=False,
                protected_file__status=FileStatusChoices.ACTIVE,
            )
            .filter(Q(expires_at__isnull=True) | Q(expires_at__gte=now))
            .filter(
                Q(generated_document__isnull=True)
                | Q(generated_document__document_status__in=ELIGIBLE_DOCUMENT_STATUSES)
            )
            .select_related("report_definition", "protected_file", "generated_document")
            .order_by("id")
        )
