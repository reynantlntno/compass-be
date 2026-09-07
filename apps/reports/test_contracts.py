from dataclasses import FrozenInstanceError
from types import SimpleNamespace

from django.test import SimpleTestCase

from apps.common.exceptions import ValidationError
from apps.reports.commands import ReportExportCommand, ReportExportLifecycleCommand, ReportRunCommand
from apps.reports.projections import aggregate_result_projection, report_export_technical_projection


class ReportsCommandContractTests(SimpleTestCase):
    def test_commands_are_frozen_and_normalize_bounded_filters(self):
        command = ReportRunCommand(
            report_key="students_profile",
            filters={"academic_year": "2025-2026", "year_level": 1},
        )
        self.assertEqual(command.filters, (("academic_year", "2025-2026"), ("year_level", "1")))
        with self.assertRaises(FrozenInstanceError):
            command.report_key = "other"

    def test_commands_reject_arbitrary_oversized_filter_sets(self):
        with self.assertRaises(ValidationError):
            ReportExportCommand(
                report_key="exit_interview_completion_summary",
                export_format="csv",
                filters={str(index): "x" for index in range(13)},
            )

    def test_aggregate_projection_rejects_non_json_objects(self):
        with self.assertRaises(ValidationError):
            aggregate_result_projection({"unsafe": object()})

    def test_aggregate_projection_accepts_flat_metric_maps(self):
        projection = aggregate_result_projection({
            "ratings_summary": {"total_count": 12},
            "by_program": [{"program_snapshot": "BSIT", "count": 12}],
            "received_honors_summary": {"with_honors": 8, "without_honors": 4},
        })
        self.assertEqual(projection["ratings_summary"]["total_count"], 12)
        with self.assertRaises(ValidationError):
            aggregate_result_projection({"rows": [{"student_number": "secret"}]})
        with self.assertRaises(ValidationError):
            aggregate_result_projection({"rows": [{"safe": {"nested": True}}]})

    def test_it_technical_projection_has_no_report_data_or_filters(self):
        export = SimpleNamespace(
            id="export-id",
            status="generated",
            export_format="csv",
            export_type="aggregate",
            requested_at=None,
            generated_at=None,
            expires_at=None,
            protected_file_id="file-id",
            generation_metadata_json={"status": "generated", "output_classification": "machine"},
        )
        projection = report_export_technical_projection(export)
        self.assertNotIn("report_key", projection)
        self.assertNotIn("filter_summary", projection)
        self.assertEqual(projection["protected_file_available"], True)

    def test_lifecycle_command_requires_a_stable_export_target(self):
        with self.assertRaises(ValidationError):
            ReportExportLifecycleCommand(export_id="")
