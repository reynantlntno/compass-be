from datetime import date
from unittest.mock import patch

from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import IntegrityError
from django.test import TestCase

from apps.organizations.academic_year import (
    AcademicYearConfigurationError,
    get_current_academic_term,
    resolve_current_academic_year,
)
from apps.organizations.models import (
    AcademicTerm,
    AcademicTermStatusChoices,
    academic_term_lifecycle_write,
)


class AcademicYearSourceOfTruthTests(TestCase):
    def _term(self, *, academic_year="2025-2026", status=AcademicTermStatusChoices.DRAFT):
        start_year = int(academic_year[:4])
        term = AcademicTerm(
            academic_year=academic_year,
            semester="Annual",
            start_date=date(start_year, 8, 1),
            end_date=date(start_year + 1, 7, 31),
            status=status,
            configuration_identifier="test-academic-term",
        )
        with academic_term_lifecycle_write():
            term.save()
        return term

    def test_missing_active_term_fails_closed(self):
        with self.assertRaises(AcademicYearConfigurationError):
            get_current_academic_term()
        with self.assertRaises(AcademicYearConfigurationError):
            resolve_current_academic_year()

    def test_active_academic_term_is_the_only_reader_source(self):
        term = self._term(status=AcademicTermStatusChoices.ACTIVE)

        self.assertEqual(get_current_academic_term().pk, term.pk)
        self.assertEqual(resolve_current_academic_year(), "2025-2026")

    def test_multiple_active_terms_fail_closed_even_if_storage_is_corrupt(self):
        class CorruptActiveQuerySet:
            def only(self, *fields):
                return self

            def __getitem__(self, key):
                return [object(), object()][key]

        with patch.object(
            AcademicTerm.objects,
            "filter",
            return_value=CorruptActiveQuerySet(),
        ):
            with self.assertRaises(AcademicYearConfigurationError):
                get_current_academic_term()

    def test_invalid_academic_year_is_rejected_by_the_domain_model(self):
        term = AcademicTerm(
            academic_year="2025-2027",
            semester="Annual",
            start_date=date(2025, 8, 1),
            end_date=date(2026, 7, 31),
            status=AcademicTermStatusChoices.DRAFT,
            configuration_identifier="test-academic-term",
        )

        with self.assertRaises(DjangoValidationError):
            term.full_clean()

    def test_direct_term_persistence_is_rejected_outside_lifecycle_service(self):
        with self.assertRaises(DjangoValidationError):
            AcademicTerm.objects.create(
                academic_year="2025-2026",
                semester="Annual",
                start_date=date(2025, 8, 1),
                end_date=date(2026, 7, 31),
                status=AcademicTermStatusChoices.DRAFT,
                configuration_identifier="direct-write",
            )

        with self.assertRaises(DjangoValidationError):
            AcademicTerm.objects.filter(status=AcademicTermStatusChoices.DRAFT).update(
                academic_year="2026-2027",
            )

        with self.assertRaises(DjangoValidationError):
            AcademicTerm.objects.bulk_create([
                AcademicTerm(
                    academic_year="2026-2027",
                    semester="Annual",
                    start_date=date(2026, 8, 1),
                    end_date=date(2027, 7, 31),
                    status=AcademicTermStatusChoices.DRAFT,
                    configuration_identifier="bulk-write",
                ),
            ])

    def test_direct_term_deletion_is_rejected_outside_lifecycle_service(self):
        term = self._term()

        with self.assertRaises(DjangoValidationError):
            term.delete()

        with self.assertRaises(DjangoValidationError):
            AcademicTerm.objects.filter(pk=term.pk).delete()

    def test_database_constraint_keeps_one_active_term(self):
        self._term(status=AcademicTermStatusChoices.ACTIVE)

        with self.assertRaises(IntegrityError):
            self._term(academic_year="2026-2027", status=AcademicTermStatusChoices.ACTIVE)
