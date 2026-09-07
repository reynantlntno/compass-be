from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase

from apps.appointments.api import ReviewDecisionSchema, review_and_schedule, submit_request


def _request():
    return SimpleNamespace(auth=SimpleNamespace(user=object()))


def _execute_operation(_request, _operation_id, _payload, operation):
    return operation()


class AppointmentsApiMutationWiringTests(SimpleTestCase):
    def test_review_and_schedule_calls_service_once_inside_operation(self):
        appointment = SimpleNamespace(reference_code="APT-1", status="SCHEDULED")
        payload = ReviewDecisionSchema(action="approve")

        with (
            patch("apps.appointments.api._run", side_effect=_execute_operation),
            patch(
                "apps.appointments.api.review_and_schedule_appointment",
                return_value=appointment,
            ) as service,
        ):
            result = review_and_schedule(_request(), "APT-1", payload)

        service.assert_called_once()
        self.assertEqual(result.value, {"reference_code": "APT-1", "status": "SCHEDULED"})

    @patch("apps.appointments.api._run", side_effect=_execute_operation)
    @patch("apps.appointments.api.submit_appointment_request")
    def test_submit_route_uses_the_shared_operation_adapter(self, service, _run):
        service.return_value = SimpleNamespace(reference_code="APT-1", status="SUBMITTED")

        result = submit_request(_request(), "APT-1")

        service.assert_called_once()
        self.assertEqual(result.value, {"reference_code": "APT-1", "status": "SUBMITTED"})
