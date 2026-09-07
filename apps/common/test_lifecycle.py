from types import SimpleNamespace

from django.test import SimpleTestCase

from apps.common.exceptions import LifecycleConflictError, StaleStateError
from apps.common.lifecycle import LifecycleContract, LifecycleRequest


class LifecycleContractTests(SimpleTestCase):
    def setUp(self):
        self.contract = LifecycleContract(
            "test.resource",
            {"DRAFT": {"PENDING"}, "PENDING": {"ACTIVE"}, "ACTIVE": set()},
        )

    def test_contract_checks_state_and_expected_version_before_persisting(self):
        target = SimpleNamespace(status="DRAFT", updated_at="v1")
        persisted = []
        audited = []
        result = self.contract.execute(
            target,
            to_state="PENDING",
            request=LifecycleRequest(
                reason_code="SUBMITTED",
                expected_state="DRAFT",
                expected_version="v1",
                evidence={"source": "test"},
            ),
            persist=lambda current, state, request, actor: persisted.append((current, state)),
            audit=lambda transition: audited.append(transition) or {"append_only": True},
        )
        self.assertEqual(result.from_state, "DRAFT")
        self.assertEqual(result.to_state, "PENDING")
        self.assertEqual(len(persisted), 1)
        self.assertEqual(len(audited), 1)

    def test_contract_rejects_stale_state_and_unknown_transition(self):
        target = SimpleNamespace(status="ACTIVE", updated_at="v1")
        with self.assertRaises(StaleStateError):
            self.contract.execute(
                target,
                to_state="PENDING",
                request=LifecycleRequest(reason_code="STALE", expected_state="DRAFT"),
            )
        target.status = "DRAFT"
        with self.assertRaises(LifecycleConflictError):
            self.contract.execute(
                target,
                to_state="ACTIVE",
                request=LifecycleRequest(reason_code="SKIP_STATE"),
            )
