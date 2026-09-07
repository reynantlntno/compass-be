"""Thin router composition for Governance's v1 API surface."""

from ninja import Router

from apps.governance.dpo_api import router as dpo_router
from apps.governance.policy_api import router as policy_router


router = Router(tags=["policies"])
router.add_router("", dpo_router)
router.add_router("", policy_router)
