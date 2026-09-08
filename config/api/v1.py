"""Canonical Django Ninja API v1 assembly."""

from django.conf import settings
from apps.account_security.api import me_router, router as auth_router
from apps.account_security.api_auth import CompassBearerAuthentication
from apps.security.api import router as files_router
from apps.access_control.api import router as authority_router
from apps.governance.api import router as policies_router
from apps.accounts.api import router as staff_accounts_router
from apps.content.api import router as content_router
from apps.appointments.api import router as appointments_router
from apps.counseling.api import router as counseling_router
from apps.inventory.api import router as inventory_router
from apps.support_needs.api import router as support_needs_router
from apps.profiles.api import router as profiles_router
from apps.referrals.api import router as referrals_router
from apps.call_slips.api import router as call_slips_router
from apps.good_moral.api import router as good_moral_router
from apps.form_collection.api import router as form_collection_router
from apps.exit_interviews.api import router as exit_interviews_router
from apps.graduate_tracer.api import router as graduate_tracer_router
from apps.reports.api import router as reports_router
from apps.privacy.api import router as privacy_router
from apps.notifications.api import router as notifications_router
from apps.imports.api import router as imports_router
from apps.backups.api import router as backups_router
from apps.system.api import router as system_router
from apps.organizations.api import router as organizations_router
from apps.assessments.api import router as assessments_router
from apps.audit.api import router as audit_router
from config.api.docs import bearer_it_admin_docs
from apps.common.api.errors import (
    handle_compass_error,
    handle_framework_error,
    handle_unexpected_error,
)
from apps.common.api.openapi import CompassNinjaAPI
from apps.common.exceptions import CompassError
from django.core.exceptions import PermissionDenied as DjangoPermissionDenied
from django.core.exceptions import ValidationError as DjangoValidationError
from django.http import Http404
from ninja.errors import HttpError
from ninja.errors import ValidationError as NinjaValidationError


_development_docs_enabled = str(
    getattr(settings, "COMPASS_ENVIRONMENT", "development")
).strip().lower() in {"development", "testing"}


api_v1 = CompassNinjaAPI(
    title="COMPASS API",
    version="1.0.0",
    description="The canonical backend API for COMPASS clients.",
    urls_namespace="compass-api-v1",
    auth=CompassBearerAuthentication(),
    docs_url="/docs/" if _development_docs_enabled else None,
    openapi_url="/openapi.json",
    docs_decorator=None if _development_docs_enabled else bearer_it_admin_docs,
)

api_v1.add_exception_handler(CompassError, handle_compass_error)
api_v1.add_exception_handler(HttpError, handle_framework_error)
api_v1.add_exception_handler(Http404, handle_framework_error)
api_v1.add_exception_handler(DjangoPermissionDenied, handle_framework_error)
api_v1.add_exception_handler(DjangoValidationError, handle_framework_error)
api_v1.add_exception_handler(NinjaValidationError, handle_framework_error)
api_v1.add_exception_handler(Exception, handle_unexpected_error)

api_v1.add_router("/auth", auth_router)
api_v1.add_router("/me", me_router)
api_v1.add_router("/files", files_router)
api_v1.add_router("/authority", authority_router)
api_v1.add_router("/policies", policies_router)
api_v1.add_router("/staff-accounts", staff_accounts_router)
api_v1.add_router("/content", content_router)
api_v1.add_router("/appointments", appointments_router)
api_v1.add_router("/counseling", counseling_router)
api_v1.add_router("/inventory", inventory_router)
api_v1.add_router("/support-needs", support_needs_router)
api_v1.add_router("/profiles", profiles_router)
api_v1.add_router("/referrals", referrals_router)
api_v1.add_router("/call-slips", call_slips_router)
api_v1.add_router("/good-moral", good_moral_router)
api_v1.add_router("/form-collections", form_collection_router)
api_v1.add_router("/exit-interviews", exit_interviews_router)
api_v1.add_router("/graduate-tracer", graduate_tracer_router)
api_v1.add_router("/reports", reports_router)
api_v1.add_router("/privacy", privacy_router)
api_v1.add_router("/notifications", notifications_router)
api_v1.add_router("/imports", imports_router)
api_v1.add_router("/backups", backups_router)
api_v1.add_router("/system", system_router)
api_v1.add_router("/organizations", organizations_router)
api_v1.add_router("/assessments", assessments_router)
api_v1.add_router("/audit", audit_router)
