# Project: COMPASS
# File: config/urls.py
# Module: config
# Purpose: Root URL configuration for the API-only Django service
# Notes: None

from django.urls import path

from apps.system.http import health_liveness, robots_txt
from config.api.v1 import api_v1


handler400 = "apps.system.http.api_bad_request"
handler403 = "apps.system.http.api_forbidden"
handler404 = "apps.system.http.api_not_found"
handler500 = "apps.system.http.api_internal_server_error"


urlpatterns = [
    path("api/v1/", api_v1.urls),
    path("health/", health_liveness, name="health-check"),
    path("robots.txt", robots_txt, name="robots-txt"),
]
