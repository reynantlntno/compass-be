# Project: COMPASS
# File: config/asgi.py
# Module: config
# Purpose: ASGI config for COMPASS project
# Notes: None

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.development")

application = get_asgi_application()
