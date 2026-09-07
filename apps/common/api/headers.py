"""Shared response headers for the COMPASS transport boundary."""

from __future__ import annotations


NOINDEX_ROBOTS_TAG = "noindex, nofollow, noarchive"


def apply_noindex_header(response):
    """Prevent compliant crawlers from indexing any COMPASS response."""

    response["X-Robots-Tag"] = NOINDEX_ROBOTS_TAG
    return response
