"""Actor-aware query boundary for account-security API reads."""

from apps.account_security.projections import project_trusted_device, project_user_activity_entry
from apps.account_security.selectors import (
    get_active_sessions,
    get_user_activity_queryset,
    get_user_trusted_devices,
)
from apps.common.contracts import PageRequest, PageResult, page_items


def get_activity_page(
    actor,
    page: PageRequest | None = None,
    *,
    category: str = "all",
) -> PageResult[dict]:
    request = page or PageRequest()
    queryset = get_user_activity_queryset(actor, category)
    return PageResult(
        items=tuple(
            project_user_activity_entry(row)
            for row in queryset[request.offset:request.offset + request.page_size]
        ),
        page=request.page,
        page_size=request.page_size,
        total=queryset.count(),
    )


def get_session_activity(actor, *, current_session_key: str = "") -> dict:
    return get_active_sessions(actor, current_session_key=current_session_key)


def get_session_page(actor, page: PageRequest, *, current_session_key: str = "") -> dict:
    value = get_active_sessions(actor, current_session_key=current_session_key)
    sessions = value.get("sessions", [])
    result = PageResult(
        items=tuple(sessions[page.offset:page.offset + page.page_size]),
        page=page.page,
        page_size=page.page_size,
        total=len(sessions),
    ).as_dict()
    result["decode"] = value.get("decode", {})
    return result


def get_trusted_device_page(actor, page: PageRequest) -> PageResult[dict]:
    queryset = get_user_trusted_devices(actor)
    return PageResult(
        items=tuple(
            project_trusted_device(row)
            for row in queryset[page.offset:page.offset + page.page_size]
        ),
        page=page.page,
        page_size=page.page_size,
        total=queryset.count(),
    )
