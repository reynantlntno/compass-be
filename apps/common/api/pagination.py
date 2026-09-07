"""Strict pagination parsing for API collection boundaries."""

from typing import Annotated

from ninja import Query

from apps.common.contracts import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    ContractValidationError,
    PageRequest,
    PageResult,
)


# These aliases are the only API-facing pagination declarations.  Keeping the
# bounds beside the framework-neutral constants ensures the OpenAPI contract
# and runtime validation cannot drift apart.
PageQuery = Annotated[int, Query(default=1, ge=1)]
PageSizeQuery = Annotated[
    int,
    Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
]


def page_request_from_values(page: int, page_size: int) -> PageRequest:
    """Build the immutable pagination value from typed route parameters."""

    try:
        return PageRequest(page=page, page_size=page_size)
    except (TypeError, ValueError, ContractValidationError) as exc:
        raise ContractValidationError("Invalid pagination parameters.") from exc


def page_request_from_query(request) -> PageRequest:
    query = getattr(request, "GET", {})
    try:
        return PageRequest(
            page=int(query.get("page", 1)),
            page_size=int(query.get("page_size", DEFAULT_PAGE_SIZE)),
        )
    except (TypeError, ValueError, ContractValidationError) as exc:
        raise ContractValidationError("Invalid pagination parameters.") from exc


def page_result(items, page_request: PageRequest) -> dict:
    result = PageResult(
        items=tuple(items[page_request.offset: page_request.offset + page_request.page_size]),
        page=page_request.page,
        page_size=page_request.page_size,
        total=len(items),
    )
    return result.as_dict()
