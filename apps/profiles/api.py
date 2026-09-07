"""Read-only client-facing Profiles API.

This cutover exposes exactly two bearer-authenticated read operations.  No
profile mutation route, generic profile-detail endpoint, search, or
unrestricted student listing is added here.
"""

from ninja import Router, Schema

from apps.common.api.operations import prepare_api_operation
from apps.common.api.pagination import PageQuery, PageSizeQuery, page_request_from_values
from apps.common.contracts import ContractValidationError
from apps.common.exceptions import ValidationError
from apps.profiles import queries as profiles_queries


router = Router(tags=["profiles"])


class SupportDirectoryEntrySchema(Schema):
    user_id: int
    display_name: str
    role: str
    designation: str


class SupportDirectoryPageSchema(Schema):
    items: list[SupportDirectoryEntrySchema]
    page: int
    page_size: int
    total: int


class SelfProfileSchema(Schema):
    user_id: int
    display_name: str
    role: str
    profile_type: str | None = None
    student_number: str | None = None
    lifecycle_status: str | None = None
    campus: str | None = None
    college: str | None = None
    department: str | None = None
    program: str | None = None
    year_level: str | None = None
    designation: str | None = None
    is_head_guidance: bool | None = None


def _actor(request):
    return request.auth.user


def _page(page: PageQuery, page_size: PageSizeQuery):
    try:
        return page_request_from_values(page, page_size)
    except ContractValidationError as error:
        raise ValidationError() from error


@router.get("/me/", response=SelfProfileSchema, exclude_unset=True, operation_id="profiles_me")
def profiles_me(request):
    prepare_api_operation(request, "profiles_me")
    return profiles_queries.my_profile(_actor(request))


@router.get(
    "/directory/",
    response=SupportDirectoryPageSchema,
    operation_id="profiles_support_directory",
)
def profiles_support_directory(
    request,
    student_id: int | None = None,
    page: PageQuery = 1,
    page_size: PageSizeQuery = 25,
):
    prepare_api_operation(request, "profiles_support_directory")
    return profiles_queries.support_directory_page(
        _actor(request),
        student_id=student_id,
        page=_page(page, page_size),
    )
