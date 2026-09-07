"""Actor-aware query boundary for the student_activation domain.

Query functions belong here when the domain receives an API/UI read. They must
compose an existing scoped selector with a fixed projection and never return
HTTP responses or serialize ORM objects directly.
"""
