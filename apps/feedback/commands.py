"""Framework-neutral mutation command boundary for the feedback domain.

Commands are frozen value objects. Domain-specific commands are added here
when a route is introduced; HTTP requests and arbitrary data dictionaries do
not cross this boundary.
"""

from typing import Protocol


class CommandInput(Protocol):
    """Marker protocol for validated, immutable domain command DTOs."""
