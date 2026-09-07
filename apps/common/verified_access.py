"""Stable, non-secret principals for verified pre-account form access."""

from __future__ import annotations

from dataclasses import dataclass

from apps.common.form_values import normalize_command_id, normalize_command_text
from apps.common.exceptions import ValidationError


@dataclass(frozen=True, slots=True)
class VerifiedFormAccessPrincipal:
    """A request-local proof of a currently verified invitation context.

    Only stable database identifiers and the bounded form target cross this
    boundary.  Selectors, verifiers, hashes, identity values, and session
    material deliberately do not belong in the principal.
    """

    invitation_id: str
    form_collection_id: str
    target_form_key: str
    form_revision_id: str | None = None
    student_profile_id: str | None = None
    unlinked_submission_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "invitation_id", normalize_command_id(self.invitation_id, "invitation_id", required=True))
        object.__setattr__(self, "form_collection_id", normalize_command_id(self.form_collection_id, "form_collection_id", required=True))
        object.__setattr__(self, "target_form_key", normalize_command_text(self.target_form_key, "target_form_key", maximum=64, required=True))
        object.__setattr__(self, "form_revision_id", normalize_command_id(self.form_revision_id, "form_revision_id"))
        object.__setattr__(self, "student_profile_id", normalize_command_id(self.student_profile_id, "student_profile_id"))
        object.__setattr__(self, "unlinked_submission_id", normalize_command_id(self.unlinked_submission_id, "unlinked_submission_id"))

    @classmethod
    def from_invitation(cls, invitation) -> "VerifiedFormAccessPrincipal":
        collection = getattr(invitation, "collection", None)
        if collection is None:
            raise ValidationError("Verified form access is invalid.")
        return cls(
            invitation_id=str(invitation.pk),
            form_collection_id=str(collection.pk),
            target_form_key=str(invitation.target_form_key),
            form_revision_id=str(collection.form_revision_id) if collection.form_revision_id else None,
            student_profile_id=str(invitation.linked_student_id) if invitation.linked_student_id else None,
            unlinked_submission_id=(
                str(invitation.unlinked_submission_id)
                if invitation.unlinked_submission_id
                else None
            ),
        )

    def matches_invitation(self, invitation) -> bool:
        return (
            str(getattr(invitation, "pk", "")) == self.invitation_id
            and str(getattr(invitation, "collection_id", "")) == self.form_collection_id
            and str(getattr(invitation, "target_form_key", "")) == self.target_form_key
        )

    def matches_response(self, response) -> bool:
        if str(getattr(response, "form_invitation_id", "")) != self.invitation_id:
            return False
        if self.student_profile_id and str(getattr(response, "student_id", "")) != self.student_profile_id:
            return False
        if self.unlinked_submission_id and str(getattr(response, "unlinked_submission_id", "")) != self.unlinked_submission_id:
            return False
        return True
