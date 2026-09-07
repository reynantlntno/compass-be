# Project: COMPASS
# File: apps/student_activation/management/commands/reissue_activation.py
# Module: apps.student_activation
# Purpose: CLI Command to reissue/generate student activation link
# Domain boundary and service policy.

from django.core.management.base import BaseCommand, CommandError

from apps.accounts.models import RoleChoices, User
from apps.student_activation.policies import can_manage_activation_invitations
from apps.common.exceptions import ValidationError
from apps.orchestration.commands import StudentActivationInvitationCommand
from apps.orchestration.use_cases import create_student_activation_invitation_for_import


class Command(BaseCommand):
    help = "Generate or reissue an account activation token for a student user."

    def add_arguments(self, parser):
        parser.add_argument("--email", required=True, help="Email of the student user.")
        parser.add_argument(
            "--actor-email",
            help="Email of the administrator issuing the token. (Required if --actor-id not provided)",
        )
        parser.add_argument(
            "--actor-id",
            type=int,
            help="Database ID of the administrator issuing the token. (Required if --actor-email not provided)",
        )

    def handle(self, *args, **options):
        email = options["email"].strip()
        actor_email = options.get("actor_email")
        actor_id = options.get("actor_id")

        # 1. Enforce actor options presence
        if not actor_email and not actor_id:
            raise CommandError("Either --actor-email or --actor-id must be provided.")

        # 2. Look up and validate actor BEFORE target student lookup
        actor = None
        try:
            if actor_id:
                actor = User.objects.get(id=actor_id)
            else:
                actor = User.objects.get(email__iexact=actor_email.strip())
        except User.DoesNotExist:
            raise CommandError("Actor user not found in the database.")

        if not actor.is_active:
            raise CommandError("Actor user account is inactive.")

        if not can_manage_activation_invitations(actor):
            raise CommandError(
                "Actor is not authorized to generate activation invitations."
            )


        # 4. Lookup and validate target student
        try:
            target_user = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            raise CommandError("Target student user was not found.")

        if target_user.role != RoleChoices.STUDENT:
            raise CommandError(
                "Activation invitations can only be issued to users with the STUDENT role."
            )
        if target_user.is_active:
            raise CommandError("Target user account is already active.")

        # 5. Generate token
        try:
            create_student_activation_invitation_for_import(
                actor,
                StudentActivationInvitationCommand(
                    user_id=str(target_user.pk),
                    source_view="reissue_command",
                ),
            )
        except ValidationError as e:
            raise CommandError(f"Validation failed: {e.message}")

        self.stdout.write(
            self.style.SUCCESS(
                f"Activation invitation generated and queued successfully for student ID: {target_user.id}"
            )
        )
