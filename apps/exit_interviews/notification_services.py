"""Transactional Exit Interview notification events."""

from django.core.signing import BadSignature, Signer

from apps.notifications.dispatch import enqueue_notification_event, fan_out_notification, safe_display_name
from apps.notifications.recipients import authorized_queue_readers


ASSIGNMENT_REFERENCE_SALT = "compass.exit-interviews.notification.assignment.v1"


def _assignment_reference(assignment) -> str:
    return Signer(salt=ASSIGNMENT_REFERENCE_SALT).sign_object({"assignment": str(assignment.pk)})


def _assignment_from_reference(reference):
    from apps.exit_interviews.models import ExitInterviewAssignment

    try:
        payload = Signer(salt=ASSIGNMENT_REFERENCE_SALT).unsign_object(reference)
    except (BadSignature, TypeError, ValueError):
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("assignment"), str):
        return None
    assignment_pk = payload["assignment"]
    return ExitInterviewAssignment.objects.select_related("student__user").filter(pk=assignment_pk).first()


def enqueue_exit_interview_event(event, response=None, *, assignment=None):
    source = response or assignment
    if response:
        source_reference = response.reference_code
        payload = {"response_reference": response.reference_code}
    elif assignment:
        source_reference = _assignment_reference(assignment)
        payload = {"assignment_reference": source_reference}
    else:
        raise ValueError("A response or assignment is required for an Exit Interview event.")
    enqueue_notification_event(
        f"exit_interview.{event}",
        payload,
        related_object=source,
        event_key=f"exit_interview:{source_reference}:{event}:{source.updated_at.isoformat()}",
    )


def handle_exit_interview_event(payload, outbox_event):
    from apps.exit_interviews.models import ExitInterviewResponse
    from apps.exit_interviews.policies import can_view_exit_response

    if payload.get("assignment_reference"):
        assignment = _assignment_from_reference(payload["assignment_reference"])
        if assignment is None:
            return
        student = assignment.student.user
        related = assignment
        action = "Reminder"
        status = "Assigned"
        fan_out_notification(
            event_key=outbox_event.event_key,
            notification_type="exit_interview_reminder",
            recipients=[student],
            title="Exit Interview reminder",
            body_preview="An Exit Interview is ready in COMPASS.",
            related_object=related,
            metadata={"action": action, "status": status},
            email_context={"action": action, "status": status},
            subject="COMPASS: Exit Interview Update",
        )
        return

    response = ExitInterviewResponse.objects.select_related("student__user").get(
        reference_code=payload["response_reference"]
    )
    action = outbox_event.event_type.rsplit(".", 1)[-1]
    if action == "submitted":
        readers = authorized_queue_readers(can_view_exit_response, response)
        fan_out_notification(
            event_key=outbox_event.event_key,
            notification_type="exit_interview_submitted",
            recipients=readers,
            title="Exit Interview submitted",
            body_preview=f"{safe_display_name(response.student)} submitted an Exit Interview for queue review.",
            related_object=response,
            metadata={"action": "Submitted", "status": "Submitted", "reference_code": response.reference_code, "student_name": safe_display_name(response.student)},
        )
    elif action == "status_changed" and response.status in {"REOPENED_FOR_CORRECTION", "VOIDED"}:
        context = {"action": "Status update", "status": response.get_status_display(), "reference_code": response.reference_code}
        fan_out_notification(
            event_key=outbox_event.event_key,
            notification_type="exit_interview_status_update",
            recipients=[response.student.user],
            title="Exit Interview status update",
            body_preview="Your Exit Interview status has changed. Open COMPASS for the current information.",
            related_object=response,
            metadata=context,
            email_context=context,
            subject="COMPASS: Exit Interview Update",
        )
