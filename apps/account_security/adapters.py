import logging
from django.conf import settings
from apps.notifications.email_adapters import DjangoEmailAdapter, EmailDeliveryError

logger = logging.getLogger(__name__)


def send_security_email(
    recipient_email: str,
    subject: str,
    text_content: str = "",
    *,
    template_key: str = "two_step_code",
    context: dict = None,
    runtime_context: dict = None,
) -> str:
    """Send an account security email (such as an OTP or password reset link) synchronously.

    This ensures immediate delivery for authentication workflows while isolating the SMTP
    interaction within an explicit adapter boundary.
    """
    adapter = DjangoEmailAdapter()
    try:
        if context is not None:
            from apps.notifications.services import send_transactional_email
            return send_transactional_email(
                recipient_email=recipient_email,
                template_key=template_key,
                context=context,
                subject=subject,
                runtime_context=runtime_context,
                adapter=adapter,
            )
        msg_id = adapter.send_email(recipient_email=recipient_email, subject=subject, text_content=text_content)
        return msg_id
    except EmailDeliveryError as e:
        logger.error(
            f"Security email delivery failed to recipient hash: "
            f"code={e.error_code}, is_retryable={e.is_retryable}"
        )
        raise e
