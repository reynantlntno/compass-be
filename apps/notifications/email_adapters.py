import socket
import smtplib
import uuid
from django.conf import settings
from django.core.mail import EmailMultiAlternatives, get_connection

from apps.governance.runtime_config import resolve_runtime_setting


class EmailDeliveryError(Exception):
    def __init__(self, message, error_code, is_retryable=True):
        super().__init__(message)
        self.error_code = error_code
        self.is_retryable = is_retryable


class DjangoEmailAdapter:
    """
    Adapter boundary around Django's core email utilities.
    Ensures SMTP exceptions are safely captured and categorized without leaking raw credentials.
    """
    def send_email(
        self,
        recipient_email: str,
        subject: str,
        text_content: str,
        html_content: str = None,
        from_email: str = None,
        reply_to: list = None
    ) -> str:
        """
        Sends an email using Django's email backend.
        Returns a mock/real message ID string or raises EmailDeliveryError.
        """
        try:
            from_addr = from_email or getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@compass.edu.ph")
            reply_addrs = reply_to or getattr(settings, "COMPASS_EMAIL_REPLY_TO", None)
            if isinstance(reply_addrs, str):
                reply_addrs = [reply_addrs]

            msg = EmailMultiAlternatives(
                subject=subject,
                body=text_content,
                from_email=from_addr,
                to=[recipient_email],
                reply_to=reply_addrs
            )

            if html_content:
                msg.attach_alternative(html_content, "text/html")

            # SMTP hosts and credentials remain deployment configuration, but
            # the bounded transport timeout is a centrally governed delivery
            # control. Set it on the connection so Django's global setting
            # cannot become a second policy source.
            connection = get_connection(fail_silently=False)
            if hasattr(connection, "timeout"):
                connection.timeout = resolve_runtime_setting(
                    "technical.delivery_operations",
                    "EMAIL_TIMEOUT",
                )
            # Use the explicitly configured connection.  EmailMessage.send()
            # does not accept a connection keyword in the supported Django
            # runtime; passing it there turns a valid SMTP setup into a
            # misleading GENERAL_DELIVERY_ERROR.
            connection.send_messages([msg])
            return f"msg_{uuid.uuid4().hex[:16]}"

        except (socket.timeout, socket.error) as e:
            raise EmailDeliveryError(
                message=f"Network error: {str(e)[:100]}",
                error_code="NETWORK_ERROR",
                is_retryable=True
            )
        except smtplib.SMTPConnectError as e:
            raise EmailDeliveryError(
                message=f"SMTP connection error: {str(e)[:100]}",
                error_code="SMTP_CONNECT_ERROR",
                is_retryable=True
            )
        except smtplib.SMTPAuthenticationError as e:
            raise EmailDeliveryError(
                message="SMTP authentication failed",
                error_code="SMTP_AUTH_ERROR",
                is_retryable=False
            )
        except smtplib.SMTPRecipientsRefused as e:
            raise EmailDeliveryError(
                message=f"Recipient address refused: {str(e)[:100]}",
                error_code="RECIPIENT_REFUSED",
                is_retryable=False
            )
        except smtplib.SMTPSenderRefused as e:
            raise EmailDeliveryError(
                message="Sender address refused",
                error_code="SENDER_REFUSED",
                is_retryable=False
            )
        except smtplib.SMTPException as e:
            raise EmailDeliveryError(
                message=f"SMTP transmission error: {str(e)[:100]}",
                error_code="SMTP_TRANSMISSION_ERROR",
                is_retryable=True
            )
        except Exception as e:
            raise EmailDeliveryError(
                message=f"General delivery exception: {str(e)[:100]}",
                error_code="GENERAL_DELIVERY_ERROR",
                is_retryable=True
            )
