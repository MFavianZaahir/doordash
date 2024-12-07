from celery import shared_task
import logging
import pyotp
logger = logging.getLogger(__name__)
from django.core.mail import send_mail

@shared_task
def send_otp_email(email, otp_secret, otp):
    print(email)
    try:
        totp_instance = pyotp.TOTP("base32secret3232", digits=6)
        # otp = totp_instance.now()
        # Debug log
        # logger.info(f"Generated OTP for {email}: {otp}")

        print(email)
        send_mail(
            "Your OTP Code",
            f"Your OTP is {otp}. It is valid for 5 minutes.",
            "favianzaahir@gmail.com",
            ["bagassatwi@gmail.com"],
            fail_silently=False,
        )
        logger.info(f"OTP email sent to {email}.")
    except Exception as e:
        logger.error(f"Failed to send OTP email to {email}: {e}")
        raise
