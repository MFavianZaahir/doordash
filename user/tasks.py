from celery import shared_task
from django.core.mail import send_mail

@shared_task
def send_otp_email(email, otp):
    subject = "Your OTP Code"
    message = f"Your OTP code is: {otp}. This code is valid for 5 minutes."
    from_email = "your_email@example.com"  # Replace with your sender email
    recipient_list = [email]

    send_mail(subject, message, from_email, recipient_list, fail_silently=False)
    return f"OTP sent to {email}"
