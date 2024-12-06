from django.contrib.auth.signals import user_logged_in
from django.db.models.signals import post_save
from django.dispatch import receiver
from django_otp.oath import totp
from django.core.mail import send_mail
from time import time
from .models import User

# Generate OTP when a user logs in
@receiver(user_logged_in)
def send_otp_on_login(sender, request, user, **kwargs):
    if user.otp_secret:
        otp_code = totp(key=user.otp_secret, step=30, digits=6, t=int(time()))
        
        # Send OTP to the user's email
        send_mail(
            'Your Login OTP',
            f'Your OTP is: {otp_code}',
            'noreply@example.com',
            [user.email],
        )
        print(f"OTP sent to {user.email}: {otp_code}")

# Assign OTP secret when a new user is created
@receiver(post_save, sender=User)
def assign_otp_secret(sender, instance, created, **kwargs):
    if created and not instance.otp_secret:
        instance.otp_secret = random_hex()
        instance.save()