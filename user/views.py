import pyotp
from .serializers import UserSerializer, CreateUserSerializer, LoginSerializer, UpdateUserSerializer
from user.models import User
from .tasks import send_otp_email
from user.permissions import IsManager
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, generics, permissions
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.parsers import MultiPartParser, FormParser
from django.core.cache import cache
from django_otp.oath import totp
from django.conf import settings
from django.core.mail import send_mail
from celery.result import AsyncResult 
from time import time
import logging
import base64
import binascii
logger = logging.getLogger(__name__)
class UserListCreateView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = CreateUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user, token_data = serializer.save()

        # Generate OTP and save the data in cache
        email = serializer.validated_data.get('email')
        otp_secret = pyotp.random_base32()
        totp_instance = pyotp.TOTP(otp_secret, interval=300)  # 5-minute window
        otp = totp_instance.now()
        print(email)
        # Store user data temporarily in cache
        cache_key = f"pending_user_{email}"
        cache.set(cache_key, {
            "user_data": serializer.validated_data,
            "otp_secret": otp_secret,
        }, timeout=300)  # OTP is valid for 5 minutes

        # Send OTP via email
        send_otp_email(email, otp, otp)
        # subject = "Your OTP for Account Verification"
        # message = f"Dear {serializer.validated_data.get('username')},\n\nYour OTP for verification is: {otp}\nThis OTP is valid for 5 minutes."
        # from_email = settings.DEFAULT_FROM_EMAIL
        # recipient_list = [email]

        # try:
        #     send_mail(subject, message, from_email, recipient_list)
        #     response_message = "OTP sent to your email."
        # except Exception as e:
        #     response_message = f"Failed to send email: {str(e)}"

        return Response({
            "message": "OTP sent to your email."
        }, status=status.HTTP_201_CREATED)

class VerifyOTPView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')

        if not email or not otp:
            logger.warning("Email or OTP missing in the verification request.")
            return Response({"error": "Email and OTP are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Retrieve pending user data from cache
            cache_key = f"pending_user_{email}"
            pending_user = cache.get(cache_key)
            if not pending_user:
                logger.warning(f"Pending user data not found for {email}.")
                return Response({"error": "OTP expired or invalid."}, status=status.HTTP_400_BAD_REQUEST)

            otp_secret = pending_user['otp_secret']
            totp_instance = pyotp.TOTP(otp_secret, interval=300)
            logger.info(f"Verifying OTP for {email}. User OTP: {otp}, Generated OTP: {totp_instance.now()}")

            # Verify the OTP
            if not totp_instance.verify(otp, valid_window=1):
                logger.warning(f"Invalid OTP for {email}.")
                return Response({"error": "Invalid OTP."}, status=status.HTTP_401_UNAUTHORIZED)

            # Create user only after successful OTP verification
            user_data = pending_user['user_data']
            user = User.objects.create_user(**user_data)
            logger.info(f"User created for {email}.")

            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)

            # Remove cached data
            cache.delete(cache_key)
            logger.info(f"Cleared cached data for {email}.")

            return Response({
                "message": "User created successfully.",
                "user": UserSerializer(user).data,
                "refresh": str(refresh),
                "access": str(refresh.access_token),
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            logger.error(f"Failed to verify OTP for {email}: {e}")
            return Response({"error": "Verification failed."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, IsManager]  # Add IsManager

class UpdateUserView(generics.UpdateAPIView):
    queryset = User.objects.all()
    serializer_class = UpdateUserSerializer
    permission_classes = [permissions.IsAuthenticated, IsManager]  # Restricted to managers

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()  # Retrieve the user instance

        # # Check if the request contains 'password'
        if 'password' in request.data:
            password = request.data.pop('password')
            instance.set_password(password)  # Hash the new password
            instance.save()  # Save the user instance

        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        return Response(serializer.data)

class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']

        try:
            user = User.objects.get(username=username)
            if not user.check_password(password):
                return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            return Response({
                "refresh": str(refresh),
                "access": str(refresh.access_token)
            }, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)