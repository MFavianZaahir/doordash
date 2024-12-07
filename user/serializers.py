from rest_framework import serializers
from user.models import User, FileUpload
from django.contrib.auth.hashers import check_password
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from .utils import random_hex
from django.core.mail import send_mail

def send_otp_email(email, otp):
    subject = "Your OTP for Account Verification"
    message = f"Your One-Time Password (OTP) is {otp}. Please use it to verify your account."
    send_mail(subject, message, 'your-email@gmail.com', [email])

def create(self, validated_data):
    otp = random_hex(8)
    email = validated_data.get("email")

    user = User.objects.create_user(**validated_data, is_active=False, otp_secret=otp)
    send_otp_email(email, otp)  # Send the OTP email

    return user


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'age', 'role', 'is_active', 'is_staff']

        def create(self, validated_data):
            user = User.objects.create(**validated_data)
            user.otp_secret = random_hex()  # Generate a secure OTP
            user.save()
            return user

class CreateUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'age', 'role', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            age=validated_data.get('age'),
            role=validated_data.get('role'),
        )

        # Assign OTP secret
        user.otp_secret = random_hex()
        user.save()

        # Generate JWT token
        refresh = RefreshToken.for_user(user)
        token_data = {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }

        return user, token_data


class UpdateUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'age', 'role', 'password']
        extra_kwargs = {
            'password': {'write_only': True, 'required': False},  # Optional for updates
        }

    def update(self, instance, validated_data):
        if 'password' in validated_data:
            # Hash the new password
            instance.set_password(validated_data.pop('password'))
        return super().update(instance, validated_data)

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

# class FileUploadSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = FileUpload
#         fields = ['id', 'user', 'file', 'uploaded_at']
#         read_only_fields =['uploaded_at']
        # extra_kwargs = {'file': {'write_only': True}}
