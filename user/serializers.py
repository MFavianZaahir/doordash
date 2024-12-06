from rest_framework import serializers
from user.models import User, FileUpload
from django.contrib.auth.hashers import check_password
from rest_framework_simplejwt.tokens import RefreshToken
# from .models import FileUpload

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'age', 'role', 'is_active', 'is_staff']

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
