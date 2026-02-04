"""Serializers for user authentication and management."""

from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password

User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    """Serializer for user registration."""

    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password],
        style={'input_type': 'password'}
    )
    password_confirm = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )

    class Meta:
        model = User
        fields = ('email', 'password', 'password_confirm')

    def validate_email(self, value):
        """Check if email already exists (case-insensitive)."""
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("Email already registered")
        return value.lower()

    def validate(self, attrs):
        """Validate that passwords match."""
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({
                "password_confirm": "Passwords do not match"
            })
        return attrs

    def create(self, validated_data):
        """Create user with hashed password."""
        # Remove password_confirm as it's not part of the User model
        validated_data.pop('password_confirm')

        # Create user with hashed password using create_user method
        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user


class LoginSerializer(serializers.Serializer):
    """Serializer for user login."""

    email = serializers.EmailField(required=True)
    password = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'}
    )

    def validate_email(self, value):
        """Normalize email to lowercase."""
        return value.lower()


class PasswordResetRequestSerializer(serializers.Serializer):
    """Serializer for password reset request."""

    email = serializers.EmailField(required=True)

    def validate_email(self, value):
        """Normalize email to lowercase."""
        return value.lower()


class PasswordResetConfirmSerializer(serializers.Serializer):
    """Serializer for password reset confirmation."""

    token = serializers.UUIDField(required=True)
    password = serializers.CharField(
        required=True,
        write_only=True,
        validators=[validate_password],
        style={'input_type': 'password'}
    )
    password_confirm = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'}
    )

    def validate(self, attrs):
        """Validate that passwords match."""
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({
                "password_confirm": "Passwords do not match"
            })
        return attrs


class InvitationSendSerializer(serializers.Serializer):
    """Serializer for sending team invitations."""

    email = serializers.EmailField(required=True)

    def validate_email(self, value):
        """Normalize email and check for duplicate users."""
        email = value.lower()

        # Check if user already exists
        if User.objects.filter(email__iexact=email).exists():
            raise serializers.ValidationError("User with this email already exists")

        return email


class InvitationAcceptSerializer(serializers.Serializer):
    """Serializer for accepting invitation and creating account."""

    token = serializers.UUIDField(required=True)
    password = serializers.CharField(
        required=True,
        write_only=True,
        validators=[validate_password],
        style={'input_type': 'password'}
    )
    password_confirm = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'}
    )

    def validate(self, attrs):
        """Validate that passwords match."""
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({
                "password_confirm": "Passwords do not match"
            })
        return attrs


class UserListSerializer(serializers.ModelSerializer):
    """Serializer for listing users with roles."""
    role_display = serializers.CharField(source='role_display_name', read_only=True)

    class Meta:
        model = User
        fields = ('id', 'email', 'role', 'role_display', 'is_active')


class UserRoleUpdateSerializer(serializers.Serializer):
    """Serializer for updating user roles."""
    role = serializers.ChoiceField(choices=User.ROLE_CHOICES, required=True)

    def validate_role(self, value):
        """Validate role is one of the valid choices."""
        valid_roles = [choice[0] for choice in User.ROLE_CHOICES]
        if value not in valid_roles:
            raise serializers.ValidationError(
                f"Invalid role. Must be one of: {', '.join(valid_roles)}"
            )
        return value
