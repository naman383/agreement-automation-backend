from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone
from datetime import timedelta
import uuid


class CustomUserManager(BaseUserManager):
    """Custom manager for email-based authentication."""

    def create_user(self, email, password=None, **extra_fields):
        """Create and return a regular user with an email and password."""
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """Create and return a superuser with an email and password."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    """Custom user model with email as the username field."""

    ROLE_CHOICES = [
        ('viewer', 'Viewer'),
        ('content_manager', 'Content Manager'),
        ('legal_reviewer', 'Legal Reviewer'),
        ('admin', 'Admin'),
    ]

    email = models.EmailField(unique=True, max_length=255)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='viewer')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    class Meta:
        db_table = 'users'
        verbose_name = 'User'
        verbose_name_plural = 'Users'

    def __str__(self):
        return self.email

    @property
    def is_admin(self):
        """Check if user is admin (role-based or staff)."""
        return self.role == 'admin' or self.is_staff

    @property
    def role_display_name(self):
        """Get human-readable role name."""
        return dict(self.ROLE_CHOICES).get(self.role, 'Unknown')


class PasswordResetToken(models.Model):
    """Model for password reset tokens."""
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='reset_tokens')
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'password_reset_tokens'
        ordering = ['-created_at']

    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(hours=1)
        super().save(*args, **kwargs)

    def is_valid(self):
        """Check if token is valid (not expired and not used)."""
        return (
            self.used_at is None and
            timezone.now() < self.expires_at
        )

    def mark_as_used(self):
        """Mark token as used."""
        self.used_at = timezone.now()
        self.save()


class Invitation(models.Model):
    """Model for team member invitations."""

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('expired', 'Expired'),
    ]

    invited_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='sent_invitations')
    email = models.EmailField(max_length=255)
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    accepted_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')

    class Meta:
        db_table = 'invitations'
        ordering = ['-created_at']

    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(days=7)
        super().save(*args, **kwargs)

    def is_valid(self):
        """Check if invitation is valid (not expired and not accepted)."""
        return (
            self.status == 'pending' and
            timezone.now() < self.expires_at
        )

    def mark_as_accepted(self):
        """Mark invitation as accepted."""
        self.accepted_at = timezone.now()
        self.status = 'accepted'
        self.save()
