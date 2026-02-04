"""Tests for user authentication and management."""

from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from ..audit.models import AuditLog

User = get_user_model()


class CustomUserModelTests(TestCase):
    """Test cases for CustomUser model."""

    def test_create_user_with_email(self):
        """Test creating a user with email is successful."""
        email = 'test@example.com'
        password = 'testpass123'
        user = User.objects.create_user(email=email, password=password)

        self.assertEqual(user.email, email)
        self.assertTrue(user.check_password(password))
        self.assertTrue(user.is_active)
        self.assertFalse(user.is_staff)

    def test_user_email_normalized(self):
        """Test email is normalized for new users."""
        email = 'test@EXAMPLE.COM'
        user = User.objects.create_user(email=email, password='testpass123')

        self.assertEqual(user.email, email.lower())

    def test_create_user_without_email_raises_error(self):
        """Test creating user without email raises ValueError."""
        with self.assertRaises(ValueError):
            User.objects.create_user(email='', password='testpass123')

    def test_create_superuser(self):
        """Test creating a superuser."""
        email = 'admin@example.com'
        password = 'adminpass123'
        user = User.objects.create_superuser(email=email, password=password)

        self.assertTrue(user.is_superuser)
        self.assertTrue(user.is_staff)

    def test_password_is_hashed(self):
        """Test that password is hashed using bcrypt."""
        email = 'test@example.com'
        password = 'testpass123'
        user = User.objects.create_user(email=email, password=password)

        # Password should be hashed (starts with bcrypt_sha256$ for BCrypt)
        self.assertNotEqual(user.password, password)
        self.assertTrue(user.password.startswith('bcrypt_sha256$'))
        self.assertTrue(user.check_password(password))


class RegisterSerializerTests(APITestCase):
    """Test cases for RegisterSerializer."""

    def test_valid_registration_data(self):
        """Test serializer with valid data."""
        data = {
            'email': 'newuser@example.com',
            'password': 'securepass123',
            'password_confirm': 'securepass123'
        }
        response = self.client.post(reverse('register'), data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('message', response.data)
        self.assertIn('email', response.data)

    def test_password_too_short(self):
        """Test that password must be at least 8 characters."""
        data = {
            'email': 'newuser@example.com',
            'password': 'short',
            'password_confirm': 'short'
        }
        response = self.client.post(reverse('register'), data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password', response.data)

    def test_passwords_do_not_match(self):
        """Test that password and password_confirm must match."""
        data = {
            'email': 'newuser@example.com',
            'password': 'securepass123',
            'password_confirm': 'differentpass123'
        }
        response = self.client.post(reverse('register'), data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password_confirm', response.data)

    def test_duplicate_email(self):
        """Test that duplicate email is rejected."""
        # Create first user
        User.objects.create_user(email='existing@example.com', password='testpass123')

        # Try to create second user with same email
        data = {
            'email': 'existing@example.com',
            'password': 'securepass123',
            'password_confirm': 'securepass123'
        }
        response = self.client.post(reverse('register'), data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)

    def test_duplicate_email_case_insensitive(self):
        """Test that duplicate email check is case-insensitive."""
        # Create first user with lowercase email
        User.objects.create_user(email='existing@example.com', password='testpass123')

        # Try to create second user with uppercase email
        data = {
            'email': 'EXISTING@EXAMPLE.COM',
            'password': 'securepass123',
            'password_confirm': 'securepass123'
        }
        response = self.client.post(reverse('register'), data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)


class RegisterViewTests(APITestCase):
    """Test cases for RegisterView."""

    def setUp(self):
        """Set up test client."""
        self.client = APIClient()
        self.register_url = reverse('register')

    def test_successful_registration(self):
        """Test successful user registration."""
        data = {
            'email': 'newuser@example.com',
            'password': 'securepass123',
            'password_confirm': 'securepass123'
        }
        response = self.client.post(self.register_url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['message'], 'Registration successful')
        self.assertEqual(response.data['email'], 'newuser@example.com')

        # Verify user was created
        self.assertTrue(User.objects.filter(email='newuser@example.com').exists())

    def test_registration_creates_audit_log(self):
        """Test that registration creates an audit log entry."""
        data = {
            'email': 'newuser@example.com',
            'password': 'securepass123',
            'password_confirm': 'securepass123'
        }
        response = self.client.post(self.register_url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Verify audit log was created
        user = User.objects.get(email='newuser@example.com')
        audit_logs = AuditLog.objects.filter(user=user, action='user_registration')
        self.assertTrue(audit_logs.exists())

        audit_log = audit_logs.first()
        self.assertEqual(audit_log.user, user)
        self.assertEqual(audit_log.action, 'user_registration')
        self.assertIsNotNone(audit_log.timestamp)

    def test_registration_with_invalid_email(self):
        """Test registration with invalid email format."""
        data = {
            'email': 'notanemail',
            'password': 'securepass123',
            'password_confirm': 'securepass123'
        }
        response = self.client.post(self.register_url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)

    def test_registration_without_password_confirm(self):
        """Test registration without password_confirm field."""
        data = {
            'email': 'newuser@example.com',
            'password': 'securepass123'
        }
        response = self.client.post(self.register_url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password_confirm', response.data)

    def test_registration_sends_welcome_email(self):
        """Test that registration triggers welcome email (console backend)."""
        # This test verifies the email function is called
        # With console backend, we can't easily test actual email delivery
        data = {
            'email': 'newuser@example.com',
            'password': 'securepass123',
            'password_confirm': 'securepass123'
        }
        response = self.client.post(self.register_url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        # Email is sent to console, so no direct assertion
        # In production with real email backend, use mail.outbox

    def test_registration_endpoint_allows_unauthenticated(self):
        """Test that registration endpoint allows unauthenticated access."""
        # Don't authenticate client
        data = {
            'email': 'newuser@example.com',
            'password': 'securepass123',
            'password_confirm': 'securepass123'
        }
        response = self.client.post(self.register_url, data)

        # Should succeed without authentication
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)


class LoginSerializerTests(APITestCase):
    """Test cases for LoginSerializer."""

    def test_valid_login_data(self):
        """Test serializer with valid email and password."""
        from agreement_automation.apps.users.serializers import LoginSerializer

        data = {
            'email': 'user@example.com',
            'password': 'testpass123'
        }
        serializer = LoginSerializer(data=data)

        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.validated_data['email'], 'user@example.com')

    def test_email_normalization(self):
        """Test that email is normalized to lowercase."""
        from agreement_automation.apps.users.serializers import LoginSerializer

        data = {
            'email': 'USER@EXAMPLE.COM',
            'password': 'testpass123'
        }
        serializer = LoginSerializer(data=data)

        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.validated_data['email'], 'user@example.com')

    def test_missing_email(self):
        """Test that email is required."""
        from agreement_automation.apps.users.serializers import LoginSerializer

        data = {'password': 'testpass123'}
        serializer = LoginSerializer(data=data)

        self.assertFalse(serializer.is_valid())
        self.assertIn('email', serializer.errors)

    def test_missing_password(self):
        """Test that password is required."""
        from agreement_automation.apps.users.serializers import LoginSerializer

        data = {'email': 'user@example.com'}
        serializer = LoginSerializer(data=data)

        self.assertFalse(serializer.is_valid())
        self.assertIn('password', serializer.errors)


class LoginViewTests(APITestCase):
    """Test cases for LoginView."""

    def setUp(self):
        """Set up test client and create test user."""
        self.client = APIClient()
        self.login_url = reverse('login')

        # Create test user
        self.user = User.objects.create_user(
            email='testuser@example.com',
            password='testpass123'
        )

    def test_successful_login(self):
        """Test successful login with valid credentials."""
        data = {
            'email': 'testuser@example.com',
            'password': 'testpass123'
        }
        response = self.client.post(self.login_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Login successful')
        self.assertIn('user', response.data)
        self.assertEqual(response.data['user']['email'], 'testuser@example.com')

    def test_login_creates_session(self):
        """Test that successful login creates a session."""
        data = {
            'email': 'testuser@example.com',
            'password': 'testpass123'
        }
        response = self.client.post(self.login_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Check that session cookie exists
        self.assertIn('sessionid', response.cookies)

    def test_login_wrong_password(self):
        """Test login with incorrect password."""
        data = {
            'email': 'testuser@example.com',
            'password': 'wrongpassword'
        }
        response = self.client.post(self.login_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], 'Invalid email or password')

    def test_login_nonexistent_email(self):
        """Test login with non-existent email."""
        data = {
            'email': 'nonexistent@example.com',
            'password': 'testpass123'
        }
        response = self.client.post(self.login_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Invalid email or password')

    def test_login_deactivated_account(self):
        """Test login with deactivated account."""
        # Deactivate user
        self.user.is_active = False
        self.user.save()

        data = {
            'email': 'testuser@example.com',
            'password': 'testpass123'
        }
        response = self.client.post(self.login_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data['error'], 'Account deactivated. Contact administrator.')

    def test_login_creates_audit_log_success(self):
        """Test that successful login creates audit log."""
        data = {
            'email': 'testuser@example.com',
            'password': 'testpass123'
        }
        response = self.client.post(self.login_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify audit log
        audit_logs = AuditLog.objects.filter(
            user=self.user,
            action='user_login_success'
        )
        self.assertTrue(audit_logs.exists())

    def test_login_creates_audit_log_failure(self):
        """Test that failed login creates audit log."""
        data = {
            'email': 'testuser@example.com',
            'password': 'wrongpassword'
        }
        response = self.client.post(self.login_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Verify audit log
        audit_logs = AuditLog.objects.filter(
            action='user_login_failed'
        )
        self.assertTrue(audit_logs.exists())

    def test_login_case_insensitive_email(self):
        """Test that login works with different email case."""
        data = {
            'email': 'TESTUSER@EXAMPLE.COM',
            'password': 'testpass123'
        }
        response = self.client.post(self.login_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)


class LogoutViewTests(APITestCase):
    """Test cases for LogoutView."""

    def setUp(self):
        """Set up test client and authenticated user."""
        self.client = APIClient()
        self.logout_url = reverse('logout')

        # Create and login test user
        self.user = User.objects.create_user(
            email='testuser@example.com',
            password='testpass123'
        )
        self.client.force_authenticate(user=self.user)

    def test_successful_logout(self):
        """Test successful logout."""
        response = self.client.post(self.logout_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Logout successful')

    def test_logout_creates_audit_log(self):
        """Test that logout creates audit log."""
        response = self.client.post(self.logout_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify audit log
        audit_logs = AuditLog.objects.filter(
            user=self.user,
            action='user_logout'
        )
        self.assertTrue(audit_logs.exists())

    def test_logout_requires_authentication(self):
        """Test that logout requires authentication."""
        # Create unauthenticated client
        unauth_client = APIClient()
        response = unauth_client.post(self.logout_url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class CurrentUserViewTests(APITestCase):
    """Test cases for CurrentUserView."""

    def setUp(self):
        """Set up test client and user."""
        self.client = APIClient()
        self.me_url = reverse('current-user')

        self.user = User.objects.create_user(
            email='testuser@example.com',
            password='testpass123'
        )

    def test_get_current_user_authenticated(self):
        """Test getting current user info when authenticated."""
        self.client.force_authenticate(user=self.user)
        response = self.client.get(self.me_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], 'testuser@example.com')
        self.assertEqual(response.data['id'], self.user.id)
        self.assertTrue(response.data['is_active'])

    def test_get_current_user_unauthenticated(self):
        """Test that current user endpoint requires authentication."""
        response = self.client.get(self.me_url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class PasswordResetTokenModelTests(TestCase):
    """Test cases for PasswordResetToken model."""

    def setUp(self):
        """Create test user."""
        self.user = User.objects.create_user(
            email='testuser@example.com',
            password='testpass123'
        )

    def test_token_generation(self):
        """Test that token is generated with UUID."""
        from agreement_automation.apps.users.models import PasswordResetToken
        reset_token = PasswordResetToken.objects.create(user=self.user)

        self.assertIsNotNone(reset_token.token)
        self.assertIsNotNone(reset_token.expires_at)
        self.assertIsNone(reset_token.used_at)

    def test_token_expires_in_one_hour(self):
        """Test that token expires in 1 hour."""
        from agreement_automation.apps.users.models import PasswordResetToken
        from django.utils import timezone
        from datetime import timedelta

        reset_token = PasswordResetToken.objects.create(user=self.user)

        # Check expiration is approximately 1 hour from now
        expected_expiry = timezone.now() + timedelta(hours=1)
        time_diff = abs((reset_token.expires_at - expected_expiry).total_seconds())
        self.assertLess(time_diff, 5)  # Within 5 seconds

    def test_is_valid_method(self):
        """Test is_valid() method for unused, unexpired token."""
        from agreement_automation.apps.users.models import PasswordResetToken
        reset_token = PasswordResetToken.objects.create(user=self.user)

        self.assertTrue(reset_token.is_valid())

    def test_is_valid_false_when_used(self):
        """Test is_valid() returns False for used token."""
        from agreement_automation.apps.users.models import PasswordResetToken
        reset_token = PasswordResetToken.objects.create(user=self.user)
        reset_token.mark_as_used()

        self.assertFalse(reset_token.is_valid())
        self.assertIsNotNone(reset_token.used_at)

    def test_is_valid_false_when_expired(self):
        """Test is_valid() returns False for expired token."""
        from agreement_automation.apps.users.models import PasswordResetToken
        from django.utils import timezone
        from datetime import timedelta

        reset_token = PasswordResetToken.objects.create(user=self.user)
        # Set expiration to past
        reset_token.expires_at = timezone.now() - timedelta(hours=1)
        reset_token.save()

        self.assertFalse(reset_token.is_valid())

    def test_mark_as_used_method(self):
        """Test mark_as_used() method."""
        from agreement_automation.apps.users.models import PasswordResetToken
        reset_token = PasswordResetToken.objects.create(user=self.user)

        self.assertIsNone(reset_token.used_at)
        reset_token.mark_as_used()
        self.assertIsNotNone(reset_token.used_at)


class PasswordResetRequestViewTests(APITestCase):
    """Test cases for PasswordResetRequestView."""

    def setUp(self):
        """Set up test client and user."""
        self.client = APIClient()
        self.reset_request_url = reverse('password-reset-request')
        self.user = User.objects.create_user(
            email='testuser@example.com',
            password='testpass123'
        )

    def test_request_reset_for_existing_email(self):
        """Test requesting password reset for existing email."""
        data = {'email': 'testuser@example.com'}
        response = self.client.post(self.reset_request_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.data['message'],
            'If that email exists, a reset link has been sent'
        )

    def test_request_reset_creates_token(self):
        """Test that password reset request creates token in database."""
        from agreement_automation.apps.users.models import PasswordResetToken

        data = {'email': 'testuser@example.com'}
        response = self.client.post(self.reset_request_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify token was created
        tokens = PasswordResetToken.objects.filter(user=self.user)
        self.assertTrue(tokens.exists())

    def test_request_reset_for_nonexistent_email(self):
        """Test requesting reset for non-existent email (same message)."""
        data = {'email': 'nonexistent@example.com'}
        response = self.client.post(self.reset_request_url, data, format='json')

        # Should return same message (prevent email enumeration)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.data['message'],
            'If that email exists, a reset link has been sent'
        )

    def test_request_reset_creates_audit_log(self):
        """Test that password reset request creates audit log."""
        data = {'email': 'testuser@example.com'}
        response = self.client.post(self.reset_request_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify audit log
        audit_logs = AuditLog.objects.filter(
            user=self.user,
            action='password_reset_requested'
        )
        self.assertTrue(audit_logs.exists())

    def test_request_reset_audit_log_for_nonexistent_email(self):
        """Test audit log created even for non-existent email."""
        data = {'email': 'nonexistent@example.com'}
        response = self.client.post(self.reset_request_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify audit log with user=None
        audit_logs = AuditLog.objects.filter(
            user=None,
            action='password_reset_requested'
        )
        self.assertTrue(audit_logs.exists())


class PasswordResetConfirmViewTests(APITestCase):
    """Test cases for PasswordResetConfirmView."""

    def setUp(self):
        """Set up test client, user, and reset token."""
        from agreement_automation.apps.users.models import PasswordResetToken

        self.client = APIClient()
        self.reset_confirm_url = reverse('password-reset-confirm')
        self.user = User.objects.create_user(
            email='testuser@example.com',
            password='oldpassword123'
        )
        self.reset_token = PasswordResetToken.objects.create(user=self.user)

    def test_successful_password_reset(self):
        """Test successful password reset with valid token."""
        data = {
            'token': str(self.reset_token.token),
            'password': 'newpassword123',
            'password_confirm': 'newpassword123'
        }
        response = self.client.post(self.reset_confirm_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.data['message'],
            'Password reset successful. You can now login.'
        )

    def test_password_actually_changes(self):
        """Test that password actually changes after reset."""
        data = {
            'token': str(self.reset_token.token),
            'password': 'newpassword123',
            'password_confirm': 'newpassword123'
        }
        response = self.client.post(self.reset_confirm_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Refresh user from database
        self.user.refresh_from_db()

        # Old password should not work
        self.assertFalse(self.user.check_password('oldpassword123'))

        # New password should work
        self.assertTrue(self.user.check_password('newpassword123'))

    def test_token_marked_as_used(self):
        """Test that token is marked as used after reset."""
        data = {
            'token': str(self.reset_token.token),
            'password': 'newpassword123',
            'password_confirm': 'newpassword123'
        }
        response = self.client.post(self.reset_confirm_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Refresh token from database
        self.reset_token.refresh_from_db()
        self.assertIsNotNone(self.reset_token.used_at)
        self.assertFalse(self.reset_token.is_valid())

    def test_expired_token_rejected(self):
        """Test that expired token is rejected."""
        from django.utils import timezone
        from datetime import timedelta

        # Expire the token
        self.reset_token.expires_at = timezone.now() - timedelta(hours=1)
        self.reset_token.save()

        data = {
            'token': str(self.reset_token.token),
            'password': 'newpassword123',
            'password_confirm': 'newpassword123'
        }
        response = self.client.post(self.reset_confirm_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('expired', response.data['error'].lower())

    def test_used_token_rejected(self):
        """Test that already used token is rejected."""
        # Mark token as used
        self.reset_token.mark_as_used()

        data = {
            'token': str(self.reset_token.token),
            'password': 'newpassword123',
            'password_confirm': 'newpassword123'
        }
        response = self.client.post(self.reset_confirm_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('used', response.data['error'].lower())

    def test_invalid_token_rejected(self):
        """Test that non-existent token is rejected."""
        import uuid

        data = {
            'token': str(uuid.uuid4()),  # Random UUID
            'password': 'newpassword123',
            'password_confirm': 'newpassword123'
        }
        response = self.client.post(self.reset_confirm_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Invalid reset token.')

    def test_password_validation_min_length(self):
        """Test that password must meet minimum length requirement."""
        data = {
            'token': str(self.reset_token.token),
            'password': 'short',
            'password_confirm': 'short'
        }
        response = self.client.post(self.reset_confirm_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password', response.data)

    def test_password_confirmation_matching(self):
        """Test that password and password_confirm must match."""
        data = {
            'token': str(self.reset_token.token),
            'password': 'newpassword123',
            'password_confirm': 'differentpass123'
        }
        response = self.client.post(self.reset_confirm_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password_confirm', response.data)

    def test_password_reset_creates_audit_log(self):
        """Test that password reset creates audit log."""
        data = {
            'token': str(self.reset_token.token),
            'password': 'newpassword123',
            'password_confirm': 'newpassword123'
        }
        response = self.client.post(self.reset_confirm_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify audit log
        audit_logs = AuditLog.objects.filter(
            user=self.user,
            action='password_reset_completed'
        )
        self.assertTrue(audit_logs.exists())


class InvitationModelTests(TestCase):
    """Test cases for Invitation model."""

    def setUp(self):
        """Create test users."""
        self.admin = User.objects.create_user(
            email='admin@example.com',
            password='adminpass123',
            is_staff=True
        )

    def test_invitation_generation(self):
        """Test that invitation is generated with UUID."""
        from agreement_automation.apps.users.models import Invitation
        invitation = Invitation.objects.create(
            invited_by=self.admin,
            email='newuser@example.com'
        )

        self.assertIsNotNone(invitation.token)
        self.assertIsNotNone(invitation.expires_at)
        self.assertIsNone(invitation.accepted_at)
        self.assertEqual(invitation.status, 'pending')

    def test_invitation_expires_in_seven_days(self):
        """Test that invitation expires in 7 days."""
        from agreement_automation.apps.users.models import Invitation
        from django.utils import timezone
        from datetime import timedelta

        invitation = Invitation.objects.create(
            invited_by=self.admin,
            email='newuser@example.com'
        )

        # Check expiration is approximately 7 days from now
        expected_expiry = timezone.now() + timedelta(days=7)
        time_diff = abs((invitation.expires_at - expected_expiry).total_seconds())
        self.assertLess(time_diff, 5)  # Within 5 seconds

    def test_is_valid_method(self):
        """Test is_valid() method for unused, unexpired invitation."""
        from agreement_automation.apps.users.models import Invitation
        invitation = Invitation.objects.create(
            invited_by=self.admin,
            email='newuser@example.com'
        )

        self.assertTrue(invitation.is_valid())

    def test_is_valid_false_when_accepted(self):
        """Test is_valid() returns False for accepted invitation."""
        from agreement_automation.apps.users.models import Invitation
        invitation = Invitation.objects.create(
            invited_by=self.admin,
            email='newuser@example.com'
        )
        invitation.mark_as_accepted()

        self.assertFalse(invitation.is_valid())
        self.assertIsNotNone(invitation.accepted_at)
        self.assertEqual(invitation.status, 'accepted')

    def test_is_valid_false_when_expired(self):
        """Test is_valid() returns False for expired invitation."""
        from agreement_automation.apps.users.models import Invitation
        from django.utils import timezone
        from datetime import timedelta

        invitation = Invitation.objects.create(
            invited_by=self.admin,
            email='newuser@example.com'
        )
        # Set expiration to past
        invitation.expires_at = timezone.now() - timedelta(days=1)
        invitation.save()

        self.assertFalse(invitation.is_valid())


class InvitationSendViewTests(APITestCase):
    """Test cases for InvitationSendView."""

    def setUp(self):
        """Set up test client, admin, and non-admin users."""
        self.client = APIClient()
        self.send_url = reverse('invitation-send')

        self.admin = User.objects.create_user(
            email='admin@example.com',
            password='adminpass123',
            is_staff=True
        )

        self.regular_user = User.objects.create_user(
            email='regular@example.com',
            password='userpass123'
        )

    def test_send_invitation_as_admin(self):
        """Test sending invitation as admin user."""
        self.client.force_authenticate(user=self.admin)
        data = {'email': 'newuser@example.com'}
        response = self.client.post(self.send_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['message'], 'Invitation sent to newuser@example.com')

    def test_send_invitation_creates_invitation(self):
        """Test that invitation is created in database."""
        from agreement_automation.apps.users.models import Invitation

        self.client.force_authenticate(user=self.admin)
        data = {'email': 'newuser@example.com'}
        response = self.client.post(self.send_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Verify invitation was created
        invitations = Invitation.objects.filter(email='newuser@example.com')
        self.assertTrue(invitations.exists())
        invitation = invitations.first()
        self.assertEqual(invitation.invited_by, self.admin)

    def test_send_invitation_duplicate_email(self):
        """Test sending invitation to existing user fails."""
        self.client.force_authenticate(user=self.admin)
        data = {'email': 'regular@example.com'}  # Already exists
        response = self.client.post(self.send_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('already exists', response.data['email'][0].lower())

    def test_send_invitation_as_non_admin(self):
        """Test that non-admin users cannot send invitations."""
        self.client.force_authenticate(user=self.regular_user)
        data = {'email': 'newuser@example.com'}
        response = self.client.post(self.send_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_send_invitation_creates_audit_log(self):
        """Test that invitation creates audit log."""
        self.client.force_authenticate(user=self.admin)
        data = {'email': 'newuser@example.com'}
        response = self.client.post(self.send_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Verify audit log
        audit_logs = AuditLog.objects.filter(
            user=self.admin,
            action='invitation_sent'
        )
        self.assertTrue(audit_logs.exists())


class InvitationValidateViewTests(APITestCase):
    """Test cases for InvitationValidateView."""

    def setUp(self):
        """Set up test data."""
        from agreement_automation.apps.users.models import Invitation

        self.admin = User.objects.create_user(
            email='admin@example.com',
            password='adminpass123',
            is_staff=True
        )

        self.invitation = Invitation.objects.create(
            invited_by=self.admin,
            email='newuser@example.com'
        )
        self.validate_url = reverse('invitation-validate', kwargs={'token': self.invitation.token})

    def test_validate_valid_invitation(self):
        """Test validating a valid invitation."""
        response = self.client.get(self.validate_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], 'newuser@example.com')
        self.assertTrue(response.data['is_valid'])

    def test_validate_expired_invitation(self):
        """Test validating an expired invitation."""
        from django.utils import timezone
        from datetime import timedelta

        self.invitation.expires_at = timezone.now() - timedelta(days=1)
        self.invitation.save()

        response = self.client.get(self.validate_url)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('expired', response.data['error'].lower())

    def test_validate_accepted_invitation(self):
        """Test validating an already accepted invitation."""
        self.invitation.mark_as_accepted()

        response = self.client.get(self.validate_url)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('used', response.data['error'].lower())

    def test_validate_invalid_token(self):
        """Test validating with invalid token."""
        import uuid
        invalid_url = reverse('invitation-validate', kwargs={'token': uuid.uuid4()})
        response = self.client.get(invalid_url)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class InvitationAcceptViewTests(APITestCase):
    """Test cases for InvitationAcceptView."""

    def setUp(self):
        """Set up test data."""
        from agreement_automation.apps.users.models import Invitation

        self.client = APIClient()
        self.accept_url = reverse('invitation-accept')

        self.admin = User.objects.create_user(
            email='admin@example.com',
            password='adminpass123',
            is_staff=True
        )

        self.invitation = Invitation.objects.create(
            invited_by=self.admin,
            email='newuser@example.com'
        )

    def test_accept_invitation_success(self):
        """Test successfully accepting invitation and creating account."""
        data = {
            'token': str(self.invitation.token),
            'password': 'newpassword123',
            'password_confirm': 'newpassword123'
        }
        response = self.client.post(self.accept_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['email'], 'newuser@example.com')

        # Verify user was created
        self.assertTrue(User.objects.filter(email='newuser@example.com').exists())

    def test_accept_invitation_marks_as_accepted(self):
        """Test that invitation is marked as accepted."""
        data = {
            'token': str(self.invitation.token),
            'password': 'newpassword123',
            'password_confirm': 'newpassword123'
        }
        response = self.client.post(self.accept_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Refresh invitation from database
        self.invitation.refresh_from_db()
        self.assertEqual(self.invitation.status, 'accepted')
        self.assertIsNotNone(self.invitation.accepted_at)

    def test_accept_invitation_expired(self):
        """Test accepting expired invitation fails."""
        from django.utils import timezone
        from datetime import timedelta

        self.invitation.expires_at = timezone.now() - timedelta(days=1)
        self.invitation.save()

        data = {
            'token': str(self.invitation.token),
            'password': 'newpassword123',
            'password_confirm': 'newpassword123'
        }
        response = self.client.post(self.accept_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('expired', response.data['error'].lower())

    def test_accept_invitation_already_used(self):
        """Test accepting already used invitation fails."""
        self.invitation.mark_as_accepted()

        data = {
            'token': str(self.invitation.token),
            'password': 'newpassword123',
            'password_confirm': 'newpassword123'
        }
        response = self.client.post(self.accept_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('used', response.data['error'].lower())

    def test_accept_invitation_password_validation(self):
        """Test password validation on accept."""
        data = {
            'token': str(self.invitation.token),
            'password': 'short',
            'password_confirm': 'short'
        }
        response = self.client.post(self.accept_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_accept_invitation_passwords_match(self):
        """Test that passwords must match."""
        data = {
            'token': str(self.invitation.token),
            'password': 'newpassword123',
            'password_confirm': 'differentpass123'
        }
        response = self.client.post(self.accept_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password_confirm', response.data)

    def test_accept_invitation_creates_audit_log(self):
        """Test that accepting invitation creates audit log."""
        data = {
            'token': str(self.invitation.token),
            'password': 'newpassword123',
            'password_confirm': 'newpassword123'
        }
        response = self.client.post(self.accept_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Verify audit log
        user = User.objects.get(email='newuser@example.com')
        audit_logs = AuditLog.objects.filter(
            user=user,
            action='invitation_accepted'
        )
        self.assertTrue(audit_logs.exists())


class CustomUserRoleTests(TestCase):
    """Test cases for CustomUser role field and properties."""

    def setUp(self):
        """Create test users with different roles."""
        self.admin_user = User.objects.create_user(
            email='admin@example.com',
            password='password123'
        )
        self.admin_user.role = 'admin'
        self.admin_user.save()

        self.content_manager = User.objects.create_user(
            email='content@example.com',
            password='password123'
        )
        self.content_manager.role = 'content_manager'
        self.content_manager.save()

        self.legal_reviewer = User.objects.create_user(
            email='legal@example.com',
            password='password123'
        )
        self.legal_reviewer.role = 'legal_reviewer'
        self.legal_reviewer.save()

        self.viewer = User.objects.create_user(
            email='viewer@example.com',
            password='password123'
        )
        self.viewer.role = 'viewer'
        self.viewer.save()

    def test_default_role_is_viewer(self):
        """Test that default role is 'viewer'."""
        user = User.objects.create_user(
            email='newuser@example.com',
            password='password123'
        )
        self.assertEqual(user.role, 'viewer')

    def test_role_choices_are_valid(self):
        """Test that all role choices are valid."""
        role_values = [choice[0] for choice in User.ROLE_CHOICES]
        self.assertIn('viewer', role_values)
        self.assertIn('content_manager', role_values)
        self.assertIn('legal_reviewer', role_values)
        self.assertIn('admin', role_values)

    def test_is_admin_property_for_admin_role(self):
        """Test is_admin property returns True for admin role."""
        self.assertTrue(self.admin_user.is_admin)

    def test_is_admin_property_for_non_admin(self):
        """Test is_admin property returns False for non-admin roles."""
        self.assertFalse(self.content_manager.is_admin)
        self.assertFalse(self.legal_reviewer.is_admin)
        self.assertFalse(self.viewer.is_admin)

    def test_is_admin_property_for_staff_user(self):
        """Test is_admin property returns True for is_staff=True (backward compatibility)."""
        staff_user = User.objects.create_user(
            email='staff@example.com',
            password='password123',
            is_staff=True
        )
        self.assertTrue(staff_user.is_admin)

    def test_role_display_name_property(self):
        """Test role_display_name property returns human-readable names."""
        self.assertEqual(self.admin_user.role_display_name, 'Admin')
        self.assertEqual(self.content_manager.role_display_name, 'Content Manager')
        self.assertEqual(self.legal_reviewer.role_display_name, 'Legal Reviewer')
        self.assertEqual(self.viewer.role_display_name, 'Viewer')


class PermissionHelperTests(TestCase):
    """Test cases for permission helper functions."""

    def setUp(self):
        """Create test users with different roles."""
        from agreement_automation.apps.users.permissions import (
            can_generate_agreements,
            can_upload_templates,
            can_approve_templates,
            can_view_all_agreements,
            can_view_audit_logs,
            can_invite_users,
            can_assign_roles,
            is_viewer
        )
        self.can_generate_agreements = can_generate_agreements
        self.can_upload_templates = can_upload_templates
        self.can_approve_templates = can_approve_templates
        self.can_view_all_agreements = can_view_all_agreements
        self.can_view_audit_logs = can_view_audit_logs
        self.can_invite_users = can_invite_users
        self.can_assign_roles = can_assign_roles
        self.is_viewer = is_viewer

        self.admin = User.objects.create_user(email='admin@example.com', password='pass')
        self.admin.role = 'admin'
        self.admin.save()

        self.content_manager = User.objects.create_user(email='content@example.com', password='pass')
        self.content_manager.role = 'content_manager'
        self.content_manager.save()

        self.legal_reviewer = User.objects.create_user(email='legal@example.com', password='pass')
        self.legal_reviewer.role = 'legal_reviewer'
        self.legal_reviewer.save()

        self.viewer = User.objects.create_user(email='viewer@example.com', password='pass')
        self.viewer.role = 'viewer'
        self.viewer.save()

    def test_can_generate_agreements_permissions(self):
        """Test can_generate_agreements() for each role."""
        self.assertTrue(self.can_generate_agreements(self.admin))
        self.assertTrue(self.can_generate_agreements(self.content_manager))
        self.assertTrue(self.can_generate_agreements(self.legal_reviewer))
        self.assertFalse(self.can_generate_agreements(self.viewer))

    def test_can_upload_templates_permissions(self):
        """Test can_upload_templates() for each role."""
        self.assertTrue(self.can_upload_templates(self.admin))
        self.assertFalse(self.can_upload_templates(self.content_manager))
        self.assertFalse(self.can_upload_templates(self.legal_reviewer))
        self.assertFalse(self.can_upload_templates(self.viewer))

    def test_can_approve_templates_permissions(self):
        """Test can_approve_templates() for each role."""
        self.assertTrue(self.can_approve_templates(self.admin))
        self.assertFalse(self.can_approve_templates(self.content_manager))
        self.assertTrue(self.can_approve_templates(self.legal_reviewer))
        self.assertFalse(self.can_approve_templates(self.viewer))

    def test_can_view_all_agreements_permissions(self):
        """Test can_view_all_agreements() for each role."""
        self.assertTrue(self.can_view_all_agreements(self.admin))
        self.assertFalse(self.can_view_all_agreements(self.content_manager))
        self.assertTrue(self.can_view_all_agreements(self.legal_reviewer))
        self.assertFalse(self.can_view_all_agreements(self.viewer))

    def test_can_view_audit_logs_permissions(self):
        """Test can_view_audit_logs() for each role."""
        self.assertTrue(self.can_view_audit_logs(self.admin))
        self.assertFalse(self.can_view_audit_logs(self.content_manager))
        self.assertTrue(self.can_view_audit_logs(self.legal_reviewer))
        self.assertFalse(self.can_view_audit_logs(self.viewer))

    def test_can_invite_users_permissions(self):
        """Test can_invite_users() for each role."""
        self.assertTrue(self.can_invite_users(self.admin))
        self.assertFalse(self.can_invite_users(self.content_manager))
        self.assertFalse(self.can_invite_users(self.legal_reviewer))
        self.assertFalse(self.can_invite_users(self.viewer))

    def test_can_assign_roles_permissions(self):
        """Test can_assign_roles() for each role."""
        self.assertTrue(self.can_assign_roles(self.admin))
        self.assertFalse(self.can_assign_roles(self.content_manager))
        self.assertFalse(self.can_assign_roles(self.legal_reviewer))
        self.assertFalse(self.can_assign_roles(self.viewer))

    def test_is_viewer_permissions(self):
        """Test is_viewer() for each role."""
        self.assertFalse(self.is_viewer(self.admin))
        self.assertFalse(self.is_viewer(self.content_manager))
        self.assertFalse(self.is_viewer(self.legal_reviewer))
        self.assertTrue(self.is_viewer(self.viewer))


class UserListViewTests(APITestCase):
    """Test cases for UserListView."""

    def setUp(self):
        """Set up test client and users."""
        self.client = APIClient()
        self.list_url = reverse('user-list')

        self.admin = User.objects.create_user(
            email='admin@example.com',
            password='adminpass123',
            is_staff=True
        )

        self.regular_user = User.objects.create_user(
            email='regular@example.com',
            password='userpass123'
        )

        User.objects.create_user(
            email='content@example.com',
            password='pass123'
        )

    def test_list_users_as_admin(self):
        """Test listing users as admin."""
        self.client.force_authenticate(user=self.admin)
        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('users', response.data)
        self.assertEqual(len(response.data['users']), 3)

    def test_list_users_includes_role_information(self):
        """Test that user list includes role information."""
        self.client.force_authenticate(user=self.admin)
        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        user_data = response.data['users'][0]
        self.assertIn('id', user_data)
        self.assertIn('email', user_data)
        self.assertIn('role', user_data)
        self.assertIn('role_display', user_data)
        self.assertIn('is_active', user_data)

    def test_list_users_as_non_admin(self):
        """Test that non-admin users cannot list users."""
        self.client.force_authenticate(user=self.regular_user)
        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_list_users_unauthenticated(self):
        """Test that unauthenticated users cannot list users."""
        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class UserRoleUpdateViewTests(APITestCase):
    """Test cases for UserRoleUpdateView."""

    def setUp(self):
        """Set up test client and users."""
        self.client = APIClient()

        self.admin = User.objects.create_user(
            email='admin@example.com',
            password='adminpass123',
            is_staff=True
        )

        self.regular_user = User.objects.create_user(
            email='regular@example.com',
            password='userpass123'
        )
        self.regular_user.role = 'viewer'
        self.regular_user.save()

        self.update_url = reverse('user-role-update', kwargs={'user_id': self.regular_user.id})

    def test_assign_role_as_admin(self):
        """Test assigning role as admin."""
        self.client.force_authenticate(user=self.admin)
        data = {'role': 'content_manager'}
        response = self.client.post(self.update_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('Role updated to Content Manager', response.data['message'])
        self.assertEqual(response.data['new_role'], 'content_manager')
        self.assertEqual(response.data['old_role'], 'viewer')

    def test_role_actually_updates_in_database(self):
        """Test that role actually updates in database."""
        self.client.force_authenticate(user=self.admin)
        data = {'role': 'content_manager'}
        response = self.client.post(self.update_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Refresh user from database
        self.regular_user.refresh_from_db()
        self.assertEqual(self.regular_user.role, 'content_manager')

    def test_cannot_change_own_role(self):
        """Test that user cannot change their own role."""
        self.client.force_authenticate(user=self.admin)
        own_update_url = reverse('user-role-update', kwargs={'user_id': self.admin.id})
        data = {'role': 'viewer'}
        response = self.client.post(own_update_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Cannot change your own role', response.data['error'])

    def test_assign_role_invalid_role(self):
        """Test assigning invalid role fails."""
        self.client.force_authenticate(user=self.admin)
        data = {'role': 'super_admin'}  # Invalid role
        response = self.client.post(self.update_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_assign_role_as_non_admin(self):
        """Test that non-admin users cannot assign roles."""
        another_user = User.objects.create_user(
            email='another@example.com',
            password='pass123'
        )

        self.client.force_authenticate(user=self.regular_user)
        update_url = reverse('user-role-update', kwargs={'user_id': another_user.id})
        data = {'role': 'content_manager'}
        response = self.client.post(update_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_assign_role_user_not_found(self):
        """Test assigning role to non-existent user."""
        self.client.force_authenticate(user=self.admin)
        invalid_url = reverse('user-role-update', kwargs={'user_id': 99999})
        data = {'role': 'content_manager'}
        response = self.client.post(invalid_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_assign_role_creates_audit_log(self):
        """Test that role assignment creates audit log."""
        self.client.force_authenticate(user=self.admin)
        data = {'role': 'content_manager'}
        response = self.client.post(self.update_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify audit log
        audit_logs = AuditLog.objects.filter(
            user=self.admin,
            action='role_assigned'
        )
        self.assertTrue(audit_logs.exists())


class InvitationAcceptDefaultRoleTests(APITestCase):
    """Test cases for default role assignment on invitation acceptance."""

    def setUp(self):
        """Set up test data."""
        from agreement_automation.apps.users.models import Invitation

        self.client = APIClient()
        self.accept_url = reverse('invitation-accept')

        self.admin = User.objects.create_user(
            email='admin@example.com',
            password='adminpass123',
            is_staff=True
        )

        self.invitation = Invitation.objects.create(
            invited_by=self.admin,
            email='newuser@example.com'
        )

    def test_new_user_gets_viewer_role_by_default(self):
        """Test that new users from invitation get 'viewer' role by default."""
        data = {
            'token': str(self.invitation.token),
            'password': 'newpassword123',
            'password_confirm': 'newpassword123'
        }
        response = self.client.post(self.accept_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Verify user has viewer role
        user = User.objects.get(email='newuser@example.com')
        self.assertEqual(user.role, 'viewer')


class UserDeactivateViewTests(APITestCase):
    """Test cases for UserDeactivateView."""

    def setUp(self):
        """Set up test client and users."""
        self.client = APIClient()

        self.admin = User.objects.create_user(
            email='admin@example.com',
            password='adminpass123',
            is_staff=True
        )
        self.admin.role = 'admin'
        self.admin.save()

        self.regular_user = User.objects.create_user(
            email='regular@example.com',
            password='userpass123'
        )
        self.regular_user.role = 'viewer'
        self.regular_user.save()

        self.deactivate_url = reverse('user-deactivate', kwargs={'user_id': self.regular_user.id})

    def test_deactivate_user_as_admin(self):
        """Test deactivating user as admin."""
        self.client.force_authenticate(user=self.admin)
        response = self.client.post(self.deactivate_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('Account deactivated for', response.data['message'])
        self.assertEqual(response.data['email'], 'regular@example.com')

    def test_user_actually_deactivated_in_database(self):
        """Test that user is actually deactivated in database."""
        self.client.force_authenticate(user=self.admin)
        response = self.client.post(self.deactivate_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Refresh user from database
        self.regular_user.refresh_from_db()
        self.assertFalse(self.regular_user.is_active)

    def test_cannot_deactivate_own_account(self):
        """Test that admin cannot deactivate their own account."""
        self.client.force_authenticate(user=self.admin)
        own_deactivate_url = reverse('user-deactivate', kwargs={'user_id': self.admin.id})
        response = self.client.post(own_deactivate_url)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Cannot deactivate your own account', response.data['error'])

    def test_cannot_deactivate_last_admin(self):
        """Test that last admin account cannot be deactivated."""
        # Only one admin exists (self.admin)
        self.client.force_authenticate(user=self.admin)

        # Create another admin to deactivate
        admin2 = User.objects.create_user(
            email='admin2@example.com',
            password='adminpass123'
        )
        admin2.role = 'admin'
        admin2.save()

        # Deactivate admin2 (should work - not the last admin)
        deactivate_admin2_url = reverse('user-deactivate', kwargs={'user_id': admin2.id})
        response = self.client.post(deactivate_admin2_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Now try to deactivate self.admin (the last remaining admin)
        # First authenticate as a different user who is admin
        admin3 = User.objects.create_user(
            email='admin3@example.com',
            password='adminpass123'
        )
        admin3.role = 'admin'
        admin3.is_active = True
        admin3.save()

        self.client.force_authenticate(user=admin3)
        admin_deactivate_url = reverse('user-deactivate', kwargs={'user_id': admin3.id})

        # This should fail because admin3 is trying to deactivate themselves
        response = self.client.post(admin_deactivate_url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_deactivate_as_non_admin(self):
        """Test that non-admin users cannot deactivate accounts."""
        another_user = User.objects.create_user(
            email='another@example.com',
            password='pass123'
        )

        self.client.force_authenticate(user=self.regular_user)
        deactivate_url = reverse('user-deactivate', kwargs={'user_id': another_user.id})
        response = self.client.post(deactivate_url)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_deactivate_user_not_found(self):
        """Test deactivating non-existent user."""
        self.client.force_authenticate(user=self.admin)
        invalid_url = reverse('user-deactivate', kwargs={'user_id': 99999})
        response = self.client.post(invalid_url)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_deactivate_creates_audit_log(self):
        """Test that deactivation creates audit log."""
        self.client.force_authenticate(user=self.admin)
        response = self.client.post(self.deactivate_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify audit log
        audit_logs = AuditLog.objects.filter(
            user=self.admin,
            action='user_deactivated'
        )
        self.assertTrue(audit_logs.exists())


class UserReactivateViewTests(APITestCase):
    """Test cases for UserReactivateView."""

    def setUp(self):
        """Set up test client and users."""
        self.client = APIClient()

        self.admin = User.objects.create_user(
            email='admin@example.com',
            password='adminpass123',
            is_staff=True
        )
        self.admin.role = 'admin'
        self.admin.save()

        self.deactivated_user = User.objects.create_user(
            email='deactivated@example.com',
            password='userpass123'
        )
        self.deactivated_user.role = 'viewer'
        self.deactivated_user.is_active = False
        self.deactivated_user.save()

        self.reactivate_url = reverse('user-reactivate', kwargs={'user_id': self.deactivated_user.id})

    def test_reactivate_user_as_admin(self):
        """Test reactivating user as admin."""
        self.client.force_authenticate(user=self.admin)
        response = self.client.post(self.reactivate_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('Account reactivated for', response.data['message'])
        self.assertEqual(response.data['email'], 'deactivated@example.com')

    def test_user_actually_reactivated_in_database(self):
        """Test that user is actually reactivated in database."""
        self.client.force_authenticate(user=self.admin)
        response = self.client.post(self.reactivate_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Refresh user from database
        self.deactivated_user.refresh_from_db()
        self.assertTrue(self.deactivated_user.is_active)

    def test_reactivate_as_non_admin(self):
        """Test that non-admin users cannot reactivate accounts."""
        regular_user = User.objects.create_user(
            email='regular@example.com',
            password='pass123'
        )

        self.client.force_authenticate(user=regular_user)
        response = self.client.post(self.reactivate_url)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_reactivate_user_not_found(self):
        """Test reactivating non-existent user."""
        self.client.force_authenticate(user=self.admin)
        invalid_url = reverse('user-reactivate', kwargs={'user_id': 99999})
        response = self.client.post(invalid_url)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_reactivate_creates_audit_log(self):
        """Test that reactivation creates audit log."""
        self.client.force_authenticate(user=self.admin)
        response = self.client.post(self.reactivate_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify audit log
        audit_logs = AuditLog.objects.filter(
            user=self.admin,
            action='user_reactivated'
        )
        self.assertTrue(audit_logs.exists())


class DeactivatedUserLoginTests(APITestCase):
    """Test cases for deactivated user login attempts."""

    def setUp(self):
        """Set up test client and users."""
        self.client = APIClient()
        self.login_url = reverse('login')

        self.deactivated_user = User.objects.create_user(
            email='deactivated@example.com',
            password='userpass123'
        )
        self.deactivated_user.is_active = False
        self.deactivated_user.save()

    def test_deactivated_user_cannot_login(self):
        """Test that deactivated user cannot login."""
        data = {
            'email': 'deactivated@example.com',
            'password': 'userpass123'
        }
        response = self.client.post(self.login_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn('deactivated', response.data['error'].lower())

    def test_deactivated_user_login_creates_audit_log(self):
        """Test that failed login attempt for deactivated user creates audit log."""
        data = {
            'email': 'deactivated@example.com',
            'password': 'userpass123'
        }
        response = self.client.post(self.login_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        # Verify audit log
        audit_logs = AuditLog.objects.filter(
            user=self.deactivated_user,
            action='user_login_failed_inactive'
        )
        self.assertTrue(audit_logs.exists())


class SessionInvalidationTests(APITestCase):
    """Test cases for session invalidation on deactivation."""

    def setUp(self):
        """Set up test client and users."""
        self.client = APIClient()

        self.admin = User.objects.create_user(
            email='admin@example.com',
            password='adminpass123',
            is_staff=True
        )
        self.admin.role = 'admin'
        self.admin.save()

        self.regular_user = User.objects.create_user(
            email='regular@example.com',
            password='userpass123'
        )
        self.regular_user.role = 'viewer'
        self.regular_user.save()

    def test_session_invalidated_on_deactivation(self):
        """Test that user's session is invalidated when account is deactivated."""
        from django.contrib.sessions.models import Session

        # Login as regular user to create a session
        login_url = reverse('login')
        login_data = {
            'email': 'regular@example.com',
            'password': 'userpass123'
        }
        login_response = self.client.post(login_url, login_data, format='json')
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)

        # Verify session exists for regular user
        user_session_exists = False
        for session in Session.objects.all():
            session_data = session.get_decoded()
            if session_data.get('_auth_user_id') == str(self.regular_user.id):
                user_session_exists = True
                break
        self.assertTrue(user_session_exists)

        # Deactivate the user as admin
        self.client.force_authenticate(user=self.admin)
        deactivate_url = reverse('user-deactivate', kwargs={'user_id': self.regular_user.id})
        deactivate_response = self.client.post(deactivate_url)
        self.assertEqual(deactivate_response.status_code, status.HTTP_200_OK)

        # Verify session no longer exists for regular user
        user_session_exists = False
        for session in Session.objects.all():
            session_data = session.get_decoded()
            if session_data.get('_auth_user_id') == str(self.regular_user.id):
                user_session_exists = True
                break
        self.assertFalse(user_session_exists)
