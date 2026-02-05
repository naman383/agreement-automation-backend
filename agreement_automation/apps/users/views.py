"""Views for user authentication and management."""

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth import get_user_model
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie
from django.middleware.csrf import get_token
from django_ratelimit.decorators import ratelimit

from .serializers import (
    RegisterSerializer,
    LoginSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    InvitationSendSerializer,
    InvitationAcceptSerializer,
    UserListSerializer,
    UserRoleUpdateSerializer
)
from .emails import send_welcome_email, send_password_reset_email, send_invitation_email
from .models import PasswordResetToken, Invitation
from ..audit.utils import log_audit_event

User = get_user_model()


class CSRFTokenView(APIView):
    """API endpoint to get CSRF token for SPA."""

    permission_classes = [AllowAny]

    @method_decorator(ensure_csrf_cookie)
    def get(self, request):
        """Return CSRF token in response body for cross-origin requests."""
        csrf_token = get_token(request)
        return Response({'csrfToken': csrf_token})


class RegisterView(APIView):
    """API endpoint for user registration."""

    permission_classes = [AllowAny]

    def post(self, request):
        """
        Register a new user.

        Expected payload:
        {
            "email": "user@example.com",
            "password": "SecurePass123",
            "password_confirm": "SecurePass123"
        }
        """
        serializer = RegisterSerializer(data=request.data)

        if serializer.is_valid():
            # Create user
            user = serializer.save()

            # Log audit event
            log_audit_event(
                user=user,
                action='user_registration',
                request=request,
                email=user.email
            )

            # Send welcome email (console backend for MVP)
            send_welcome_email(user)

            return Response(
                {
                    "message": "Registration successful",
                    "email": user.email
                },
                status=status.HTTP_201_CREATED
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    """API endpoint for user login."""

    permission_classes = [AllowAny]

    # @method_decorator(ratelimit(key='ip', rate='5/15m', method='POST'))  # Temporarily disabled - cache table needs setup
    def post(self, request):
        """
        Authenticate user and create session.

        Expected payload:
        {
            "email": "user@example.com",
            "password": "SecurePass123"
        }
        """
        # Check if rate limited
        if getattr(request, 'limited', False):
            return Response(
                {"error": "Too many login attempts. Please try again in 15 minutes."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        serializer = LoginSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']

        # Check if user exists first
        try:
            user = User.objects.get(email=email)
            # Check if account is active before authentication
            if not user.is_active:
                # log_audit_event(  # Temporarily disabled
                #     user=user,
                #     action='user_login_failed_inactive',
                #     request=request,
                #     email=email
                # )
                return Response(
                    {"error": "Account deactivated. Contact administrator."},
                    status=status.HTTP_403_FORBIDDEN
                )
        except User.DoesNotExist:
            # User doesn't exist - fall through to authenticate (which will fail)
            pass

        # Authenticate user
        user = authenticate(request, username=email, password=password)

        if user is not None:
            # Create session
            login(request, user)

            # Log successful login
            # log_audit_event(  # Temporarily disabled
            #     user=user,
            #     action='user_login_success',
            #     request=request,
            #     email=email
            # )

            # Get CSRF token to send to frontend
            csrf_token = get_token(request)

            return Response(
                {
                    "message": "Login successful",
                    "user": {
                        "id": user.id,
                        "email": user.email
                    },
                    "csrfToken": csrf_token
                },
                status=status.HTTP_200_OK
            )
        else:
            # Log failed login attempt
            # log_audit_event(  # Temporarily disabled
            #     user=None,
            #     action='user_login_failed',
            #     request=request,
            #     email=email
            # )

            return Response(
                {"error": "Invalid email or password"},
                status=status.HTTP_400_BAD_REQUEST
            )


class LogoutView(APIView):
    """API endpoint for user logout."""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        """Destroy user session and logout."""
        user = request.user

        # Log logout event
        log_audit_event(
            user=user,
            action='user_logout',
            request=request,
            email=user.email
        )

        # Destroy session
        logout(request)

        return Response(
            {"message": "Logout successful"},
            status=status.HTTP_200_OK
        )


class CurrentUserView(APIView):
    """API endpoint to get current authenticated user."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Return current user information."""
        user = request.user
        return Response(
            {
                "id": user.id,
                "email": user.email,
                "full_name": getattr(user, 'full_name', '') or user.email.split('@')[0],
                "role": user.role,
                "is_active": user.is_active
            },
            status=status.HTTP_200_OK
        )


class PasswordResetRequestView(APIView):
    """API endpoint for password reset request."""

    permission_classes = [AllowAny]

    def post(self, request):
        """
        Request password reset.

        Expected payload:
        {
            "email": "user@example.com"
        }
        """
        serializer = PasswordResetRequestSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data['email']

        # Check if user exists
        try:
            user = User.objects.get(email=email)

            # Generate reset token
            reset_token = PasswordResetToken.objects.create(user=user)

            # Send password reset email
            send_password_reset_email(user, reset_token.token)

            # Log password reset request
            log_audit_event(
                user=user,
                action='password_reset_requested',
                request=request,
                email=email
            )
        except User.DoesNotExist:
            # Log attempt for non-existent email (security monitoring)
            log_audit_event(
                user=None,
                action='password_reset_requested',
                request=request,
                email=email
            )

        # Always return same message (prevent email enumeration)
        return Response(
            {"message": "If that email exists, a reset link has been sent"},
            status=status.HTTP_200_OK
        )


class PasswordResetConfirmView(APIView):
    """API endpoint for password reset confirmation."""

    permission_classes = [AllowAny]

    def post(self, request):
        """
        Confirm password reset with token.

        Expected payload:
        {
            "token": "550e8400-e29b-41d4-a716-446655440000",
            "password": "NewSecurePass123",
            "password_confirm": "NewSecurePass123"
        }
        """
        serializer = PasswordResetConfirmSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        token_uuid = serializer.validated_data['token']
        new_password = serializer.validated_data['password']

        # Find token
        try:
            reset_token = PasswordResetToken.objects.get(token=token_uuid)
        except PasswordResetToken.DoesNotExist:
            return Response(
                {"error": "Invalid reset token."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if token is valid
        if not reset_token.is_valid():
            # Check if expired
            if reset_token.used_at is not None:
                return Response(
                    {"error": "Reset token already used."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            else:
                return Response(
                    {"error": "Reset link expired. Request a new one."},
                    status=status.HTTP_400_BAD_REQUEST
                )

        # Update user password
        user = reset_token.user
        user.set_password(new_password)
        user.save()

        # Mark token as used
        reset_token.mark_as_used()

        # Log password change
        log_audit_event(
            user=user,
            action='password_reset_completed',
            request=request,
            email=user.email
        )

        return Response(
            {"message": "Password reset successful. You can now login."},
            status=status.HTTP_200_OK
        )


class InvitationSendView(APIView):
    """API endpoint for sending team invitations (admin only)."""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        Send team invitation.

        Expected payload:
        {
            "email": "newteammember@example.com"
        }
        """
        # Check if user is admin
        if not request.user.is_admin:
            return Response(
                {"error": "You do not have permission to perform this action."},
                status=status.HTTP_403_FORBIDDEN
            )

        serializer = InvitationSendSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data['email']

        # Create invitation
        invitation = Invitation.objects.create(
            invited_by=request.user,
            email=email
        )

        # Send invitation email
        admin_name = request.user.email.split('@')[0]  # Use email prefix as name
        send_invitation_email(email, invitation.token, admin_name)

        # Log invitation event
        log_audit_event(
            user=request.user,
            action='invitation_sent',
            request=request,
            email=email
        )

        return Response(
            {
                "message": f"Invitation sent to {email}",
                "email": email
            },
            status=status.HTTP_201_CREATED
        )


class InvitationValidateView(APIView):
    """API endpoint for validating invitation tokens."""

    permission_classes = [AllowAny]

    def get(self, request, token):
        """
        Validate invitation token.

        URL: /api/v1/auth/invitations/validate/<token>/
        """
        try:
            invitation = Invitation.objects.get(token=token)
        except Invitation.DoesNotExist:
            return Response(
                {"error": "Invalid invitation token."},
                status=status.HTTP_404_NOT_FOUND
            )

        # Check if invitation is valid
        if not invitation.is_valid():
            # Check if expired
            if invitation.status == 'accepted':
                return Response(
                    {"error": "Invitation already used."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            else:
                return Response(
                    {"error": "Invitation expired. Contact administrator for a new invitation."},
                    status=status.HTTP_400_BAD_REQUEST
                )

        return Response(
            {
                "email": invitation.email,
                "expires_at": invitation.expires_at,
                "is_valid": True
            },
            status=status.HTTP_200_OK
        )


class InvitationAcceptView(APIView):
    """API endpoint for accepting invitations and creating accounts."""

    permission_classes = [AllowAny]

    def post(self, request):
        """
        Accept invitation and create account.

        Expected payload:
        {
            "token": "550e8400-e29b-41d4-a716-446655440000",
            "password": "NewSecurePass123",
            "password_confirm": "NewSecurePass123"
        }
        """
        serializer = InvitationAcceptSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        token_uuid = serializer.validated_data['token']
        password = serializer.validated_data['password']

        # Find invitation
        try:
            invitation = Invitation.objects.get(token=token_uuid)
        except Invitation.DoesNotExist:
            return Response(
                {"error": "Invalid invitation token."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if invitation is valid
        if not invitation.is_valid():
            # Check if expired or accepted
            if invitation.status == 'accepted':
                return Response(
                    {"error": "Invitation already used."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            else:
                return Response(
                    {"error": "Invitation expired. Contact administrator for a new invitation."},
                    status=status.HTTP_400_BAD_REQUEST
                )

        # Create user account with default 'viewer' role
        user = User.objects.create_user(
            email=invitation.email,
            password=password
        )
        user.role = 'viewer'  # Set default role explicitly
        user.save()

        # Mark invitation as accepted
        invitation.mark_as_accepted()

        # Send welcome email
        send_welcome_email(user)

        # Log account creation via invitation
        log_audit_event(
            user=user,
            action='invitation_accepted',
            request=request,
            email=user.email
        )

        return Response(
            {
                "message": "Account created successfully. You can now login.",
                "email": user.email
            },
            status=status.HTTP_201_CREATED
        )


class UserListView(APIView):
    """API endpoint for listing users with roles (admin only)."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        List all users with their roles.

        URL: /api/v1/users/
        """
        # Check if user is admin
        if not request.user.is_admin:
            return Response(
                {"error": "You do not have permission to perform this action."},
                status=status.HTTP_403_FORBIDDEN
            )

        users = User.objects.all().order_by('email')
        serializer = UserListSerializer(users, many=True)

        return Response(
            {"users": serializer.data},
            status=status.HTTP_200_OK
        )


class UserRoleUpdateView(APIView):
    """API endpoint for updating user roles (admin only)."""

    permission_classes = [IsAuthenticated]

    def post(self, request, user_id):
        """
        Update user role.

        Expected payload:
        {
            "role": "content_manager"
        }

        URL: /api/v1/users/<id>/assign-role/
        """
        # Check if user is admin
        if not request.user.is_admin:
            return Response(
                {"error": "You do not have permission to perform this action."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Validate request data
        serializer = UserRoleUpdateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        new_role = serializer.validated_data['role']

        # Get target user
        try:
            target_user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {"error": "User not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        # Prevent users from changing their own role
        if request.user.id == target_user.id:
            return Response(
                {"error": "Cannot change your own role."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Store old role for audit log
        old_role = target_user.role

        # Update role
        target_user.role = new_role
        target_user.save()

        # Log role assignment
        log_audit_event(
            user=request.user,
            action='role_assigned',
            request=request,
            email=target_user.email,
            old_role=old_role,
            new_role=new_role,
            target_user_id=target_user.id
        )

        return Response(
            {
                "message": f"Role updated to {target_user.role_display_name} for {target_user.email}",
                "user_id": target_user.id,
                "email": target_user.email,
                "old_role": old_role,
                "new_role": new_role
            },
            status=status.HTTP_200_OK
        )


def invalidate_user_sessions(user_id):
    """Invalidate all sessions for a given user."""
    from django.contrib.sessions.models import Session

    # Find all sessions and check if they belong to the user
    for session in Session.objects.all():
        session_data = session.get_decoded()
        if session_data.get('_auth_user_id') == str(user_id):
            session.delete()


class UserDeactivateView(APIView):
    """API endpoint for deactivating user accounts (admin only)."""

    permission_classes = [IsAuthenticated]

    def post(self, request, user_id):
        """
        Deactivate user account.

        URL: /api/v1/auth/users/<id>/deactivate/
        """
        # Check if user is admin
        if not request.user.is_admin:
            return Response(
                {"error": "You do not have permission to perform this action."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Get target user
        try:
            target_user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {"error": "User not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        # Prevent users from deactivating their own account
        if request.user.id == target_user.id:
            return Response(
                {"error": "Cannot deactivate your own account."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Prevent deactivating the last admin account
        if target_user.is_admin:
            active_admin_count = User.objects.filter(
                role='admin',
                is_active=True
            ).count()

            if active_admin_count <= 1:
                return Response(
                    {"error": "Cannot deactivate the last admin account."},
                    status=status.HTTP_400_BAD_REQUEST
                )

        # Deactivate user
        target_user.is_active = False
        target_user.save()

        # Invalidate all sessions for the user
        invalidate_user_sessions(target_user.id)

        # Log deactivation
        log_audit_event(
            user=request.user,
            action='user_deactivated',
            request=request,
            email=target_user.email,
            target_user_id=target_user.id
        )

        return Response(
            {
                "message": f"Account deactivated for {target_user.email}",
                "user_id": target_user.id,
                "email": target_user.email
            },
            status=status.HTTP_200_OK
        )


class UserReactivateView(APIView):
    """API endpoint for reactivating user accounts (admin only)."""

    permission_classes = [IsAuthenticated]

    def post(self, request, user_id):
        """
        Reactivate user account.

        URL: /api/v1/auth/users/<id>/reactivate/
        """
        # Check if user is admin
        if not request.user.is_admin:
            return Response(
                {"error": "You do not have permission to perform this action."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Get target user
        try:
            target_user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {"error": "User not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        # Reactivate user
        target_user.is_active = True
        target_user.save()

        # Log reactivation
        log_audit_event(
            user=request.user,
            action='user_reactivated',
            request=request,
            email=target_user.email,
            target_user_id=target_user.id
        )

        return Response(
            {
                "message": f"Account reactivated for {target_user.email}",
                "user_id": target_user.id,
                "email": target_user.email
            },
            status=status.HTTP_200_OK
        )
