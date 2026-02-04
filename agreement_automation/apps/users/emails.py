"""Email utilities for user management."""

from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings


def send_welcome_email(user):
    """
    Send welcome email to newly registered user.

    Args:
        user: User instance

    Returns:
        Number of successfully delivered emails (0 or 1)
    """
    try:
        # Render email template
        message = render_to_string('emails/welcome.txt', {'user': user})

        # Send email
        result = send_mail(
            subject='Welcome to Agreement Automation System',
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )
        return result
    except Exception as e:
        # Log error but don't fail the registration process
        print(f"Failed to send welcome email to {user.email}: {e}")
        return 0


def send_password_reset_email(user, token):
    """
    Send password reset email with reset link.

    Args:
        user: User instance
        token: UUID token for password reset

    Returns:
        Number of successfully delivered emails (0 or 1)
    """
    try:
        # Generate reset link
        reset_link = f"http://localhost:3000/reset-password?token={token}"

        # Render email template
        message = render_to_string('emails/password_reset.txt', {
            'user': user,
            'reset_link': reset_link,
            'token': token
        })

        # Send email
        result = send_mail(
            subject='Password Reset Request - Agreement Automation',
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )
        return result
    except Exception as e:
        # Log error but don't fail the reset request
        print(f"Failed to send password reset email to {user.email}: {e}")
        return 0


def send_invitation_email(email, token, admin_name):
    """
    Send invitation email with signup link.

    Args:
        email: Email address to send invitation to
        token: UUID token for invitation
        admin_name: Name of admin who sent the invitation

    Returns:
        Number of successfully delivered emails (0 or 1)
    """
    try:
        # Generate signup link
        signup_link = f"http://localhost:3000/signup/{token}"

        # Render email template
        message = render_to_string('emails/invitation.txt', {
            'email': email,
            'signup_link': signup_link,
            'token': token,
            'admin_name': admin_name
        })

        # Send email
        result = send_mail(
            subject="You're Invited to Agreement Automation System",
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False,
        )
        return result
    except Exception as e:
        # Log error but don't fail the invitation
        print(f"Failed to send invitation email to {email}: {e}")
        return 0
