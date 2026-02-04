"""Utility functions for audit logging."""

from .models import AuditLog


def log_audit_event(user, action, request=None, **metadata):
    """
    Log an audit event.

    Args:
        user: User instance (can be None for anonymous actions)
        action: String describing the action (e.g., 'user_registration', 'login_attempt')
        request: Django request object (optional, used to extract IP and user agent)
        **metadata: Additional key-value pairs to store in metadata field

    Returns:
        AuditLog instance
    """
    ip_address = None
    user_agent = None

    if request:
        # Extract IP address (handle proxy headers)
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip_address = x_forwarded_for.split(',')[0].strip()
        else:
            ip_address = request.META.get('REMOTE_ADDR')

        # Extract user agent
        user_agent = request.META.get('HTTP_USER_AGENT', '')

    return AuditLog.objects.create(
        user=user,
        action=action,
        ip_address=ip_address,
        user_agent=user_agent,
        metadata=metadata
    )
