"""Permission helpers for role-based access control."""


def can_generate_agreements(user):
    """Check if user can generate agreements."""
    return user.role in ['content_manager', 'legal_reviewer', 'admin']


def can_upload_templates(user):
    """Check if user can upload templates."""
    return user.role == 'admin'


def can_approve_templates(user):
    """Check if user can approve templates."""
    return user.role in ['legal_reviewer', 'admin']


def can_view_all_agreements(user):
    """Check if user can view all agreements."""
    return user.role in ['legal_reviewer', 'admin']


def can_view_audit_logs(user):
    """Check if user can view audit logs."""
    return user.role in ['legal_reviewer', 'admin']


def can_invite_users(user):
    """Check if user can invite users."""
    return user.role == 'admin'


def can_assign_roles(user):
    """Check if user can assign roles."""
    return user.role == 'admin'


def is_viewer(user):
    """Check if user is viewer (read-only)."""
    return user.role == 'viewer'
