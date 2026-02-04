"""URL patterns for user authentication endpoints."""

from django.urls import path
from .views import (
    CSRFTokenView,
    RegisterView,
    LoginView,
    LogoutView,
    CurrentUserView,
    PasswordResetRequestView,
    PasswordResetConfirmView,
    InvitationSendView,
    InvitationValidateView,
    InvitationAcceptView,
    UserListView,
    UserRoleUpdateView,
    UserDeactivateView,
    UserReactivateView
)

urlpatterns = [
    path('csrf/', CSRFTokenView.as_view(), name='csrf-token'),
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('me/', CurrentUserView.as_view(), name='current-user'),
    path('password-reset/request/', PasswordResetRequestView.as_view(), name='password-reset-request'),
    path('password-reset/confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('invitations/send/', InvitationSendView.as_view(), name='invitation-send'),
    path('invitations/validate/<uuid:token>/', InvitationValidateView.as_view(), name='invitation-validate'),
    path('invitations/accept/', InvitationAcceptView.as_view(), name='invitation-accept'),
    path('users/', UserListView.as_view(), name='user-list'),
    path('users/<int:user_id>/assign-role/', UserRoleUpdateView.as_view(), name='user-role-update'),
    path('users/<int:user_id>/deactivate/', UserDeactivateView.as_view(), name='user-deactivate'),
    path('users/<int:user_id>/reactivate/', UserReactivateView.as_view(), name='user-reactivate'),
]
