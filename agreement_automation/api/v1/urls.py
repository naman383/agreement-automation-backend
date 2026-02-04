"""
API v1 URL Configuration
"""
from django.urls import path, include
from .views import HealthCheckView

urlpatterns = [
    path('health/', HealthCheckView.as_view(), name='health-check'),
    path('auth/', include('agreement_automation.apps.users.urls')),
    path('templates/', include('agreement_automation.apps.templates.urls')),
    path('agreements/', include('agreement_automation.apps.agreements.urls')),
    path('integrations/', include('agreement_automation.apps.integrations.urls')),
]
