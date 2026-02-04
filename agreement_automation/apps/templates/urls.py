"""URL patterns for template management endpoints."""

from django.urls import path, include
from .views import (
    DiagnosticUploadView,
    TemplateListView,
    TemplateDetailView,
    PlaceholderConfigView,
    TemplateUploadView,
    TemplatePreviewView,
    TemplateApproveView,
    TemplateNewVersionView,
    TemplateVersionListView,
    TemplateDeprecateView,
    PlaceholderScanView,
    VisualEditorView
)

urlpatterns = [
    path('diagnostic/', DiagnosticUploadView.as_view(), name='diagnostic-upload'),
    path('', TemplateListView.as_view(), name='template-list'),
    path('<int:template_id>/', TemplateDetailView.as_view(), name='template-detail'),
    path('<int:template_id>/placeholders/', PlaceholderConfigView.as_view(), name='placeholder-config'),
    path('<int:template_id>/scan-placeholders/', PlaceholderScanView.as_view(), name='placeholder-scan'),
    path('upload/', TemplateUploadView.as_view(), name='template-upload'),
    path('<int:template_id>/preview/', TemplatePreviewView.as_view(), name='template-preview'),
    path('<int:template_id>/approve/', TemplateApproveView.as_view(), name='template-approve'),
    path('<int:template_id>/new-version/', TemplateNewVersionView.as_view(), name='template-new-version'),
    path('<int:template_id>/versions/', TemplateVersionListView.as_view(), name='template-versions'),
    path('<int:template_id>/deprecate/', TemplateDeprecateView.as_view(), name='template-deprecate'),
    path('<int:template_id>/visual-editor/', VisualEditorView.as_view(), name='visual-editor'),
]

# Include visual builder URLs
urlpatterns += [
    path('', include('agreement_automation.apps.templates.urls_visual')),
]
