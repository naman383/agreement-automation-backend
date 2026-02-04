"""URL patterns for Visual Template Builder"""

from django.urls import path
from .views_visual import (
    VisualTemplateUploadView,
    VisualPlaceholderView,
    VisualTemplateDetailView,
    VisualTemplateListView,
    VisualAgreementCreateView,
    VisualAgreementUpdateView,
    VisualAgreementGenerateView,
)

urlpatterns = [
    # Template management
    path('visual/', VisualTemplateListView.as_view(), name='visual-template-list'),
    path('visual/upload/', VisualTemplateUploadView.as_view(), name='visual-template-upload'),
    path('visual/<int:template_id>/', VisualTemplateDetailView.as_view(), name='visual-template-detail'),

    # Placeholder management
    path('visual/<int:template_id>/placeholders/', VisualPlaceholderView.as_view(), name='visual-placeholders-list'),
    path('visual/<int:template_id>/placeholders/<int:placeholder_id>/', VisualPlaceholderView.as_view(), name='visual-placeholder-detail'),

    # Agreement generation
    path('visual/agreements/create/', VisualAgreementCreateView.as_view(), name='visual-agreement-create'),
    path('visual/agreements/<int:agreement_id>/', VisualAgreementUpdateView.as_view(), name='visual-agreement-update'),
    path('visual/agreements/<int:agreement_id>/generate/', VisualAgreementGenerateView.as_view(), name='visual-agreement-generate'),
]
