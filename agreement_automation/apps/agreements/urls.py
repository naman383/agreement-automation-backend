"""URL patterns for agreement generation endpoints."""

from django.urls import path
from .views import (
    AgreementTemplateListView,
    AgreementStartView,
    AgreementFieldValidateView,
    AgreementUpdateDataView,
    AgreementPreviewView,
    AgreementGenerateView,
    AgreementDownloadView,
    AgreementListView,
    AgreementDetailView
)

urlpatterns = [
    path('templates/', AgreementTemplateListView.as_view(), name='agreement-templates'),
    path('start/', AgreementStartView.as_view(), name='agreement-start'),
    path('list/', AgreementListView.as_view(), name='agreement-list'),
    path('<int:agreement_id>/', AgreementDetailView.as_view(), name='agreement-detail'),
    path('<int:agreement_id>/validate-field/', AgreementFieldValidateView.as_view(), name='agreement-field-validate'),
    path('<int:agreement_id>/update-data/', AgreementUpdateDataView.as_view(), name='agreement-update-data'),
    path('<int:agreement_id>/preview/', AgreementPreviewView.as_view(), name='agreement-preview'),
    path('<int:agreement_id>/generate/', AgreementGenerateView.as_view(), name='agreement-generate'),
    path('<int:agreement_id>/download/', AgreementDownloadView.as_view(), name='agreement-download'),
]
