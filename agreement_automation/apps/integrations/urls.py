"""URL patterns for integrations endpoints."""

from django.urls import path
from .views import (
    DataSourceCreateView,
    DataSourceTestView,
    DataSnapshotCreateView,
    DataSourceListView
)

urlpatterns = [
    path('data-sources/create/', DataSourceCreateView.as_view(), name='data-source-create'),
    path('data-sources/list/', DataSourceListView.as_view(), name='data-source-list'),
    path('data-sources/<int:data_source_id>/test/', DataSourceTestView.as_view(), name='data-source-test'),
    path('data-sources/<int:data_source_id>/snapshot/', DataSnapshotCreateView.as_view(), name='data-snapshot-create'),
]
