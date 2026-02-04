"""Models for external data source integrations."""

from django.db import models
from django.contrib.auth import get_user_model
from agreement_automation.apps.templates.models import Template

User = get_user_model()


class DataSource(models.Model):
    """Base model for external data sources."""

    SOURCE_TYPES = [
        ('google_sheets', 'Google Sheets'),
        ('google_forms', 'Google Forms'),
    ]

    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('error', 'Error'),
    ]

    name = models.CharField(max_length=255)
    source_type = models.CharField(max_length=50, choices=SOURCE_TYPES)
    template = models.ForeignKey(Template, on_delete=models.CASCADE, related_name='data_sources')
    connection_config = models.JSONField()  # Stores API credentials, spreadsheet ID, etc.
    field_mapping = models.JSONField()  # Maps data source fields to template placeholders
    transformation_rules = models.JSONField(default=dict)  # Date format, currency, text casing rules
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='inactive')
    last_tested_at = models.DateTimeField(null=True, blank=True)
    last_sync_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(null=True, blank=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_data_sources')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'data_sources'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} ({self.source_type})"


class DataSnapshot(models.Model):
    """Immutable snapshot of data retrieved from external sources."""

    data_source = models.ForeignKey(DataSource, on_delete=models.PROTECT, related_name='snapshots')
    snapshot_data = models.JSONField()  # Complete raw data from source
    transformed_data = models.JSONField()  # Data after transformations applied
    checksum_sha256 = models.CharField(max_length=64)  # For data integrity verification
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)

    class Meta:
        db_table = 'data_snapshots'
        ordering = ['-created_at']

    def __str__(self):
        return f"Snapshot from {self.data_source.name} at {self.created_at}"
