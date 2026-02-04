"""Models for template management."""

from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

# Import visual template models
from .models_visual import (
    VisualTemplate,
    VisualPlaceholder,
    PlaceholderRegion,
    VisualAgreement
)


class Template(models.Model):
    """Model for agreement templates."""

    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('approved', 'Approved'),
        ('deprecated', 'Deprecated'),
    ]

    name = models.CharField(max_length=255)
    category = models.CharField(max_length=100)
    file_path = models.FileField(upload_to='templates/%Y/%m/')
    checksum_sha256 = models.CharField(max_length=64)
    version = models.IntegerField(default=1)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')
    parent_template = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='versions'
    )
    uploaded_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='uploaded_templates'
    )
    approved_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='approved_templates'
    )
    approved_at = models.DateTimeField(null=True, blank=True)
    deprecated_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='deprecated_templates'
    )
    deprecated_at = models.DateTimeField(null=True, blank=True)
    deprecation_reason = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'templates'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} (v{self.version})"


class Placeholder(models.Model):
    """Model for template placeholders."""

    FIELD_TYPE_CHOICES = [
        ('text', 'Text'),
        ('number', 'Number'),
        ('date', 'Date'),
        ('currency', 'Currency'),
        ('pan_number', 'PAN Number'),
        ('gst_number', 'GST Number'),
        ('dropdown', 'Dropdown'),
        ('checkbox', 'Checkbox'),
    ]

    template = models.ForeignKey(Template, on_delete=models.CASCADE, related_name='placeholders')
    name = models.CharField(max_length=100)
    display_label = models.CharField(max_length=255)
    field_type = models.CharField(max_length=20, choices=FIELD_TYPE_CHOICES, default='text')
    is_required = models.BooleanField(default=True)
    position_index = models.IntegerField(default=0)
    validation_rules = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'placeholders'
        unique_together = [['template', 'name']]
        ordering = ['position_index']

    def __str__(self):
        return f"{self.template.name}: {{{{self.name}}}}"


class TemplateVisualMapping(models.Model):
    """Visual editor mapping for template documents."""

    template = models.OneToOneField(
        Template,
        on_delete=models.CASCADE,
        related_name='visual_mapping'
    )
    rendered_html = models.TextField(help_text='Cached HTML rendering of the template')
    page_data = models.JSONField(
        default=dict,
        help_text='Page breaks, dimensions, and metadata'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'template_visual_mappings'

    def __str__(self):
        return f"Visual mapping for {self.template.name}"


class PlaceholderVisualMarker(models.Model):
    """Visual marker for placeholders in the visual editor."""

    placeholder = models.OneToOneField(
        Placeholder,
        on_delete=models.CASCADE,
        related_name='visual_marker'
    )
    mapping = models.ForeignKey(
        TemplateVisualMapping,
        on_delete=models.CASCADE,
        related_name='markers'
    )
    page_number = models.IntegerField(help_text='Which page this marker appears on (1-indexed)')
    x_position = models.FloatField(help_text='X coordinate (percentage from left)')
    y_position = models.FloatField(help_text='Y coordinate (percentage from top)')
    width = models.FloatField(help_text='Width (percentage of page width)')
    height = models.FloatField(help_text='Height (percentage of page height)')
    marker_color = models.CharField(max_length=7, default='#DC2626')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'placeholder_visual_markers'
        ordering = ['page_number', 'y_position', 'x_position']

    def __str__(self):
        return f"Marker for {self.placeholder.name} on page {self.page_number}"
