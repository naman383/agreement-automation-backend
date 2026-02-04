"""
Visual Template Builder Models
Separate from existing template system for parallel operation
"""

from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()


class VisualTemplate(models.Model):
    """
    Visual template with region-based placeholders.
    User selects regions in document to create placeholders.
    """

    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    category = models.CharField(max_length=100, blank=True)

    # Original document (no placeholders in it)
    original_file = models.FileField(upload_to='visual_templates/%Y/%m/')

    # Cached HTML preview for editor
    html_preview = models.TextField(blank=True)

    # Document structure
    document_structure = models.JSONField(default=dict, help_text='Paragraph/run structure from python-docx')

    # Metadata
    file_size = models.IntegerField(default=0)
    page_count = models.IntegerField(default=1)
    checksum = models.CharField(max_length=64, blank=True)

    # Status
    STATUS_CHOICES = [
        ('draft', 'Draft - Being Built'),
        ('active', 'Active - Ready for Use'),
        ('archived', 'Archived'),
    ]
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')

    # Legacy link (optional - if migrating from old template)
    legacy_template = models.ForeignKey(
        'templates.Template',  # String reference to avoid circular import
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='visual_version'
    )

    # Tracking
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='visual_templates_created')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'visual_templates'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} (Visual)"


class VisualPlaceholder(models.Model):
    """
    Placeholder created by selecting region in document.
    Stores both visual coordinates and DOCX structure position.
    """

    template = models.ForeignKey(
        VisualTemplate,
        on_delete=models.CASCADE,
        related_name='placeholders'
    )

    # Field definition
    field_name = models.CharField(max_length=100, help_text='Internal name: party_a_name')
    field_label = models.CharField(max_length=255, help_text='Display label: Party A Name')

    FIELD_TYPE_CHOICES = [
        ('text', 'Text'),
        ('textarea', 'Long Text'),
        ('number', 'Number'),
        ('date', 'Date'),
        ('email', 'Email Address'),
        ('phone', 'Phone Number'),
        ('currency', 'Currency (₹)'),
        ('pan_number', 'PAN Number'),
        ('gst_number', 'GST Number'),
        ('dropdown', 'Dropdown Selection'),
        ('checkbox', 'Checkbox'),
    ]
    field_type = models.CharField(max_length=50, choices=FIELD_TYPE_CHOICES, default='text')

    # Validation
    is_required = models.BooleanField(default=True)
    validation_rules = models.JSONField(
        default=dict,
        help_text='{"min_length": 5, "max_length": 100, "regex": "pattern"}'
    )
    dropdown_options = models.JSONField(
        default=list,
        help_text='["Option 1", "Option 2", "Option 3"]'
    )

    # UI
    placeholder_text = models.CharField(
        max_length=255,
        default='_____________',
        help_text='Text shown in document before filling'
    )
    help_text = models.TextField(blank=True, help_text='Help text shown to user')
    position_index = models.IntegerField(default=0, help_text='Order in form')

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'visual_placeholders'
        ordering = ['template', 'position_index']
        unique_together = [['template', 'field_name']]

    def __str__(self):
        return f"{self.template.name}: {self.field_label}"


class PlaceholderRegion(models.Model):
    """
    Physical location of placeholder in document.
    Multiple regions can map to same placeholder (e.g., party name appears twice).
    """

    placeholder = models.ForeignKey(
        VisualPlaceholder,
        on_delete=models.CASCADE,
        related_name='regions'
    )

    # DOCX structure position (primary - most accurate)
    paragraph_index = models.IntegerField(help_text='Which paragraph (0-indexed)')
    run_index = models.IntegerField(default=0, help_text='Which run in paragraph')
    char_start = models.IntegerField(help_text='Character start position in run')
    char_end = models.IntegerField(help_text='Character end position in run')

    # Visual coordinates (secondary - for HTML preview)
    page_number = models.IntegerField(default=1)
    x_percent = models.FloatField(help_text='X position as % of page width')
    y_percent = models.FloatField(help_text='Y position as % of page height')
    width_percent = models.FloatField(help_text='Width as % of page width')
    height_percent = models.FloatField(help_text='Height as % of page height')

    # Reference
    selected_text = models.CharField(
        max_length=500,
        help_text='Original text that was selected'
    )

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'placeholder_regions'
        ordering = ['placeholder', 'paragraph_index', 'char_start']

    def __str__(self):
        return f"{self.placeholder.field_name} @ para:{self.paragraph_index}"


class VisualAgreement(models.Model):
    """
    Agreement generated from visual template.
    Stores filled data and generated document.
    """

    template = models.ForeignKey(
        VisualTemplate,
        on_delete=models.PROTECT,
        related_name='agreements'
    )

    # Filled data
    field_values = models.JSONField(
        default=dict,
        help_text='{"party_a_name": "ABC Company", "date": "2026-02-03"}'
    )

    # Generated files
    generated_file = models.FileField(
        upload_to='visual_agreements/%Y/%m/',
        blank=True,
        null=True,
        help_text='Final DOCX with filled data'
    )
    pdf_file = models.FileField(
        upload_to='visual_agreements_pdf/%Y/%m/',
        blank=True,
        null=True,
        help_text='PDF export'
    )

    # Status
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('completed', 'Completed'),
        ('signed', 'Signed'),
        ('archived', 'Archived'),
    ]
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')

    # Tracking
    generated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'visual_agreements'
        ordering = ['-created_at']

    def __str__(self):
        return f"Agreement from {self.template.name} ({self.created_at.strftime('%Y-%m-%d')})"
