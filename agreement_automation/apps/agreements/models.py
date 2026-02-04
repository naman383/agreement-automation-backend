"""Models for agreement generation."""

from django.db import models
from django.contrib.auth import get_user_model
from agreement_automation.apps.templates.models import Template

User = get_user_model()


class UserTemplateUsage(models.Model):
    """Model for tracking template usage by users."""

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='template_usage')
    template = models.ForeignKey(Template, on_delete=models.CASCADE, related_name='user_usage')
    last_used_at = models.DateTimeField(auto_now=True)
    usage_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'user_template_usage'
        unique_together = [['user', 'template']]
        ordering = ['-last_used_at']

    def __str__(self):
        return f"{self.user.email} - {self.template.name} (used {self.usage_count} times)"


class Agreement(models.Model):
    """Model for generated agreements."""

    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('generated', 'Generated'),
        ('downloaded', 'Downloaded'),
    ]

    agreement_id = models.CharField(max_length=20, unique=True, null=True, blank=True)  # AGR-YYYY-NNNNN
    template = models.ForeignKey(Template, on_delete=models.PROTECT, related_name='agreements')
    template_version = models.IntegerField()
    generated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='generated_agreements')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')
    placeholder_data = models.JSONField()  # Stores all filled placeholder values
    file_path = models.FileField(upload_to='agreements/%Y/%m/', null=True, blank=True)
    checksum_sha256 = models.CharField(max_length=64, null=True, blank=True)
    integrity_verified = models.BooleanField(default=False)
    regeneration_of_agreement_id = models.CharField(max_length=20, null=True, blank=True)  # Links to original if regenerated
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    generated_at = models.DateTimeField(null=True, blank=True)
    downloaded_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'agreements'
        ordering = ['-created_at']

    def __str__(self):
        return f"Agreement from {self.template.name} v{self.template_version} by {self.generated_by.email if self.generated_by else 'Unknown'}"
