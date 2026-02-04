"""Serializers for template management."""

from rest_framework import serializers
from .models import Template


class TemplateListSerializer(serializers.ModelSerializer):
    """Serializer for listing templates."""
    uploaded_by_email = serializers.CharField(source='uploaded_by.email', read_only=True)
    approved_by_email = serializers.CharField(source='approved_by.email', read_only=True, allow_null=True)

    class Meta:
        model = Template
        fields = ('id', 'name', 'category', 'status', 'version', 'uploaded_by_email', 'approved_by_email', 'approved_at', 'created_at')


class TemplateDetailSerializer(serializers.ModelSerializer):
    """Serializer for template details."""
    uploaded_by = serializers.SerializerMethodField()
    approved_by = serializers.SerializerMethodField()
    placeholders = serializers.SerializerMethodField()

    class Meta:
        model = Template
        fields = ('id', 'name', 'category', 'status', 'version', 'uploaded_by', 'approved_by', 'approved_at', 'created_at', 'updated_at', 'file_path', 'checksum_sha256', 'placeholders')

    def get_uploaded_by(self, obj):
        if obj.uploaded_by:
            return {
                'id': obj.uploaded_by.id,
                'email': obj.uploaded_by.email,
                'full_name': obj.uploaded_by.full_name if hasattr(obj.uploaded_by, 'full_name') else obj.uploaded_by.email
            }
        return None

    def get_approved_by(self, obj):
        if obj.approved_by:
            return {
                'id': obj.approved_by.id,
                'email': obj.approved_by.email,
                'full_name': obj.approved_by.full_name if hasattr(obj.approved_by, 'full_name') else obj.approved_by.email
            }
        return None

    def get_placeholders(self, obj):
        placeholders = obj.placeholders.all()
        return [{
            'id': p.id,
            'name': p.name,
            'label': p.display_label,  # Map display_label to label for frontend
            'field_type': p.field_type,
            'required': p.is_required,  # Map is_required to required for frontend
            'validation_rules': p.validation_rules
        } for p in placeholders]


class TemplateUploadSerializer(serializers.Serializer):
    """Serializer for uploading templates."""
    file = serializers.FileField(required=True)
    name = serializers.CharField(max_length=255, required=True)
    category = serializers.CharField(max_length=100, required=False, allow_blank=True, default='')

    def validate_file(self, value):
        """Validate uploaded file."""
        # Check file size (10MB max)
        if value.size > 10 * 1024 * 1024:  # 10MB in bytes
            raise serializers.ValidationError("File size exceeds 10MB limit")

        # Check file extension - this is sufficient, MIME type unreliable across browsers
        if not value.name.lower().endswith('.docx'):
            raise serializers.ValidationError("Only DOCX format is supported. File must have .docx extension.")

        # MIME type check removed - browsers send inconsistent types for DOCX files

        return value
