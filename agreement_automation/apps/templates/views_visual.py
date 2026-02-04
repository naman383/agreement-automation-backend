"""
API Views for Visual Template Builder
RESTful endpoints for the visual builder system
"""

from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny

from .models_visual import (
    VisualTemplate,
    VisualPlaceholder,
    PlaceholderRegion,
    VisualAgreement
)
from .services_visual import (
    VisualTemplateProcessor,
    RegionSelector,
    VisualAgreementGenerator
)
from .views import CsrfExemptSessionAuthentication


@method_decorator(csrf_exempt, name='dispatch')
class VisualTemplateUploadView(APIView):
    """Upload DOCX for visual template builder"""

    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        Upload and process DOCX file.
        Returns template_id and preview data.
        """
        try:
            # Get uploaded file
            if 'file' not in request.FILES:
                return Response(
                    {"error": "No file uploaded"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            uploaded_file = request.FILES['file']
            name = request.data.get('name', uploaded_file.name.replace('.docx', ''))
            description = request.data.get('description', '')
            category = request.data.get('category', '')

            # Validate file type
            if not uploaded_file.name.endswith('.docx'):
                return Response(
                    {"error": "Only .docx files are supported"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Process document
            processed = VisualTemplateProcessor.process_upload(uploaded_file)

            # Create visual template
            visual_template = VisualTemplate.objects.create(
                name=name,
                description=description,
                category=category,
                original_file=uploaded_file,
                html_preview=processed['html_preview'],
                document_structure=processed['document_structure'],
                page_count=processed['page_count'],
                file_size=processed['file_size'],
                checksum=processed['checksum'],
                status='draft',
                created_by=request.user
            )

            return Response({
                'template_id': visual_template.id,
                'name': visual_template.name,
                'html_preview': visual_template.html_preview,
                'document_structure': visual_template.document_structure,
                'page_count': visual_template.page_count,
                'status': 'success',
                'message': 'Template uploaded successfully'
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            import traceback
            print(f"Upload error: {str(e)}")
            print(traceback.format_exc())
            return Response(
                {"error": f"Failed to process upload: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


@method_decorator(csrf_exempt, name='dispatch')
class VisualPlaceholderView(APIView):
    """CRUD operations for visual placeholders"""

    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, template_id):
        """Get all placeholders for template"""
        try:
            template = VisualTemplate.objects.get(id=template_id)

            placeholders_data = []
            for placeholder in template.placeholders.all():
                regions_data = []
                for region in placeholder.regions.all():
                    regions_data.append({
                        'id': region.id,
                        'paragraph_index': region.paragraph_index,
                        'run_index': region.run_index,
                        'char_start': region.char_start,
                        'char_end': region.char_end,
                        'page_number': region.page_number,
                        'x_percent': region.x_percent,
                        'y_percent': region.y_percent,
                        'width_percent': region.width_percent,
                        'height_percent': region.height_percent,
                        'selected_text': region.selected_text
                    })

                placeholders_data.append({
                    'id': placeholder.id,
                    'field_name': placeholder.field_name,
                    'field_label': placeholder.field_label,
                    'field_type': placeholder.field_type,
                    'is_required': placeholder.is_required,
                    'validation_rules': placeholder.validation_rules,
                    'dropdown_options': placeholder.dropdown_options,
                    'placeholder_text': placeholder.placeholder_text,
                    'help_text': placeholder.help_text,
                    'position_index': placeholder.position_index,
                    'regions': regions_data
                })

            return Response({
                'template_id': template.id,
                'template_name': template.name,
                'placeholders': placeholders_data,
                'count': len(placeholders_data)
            })

        except VisualTemplate.DoesNotExist:
            return Response(
                {"error": "Template not found"},
                status=status.HTTP_404_NOT_FOUND
            )

    def post(self, request, template_id):
        """Create new placeholder from selection"""
        try:
            template = VisualTemplate.objects.get(id=template_id)

            # Get data
            field_config = request.data.get('field_config', {})
            selection_data = request.data.get('selection_data', {})

            print(f"Creating placeholder for template {template_id}")
            print(f"Field config: {field_config}")
            print(f"Selection data: {selection_data}")

            # Check for duplicate field name
            field_name = field_config.get('field_name')
            if VisualPlaceholder.objects.filter(template=template, field_name=field_name).exists():
                return Response(
                    {"error": f"Field name '{field_name}' already exists in this template. Please use a different name."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Create placeholder
            placeholder = VisualPlaceholder.objects.create(
                template=template,
                field_name=field_config.get('field_name'),
                field_label=field_config.get('field_label'),
                field_type=field_config.get('field_type', 'text'),
                is_required=field_config.get('is_required', True),
                validation_rules=field_config.get('validation_rules', {}),
                dropdown_options=field_config.get('dropdown_options', []),
                placeholder_text=selection_data.get('selected_text', '_____'),
                help_text=field_config.get('help_text', ''),
                position_index=field_config.get('position_index', 0)
            )

            # Create region from selection
            region_data = RegionSelector.create_region_from_selection(selection_data)

            # Refine position using document structure
            exact_position = RegionSelector.find_exact_position(
                template.document_structure,
                region_data['selected_text'],
                region_data['paragraph_index']
            )

            region = PlaceholderRegion.objects.create(
                placeholder=placeholder,
                paragraph_index=exact_position['paragraph_index'],
                run_index=exact_position['run_index'],
                char_start=exact_position['char_start'],
                char_end=exact_position['char_end'],
                page_number=region_data['page_number'],
                x_percent=region_data['x_percent'],
                y_percent=region_data['y_percent'],
                width_percent=region_data['width_percent'],
                height_percent=region_data['height_percent'],
                selected_text=region_data['selected_text']
            )

            return Response({
                'placeholder_id': placeholder.id,
                'region_id': region.id,
                'message': 'Placeholder created successfully'
            }, status=status.HTTP_201_CREATED)

        except VisualTemplate.DoesNotExist:
            return Response(
                {"error": "Template not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            import traceback
            print(f"Create placeholder error: {str(e)}")
            print(traceback.format_exc())
            return Response(
                {"error": f"Failed to create placeholder: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def put(self, request, template_id, placeholder_id):
        """Update placeholder configuration"""
        try:
            placeholder = VisualPlaceholder.objects.get(
                id=placeholder_id,
                template_id=template_id
            )

            # Update fields
            for field in ['field_label', 'field_type', 'is_required',
                         'validation_rules', 'dropdown_options', 'help_text', 'position_index']:
                if field in request.data:
                    setattr(placeholder, field, request.data[field])

            placeholder.save()

            return Response({
                'message': 'Placeholder updated successfully',
                'placeholder_id': placeholder.id
            })

        except VisualPlaceholder.DoesNotExist:
            return Response(
                {"error": "Placeholder not found"},
                status=status.HTTP_404_NOT_FOUND
            )

    def delete(self, request, template_id, placeholder_id):
        """Delete placeholder and its regions"""
        try:
            placeholder = VisualPlaceholder.objects.get(
                id=placeholder_id,
                template_id=template_id
            )
            placeholder.delete()

            return Response({
                'message': 'Placeholder deleted successfully'
            })

        except VisualPlaceholder.DoesNotExist:
            return Response(
                {"error": "Placeholder not found"},
                status=status.HTTP_404_NOT_FOUND
            )


@method_decorator(csrf_exempt, name='dispatch')
class VisualTemplateDetailView(APIView):
    """Get/Update/Delete visual template"""

    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, template_id):
        """Get template details"""
        try:
            template = VisualTemplate.objects.get(id=template_id)

            return Response({
                'id': template.id,
                'name': template.name,
                'description': template.description,
                'category': template.category,
                'html_preview': template.html_preview,
                'page_count': template.page_count,
                'status': template.status,
                'created_at': template.created_at,
                'updated_at': template.updated_at,
                'placeholder_count': template.placeholders.count()
            })

        except VisualTemplate.DoesNotExist:
            return Response(
                {"error": "Template not found"},
                status=status.HTTP_404_NOT_FOUND
            )

    def put(self, request, template_id):
        """Update template (name, description, status)"""
        try:
            template = VisualTemplate.objects.get(id=template_id)

            for field in ['name', 'description', 'category', 'status']:
                if field in request.data:
                    setattr(template, field, request.data[field])

            template.save()

            return Response({
                'message': 'Template updated successfully'
            })

        except VisualTemplate.DoesNotExist:
            return Response(
                {"error": "Template not found"},
                status=status.HTTP_404_NOT_FOUND
            )


@method_decorator(csrf_exempt, name='dispatch')
class VisualAgreementCreateView(APIView):
    """Create new agreement from visual template"""

    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """Create draft agreement"""
        try:
            template_id = request.data.get('template_id')

            template = VisualTemplate.objects.get(id=template_id)

            # Check template is active
            if template.status != 'active':
                return Response(
                    {"error": "Template is not active"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Create agreement
            agreement = VisualAgreement.objects.create(
                template=template,
                field_values={},
                status='draft',
                generated_by=request.user
            )

            # Get placeholders for form
            placeholders = []
            for p in template.placeholders.all():
                placeholders.append({
                    'field_name': p.field_name,
                    'field_label': p.field_label,
                    'field_type': p.field_type,
                    'is_required': p.is_required,
                    'dropdown_options': p.dropdown_options,
                    'help_text': p.help_text,
                    'position_index': p.position_index
                })

            return Response({
                'agreement_id': agreement.id,
                'template_name': template.name,
                'placeholders': placeholders,
                'status': 'draft'
            }, status=status.HTTP_201_CREATED)

        except VisualTemplate.DoesNotExist:
            return Response(
                {"error": "Template not found"},
                status=status.HTTP_404_NOT_FOUND
            )


@method_decorator(csrf_exempt, name='dispatch')
class VisualAgreementUpdateView(APIView):
    """Update agreement field values"""

    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [IsAuthenticated]

    def put(self, request, agreement_id):
        """Update field values"""
        try:
            agreement = VisualAgreement.objects.get(id=agreement_id)

            field_values = request.data.get('field_values', {})
            agreement.field_values = field_values
            agreement.save()

            return Response({
                'message': 'Agreement updated successfully',
                'field_values': agreement.field_values
            })

        except VisualAgreement.DoesNotExist:
            return Response(
                {"error": "Agreement not found"},
                status=status.HTTP_404_NOT_FOUND
            )


@method_decorator(csrf_exempt, name='dispatch')
class VisualAgreementGenerateView(APIView):
    """Generate final DOCX with filled data"""

    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, agreement_id):
        """Generate DOCX file"""
        try:
            from django.core.files.base import ContentFile
            import uuid

            agreement = VisualAgreement.objects.get(id=agreement_id)

            # Generate DOCX
            docx_bytes = VisualAgreementGenerator.generate(
                agreement.template,
                agreement.field_values
            )

            # Save file
            filename = f"agreement_{agreement.id}_{uuid.uuid4().hex[:8]}.docx"
            agreement.generated_file.save(filename, ContentFile(docx_bytes.read()))
            agreement.status = 'completed'
            agreement.save()

            return Response({
                'message': 'Agreement generated successfully',
                'download_url': agreement.generated_file.url,
                'status': 'completed'
            })

        except VisualAgreement.DoesNotExist:
            return Response(
                {"error": "Agreement not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            import traceback
            print(f"Generate error: {str(e)}")
            print(traceback.format_exc())
            return Response(
                {"error": f"Failed to generate agreement: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


@method_decorator(csrf_exempt, name='dispatch')
class VisualTemplateListView(APIView):
    """List all visual templates"""

    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Get all templates"""
        templates = VisualTemplate.objects.all()

        data = []
        for t in templates:
            data.append({
                'id': t.id,
                'name': t.name,
                'category': t.category,
                'status': t.status,
                'placeholder_count': t.placeholders.count(),
                'created_at': t.created_at,
                'page_count': t.page_count
            })

        return Response({
            'templates': data,
            'count': len(data)
        })
