"""Views for data source integrations."""

import hashlib
import json
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from .models import DataSource, DataSnapshot
from agreement_automation.apps.templates.models import Template
from agreement_automation.apps.audit.utils import log_audit_event


@method_decorator(csrf_exempt, name='dispatch')
class DataSourceCreateView(APIView):
    """API endpoint for creating data source connection."""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        """Create new data source connection."""
        # Only admins can create data sources
        if request.user.role not in ['admin']:
            return Response(
                {"error": "Only admins can create data source connections."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Get required fields
        name = request.data.get('name')
        source_type = request.data.get('source_type')
        template_id = request.data.get('template_id')
        connection_config = request.data.get('connection_config', {})
        field_mapping = request.data.get('field_mapping', {})
        transformation_rules = request.data.get('transformation_rules', {})

        if not all([name, source_type, template_id]):
            return Response(
                {"error": "name, source_type, and template_id are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate template exists
        try:
            template = Template.objects.get(id=template_id)
        except Template.DoesNotExist:
            return Response(
                {"error": "Template not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        # Create data source
        data_source = DataSource.objects.create(
            name=name,
            source_type=source_type,
            template=template,
            connection_config=connection_config,
            field_mapping=field_mapping,
            transformation_rules=transformation_rules,
            created_by=request.user
        )

        # Log event
        log_audit_event(
            user=request.user,
            action='data_source_created',
            request=request,
            data_source_id=data_source.id,
            source_type=source_type
        )

        return Response({
            "message": "Data source created successfully.",
            "data_source_id": data_source.id,
            "name": data_source.name,
            "status": data_source.status
        }, status=status.HTTP_201_CREATED)


@method_decorator(csrf_exempt, name='dispatch')
class DataSourceTestView(APIView):
    """API endpoint for testing data source connection."""

    permission_classes = [IsAuthenticated]

    def post(self, request, data_source_id):
        """Test data source connection."""
        # Only admins can test data sources
        if request.user.role not in ['admin']:
            return Response(
                {"error": "Only admins can test data source connections."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Get data source
        try:
            data_source = DataSource.objects.get(id=data_source_id)
        except DataSource.DoesNotExist:
            return Response(
                {"error": "Data source not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        # Test connection based on source type
        try:
            if data_source.source_type == 'google_sheets':
                # Mock test for MVP (actual Google Sheets API would be called here)
                test_result = {
                    "success": True,
                    "message": "Connection successful (mock test for MVP)",
                    "sample_data": {
                        "creator_name": "John Doe",
                        "fee_amount": "50000"
                    }
                }
            elif data_source.source_type == 'google_forms':
                # Mock test for MVP
                test_result = {
                    "success": True,
                    "message": "Connection successful (mock test for MVP)",
                    "sample_data": {}
                }
            else:
                test_result = {
                    "success": False,
                    "message": "Unsupported source type"
                }

            # Update data source status
            if test_result['success']:
                data_source.status = 'active'
                data_source.error_message = None
            else:
                data_source.status = 'error'
                data_source.error_message = test_result['message']

            data_source.last_tested_at = timezone.now()
            data_source.save()

            # Log event
            log_audit_event(
                user=request.user,
                action='data_source_tested',
                request=request,
                data_source_id=data_source.id,
                test_success=test_result['success']
            )

            return Response({
                "message": "Connection test completed.",
                "test_result": test_result,
                "status": data_source.status
            }, status=status.HTTP_200_OK)

        except Exception as e:
            data_source.status = 'error'
            data_source.error_message = str(e)
            data_source.save()

            return Response(
                {"error": f"Connection test failed: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


@method_decorator(csrf_exempt, name='dispatch')
class DataSnapshotCreateView(APIView):
    """API endpoint for creating immutable data snapshot."""

    permission_classes = [IsAuthenticated]

    def post(self, request, data_source_id):
        """Create data snapshot from source."""
        # Get data source
        try:
            data_source = DataSource.objects.get(id=data_source_id)
        except DataSource.DoesNotExist:
            return Response(
                {"error": "Data source not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        # Check data source is active
        if data_source.status != 'active':
            return Response(
                {"error": "Data source is not active. Test connection first."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Fetch data from source (mock for MVP)
            snapshot_data = {
                "source": data_source.source_type,
                "fetched_at": timezone.now().isoformat(),
                "raw_data": {
                    "creator_name": "John Doe",
                    "fee_amount": "50000",
                    "project_name": "Sample Project"
                }
            }

            # Apply transformations
            transformed_data = apply_transformations(
                snapshot_data['raw_data'],
                data_source.transformation_rules
            )

            # Calculate checksum
            data_str = json.dumps(snapshot_data, sort_keys=True)
            checksum = hashlib.sha256(data_str.encode()).hexdigest()

            # Create snapshot
            snapshot = DataSnapshot.objects.create(
                data_source=data_source,
                snapshot_data=snapshot_data,
                transformed_data=transformed_data,
                checksum_sha256=checksum,
                created_by=request.user
            )

            # Update last sync
            data_source.last_sync_at = timezone.now()
            data_source.save()

            # Log event
            log_audit_event(
                user=request.user,
                action='data_snapshot_created',
                request=request,
                data_source_id=data_source.id,
                snapshot_id=snapshot.id,
                checksum=checksum
            )

            return Response({
                "message": "Data snapshot created successfully.",
                "snapshot_id": snapshot.id,
                "checksum": checksum,
                "transformed_data": transformed_data
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response(
                {"error": f"Snapshot creation failed: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


def apply_transformations(data, transformation_rules):
    """Apply transformation rules to data."""
    transformed = {}

    for field, value in data.items():
        # Apply field-specific transformations
        field_rules = transformation_rules.get(field, {})

        transformed_value = value

        # Date format transformation
        if field_rules.get('type') == 'date':
            # Would convert date formats here
            transformed_value = value

        # Currency transformation
        elif field_rules.get('type') == 'currency':
            # Would format currency here
            transformed_value = value

        # Text casing transformation
        elif field_rules.get('text_case'):
            if field_rules['text_case'] == 'upper':
                transformed_value = str(value).upper()
            elif field_rules['text_case'] == 'lower':
                transformed_value = str(value).lower()
            elif field_rules['text_case'] == 'title':
                transformed_value = str(value).title()

        transformed[field] = transformed_value

    return transformed


class DataSourceListView(APIView):
    """API endpoint for listing data sources."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        """List all data sources."""
        # Only admins can view data sources
        if request.user.role not in ['admin']:
            return Response(
                {"error": "Only admins can view data sources."},
                status=status.HTTP_403_FORBIDDEN
            )

        data_sources = DataSource.objects.all()

        data_sources_data = []
        for ds in data_sources:
            data_sources_data.append({
                'id': ds.id,
                'name': ds.name,
                'source_type': ds.source_type,
                'template_id': ds.template.id,
                'template_name': ds.template.name,
                'status': ds.status,
                'last_tested_at': ds.last_tested_at,
                'last_sync_at': ds.last_sync_at,
                'error_message': ds.error_message,
                'created_at': ds.created_at
            })

        return Response({
            'data_sources': data_sources_data
        }, status=status.HTTP_200_OK)
