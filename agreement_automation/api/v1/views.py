"""
API v1 Views
"""
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from datetime import datetime


class HealthCheckView(APIView):
    """
    Health check endpoint for monitoring system status.
    Returns health status and timestamp.
    """
    permission_classes = [AllowAny]  # No authentication required for health check

    def get(self, request):
        return Response({
            "status": "healthy",
            "timestamp": datetime.now().isoformat()
        })
