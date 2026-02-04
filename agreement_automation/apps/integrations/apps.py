"""App configuration for integrations."""

from django.apps import AppConfig


class IntegrationsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'agreement_automation.apps.integrations'
