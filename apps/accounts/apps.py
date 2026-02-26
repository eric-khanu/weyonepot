from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class AccountsConfig(AppConfig):
    """Accounts app configuration"""
    
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.accounts'
    verbose_name = _('Accounts')
    
    def ready(self):
        """
        Import signals when app is ready
        """
        try:
            import apps.accounts.signals  # noqa
        except ImportError:
            pass