# forum/middleware/sql_monitor.py

from django.http import HttpResponseForbidden
import logging
import re
from forum.utils.db_utils import DatabaseManager

logger = logging.getLogger(__name__)

class SQLInjectionDetectionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        # Utiliser les mêmes patterns que DatabaseManager
        self.patterns = [
            re.compile(pattern, re.IGNORECASE) 
            for pattern in DatabaseManager.DANGEROUS_PATTERNS
        ]

    def __call__(self, request):
        if not self.is_safe_request(request):
            ip = request.META.get('REMOTE_ADDR')
            user = request.user if request.user.is_authenticated else 'Anonymous'
            logger.warning(f"Tentative d'injection SQL détectée de {ip} (User: {user})")
            return HttpResponseForbidden("Requête non autorisée", content_type="text/plain")
        return self.get_response(request)

    def is_safe_request(self, request):
        """Vérifie si une requête est sûre"""
        # Vérifier GET params
        for value in request.GET.values():
            if self._contains_sql_injection(value):
                return False

        # Vérifier POST params
        for value in request.POST.values():
            if self._contains_sql_injection(value):
                return False

        return True

    def _contains_sql_injection(self, value):
        """Vérifie si une valeur contient une tentative d'injection SQL"""
        if not value:
            return False

        value = str(value)

        # Vérifier les keywords interdits
        value_upper = value.upper()
        for keyword in DatabaseManager.FORBIDDEN_KEYWORDS:
            if keyword in value_upper:
                return True

        # Vérifier les patterns dangereux
        for pattern in self.patterns:
            if pattern.search(value):
                return True

        return False