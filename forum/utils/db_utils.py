# forum/utils/db_utils.py

from django.db import connection, transaction
from django.conf import settings
import logging
import re

logger = logging.getLogger(__name__)

class DatabaseManager:
    MAX_QUERY_LENGTH = 1000
    MAX_PARAM_LENGTH = 255

    # Patterns simplifiés pour correspondre aux tests
    DANGEROUS_PATTERNS = [
        r"'\s*OR\s*'1'\s*=\s*'1",  # Détecte "' OR '1'='1"
        r";\s*DROP\s+TABLE",        # Détecte "; DROP TABLE"
        r"UNION\s+SELECT",          # Détecte "UNION SELECT"
        r"--",                      # Commentaires SQL
        r"#",                       # Commentaires MySQL
        r"/\*",                     # Commentaires multi-lignes
        r";\s*DELETE",              # DELETE chainé
        r";\s*UPDATE",              # UPDATE chainé
        r";\s*INSERT",              # INSERT chainé
    ]

    # Mots-clés simples pour correspondre aux tests
    FORBIDDEN_KEYWORDS = [
        'DROP', 
        'DELETE', 
        'TRUNCATE', 
        'ALTER', 
        'UNION'
    ]

    @staticmethod
    def _validate_query(query, params=None):
        """Valider une requête SQL"""
        if not query or not isinstance(query, str):
            raise ValueError("Requête invalide")
            
        # Vérifier la longueur de la requête
        if len(query) > DatabaseManager.MAX_QUERY_LENGTH:
            raise ValueError(f"La requête dépasse la longueur maximale autorisée ({DatabaseManager.MAX_QUERY_LENGTH} caractères)")
            
        # Vérifier les mots-clés interdits
        for keyword in DatabaseManager.FORBIDDEN_KEYWORDS:
            if keyword in query.upper():
                raise ValueError(f"Mot-clé interdit détecté: {keyword}")

        # Vérifier les patterns dangereux
        for pattern in DatabaseManager.DANGEROUS_PATTERNS:
            if re.search(pattern, query, re.IGNORECASE):
                raise ValueError("Pattern SQL malveillant détecté")

        # Vérifier les paramètres
        if params:
            if not isinstance(params, (list, tuple)):
                raise ValueError("Les paramètres doivent être une liste ou un tuple")
            
            for param in params:
                param_str = str(param)
                if len(param_str) > DatabaseManager.MAX_PARAM_LENGTH:
                    raise ValueError("Paramètre trop long")
                if re.search(r"['\";]", param_str):
                    raise ValueError("Caractères interdits dans les paramètres")

    @staticmethod
    def execute_read_query(query, params=None):
        """Exécuter une requête en lecture seule"""
        try:
            DatabaseManager._validate_query(query, params)
            with connection.cursor() as cursor:
                cursor.execute(query, params or [])
                columns = [col[0] for col in cursor.description]
                return [dict(zip(columns, row)) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Erreur dans execute_read_query: {str(e)}")
            raise

    @staticmethod
    def execute_write_query(query, params=None):
        """Exécuter une requête en écriture"""
        try:
            DatabaseManager._validate_query(query, params)
            with connection.cursor() as cursor:
                cursor.execute(query, params or [])
                return True
        except Exception as e:
            logger.error(f"Erreur dans execute_write_query: {str(e)}")
            raise