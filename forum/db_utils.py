# forum/db_utils.py

from django.db import connection, transaction
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class DatabaseManager:
    @staticmethod
    def execute_read_query(query, params=None):
        """Exécuter une requête en lecture seule de manière sécurisée"""
        try:
            with connection.cursor() as cursor:
                cursor.execute(query, params or [])
                columns = [col[0] for col in cursor.description]
                return [dict(zip(columns, row)) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Erreur dans la requête: {e}")
            return None

    @staticmethod
    @transaction.atomic
    def execute_write_query(query, params=None):
        """Exécuter une requête en écriture de manière sécurisée"""
        try:
            with connection.cursor() as cursor:
                cursor.execute(query, params or [])
                return True
        except Exception as e:
            logger.error(f"Erreur dans la requête d'écriture: {e}")
            return False

    @staticmethod
    def get_topic_stats(topic_id):
        """Obtenir des statistiques détaillées sur un topic"""
        query = """
            SELECT 
                t.title,
                t.created_at,
                COUNT(DISTINCT c.id) as comment_count,
                COUNT(DISTINCT l.id) as like_count
            FROM forum_topic t
            LEFT JOIN forum_comment c ON c.topic_id = t.id
            LEFT JOIN forum_topic_likes l ON l.topic_id = t.id
            WHERE t.id = %s
            GROUP BY t.id, t.title, t.created_at
        """
        return DatabaseManager.execute_read_query(query, [topic_id])