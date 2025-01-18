# Create heavy_queries.py
from django.db import models, connection
from django.core.cache import cache
import hashlib

class ComplexQueryManager:
    @staticmethod
    def execute_heavy_query(query, params=None, cache_time=300):
        # Créer un hash unique pour la requête
        query_hash = hashlib.md5(
            f"{query}_{str(params)}".encode()
        ).hexdigest()
        
        # Vérifier le cache
        cached_result = cache.get(query_hash)
        if cached_result:
            return cached_result
            
        with connection.cursor() as cursor:
            cursor.execute(query, params or [])
            result = cursor.fetchall()
            
            # Mettre en cache
            cache.set(query_hash, result, cache_time)
            
            return result