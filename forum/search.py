# forum/search.py

from django.db.models import Q
from django.core.cache import cache
from django.conf import settings

class SearchManager:
    @staticmethod
    def search_all(query, user=None):
        """Recherche sécurisée globale"""
        # Nettoyer la requête
        clean_query = SearchManager.clean_query(query)
        
        # Construire la requête
        base_query = Q(title__icontains=clean_query) | Q(content__icontains=clean_query)
        
        # Ajouter les conditions de sécurité
        if user and not user.is_staff:
            base_query &= (Q(is_private=False) | Q(author=user) | Q(members=user))
            
        return Topic.objects.filter(base_query).distinct()

    @staticmethod
    def clean_query(query):
        """Nettoyer la requête de recherche"""
        import re
        # Supprimer les caractères spéciaux
        clean = re.sub(r'[^\w\s]', '', query)
        # Limiter la longueur
        return clean[:100]