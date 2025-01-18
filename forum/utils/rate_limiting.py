# Create rate_limiting.py
from django.core.cache import cache
from django.core.exceptions import PermissionDenied
from functools import wraps
import time

def rate_limit(key_prefix, limit=100, period=3600):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            # Créer une clé unique par utilisateur/IP
            cache_key = f"{key_prefix}_{request.user.id or request.META.get('REMOTE_ADDR')}"
            
            # Vérifier le nombre de requêtes
            requests = cache.get(cache_key, 0)
            if requests >= limit:
                raise PermissionDenied("Trop de requêtes. Réessayez plus tard.")
            
            # Incrémenter le compteur
            cache.set(cache_key, requests + 1, period)
            
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator