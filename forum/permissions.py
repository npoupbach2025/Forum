# forum/permissions.py

from functools import wraps
from django.shortcuts import redirect
from django.contrib import messages
from django.core.exceptions import PermissionDenied

def admin_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if request.user.is_authenticated and request.user.is_superuser:
            return view_func(request, *args, **kwargs)
        messages.error(request, "Accès réservé aux administrateurs.")
        return redirect('forum:home')
    return _wrapped_view

def moderator_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if request.user.is_authenticated and (request.user.is_superuser or request.user.is_staff):
            return view_func(request, *args, **kwargs)
        messages.error(request, "Accès réservé aux modérateurs.")
        return redirect('forum:home')
    return _wrapped_view