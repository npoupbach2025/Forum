from django.utils import timezone
from django.contrib.auth.models import User
from .models import Topic

def forum_stats(request):
    """
    Ajoute les statistiques globales du forum au contexte de tous les templates
    """
    # Récupérer les statistiques globales
    total_members = User.objects.count()
    total_discussions = Topic.objects.count()
    
    # Récupérer les utilisateurs en ligne
    online_users = User.objects.filter(
        last_login__gte=timezone.now() - timezone.timedelta(minutes=5)
    ).exclude(id=request.user.id if request.user.is_authenticated else None)
    
    online_count = online_users.count()
    if request.user.is_authenticated:
        online_count += 1
    
    return {
        'total_members': total_members,
        'total_discussions': total_discussions,
        'online_count': online_count,
    }
