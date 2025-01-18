import re
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import transaction
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.utils import timezone
from django.http import JsonResponse, HttpResponse
from django.urls import reverse
from datetime import timedelta
from django.contrib.auth.forms import UserCreationForm
from django.contrib import messages
from django.contrib.auth import logout
from .models import UserProfile, Category, Topic, Comment, FriendRequest, Activity, Report
from django.contrib import admin
from django.http import JsonResponse
from django.contrib.auth.models import User
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.decorators import user_passes_test
from django.utils import timezone
from datetime import timedelta
from django.db import models
from django.db.models import Count, Q
from .permissions import admin_required, moderator_required
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.hashers import make_password
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from django.core.validators import MinLengthValidator
from django.utils.translation import gettext_lazy as _
import os
from django.db import connection
from .db_utils import DatabaseManager
from .search import SearchManager
from django.db import transaction
from captcha.fields import CaptchaField
from django.core.exceptions import ValidationError
from .models import LoginAttempt, CaptchaRequirement
from django import forms  
from .models import LoginAttempt
from django_ratelimit.decorators import ratelimit
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django_ratelimit.decorators import ratelimit
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
 
class UserMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
 
    def __call__(self, request):
        if request.user.is_authenticated:
            try:
                # Tenter d'accéder au profil
                profile = request.user.profile
            except:
                # Si le profil n'existe pas, le créer
                from .models import UserProfile
                last_profile = UserProfile.objects.order_by('-forum_id').first()
                new_forum_id = 1000 if not last_profile else last_profile.forum_id + 1
                profile = UserProfile.objects.create(
                    user=request.user,
                    forum_id=new_forum_id
                )
 
            # Mettre à jour last_activity
            profile.last_activity = timezone.now()
            profile.save(update_fields=['last_activity'])
 
        return self.get_response(request)
 
def is_moderator(user):
    return user.is_superuser or user.is_staff
 
@login_required
def profile_view(request, username):
    profile_user = get_object_or_404(User, username=username)
    user_topics = Topic.objects.filter(author=profile_user).order_by('-created_at')
    user_comments = Comment.objects.filter(author=profile_user).order_by('-created_at')
   
    # Combiner les topics et commentaires pour l'activité récente
    recent_activities = []
    for topic in user_topics[:5]:
        recent_activities.append({
            'type': 'topic',
            'title': topic.title,
            'id': topic.id,
            'created_at': topic.created_at
        })
   
    for comment in user_comments[:5]:
        recent_activities.append({
            'type': 'comment',
            'title': f'Réponse dans "{comment.topic.title}"',
            'id': comment.topic.id,
            'created_at': comment.created_at
        })
   
    # Trier par date et prendre les 5 plus récents
    recent_activities.sort(key=lambda x: x['created_at'], reverse=True)
    recent_activities = recent_activities[:5]
   
    context = {
        'profile_user': profile_user,
        'profile': profile_user.profile,
        'user_chats': Topic.get_user_chats(request.user),
        'total_topics': user_topics.count(),
        'total_comments': Comment.objects.filter(author=profile_user).count(),
        'recent_activity': recent_activities,
        'is_friend': profile_user.profile in request.user.profile.friends.all() if request.user != profile_user else None,
        'total_friends': profile_user.profile.friends.count()
    }
   
    return render(request, 'forum/profile.html', context)
 
 
def search_topics(request, query):
    """Recherche sécurisée dans les topics"""
    # Utiliser Q objects pour des recherches complexes
    return Topic.objects.filter(
        Q(title__icontains=query) |
        Q(content__icontains=query),
        is_private=False
    ).select_related('author').order_by('-created_at')
 
def get_user_stats(request, user_id):
    query = """
        SELECT
            COUNT(DISTINCT t.id) as total_topics,
            COUNT(DISTINCT c.id) as total_comments
        FROM forum_topic t
        LEFT JOIN forum_comment c ON c.author_id = %s
        WHERE t.author_id = %s
    """
    stats = DatabaseManager.execute_read_query(
        query,
        [user_id, user_id],
        cache_key=f"user_stats_{user_id}"
    )
    return JsonResponse(stats[0] if stats else {})
 
 
def search_view(request):
    query = request.GET.get('q', '')
    results = SearchManager.search_all(query, request.user)
    return render(request, 'forum/search.html', {'results': results})
 
def topic_stats_view(request, topic_id):
    stats = DatabaseManager.get_topic_stats(topic_id)
    return render(request, 'forum/topic_stats.html', {'stats': stats})
 
@login_required
def change_password(request):
    if request.method == 'POST':
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
 
        # Vérifier que l'utilisateur a bien entré tous les champs
        if not all([current_password, new_password, confirm_password]):
            messages.error(request, 'Veuillez remplir tous les champs pour changer votre mot de passe.')
            return redirect('forum:profile', username=request.user.username)
 
        # Vérifier que le nouveau mot de passe et la confirmation correspondent
        if new_password != confirm_password:
            messages.error(request, 'Le nouveau mot de passe et sa confirmation ne correspondent pas.')
            return redirect('forum:profile', username=request.user.username)
 
        # Vérifier que l'ancien mot de passe est correct
        if not request.user.check_password(current_password):
            messages.error(request, 'Votre mot de passe actuel est incorrect.')
            return redirect('forum:profile', username=request.user.username)
 
        try:
            # Valider le nouveau mot de passe
            validate_password(new_password, request.user)
           
            # Si tout est bon, on change le mot de passe
            request.user.set_password(new_password)
            request.user.save()
           
            # Mettre à jour la session pour éviter la déconnexion
            update_session_auth_hash(request, request.user)
           
            messages.success(request, 'Votre mot de passe a été modifié avec succès.')
        except ValidationError as e:
            messages.error(request, '\n'.join(e.messages))
        except Exception as e:
            messages.error(request, 'Une erreur est survenue lors du changement de mot de passe.')
       
        return redirect('forum:profile', username=request.user.username)
 
    return redirect('forum:profile', username=request.user.username)
 
@login_required
def update_bio(request):
    if request.method == 'POST':
        bio = request.POST.get('bio')
        request.user.profile.bio = bio
        request.user.profile.save()
        messages.success(request, 'Bio mise à jour avec succès.')
   
    return redirect('forum:profile', username=request.user.username)
 
@login_required
def remove_friend(request):
    if request.method == 'POST':
        friend_id = request.POST.get('friend_id')
        try:
            friend_profile = UserProfile.objects.get(forum_id=friend_id)
            request.user.profile.friends.remove(friend_profile)
            friend_profile.friends.remove(request.user.profile)
            messages.success(request, 'Ami supprimé avec succès.')
        except UserProfile.DoesNotExist:
            messages.error(request, 'Utilisateur non trouvé.')
   
    return redirect('forum:profile', username=request.user.username)
 
@login_required
def update_avatar(request):
    if request.method == 'POST' and request.FILES.get('avatar'):
        profile = request.user.profile
        # Si l'utilisateur avait déjà un avatar, on le supprime
        if profile.avatar:
            profile.avatar.delete()
       
        profile.avatar = request.FILES['avatar']
        profile.save()
        messages.success(request, 'Photo de profil mise à jour avec succès.')
   
    return redirect('forum:profile', username=request.user.username)
 
@login_required
def mod_reports(request):
    if not request.user.is_staff and not is_moderator(request.user):
        messages.error(request, "Vous n'avez pas les permissions nécessaires.")
        return redirect('forum:home')
       
    # Récupérer tous les signalements
    reports = Report.objects.all().order_by('-created_at')
   
    # Filtrer par statut si spécifié
    status_filter = request.GET.get('status')
    if status_filter and status_filter != 'all':
        reports = reports.filter(status=status_filter)
   
    context = {
        'reports': reports,
        'report_types': Report.REPORT_TYPES,
        'status_choices': Report.STATUS_CHOICES,
        'current_status': status_filter or 'all'
    }
   
    return render(request, 'forum/moderation/reports.html', context)
 
@login_required
def handle_report(request, report_id):
    if not request.user.is_staff and not is_moderator(request.user):
        messages.error(request, "Vous n'avez pas les permissions nécessaires.")
        return redirect('forum:home')
       
    report = get_object_or_404(Report, id=report_id)
    action = request.POST.get('action')
   
    if action == 'resolve':
        report.status = 'resolved'
        report.handled_by = request.user
        report.handled_at = timezone.now()
        report.save()
        messages.success(request, "Le signalement a été marqué comme résolu.")
    elif action == 'dismiss':
        report.status = 'dismissed'
        report.handled_by = request.user
        report.handled_at = timezone.now()
        report.save()
        messages.success(request, "Le signalement a été rejeté.")
       
    return redirect('forum:mod_reports')
 
@user_passes_test(is_moderator)
def mod_dashboard(request):
    context = {
        'total_users': User.objects.count(),
        'total_topics': Topic.objects.count(),
        'total_comments': Comment.objects.count(),
        'recent_topics': Topic.objects.order_by('-created_at')[:5],
        'recent_users': User.objects.order_by('-date_joined')[:5],
        'user_chats': Topic.get_user_chats(request.user) if request.user.is_authenticated else None,
    }
    return render(request, 'forum/moderation/dashboard.html', context)
 
@user_passes_test(is_moderator)
def mod_users(request):
    users = User.objects.all().order_by('-date_joined')
    context = {
        'users': users,
        'user_chats': Topic.get_user_chats(request.user) if request.user.is_authenticated else None,
    }
    return render(request, 'forum/moderation/users.html', context)
 
@user_passes_test(is_moderator)
def mod_topics(request):
    topics = Topic.objects.all().order_by('-created_at')
    context = {
        'topics': topics,
        'user_chats': Topic.get_user_chats(request.user) if request.user.is_authenticated else None,
    }
    return render(request, 'forum/moderation/topics.html', context)
 
@user_passes_test(is_moderator)
def mod_reports(request):
    reports = Report.objects.filter(status='pending').order_by('-created_at')
    context = {
        'reports': reports,
        'user_chats': Topic.get_user_chats(request.user) if request.user.is_authenticated else None,
    }
    print(f"Debug - Reports count: {reports.count()}")  # Debug
    return render(request, 'forum/moderation/reports.html', context)
 
@user_passes_test(is_moderator)
def handle_report(request, report_id):
    if request.method == 'POST':
        report = get_object_or_404(Report, id=report_id)
        action = request.POST.get('action')
       
        if action == 'resolve':
            report.status = 'resolved'
            report.handled_by = request.user
            report.handled_at = timezone.now()
            report.save()
            messages.success(request, 'Signalement résolu.')
        elif action == 'dismiss':
            report.status = 'dismissed'
            report.handled_by = request.user
            report.handled_at = timezone.now()
            report.save()
            messages.success(request, 'Signalement rejeté.')
           
    return redirect('forum:mod_reports')
 
@user_passes_test(is_moderator)
def mod_delete_user(request, user_id):
    if request.method == 'POST':
        user = get_object_or_404(User, id=user_id)
        if user != request.user and not user.is_superuser:
            username = user.username
            user.delete()
            messages.success(request, f"L'utilisateur {username} a été supprimé.")
        else:
            messages.error(request, "Impossible de supprimer cet utilisateur.")
    return redirect('forum:mod_users')
 
@user_passes_test(is_moderator)
def mod_edit_user(request, user_id):
    if request.method == 'POST':
        user = get_object_or_404(User, id=user_id)
        if user != request.user and not user.is_superuser:
            try:
                user.username = request.POST.get('username')
                user.email = request.POST.get('email')
                user.is_staff = request.POST.get('status') == 'mod'
                user.save()
                messages.success(request, f"L'utilisateur {user.username} a été modifié.")
                return JsonResponse({
                    'success': True,
                    'username': user.username,
                    'email': user.email,
                    'status': 'mod' if user.is_staff else 'user'
                })
            except Exception as e:
                return JsonResponse({
                    'success': False,
                    'error': str(e)
                }, status=400)
        else:
            return JsonResponse({
                'success': False,
                'error': "Impossible de modifier cet utilisateur."
            }, status=403)
    return JsonResponse({'success': False, 'error': "Méthode non autorisée."}, status=405)
 
 
# forum/views.py
 
@user_passes_test(is_moderator)
def mod_delete_user(request, user_id):
    if request.method == 'POST':
        user = get_object_or_404(User, id=user_id)
        if user != request.user and not user.is_superuser:
            username = user.username
            user.delete()
            messages.success(request, f"L'utilisateur {username} a été supprimé.")
        else:
            messages.error(request, "Impossible de supprimer cet utilisateur.")
    return redirect('forum:mod_users')
 
@user_passes_test(is_moderator)
def mod_edit_user(request, user_id):
    if request.method == 'POST':
        user = get_object_or_404(User, id=user_id)
        if user != request.user and not user.is_superuser:
            try:
                user.username = request.POST.get('username')
                user.email = request.POST.get('email')
                user.is_staff = request.POST.get('status') == 'mod'
                user.save()
                messages.success(request, f"L'utilisateur {user.username} a été modifié.")
                return JsonResponse({
                    'success': True,
                    'username': user.username,
                    'email': user.email,
                    'status': 'mod' if user.is_staff else 'user'
                })
            except Exception as e:
                return JsonResponse({
                    'success': False,
                    'error': str(e)
                }, status=400)
        else:
            return JsonResponse({
                'success': False,
                'error': "Impossible de modifier cet utilisateur."
            }, status=403)
    return JsonResponse({'success': False, 'error': "Méthode non autorisée."}, status=405)
 
def is_moderator(user):
    return user.is_superuser or user.is_staff
 
@user_passes_test(is_moderator)
def mod_dashboard(request):
    context = {
        'total_users': User.objects.count(),
        'total_topics': Topic.objects.count(),
        'total_comments': Comment.objects.count(),
        'recent_topics': Topic.objects.order_by('-created_at')[:5],
        'recent_users': User.objects.order_by('-date_joined')[:5],
    }
    return render(request, 'forum/moderation/dashboard.html', context)
 
@user_passes_test(is_moderator)
def mod_users(request):
    users = User.objects.all().order_by('-date_joined')
    return render(request, 'forum/moderation/users.html', {'users': users})
 
@user_passes_test(is_moderator)
def mod_topics(request):
    topics = Topic.objects.all().order_by('-created_at')
    return render(request, 'forum/moderation/topics.html', {'topics': topics})
 
@user_passes_test(is_moderator)
def mod_reports(request):
    # Récupérer tous les signalements, triés par date décroissante
    reports = Report.objects.all().order_by('-created_at')
   
    # Appliquer le filtre si demandé
    status_filter = request.GET.get('status')
    if status_filter and status_filter != 'all':
        reports = reports.filter(status=status_filter)
   
    context = {
        'reports': reports,
        'user_chats': Topic.get_user_chats(request.user) if request.user.is_authenticated else None,
    }
    return render(request, 'forum/moderation/reports.html', context)
 
 
def rules_view(request):
    return render(request, 'forum/rules.html', {
        'user_chats': Topic.get_user_chats(request.user) if request.user.is_authenticated else None
    })
 
@admin_required
def admin_dashboard(request):
    stats = {
        'total_users': User.objects.count(),
        'total_topics': Topic.objects.count(),
        'total_comments': Comment.objects.count(),
        'categories': Category.objects.annotate(topics_count=Count('topics')),
        'recent_users': User.objects.order_by('-date_joined')[:5],
        'recent_topics': Topic.objects.order_by('-created_at')[:5],
    }
    return render(request, 'forum/admin/dashboard.html', stats)
 
@admin_required
def manage_users(request):
    users = User.objects.all().order_by('-date_joined')
    return render(request, 'forum/admin/manage_users.html', {'users': users})
 
@admin_required
def delete_user(request, user_id):
    if request.method == 'POST':
        user = get_object_or_404(User, id=user_id)
        if user != request.user:  # Empêcher l'auto-suppression
            user.delete()
            messages.success(request, f"L'utilisateur {user.username} a été supprimé.")
        else:
            messages.error(request, "Vous ne pouvez pas supprimer votre propre compte.")
    return redirect('forum:admin_manage_users')
 
@admin_required
def manage_categories(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description')
        if name and description:
            Category.objects.create(name=name, description=description)
            messages.success(request, f"La catégorie {name} a été créée.")
            return redirect('forum:admin_manage_categories')
       
    categories = Category.objects.annotate(topics_count=Count('topics'))
    return render(request, 'forum/admin/manage_categories.html', {'categories': categories})
 
@admin_required
def delete_category(request, category_id):
    if request.method == 'POST':
        category = get_object_or_404(Category, id=category_id)
        category.delete()
        messages.success(request, f"La catégorie {category.name} a été supprimée.")
    return redirect('forum:admin_manage_categories')
 
@user_passes_test(is_moderator)
def moderate_topic(request, topic_id):
    topic = get_object_or_404(Topic, id=topic_id)
    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'delete':
            topic.delete()
            messages.success(request, "Le sujet a été supprimé.")
            return redirect('forum:mod_topics')
        elif action == 'close':
            topic.is_closed = not topic.is_closed
            topic.save()
            messages.success(request, "Le statut de fermeture a été modifié.")
            return redirect('forum:mod_topics')
   
    # Si ce n'est pas une requête POST ou si l'action n'est pas reconnue,
    # rediriger vers la liste des topics
    return redirect('forum:mod_topics')
 
@login_required
def create_topic(request, category_name=None):
    if request.method == 'POST':
        form = TopicForm(request.POST)
        if form.is_valid():
            topic = form.save(commit=False)
            topic.author = request.user
            topic.save()
            
            # Créer une activité pour la nouvelle discussion
            Activity.objects.create(
                user=request.user,
                type='new_topic',
                topic=topic,
                content=f"a créé une nouvelle discussion : {topic.title}"
            )
            
            messages.success(request, 'Discussion créée avec succès!')
            return redirect('forum:topic_view', topic_id=topic.id)
    else:
        initial = {}
        if category_name:
            category = get_object_or_404(Category, name=category_name)
            initial['category'] = category
        form = TopicForm(initial=initial)
    
    return render(request, 'forum/create_topic.html', {'form': form})

@login_required
def reply_topic(request, topic_id):
    topic = get_object_or_404(Topic, id=topic_id)
    
    if request.method == 'POST':
        content = request.POST.get('content')
        if content:
            comment = Comment.objects.create(
                content=content,
                author=request.user,
                topic=topic
            )
            
            # Créer une activité pour la nouvelle réponse
            Activity.objects.create(
                user=request.user,
                type='new_reply',
                topic=topic,
                comment=comment
            )
            
            return JsonResponse({
                'status': 'success',
                'comment': {
                    'id': comment.id,
                    'content': comment.content,
                    'author': comment.author.username,
                    'created_at': comment.created_at.strftime('%Y-%m-%d %H:%M:%S')
                }
            })
        else:
            return JsonResponse({
                'status': 'error',
                'error': 'Contenu manquant.'
            })
    return JsonResponse({
        'status': 'error',
        'error': 'Méthode non autorisée.'
    }, status=405)
 
 
 
class HttpResponseTooManyRequests(HttpResponse):
    status_code = 429
 
def ratelimit_handler(request, exception):
    return HttpResponseTooManyRequests("Too many requests. Please try again later.")
 
def get_online_users():
    # Considère un utilisateur comme en ligne s'il a été actif dans les 5 dernières minutes
    time_threshold = timezone.now() - timedelta(minutes=5)
    return UserProfile.objects.filter(last_activity__gte=time_threshold).count()

def get_online_users_list():
    time_threshold = timezone.now() - timedelta(minutes=5)
    return UserProfile.objects.filter(last_activity__gte=time_threshold).select_related('user')

def get_recent_activities(limit=10):
    # Récupérer les activités récentes (topics et commentaires)
    recent_topics = Topic.objects.select_related('author').order_by('-created_at')[:limit]
    recent_comments = Comment.objects.select_related('author', 'topic').order_by('-created_at')[:limit]
    
    # Combiner et trier les activités
    activities = []
    
    for topic in recent_topics:
        activities.append({
            'type': 'topic',
            'user': topic.author,
            'content': topic.title,
            'date': topic.created_at,
            'topic': topic
        })
    
    for comment in recent_comments:
        activities.append({
            'type': 'comment',
            'user': comment.author,
            'content': comment.content[:100] + '...' if len(comment.content) > 100 else comment.content,
            'date': comment.created_at,
            'topic': comment.topic
        })
    
    # Trier par date décroissante
    activities.sort(key=lambda x: x['date'], reverse=True)
    return activities[:limit]

def create_default_categories():
    default_categories = [
        {
            'name': 'Général',
            'description': 'Discussions générales et présentations'
        },
        {
            'name': 'Actualités',
            'description': 'Actualités et nouveautés'
        },
        {
            'name': 'Aide',
            'description': 'Besoin d\'aide ? C\'est ici !'
        },
        {
            'name': 'Suggestions',
            'description': 'Vos idées pour améliorer le forum'
        },
        {
            'name': 'Off-Topic',
            'description': 'Discussions diverses hors-sujet'
        }
    ]

    # Supprimer toutes les anciennes catégories
    Category.objects.all().delete()
    
    # Créer les nouvelles catégories
    for category in default_categories:
        Category.objects.get_or_create(
            name=category['name'],
            defaults={'description': category['description']}
        )

def home(request):
    """Vue pour la page d'accueil"""
    categories = Category.objects.all()
    activities = Activity.objects.select_related('user', 'topic').order_by('-created_at')[:10]
    
    activities_data = []
    for activity in activities:
        activity_info = {
            'user': activity.user,
            'created_at': activity.created_at,
            'type': activity.type,
        }
        
        if activity.type == 'new_topic':
            activity_info['message'] = f"a créé une nouvelle discussion : {activity.topic.title}"
            activity_info['link'] = reverse('forum:topic_view', args=[activity.topic.id])
        elif activity.type == 'new_reply':
            activity_info['message'] = f"a répondu à la discussion : {activity.topic.title}"
            activity_info['link'] = reverse('forum:topic_view', args=[activity.topic.id])
        elif activity.type == 'new_member':
            activity_info['message'] = "a rejoint le forum"
            activity_info['link'] = None
        
        activities_data.append(activity_info)
    
    return render(request, 'forum/home.html', {
        'categories': categories,
        'activities': activities_data,
    })
 
def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(username=username, password=password)

        # Vérifier si l'utilisateur existe
        try:
            user_obj = User.objects.get(username=username)
        except User.DoesNotExist:
            messages.error(request, "Nom d'utilisateur incorrect.")
            return redirect('forum:login')

        # Obtenir l'adresse IP
        ip_address = request.META.get('REMOTE_ADDR')
        
        # Vérifier si l'utilisateur est bloqué
        is_locked, time_remaining = LoginAttempt.is_locked_out(user_obj, ip_address)
        if is_locked:
            messages.error(request, f'Compte temporairement bloqué. Réessayez dans {time_remaining} secondes.')
            return redirect('forum:login')

        # Vérifier si le captcha est requis
        requires_captcha = CaptchaRequirement.is_required(user_obj, ip_address)
        form = LoginForm(request.POST, requires_captcha=requires_captcha)

        if not form.is_valid():
            messages.error(request, 'Formulaire invalide. Veuillez réessayer.')
            return render(request, 'forum/login.html', {'form': form})

        if user is not None:
            # Réinitialiser les tentatives échouées en cas de succès
            LoginAttempt.reset_failed_attempts(user_obj, ip_address)
            
            # Enregistrer la tentative réussie
            LoginAttempt.objects.create(
                user=user_obj,
                ip_address=ip_address,
                was_successful=True
            )
            
            login(request, user)
            return redirect('forum:home')
        else:
            # Enregistrer la tentative échouée
            LoginAttempt.objects.create(
                user=user_obj,
                ip_address=ip_address,
                was_successful=False
            )
            
            # Vérifier le nombre de tentatives échouées
            failed_attempts = LoginAttempt.get_failed_attempts(user_obj, ip_address)
            
            # Activer le captcha après 3 tentatives échouées
            if failed_attempts >= 3:
                CaptchaRequirement.require_captcha(user_obj, ip_address)

            messages.error(request, 'Mot de passe incorrect.')
            return redirect('forum:login')
    
    # GET request - afficher le formulaire
    requires_captcha = False
    if request.user.is_authenticated:
        ip_address = request.META.get('REMOTE_ADDR')
        requires_captcha = CaptchaRequirement.is_required(request.user, ip_address)
    
    form = LoginForm(requires_captcha=requires_captcha)
    return render(request, 'forum/login.html', {'form': form})
 
def register(request):
    if request.method == 'POST':
        try:
            username = request.POST.get('username')
            password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')

            # Vérification des champs
            if not all([username, password, confirm_password]):
                messages.error(request, "Tous les champs sont requis.")
                return render(request, 'forum/register.html')

            # Vérification des mots de passe
            if password != confirm_password:
                messages.error(request, "Les mots de passe ne correspondent pas.")
                return render(request, 'forum/register.html')

            # Vérification de la longueur du mot de passe
            if len(password) < 8:
                messages.error(request, "Le mot de passe doit contenir au moins 8 caractères.")
                return render(request, 'forum/register.html')

            # Vérification de la complexité du mot de passe
            if not any(c.isupper() for c in password) or \
               not any(c.islower() for c in password) or \
               not any(c.isdigit() for c in password):
                messages.error(request, "Le mot de passe doit contenir au moins une majuscule, une minuscule et un chiffre.")
                return render(request, 'forum/register.html')

            # Vérification de l'unicité du nom d'utilisateur
            if User.objects.filter(username=username).exists():
                messages.error(request, "Ce nom d'utilisateur est déjà pris.")
                return render(request, 'forum/register.html')

            # Vérification de la longueur du nom d'utilisateur
            if len(username) < 3:
                messages.error(request, "Le nom d'utilisateur doit contenir au moins 3 caractères.")
                return render(request, 'forum/register.html')

            # Vérification des caractères autorisés dans le nom d'utilisateur
            if not re.match("^[a-zA-Z0-9_-]+$", username):
                messages.error(request, "Le nom d'utilisateur ne peut contenir que des lettres, des chiffres, des tirets et des underscores.")
                return render(request, 'forum/register.html')

            # Créer l'utilisateur
            user = User.objects.create_user(
                username=username,
                password=password
            )

            # Obtenir le dernier forum_id de manière sécurisée
            last_profile = UserProfile.objects.all().order_by('-forum_id').select_for_update().first()
            new_forum_id = 1000 if not last_profile else last_profile.forum_id + 1

            # Créer le profil utilisateur
            try:
                UserProfile.objects.create(
                    user=user,
                    forum_id=new_forum_id
                )
            except Exception as e:
                user.delete()
                raise Exception("Erreur lors de la création du profil utilisateur")

            messages.success(request, "Compte créé avec succès! Vous pouvez maintenant vous connecter.")
            return redirect('forum:login')

        except Exception as e:
            messages.error(request, f"Une erreur est survenue lors de la création du compte: {str(e)}")
            return render(request, 'forum/register.html')

    return render(request, 'forum/register.html')
 
 
 
@login_required
def create_private_topic(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        content = request.POST.get('content')
        friend_id = request.POST.get('friend')
       
        if title and content and friend_id:
            try:
                friend = Profile.objects.get(id=friend_id)
               
                # Vérifier si une discussion existe déjà
                existing_chat = Topic.objects.filter(
                    (Q(author=request.user) & Q(with_friend=friend)) |
                    (Q(author=friend.user) & Q(with_friend=request.user.profile)),
                    is_private=True
                ).first()
               
                if existing_chat:
                    return JsonResponse({
                        'success': True,
                        'chat_id': existing_chat.id,
                        'friend_username': friend.user.username,
                        'message': 'Discussion existante'
                    })
               
                # Si pas de discussion existante, en créer une nouvelle
                private_category, _ = Category.objects.get_or_create(
                    name='private',
                    defaults={'description': 'Forums privés'}
                )
               
                topic = Topic.objects.create(
                    title=title,
                    author=request.user,
                    category=private_category,
                    with_friend=friend,
                    is_private=True
                )
               
                # Créer une activité pour la nouvelle discussion
                Activity.objects.create(
                    user=request.user,
                    type='new_topic',
                    topic=topic,
                    content=f"a créé une nouvelle discussion privée : {title}"
                )
               
                return JsonResponse({
                    'success': True,
                    'chat_id': topic.id,
                    'friend_username': friend.user.username,
                    'message': 'Nouvelle discussion créée'
                })
               
            except Profile.DoesNotExist:
                return JsonResponse({
                    'success': False,
                    'error': 'Ami non trouvé.'
                })
            except Exception as e:
                return JsonResponse({
                    'success': False,
                    'error': str(e)
                })
        else:
            return JsonResponse({
                'success': False,
                'error': 'Titre et ami requis.'
            })
   
    return JsonResponse({
        'success': False,
        'error': 'Méthode non autorisée.'
    }, status=405)
 
 
 
@login_required
def reply_topic(request, topic_id):
    topic = get_object_or_404(Topic, id=topic_id)
   
    if request.method == 'POST':
        content = request.POST.get('content')
        if content:
            comment = Comment.objects.create(
                content=content,
                author=request.user,
                topic=topic
            )
           
            # Créer une activité pour la nouvelle réponse
            Activity.objects.create(
                user=request.user,
                type='new_reply',
                topic=topic,
                comment=comment
            )
           
            return JsonResponse({
                'status': 'success',
                'comment': {
                    'id': comment.id,
                    'content': comment.content,
                    'author': comment.author.username,
                    'created_at': comment.created_at.strftime('%Y-%m-%d %H:%M:%S')
                }
            })
        else:
            return JsonResponse({
                'status': 'error',
                'error': 'Contenu manquant.'
            })
    return JsonResponse({
        'status': 'error',
        'error': 'Méthode non autorisée.'
    }, status=405)
 
 
 
@login_required
def topic_view(request, topic_id):
    from django.shortcuts import render, redirect, get_object_or_404
    from django.contrib.auth.decorators import login_required
    from django.contrib.auth.forms import UserCreationForm
    from django.contrib import messages
    from django.contrib.auth import logout
    from .models import UserProfile, Category, Topic, Comment, FriendRequest
    topic = get_object_or_404(Topic, id=topic_id)
    comments = topic.comments.all().order_by('created_at')
   
    # Incrémenter le compteur de vues
    topic.views += 1
    topic.save()
   
    context = {
        'topic': topic,
        'comments': comments,
    }
    return render(request, 'forum/topic.html', context)
 
@login_required
def category_view(request, category_name):
    # Dictionnaire des icônes pour chaque catégorie
    category_icons = {
        'technologies': 'fa-laptop-code',
        'gaming': 'fa-gamepad',
        'art': 'fa-palette',
        'announcements': 'fa-bullhorn',
        'rules': 'fa-gavel'
    }
   
    # Récupérer ou créer la catégorie
    category, created = Category.objects.get_or_create(
        name=category_name,
        defaults={
            'description': f'Espace de discussion dédié à {category_name}',
            'created_at': timezone.now()
        }
    )
   
    # Gérer les filtres
    filter_type = request.GET.get('filter', 'recent')
   
    # Base query
    posts_query = Topic.objects.filter(category=category)
   
    # Appliquer les filtres
    if filter_type == 'popular':
        posts = posts_query.annotate(
            comment_count=Count('comments')
        ).order_by('-comment_count', '-created_at')
    else:  # recent
        posts = posts_query.order_by('-created_at')
   
    # Statistiques de la catégorie
    stats = {
        'total_posts': posts.count(),
        'total_members': User.objects.filter(
            topics__category=category
        ).distinct().count(),
        'active_discussions': posts.filter(
            created_at__gte=timezone.now() - timedelta(days=7)
        ).count(),
        'total_comments': sum(
            post.comments.count() for post in posts
        ),
        'moderators': category.moderators.all(),
    }
   
    # Derniers utilisateurs actifs dans la catégorie
    active_users = User.objects.filter(
        Q(topics__category=category) | Q(comments__topic__category=category)
    ).distinct().order_by('-last_login')[:5]
   
    # Discussions populaires
    popular_posts = posts_query.annotate(
        comment_count=Count('comments')
    ).order_by('-comment_count')[:3]
   
    context = {
        'category': category,
        'category_name': category_name.title(),
        'category_icon': category_icons.get(category_name.lower(), 'fa-folder'),
        'posts': posts,
        'stats': stats,
        'active_users': active_users,
        'popular_posts': popular_posts,
        'user_chats': Topic.get_user_chats(request.user),
        'current_filter': filter_type,
        'is_moderator': request.user in category.moderators.all(),
        'can_create_topic': request.user.is_authenticated,
        'friends': request.user.profile.friends.all(),
    }
   
    return render(request, 'forum/category.html', context)
 
def rules_view(request):
    context = {
        'user_chats': Topic.get_user_chats(request.user) if request.user.is_authenticated else None,
        'total_users': User.objects.count(),
        'total_messages': Comment.objects.count(),
        'online_users': User.objects.filter(is_active=True),
    }
    return render(request, 'forum/rules.html', context)
 
@login_required
def create_public_topic(request):
    return render(request, 'forum/create_public_topic.html', {
        'category': request.GET.get('category')
    })
 
@login_required
def create_private_topic(request):
    return render(request, 'forum/create_private_topic.html')
 
@login_required
def create_topic(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        friend_id = request.POST.get('friend')
       
        if title and friend_id:
            try:
                friend_profile = UserProfile.objects.get(id=friend_id)
               
                # Vérifier si une discussion existe déjà
                existing_chat = Topic.objects.filter(
                    (Q(author=request.user) & Q(with_friend=friend_profile)) |
                    (Q(author=friend_profile.user) & Q(with_friend=request.user.profile)),
                    is_private=True
                ).first()
               
                if existing_chat:
                    return JsonResponse({
                        'success': True,
                        'chat_id': existing_chat.id,
                        'friend_username': friend_profile.user.username,
                        'message': 'Discussion existante'
                    })
               
                # Si pas de discussion existante, en créer une nouvelle
                private_category, _ = Category.objects.get_or_create(
                    name='private',
                    defaults={'description': 'Forums privés'}
                )
               
                topic = Topic.objects.create(
                    title=title,
                    author=request.user,
                    category=private_category,
                    with_friend=friend_profile,
                    is_private=True
                )
               
                # Créer une activité pour la nouvelle discussion
                Activity.objects.create(
                    user=request.user,
                    type='new_topic',
                    topic=topic,
                    content=f"a créé une nouvelle discussion privée : {title}"
                )
               
                return JsonResponse({
                    'success': True,
                    'chat_id': topic.id,
                    'friend_username': friend_profile.user.username,
                    'message': 'Nouvelle discussion créée'
                })
               
            except UserProfile.DoesNotExist:
                return JsonResponse({
                    'success': False,
                    'error': 'Ami non trouvé.'
                })
            except Exception as e:
                return JsonResponse({
                    'success': False,
                    'error': str(e)
                })
        else:
            return JsonResponse({
                'success': False,
                'error': 'Titre et ami requis.'
            })
   
    return JsonResponse({
        'success': False,
        'error': 'Méthode non autorisée.'
    }, status=405)
 
 
@login_required
def add_friend(request):
    if request.method == 'POST':
        friend_id = request.POST.get('friend_id')
        try:
            friend_profile = UserProfile.objects.get(forum_id=friend_id)
            if friend_profile != request.user.profile:
                FriendRequest.objects.create(
                    from_user=request.user.profile,
                    to_user=friend_profile
                )
                messages.success(request, 'Demande d\'ami envoyée!')
            else:
                messages.error(request, 'Vous ne pouvez pas vous ajouter vous-même.')
        except UserProfile.DoesNotExist:
            messages.error(request, 'Utilisateur non trouvé.')
    return redirect('forum:home')
 
@login_required
def handle_friend_request(request, request_id):
    if request.method == 'POST':
        friend_request = FriendRequest.objects.get(id=request_id)
        action = request.POST.get('action')
       
        if action == 'accept':
            friend_request.status = 'accepted'
            friend_request.save()
            friend_request.from_user.friends.add(friend_request.to_user)
            messages.success(request, 'Demande d\'ami acceptée!')
        elif action == 'reject':
            friend_request.status = 'rejected'
            friend_request.save()
            messages.success(request, 'Demande d\'ami rejetée.')
           
    return redirect('forum:home')
 
 
def announcements_view(request):
    context = {
        'news': [
            {
                'title': 'Piratage des données de grandes entreprises en 2024',
                'content': "En 2024, plusieurs grandes entreprises ont été victimes de cyberattaques massives. "
                           "Des données sensibles appartenant à des millions d'utilisateurs ont été compromises. "
                           "L'attaque la plus marquante a touché une plateforme de commerce électronique, où des données bancaires et personnelles ont été exposées, "
                           "rappelant à quel point la cybersécurité est cruciale.",
                'type': 'article'
            },
            {
                'title': 'Vidéo éducative sur la cybersécurité',
                'content': 'https://www.youtube.com/embed/XQpK1mzbKoc',
                'type': 'video'
            },
            {
                'title': 'Rançongiciel ciblant les systèmes hospitaliers',
                'content': "Un groupe de hackers a récemment utilisé un rançongiciel pour paralyser les systèmes informatiques de plusieurs hôpitaux en Europe. "
                           "Ces attaques ont empêché l'accès aux données des patients, provoquant des retards dans les soins. "
                           "Les experts recommandent de renforcer la sécurité des systèmes dans les établissements de santé pour éviter de telles situations à l'avenir.",
                'type': 'article'
            }
        ]
    }
    return render(request, 'forum/announcements.html', context)
 
@login_required
def chat_view(request, topic_id):
    topic = get_object_or_404(Topic, id=topic_id)
   
    if request.method == 'POST':
        content = request.POST.get('content')
        if content:
            Comment.objects.create(
                topic=topic,
                author=request.user,
                content=content
            )
   
    context = {
        'topic': topic,
        'messages': topic.comments.all(),
        'user_chats': Topic.get_user_chats(request.user)
    }
    return render(request, 'forum/chat.html', context)
 
@login_required
def load_chat(request, topic_id):
    topic = get_object_or_404(Topic, id=topic_id)
    return render(request, 'forum/chat_content.html', {
        'topic': topic,
        'messages': topic.comments.all()
    })
 
@login_required
def delete_chat(request, chat_id):
    if request.method == 'POST':
        chat = get_object_or_404(Topic, id=chat_id)
        if chat.author == request.user or chat.with_friend == request.user.profile:
            chat.delete()
            return JsonResponse({'success': True})
    return JsonResponse({'success': False})
 
class LoginForm(forms.Form):
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)
    captcha = CaptchaField(required=False)
 
    def __init__(self, *args, **kwargs):
        self.requires_captcha = kwargs.pop('requires_captcha', False)
        super().__init__(*args, **kwargs)
        if self.requires_captcha:
            self.fields['captcha'].required = True
 
def logout_view(request):
    """Vue pour gérer la déconnexion des utilisateurs"""
    logout(request)
    messages.success(request, 'Vous avez été déconnecté avec succès.')
    return redirect('forum:login')
 
@login_required
def create_private_topic(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        description = request.POST.get('description')
        access_type = request.POST.get('access_type')
        password = request.POST.get('password')
        friend_ids = request.POST.getlist('friends[]')
       
        if title and description:
            topic = Topic.objects.create(
                title=title,
                content=description,
                author=request.user,
                is_private=True,
                password=password if access_type == 'password' else None
            )
           
            # Ajouter les amis sélectionnés
            if friend_ids:
                for friend_id in friend_ids:
                    try:
                        friend = UserProfile.objects.get(id=friend_id)
                        topic.members.add(friend.user)
                    except UserProfile.DoesNotExist:
                        continue
           
            # Créer une activité pour la nouvelle discussion
            Activity.objects.create(
                user=request.user,
                type='new_topic',
                topic=topic,
                content=f"a créé une nouvelle discussion privée : {title}"
            )
           
            messages.success(request, 'Forum privé créé avec succès!')
            return redirect('forum:topic_view', topic_id=topic.id)
        else:
            messages.error(request, 'Veuillez remplir tous les champs requis.')
   
    return redirect('forum:home')
 
@login_required
def report_topic(request, topic_id):
    topic = get_object_or_404(Topic, id=topic_id)
   
    if request.method == 'POST':
        reason = request.POST.get('reason')
        details = request.POST.get('details')
       
        if reason and reason in dict(Report.REPORT_TYPES):
            # Vérifier si un rapport existe déjà
            existing_report = Report.objects.filter(
                topic=topic,
                reporter=request.user,
                status='pending'
            ).exists()
           
            if existing_report:
                messages.warning(request, "Vous avez déjà signalé cette discussion. Les modérateurs vont l'examiner.")
            else:
                report = Report.objects.create(
                    topic=topic,
                    reporter=request.user,
                    reason=reason,
                    details=details
                )
                messages.success(request, "Merci pour votre signalement. Les modérateurs vont l'examiner.")
        else:
            messages.error(request, "Veuillez sélectionner une raison valide pour le signalement.")
   
    return redirect('forum:topic_view', topic_id=topic_id)
 
def send_notification(request, title, message):
    """Envoie une notification au navigateur"""
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({
            'notification': {
                'title': title,
                'body': message
            }
        })
    return HttpResponse()
 
@login_required
def create_topic(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        content = request.POST.get('content')
        category_name = request.POST.get('category')
        
        if not all([title, content, category_name]):
            messages.error(request, 'Veuillez remplir tous les champs.')
            return redirect('forum:create_topic')
        
        try:
            category = Category.objects.get(name=category_name)
            Topic.objects.create(
                title=title,
                content=content,
                author=request.user,
                category=category
            )
            return redirect('forum:category', category_name=category_name)
            
        except Category.DoesNotExist:
            messages.error(request, 'Catégorie invalide.')
            return redirect('forum:create_topic')
    
    return render(request, 'forum/create_topic.html')
 
@login_required
def reply_topic(request, topic_id):
    if request.method == 'POST':
        content = request.POST.get('content')
        if not content:
            messages.error(request, 'Le contenu ne peut pas être vide.')
            return redirect('forum:topic_view', topic_id=topic_id)
 
        topic = get_object_or_404(Topic, id=topic_id)
       
        # Vérifier si l'utilisateur a accès à cette discussion
        if topic.is_private and not (topic.author == request.user or request.user in topic.participants.all()):
            messages.error(request, "Vous n'avez pas accès à cette discussion.")
            return redirect('forum:home')
 
        comment = Comment.objects.create(
            content=content,
            author=request.user,
            topic=topic
        )
       
        # Envoyer une notification
        send_notification(
            request,
            "Nouvelle réponse",
            f"{request.user.username} a répondu à la discussion : {topic.title}"
        )
 
        # Créer une activité pour la réponse
        Activity.objects.create(
            user=request.user,
            type='new_reply',
            topic=topic,
            comment=comment
        )
       
        messages.success(request, 'Réponse ajoutée avec succès.')
        return redirect('forum:topic_view', topic_id=topic_id)
 
    return redirect('forum:topic_view', topic_id=topic_id)
 
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def protected_view(request):
    return Response({'message': 'This is a protected view'})

def members_list(request):
    """Vue pour afficher la liste des membres"""
    members = User.objects.all().order_by('-date_joined')
    return render(request, 'forum/members.html', {
        'members': members,
    })

def topics_list(request):
    """Vue pour afficher la liste des discussions"""
    topics = Topic.objects.all().order_by('-created_at')
    return render(request, 'forum/topics.html', {
        'topics': topics,
    })

@login_required
def create_category_topic(request, category_name=None):
    if request.method == 'POST':
        category = get_object_or_404(Category, name=category_name)
        title = request.POST.get('title')
        content = request.POST.get('content')
        
        if title and content:
            topic = Topic.objects.create(
                title=title,
                content=content,
                category=category,
                author=request.user
            )
            
            # Créer une activité pour la nouvelle discussion
            Activity.objects.create(
                user=request.user,
                type='new_topic',
                topic=topic
            )
            
            return JsonResponse({
                'status': 'success',
                'topic': {
                    'id': topic.id,
                    'title': topic.title,
                    'author': topic.author.username
                },
                'redirect_url': reverse('forum:category', args=[category_name])
            })
        else:
            return JsonResponse({
                'status': 'error',
                'error': 'Titre et contenu requis.'
            })
    
    return JsonResponse({
        'status': 'error',
        'error': 'Méthode non autorisée.'
    }, status=405)

@login_required
def edit_topic(request, topic_id):
    topic = get_object_or_404(Topic, id=topic_id)
    
    # Vérifier que l'utilisateur est l'auteur du topic
    if topic.author != request.user:
        messages.error(request, "Vous n'avez pas la permission de modifier ce message.")
        return redirect('forum:topic_view', topic_id=topic.id)
    
    if request.method == 'POST':
        content = request.POST.get('content')
        if content:
            topic.content = content
            topic.save()
            messages.success(request, "Message modifié avec succès.")
            return redirect('forum:topic_view', topic_id=topic.id)
    
    return JsonResponse({'success': True})

@login_required
def delete_topic(request, topic_id):
    topic = get_object_or_404(Topic, id=topic_id)
    
    # Vérifier que l'utilisateur est l'auteur du topic
    if topic.author != request.user:
        messages.error(request, "Vous n'avez pas la permission de supprimer ce message.")
        return redirect('forum:topic_view', topic_id=topic.id)
    
    category = topic.category
    topic.delete()
    messages.success(request, "Message supprimé avec succès.")
    return redirect('forum:category', category_name=category.name)

@login_required
def edit_comment(request, comment_id):
    comment = get_object_or_404(Comment, id=comment_id)
    
    # Vérifier que l'utilisateur est l'auteur du commentaire
    if comment.author != request.user:
        messages.error(request, "Vous n'avez pas la permission de modifier ce commentaire.")
        return redirect('forum:topic_view', topic_id=comment.topic.id)
    
    if request.method == 'POST':
        content = request.POST.get('content')
        if content:
            comment.content = content
            comment.save()
            messages.success(request, "Commentaire modifié avec succès.")
            return redirect('forum:topic_view', topic_id=comment.topic.id)
    
    return JsonResponse({'success': True})

@login_required
def delete_comment(request, comment_id):
    comment = get_object_or_404(Comment, id=comment_id)
    
    # Vérifier que l'utilisateur est l'auteur du commentaire
    if comment.author != request.user:
        messages.error(request, "Vous n'avez pas la permission de supprimer ce commentaire.")
        return redirect('forum:topic_view', topic_id=comment.topic.id)
    
    topic_id = comment.topic.id
    comment.delete()
    messages.success(request, "Commentaire supprimé avec succès.")
    return redirect('forum:topic_view', topic_id=topic_id)