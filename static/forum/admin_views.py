# forum/admin_views.py

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.models import User
from django.contrib import messages
from django.db.models import Count
from .models import Category, Topic, Comment
from django.contrib.auth.decorators import login_required, user_passes_test

def is_admin(user):
    return user.is_superuser

@user_passes_test(is_admin)
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

@user_passes_test(is_admin)
def manage_users(request):
    users = User.objects.all().order_by('-date_joined')
    return render(request, 'forum/admin/manage_users.html', {'users': users})

@user_passes_test(is_admin)
def delete_user(request, user_id):
    if request.method == 'POST':
        user = get_object_or_404(User, id=user_id)
        if user != request.user:  # Empêcher l'auto-suppression
            user.delete()
            messages.success(request, f"L'utilisateur {user.username} a été supprimé.")
        else:
            messages.error(request, "Vous ne pouvez pas supprimer votre propre compte.")
    return redirect('forum:admin_manage_users')

@user_passes_test(is_admin)
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

@user_passes_test(is_admin)
def delete_category(request, category_id):
    if request.method == 'POST':
        category = get_object_or_404(Category, id=category_id)
        category.delete()
        messages.success(request, f"La catégorie {category.name} a été supprimée.")
    return redirect('forum:admin_manage_categories')

@user_passes_test(is_admin)
def moderate_topic(request, topic_id):
    topic = get_object_or_404(Topic, id=topic_id)
    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'delete':
            topic.delete()
            messages.success(request, "Le sujet a été supprimé.")
            return redirect('forum:home')
        elif action == 'pin':
            topic.is_pinned = not topic.is_pinned
            topic.save()
            messages.success(request, "Le statut d'épinglage a été modifié.")
        elif action == 'close':
            topic.is_closed = not topic.is_closed
            topic.save()
            messages.success(request, "Le statut de fermeture a été modifié.")
    
    return render(request, 'forum/admin/moderate_topic.html', {'topic': topic})