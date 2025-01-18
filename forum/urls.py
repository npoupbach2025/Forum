from django.urls import path
from django.contrib.auth import views as auth_views
from . import views
from django.urls import path, include

app_name = 'forum'

urlpatterns = [
    path('register/', views.register, name='register'),
    path('home/', views.home, name='home'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('create-topic/', views.create_topic, name='create_topic'),
    path('add-friend/', views.add_friend, name='add_friend'),
    path('handle-friend-request/<int:request_id>/', views.handle_friend_request, name='handle_friend_request'),
    path('chat/<int:topic_id>/', views.chat_view, name='chat'),
    path('chat/<int:topic_id>/load/', views.load_chat, name='load_chat'),
    path('chat/<int:chat_id>/delete/', views.delete_chat, name='delete_chat'),
    path('category/<str:category_name>/', views.category_view, name='category'),
    path('category/<str:category_name>/create-topic/', views.create_category_topic, name='create_category_topic'),
    path('topic/<int:topic_id>/reply/', views.reply_topic, name='reply_topic'),
    path('topic/<int:topic_id>/edit/', views.edit_topic, name='edit_topic'),
    path('topic/<int:topic_id>/delete/', views.delete_topic, name='delete_topic'),
    path('comment/<int:comment_id>/edit/', views.edit_comment, name='edit_comment'),
    path('comment/<int:comment_id>/delete/', views.delete_comment, name='delete_comment'),
    path('create-private-topic/', views.create_private_topic, name='create_private_topic'),
    path('topic/create/public/', views.create_public_topic, name='create_public_topic'),
    path('topic/create/private/', views.create_private_topic, name='create_private_topic'),
    path('rules/', views.rules_view, name='rules'),
    path('mod/dashboard/', views.mod_dashboard, name='admin_dashboard'),
    path('mod/users/', views.mod_users, name='mod_users'),
    path('mod/topics/', views.mod_topics, name='mod_topics'),
    path('mod/reports/', views.mod_reports, name='mod_reports'),
    path('mod/reports/<int:report_id>/handle/', views.handle_report, name='handle_report'),
    path('mod/users/<int:user_id>/delete/', views.mod_delete_user, name='mod_delete_user'),
    path('mod/users/<int:user_id>/edit/', views.mod_edit_user, name='mod_edit_user'),
    path('mod/topic/<int:topic_id>/moderate/', views.moderate_topic, name='moderate_topic'),
    path('topic/<int:topic_id>/report/', views.report_topic, name='report_topic'),
    path('profile/change-password/', views.change_password, name='change_password'),
    path('profile/update-bio/', views.update_bio, name='update_bio'),
    path('profile/remove-friend/', views.remove_friend, name='remove_friend'),
    path('profile/<str:username>/', views.profile_view, name='profile'),
    path('announcements/', views.announcements_view, name='announcements'),
    path('topic/<int:topic_id>/', views.topic_view, name='topic_view'),
    path('login/', views.login_view, name='login'),
    path('protected/', views.protected_view, name='protected_view'),
    path('captcha/', include('captcha.urls')),
    path('password-reset/', 
        auth_views.PasswordResetView.as_view(
            template_name='forum/password_reset.html',
            email_template_name='forum/password_reset_email.html',
            success_url='/password-reset/done/'
        ),
        name='password_reset'),
         
    path('password-reset/done/', 
        auth_views.PasswordResetDoneView.as_view(
            template_name='forum/password_reset_done.html'
        ),
        name='password_reset_done'),
         
    path('reset/<uidb64>/<token>/', 
        auth_views.PasswordResetConfirmView.as_view(
            template_name='forum/password_reset_confirm.html'
        ),
        name='password_reset_confirm'),
         
    path('reset/done/', 
        auth_views.PasswordResetCompleteView.as_view(
            template_name='forum/password_reset_complete.html'
        ),
        name='password_reset_complete'),
    path('members/', views.members_list, name='members'),
    path('topics/', views.topics_list, name='topics'),
    path('protected/', views.protected_view, name='protected_view'),
]