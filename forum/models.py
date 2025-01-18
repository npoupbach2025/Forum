from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.validators import MinLengthValidator, RegexValidator, MaxLengthValidator, URLValidator
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from datetime import timedelta
import os
import re
from django.utils import timezone
from datetime import timedelta
import math


class LoginAttempt(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='login_attempts')
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField()
    was_successful = models.BooleanField(default=False)

    @classmethod
    def get_failed_attempts(cls, user, ip_address, within_minutes=30):
        time_threshold = timezone.now() - timedelta(minutes=within_minutes)
        return cls.objects.filter(
            user=user,
            ip_address=ip_address,
            timestamp__gt=time_threshold,
            was_successful=False
        ).count()

    @classmethod
    def get_lockout_time(cls, failed_attempts):
        """Retourne le temps de blocage en secondes basé sur le nombre d'échecs"""
        if failed_attempts < 5:
            return 0
        # Augmentation exponentielle: 30s, 60s, 120s, 240s, etc.
        return int(30 * math.pow(2, failed_attempts - 5))

    @classmethod
    def is_locked_out(cls, user, ip_address):
        failed_attempts = cls.get_failed_attempts(user, ip_address)
        lockout_time = cls.get_lockout_time(failed_attempts)
        if lockout_time == 0:
            return False, 0

        last_attempt = cls.objects.filter(
            user=user,
            ip_address=ip_address,
            was_successful=False
        ).order_by('-timestamp').first()

        if not last_attempt:
            return False, 0

        time_elapsed = (timezone.now() - last_attempt.timestamp).total_seconds()
        if time_elapsed < lockout_time:
            return True, lockout_time - int(time_elapsed)
        return False, 0

    @classmethod
    def reset_failed_attempts(cls, user, ip_address):
        cls.objects.filter(
            user=user,
            ip_address=ip_address,
            was_successful=False
        ).delete()

    class Meta:
        ordering = ['-timestamp']

class CaptchaRequirement(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now=True)
    required_until = models.DateTimeField()

    @classmethod
    def is_required(cls, user, ip_address):
        """Vérifie si le CAPTCHA est requis pour cette combinaison user/IP"""
        requirement = cls.objects.filter(
            user=user,
            ip_address=ip_address,
            required_until__gt=timezone.now()
        ).first()
        return bool(requirement)

    @classmethod
    def require_captcha(cls, user, ip_address, duration_minutes=30):
        """Active l'exigence de CAPTCHA pour une durée donnée"""
        cls.objects.update_or_create(
            user=user,
            ip_address=ip_address,
            defaults={
                'required_until': timezone.now() + timedelta(minutes=duration_minutes)
            }
        )



def validate_username(value):
    if len(value) < 3:
        raise ValidationError(
            _('Le nom d\'utilisateur doit contenir au moins 3 caractères')
        )
    if not value.replace('_', '').replace('-', '').isalnum():
        raise ValidationError(
            _('Le nom d\'utilisateur ne peut contenir que des lettres, chiffres, tirets et underscores')
        )



def validate_avatar_extension(value):
    ext = os.path.splitext(value.name)[1]
    valid_extensions = ['.jpg', '.jpeg', '.png', '.gif']
    if not ext.lower() in valid_extensions:
        raise ValidationError('Format de fichier non supporté. Utilisez JPG, PNG ou GIF.')

def validate_avatar_size(value):
    filesize = value.size
    if filesize > 5 * 1024 * 1024:  # 5MB
        raise ValidationError("La taille maximum de l'avatar est 5MB")

def validate_bio_content(value):
    # Vérifier les contenus malveillants
    patterns = [
        r'<[^>]*script',  # Scripts
        r'javascript:',    # JavaScript dans les liens
        r'data:',         # Data URIs
        r'&lt;script&gt;' # Scripts encodés
    ]
    for pattern in patterns:
        if re.search(pattern, value, re.IGNORECASE):
            raise ValidationError("Contenu non autorisé détecté dans la bio")

class UserProfileManager(models.Manager):
    def create_profile(self, user):
        # Obtenir le dernier forum_id
        last_profile = self.order_by('-forum_id').first()
        new_forum_id = 1000 if not last_profile else last_profile.forum_id + 1
        
        # Créer le nouveau profil
        return self.create(
            user=user,
            forum_id=new_forum_id
        )

class UserProfile(models.Model):
    user = models.OneToOneField(
        User, 
        on_delete=models.CASCADE, 
        related_name='profile',
        verbose_name=_("Utilisateur")
    )
    forum_id = models.PositiveIntegerField(
        unique=True, 
        editable=False,
        verbose_name=_("ID Forum"),
        default=1000
    )
    avatar = models.ImageField(
        upload_to='avatars/',
        null=True,
        blank=True,
        verbose_name=_("Avatar")
    )
    bio = models.TextField(
        max_length=500,
        blank=True,
        default="",
        validators=[
            MinLengthValidator(10, message=_("La bio doit contenir au moins 10 caractères")),
            MaxLengthValidator(500, message=_("La bio ne peut pas dépasser 500 caractères")),
            validate_bio_content
        ],
        verbose_name=_("Biographie")
    )
    friends = models.ManyToManyField(
        'self',
        blank=True,
        symmetrical=True,
        verbose_name=_("Amis")
    )
    last_activity = models.DateTimeField(
        default=timezone.now,
        verbose_name=_("Dernière activité")
    )
    last_login_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        verbose_name=_("Dernière IP de connexion"),
        help_text=_("Dernière adresse IP utilisée pour la connexion")
    )
    failed_login_attempts = models.PositiveIntegerField(
        default=0,
        verbose_name=_("Tentatives de connexion échouées")
    )
    last_failed_login = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("Dernière tentative échouée")
    )
    is_banned = models.BooleanField(
        default=False,
        verbose_name=_("Banni"),
        help_text=_("Indique si l'utilisateur est banni du forum")
    )
    ban_reason = models.TextField(
        blank=True,
        verbose_name=_("Raison du bannissement")
    )
    email_verified = models.BooleanField(
        default=False,
        verbose_name=_("Email vérifié")
    )
    security_questions_set = models.BooleanField(
        default=False,
        verbose_name=_("Questions de sécurité configurées")
    )
    two_factor_enabled = models.BooleanField(
        default=False,
        verbose_name=_("2FA activé")
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_("Date de création")
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name=_("Dernière mise à jour")
    )

    objects = UserProfileManager()

    @property
    def is_online(self):
        """Retourne True si l'utilisateur a été actif dans les 5 dernières minutes"""
        now = timezone.now()
        five_minutes_ago = now - timedelta(minutes=5)
        return self.last_activity >= five_minutes_ago

    class Meta:
        verbose_name = _("Profil utilisateur")
        verbose_name_plural = _("Profils utilisateurs")
        indexes = [
            models.Index(fields=['forum_id']),
            models.Index(fields=['created_at']),
            models.Index(fields=['last_activity'])
        ]

    def save(self, *args, **kwargs):
        if not self.forum_id:
            last_profile = UserProfile.objects.order_by('-forum_id').first()
            self.forum_id = (last_profile.forum_id + 1) if last_profile else 1
        
        # Nettoyer la bio avant la sauvegarde
        self.bio = self.clean_bio(self.bio)
        
        # Supprimer l'ancien avatar si un nouveau est téléchargé
        if self.pk:
            try:
                old_profile = UserProfile.objects.get(pk=self.pk)
                if old_profile.avatar and self.avatar != old_profile.avatar:
                    old_profile.avatar.delete(save=False)
            except UserProfile.DoesNotExist:
                pass
                
        super().save(*args, **kwargs)

    def clean(self):
        super().clean()
        # Validation supplémentaire de la bio
        if len(self.bio) > 500:
            raise ValidationError({'bio': _("La bio ne peut pas dépasser 500 caractères.")})
        
        # Vérifier le format de l'adresse IP
        if self.last_login_ip:
            try:
                ip_parts = self.last_login_ip.split('.')
                if len(ip_parts) != 4:
                    raise ValidationError({'last_login_ip': _("Format d'adresse IP invalide")})
            except:
                raise ValidationError({'last_login_ip': _("Format d'adresse IP invalide")})

    def clean_bio(self, bio_text):
        """Nettoyer et sécuriser le contenu de la bio"""
        # Supprimer les balises HTML dangereuses
        bio_text = re.sub(r'<[^>]*>', '', bio_text)
        # Échapper les caractères spéciaux
        bio_text = bio_text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        # Limiter la longueur
        return bio_text[:500]

    def add_friend(self, friend):
        """Ajouter un ami avec vérifications de sécurité"""
        if friend != self and not self.is_banned and not friend.is_banned:
            if not self.friends.filter(id=friend.id).exists():
                self.friends.add(friend)
                friend.friends.add(self)
                return True
        return False

    def remove_friend(self, friend):
        """Supprimer un ami de manière sécurisée"""
        if self.friends.filter(id=friend.id).exists():
            self.friends.remove(friend)
            friend.friends.remove(self)
            return True
        return False

    def get_friend_count(self):
        """Obtenir le nombre d'amis actifs"""
        return self.friends.filter(is_banned=False).count()

    def is_friend_with(self, user):
        """Vérifier si l'utilisateur est ami avec un autre utilisateur"""
        if not user or not hasattr(user, 'profile'):
            return False
        return self.friends.filter(id=user.profile.id, is_banned=False).exists()

    def ban_user(self, reason, admin_user=None):
        """Bannir un utilisateur avec traçabilité"""
        if not self.is_banned:
            self.is_banned = True
            self.ban_reason = f"Banni par {admin_user} le {timezone.now()}: {reason}"
            self.save()
            # Notifier l'utilisateur par email
            self.user.email_user(
                'Votre compte a été banni',
                f'Votre compte a été banni pour la raison suivante: {reason}'
            )
            return True
        return False

    def unban_user(self, admin_user=None):
        """Débannir un utilisateur avec traçabilité"""
        if self.is_banned:
            self.is_banned = False
            self.ban_reason = f"Débanni par {admin_user} le {timezone.now()}"
            self.reset_failed_login_attempts()
            self.save()
            return True
        return False

    def reset_failed_login_attempts(self):
        """Réinitialiser les tentatives de connexion échouées"""
        self.failed_login_attempts = 0
        self.last_failed_login = None
        self.save(update_fields=['failed_login_attempts', 'last_failed_login'])

    def increment_failed_login_attempts(self, ip_address=None):
        """Incrémenter le compteur de tentatives de connexion échouées"""
        self.failed_login_attempts += 1
        self.last_failed_login = timezone.now()
        if ip_address:
            self.last_login_ip = ip_address
        self.save(update_fields=['failed_login_attempts', 'last_failed_login', 'last_login_ip'])

    @property
    def is_locked_out(self):
        """Vérifier si le compte est verrouillé"""
        if self.last_failed_login and self.failed_login_attempts >= 5:
            lockout_period = timedelta(minutes=15)
            return timezone.now() - self.last_failed_login < lockout_period
        return False

    def get_avatar_url(self):
        """Obtenir l'URL de l'avatar de manière sécurisée"""
        if self.avatar and hasattr(self.avatar, 'url'):
            return self.avatar.url
        return '/static/forum/img/default_avatar.png'

    def __str__(self):
        """Représentation textuelle sécurisée du profil"""
        return f"{self.user.username} (#{self.forum_id})"

    def get_absolute_url(self):
        """Obtenir l'URL du profil de manière sécurisée"""
        from django.urls import reverse
        return reverse('forum:profile', kwargs={'username': self.user.username})

    def get_activity_status(self):
        """Obtenir le statut d'activité de l'utilisateur"""
        if not self.last_activity:
            return 'offline'
        
        time_since_activity = timezone.now() - self.last_activity
        if time_since_activity < timedelta(minutes=5):
            return 'online'
        elif time_since_activity < timedelta(minutes=30):
            return 'away'
        return 'offline'

    def get_recent_activity(self, limit=5):
        """Obtenir les activités récentes de l'utilisateur"""
        from .models import Topic, Comment
        
        recent_topics = Topic.objects.filter(author=self.user).order_by('-created_at')[:limit]
        recent_comments = Comment.objects.filter(author=self.user).order_by('-created_at')[:limit]
        
        activity = []
        for topic in recent_topics:
            activity.append({
                'type': 'topic',
                'content': topic.title,
                'date': topic.created_at,
                'url': topic.get_absolute_url()
            })
        
        for comment in recent_comments:
            activity.append({
                'type': 'comment',
                'content': comment.content[:100],
                'date': comment.created_at,
                'url': comment.topic.get_absolute_url()
            })
        
        return sorted(activity, key=lambda x: x['date'], reverse=True)[:limit]

    def can_access_private_topic(self, topic):
        """Vérifier si l'utilisateur peut accéder à un sujet privé"""
        if not topic.is_private:
            return True
        return (self.user == topic.author or 
                self == topic.with_friend or 
                self.user in topic.members.all())

    def notify_user(self, notification_type, content):
        """Envoyer une notification à l'utilisateur"""
        from django.core.mail import send_mail
        
        if notification_type == 'ban':
            subject = 'Votre compte a été banni'
        elif notification_type == 'warning':
            subject = 'Avertissement concernant votre compte'
        else:
            subject = 'Notification du forum'
        
        if self.user.email:
            try:
                send_mail(
                    subject,
                    content,
                    'noreply@forum.com',
                    [self.user.email],
                    fail_silently=True
                )
            except Exception as e:
                logger.error(f"Erreur d'envoi d'email à {self.user.username}: {str(e)}")

    def get_reputation_score(self):
        """Calculer le score de réputation de l'utilisateur"""
        from django.db.models import Count
        
        topics_count = Topic.objects.filter(author=self.user).count()
        comments_count = Comment.objects.filter(author=self.user).count()
        likes_received = (Topic.objects.filter(author=self.user, likes__isnull=False).count() +
                        Comment.objects.filter(author=self.user, likes__isnull=False).count())
        
        return (topics_count * 10) + (comments_count * 5) + (likes_received * 2)

    def log_security_event(self, event_type, details):
        """Enregistrer un événement de sécurité"""
        from django.contrib.admin.models import LogEntry, ADDITION
        from django.contrib.contenttypes.models import ContentType
        
        LogEntry.objects.create(
            user_id=self.user.id,
            content_type_id=ContentType.objects.get_for_model(self).id,
            object_id=self.id,
            object_repr=str(self),
            action_flag=ADDITION,
            change_message=f"Security event: {event_type} - {details}"
        )

    def delete_user_data(self):
        """Supprimer les données de l'utilisateur de manière sécurisée"""
        # Suppression de l'avatar
        if self.avatar:
            self.avatar.delete(save=False)
        
        # Anonymisation des données
        self.bio = "[Compte supprimé]"
        self.last_login_ip = None
        self.save()
        
        # Suppression des relations
        self.friends.clear()
        
        # Marquer les contenus comme supprimés
        Topic.objects.filter(author=self.user).update(
            content="[Contenu supprimé]",
            title="[Sujet supprimé]"
        )
        Comment.objects.filter(author=self.user).update(
            content="[Commentaire supprimé]"
        )

    def generate_backup_codes(self, count=8):
        """Générer des codes de récupération pour l'authentification 2FA"""
        import secrets
        import string
        
        alphabet = string.ascii_letters + string.digits
        codes = []
        
        for _ in range(count):
            code = ''.join(secrets.choice(alphabet) for _ in range(16))
            codes.append(code[:4] + '-' + code[4:8] + '-' + code[8:12] + '-' + code[12:])
        
        return codes

    def validate_security_question(self, question, answer):
        """Valider la réponse à une question de sécurité"""
        from django.contrib.auth.hashers import check_password
        
        if not self.security_questions_set:
            return False
            
        try:
            stored_answer = SecurityQuestion.objects.get(
                user=self.user,
                question=question
            ).answer_hash
            
            return check_password(answer.lower().strip(), stored_answer)
        except SecurityQuestion.DoesNotExist:
            return False

    def get_online_friends(self):
        """Retourne la liste des amis en ligne (connectés dans les 5 dernières minutes)"""
        five_minutes_ago = timezone.now() - timedelta(minutes=5)
        return self.friends.filter(user__last_login__gte=five_minutes_ago)

class Activity(models.Model):
    ACTIVITY_TYPES = [
        ('new_topic', 'Nouvelle discussion'),
        ('new_reply', 'Nouvelle réponse'),
        ('new_member', 'Nouveau membre'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    type = models.CharField(max_length=20, choices=ACTIVITY_TYPES, default='new_member')
    topic = models.ForeignKey('Topic', on_delete=models.CASCADE, null=True, blank=True)
    comment = models.ForeignKey('Comment', on_delete=models.CASCADE, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name_plural = 'Activities'

    def __str__(self):
        return f"{self.user.username} - {self.get_type_display()}"

class Category(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    moderators = models.ManyToManyField(User, related_name='moderated_categories', blank=True)

    class Meta:
        verbose_name_plural = "Categories"
        ordering = ['name']

    def __str__(self):
        return self.name

class Topic(models.Model):
    title = models.CharField(max_length=200)
    content = models.TextField(blank=True)
    category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name='topics', null=True, blank=True)
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name='topics')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    views = models.PositiveIntegerField(default=0)
    likes = models.ManyToManyField(User, related_name='liked_topics', blank=True)
    is_pinned = models.BooleanField(default=False)
    is_closed = models.BooleanField(default=False)
    with_friend = models.ForeignKey(UserProfile, on_delete=models.SET_NULL, null=True, blank=True, related_name='shared_topics')
    
    # Nouveaux champs pour les forums privés
    is_private = models.BooleanField(default=False)
    password = models.CharField(max_length=128, null=True, blank=True)
    members = models.ManyToManyField(User, related_name='private_topics', blank=True)
    access_type = models.CharField(
        max_length=20,
        choices=[
            ('public', 'Public'),
            ('private', 'Privé'),
            ('password', 'Protégé par mot de passe'),
            ('invite', 'Sur invitation uniquement')
        ],
        default='public'
    )

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.title
    


    @classmethod
    def get_trending_topics(cls, limit=10):
        """Obtenir les topics tendance de manière sécurisée"""
        query = """
            SELECT 
                t.id,
                t.title,
                COUNT(DISTINCT c.id) as comment_count,
                COUNT(DISTINCT l.id) as like_count
            FROM forum_topic t
            LEFT JOIN forum_comment c ON c.topic_id = t.id
            LEFT JOIN forum_topic_likes l ON l.topic_id = t.id
            WHERE t.created_at >= NOW() - INTERVAL '7 days'
            AND t.is_private = FALSE
            GROUP BY t.id, t.title
            ORDER BY comment_count DESC, like_count DESC
            LIMIT %s
        """
        from .db_utils import DatabaseManager
        return DatabaseManager.execute_read_query(query, [limit])

    @classmethod
    def get_user_chats(cls, user):
        return cls.objects.filter(
            models.Q(author=user) | 
            models.Q(with_friend=user.profile) |
            models.Q(members=user),
            models.Q(with_friend__isnull=False) | models.Q(is_private=True)
        ).order_by('-created_at')
    
    def can_access(self, user):
        """Vérifie si un utilisateur peut accéder au topic"""
        if not self.is_private:
            return True
        return (
            user == self.author or
            (self.with_friend and self.with_friend.user == user) or
            user in self.members.all()
        )
    
    def add_member(self, user):
        """Ajoute un membre au forum privé"""
        if self.is_private and user not in self.members.all():
            self.members.add(user)
    
    def remove_member(self, user):
        """Retire un membre du forum privé"""
        if self.is_private and user in self.members.all():
            self.members.remove(user)


class Report(models.Model):
    REPORT_TYPES = [
        ('spam', 'Spam'),
        ('inappropriate', 'Contenu inapproprié'),
        ('harassment', 'Harcèlement'),
        ('other', 'Autre')
    ]
    
    STATUS_CHOICES = [
        ('pending', 'En attente'),
        ('resolved', 'Résolu'),
        ('dismissed', 'Rejeté')
    ]

    topic = models.ForeignKey(Topic, on_delete=models.CASCADE, related_name='reports')
    reporter = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reported_topics')
    reason = models.CharField(max_length=20, choices=REPORT_TYPES)
    details = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    handled_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='handled_reports')
    handled_at = models.DateTimeField(null=True, blank=True)

    
class Comment(models.Model):
    topic = models.ForeignKey(Topic, on_delete=models.CASCADE, related_name='comments')
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name='comments')
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    parent = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='replies')
    likes = models.ManyToManyField(User, related_name='liked_comments', blank=True)
    
    class Meta:
        ordering = ['created_at']

    def __str__(self):
        return f"Comment by {self.author.username} on {self.topic.title}"

class FriendRequest(models.Model):
    from_user = models.ForeignKey(UserProfile, on_delete=models.CASCADE, related_name='sent_requests')
    to_user = models.ForeignKey(UserProfile, on_delete=models.CASCADE, related_name='received_requests')
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=10, choices=[
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('rejected', 'Rejected')
    ], default='pending')

def get_user_chats(user):
    return Topic.objects.filter(with_friend__isnull=False).filter(
        models.Q(author=user) | models.Q(with_friend=user.profile)
    ).order_by('-created_at')

# il faut qu'on Décommente ces lignes si on veux  réactiver les signaux plus tard
# @receiver(post_save, sender=User)
# def create_user_profile(sender, instance, created, **kwargs):
#     if created:
#         last_profile = UserProfile.objects.order_by('-forum_id').first()
#         new_forum_id = 1000 if not last_profile else last_profile.forum_id + 1
#         UserProfile.objects.create(user=instance, forum_id=new_forum_id)

# @receiver(post_save, sender=User)
# def save_user_profile(sender, instance, **kwargs):
#     try:
#         instance.profile.save()
#     except UserProfile.DoesNotExist:
#         pass