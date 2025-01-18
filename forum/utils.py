from datetime import datetime
from django.contrib.sessions.models import Session
from django.contrib.auth.models import User
 
def get_online_users():
    sessions = Session.objects.filter(expire_date__gte=datetime.now())
    user_ids = [session.get_decoded().get('_auth_user_id') for session in sessions if '_auth_user_id' in session.get_decoded()]
    return User.objects.filter(id__in=user_ids)