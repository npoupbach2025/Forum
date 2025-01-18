from django.core.management.base import BaseCommand
from django.db import connection
from django.contrib.auth.models import User
from forum.utils.db_utils import DatabaseManager
import sys

class Command(BaseCommand):
    help = 'Test manuel de la sécurité SQL'

    def handle(self, *args, **options):
        print("Test de sécurité SQL...")
        
        # Test 1: Injection basique
        try:
            DatabaseManager.execute_read_query(
                "SELECT * FROM auth_user WHERE username = 'admin' OR '1'='1'"
            )
            print("❌ Test 1 échoué: L'injection SQL basique n'a pas été bloquée")
        except ValueError:
            print("✅ Test 1 réussi: Injection SQL basique bloquée")

        # Test 2: Injection dans les paramètres
        try:
            DatabaseManager.execute_read_query(
                "SELECT * FROM auth_user WHERE username = %s",
                ["admin'; DROP TABLE auth_user; --"]
            )
            print("❌ Test 2 échoué: L'injection dans les paramètres n'a pas été bloquée")
        except ValueError:
            print("✅ Test 2 réussi: Injection dans les paramètres bloquée")

        # Test 3: Vérifier que les requêtes légitimes fonctionnent
        try:
            DatabaseManager.execute_read_query(
                "SELECT username FROM auth_user WHERE id = %s",
                [1]
            )
            print("✅ Test 3 réussi: Les requêtes légitimes fonctionnent")
        except Exception as e:
            print(f"❌ Test 3 échoué: Les requêtes légitimes ne fonctionnent pas: {e}")