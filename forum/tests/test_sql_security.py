from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from forum.utils.db_utils import DatabaseManager

class SQLInjectionTests(TestCase):
    """Test cases for SQL injection prevention"""
    
    @classmethod
    def setUpTestData(cls):
        # Create test user that will be used for all tests
        cls.test_user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )

    def setUp(self):
        # Setup run before each test method
        self.client = Client()
        self.client.login(username='testuser', password='testpass123')

    def test_basic_sql_injection(self):
        """Test basic SQL injection attempts in URL parameters"""
        malicious_inputs = [
            "' OR '1'='1",
            "admin'--",
            "'; DROP TABLE users; --",
            "1 UNION SELECT username, password FROM auth_user--",
        ]
        
        for malicious_input in malicious_inputs:
            response = self.client.get(
                reverse('forum:home'), 
                {'search': malicious_input}
            )
            self.assertEqual(response.status_code, 403)

    def test_database_manager_validation(self):
        """Test DatabaseManager query validation"""
        dangerous_queries = [
            ("DROP TABLE users;", []),
            ("DELETE FROM users;", []),
            ("SELECT * FROM users WHERE username = '' OR '1'='1';", []),
        ]
        
        for query, params in dangerous_queries:
            with self.assertRaises(ValueError):
                DatabaseManager._validate_query(query, params)
    
    def test_safe_queries(self):
        """Test that legitimate queries are allowed"""
        safe_queries = [
            ("SELECT username FROM auth_user WHERE id = %s", [1]),
            ("SELECT COUNT(*) FROM forum_topic", []),
        ]
        
        for query, params in safe_queries:
            try:
                DatabaseManager._validate_query(query, params)
            except ValueError as e:
                self.fail(f"Safe query was rejected: {str(e)}")
    
    def test_parameter_validation(self):
        """Test validation of query parameters"""
        dangerous_params = [
            ["' OR '1'='1"],
            ["'; DROP TABLE users; --"],
            ["admin'--"],
        ]
        
        query = "SELECT * FROM users WHERE username = %s"
        
        for params in dangerous_params:
            with self.assertRaises(ValueError):
                DatabaseManager._validate_query(query, params)
    
    def test_query_length_limit(self):
        """Test query length restrictions"""
        long_query = "SELECT * FROM users WHERE " + "x" * 1000
        with self.assertRaises(ValueError):
            DatabaseManager._validate_query(long_query, [])

    def test_read_query_execution(self):
        """Test execution of read queries"""
        query = "SELECT username FROM auth_user WHERE id = %s"
        try:
            result = DatabaseManager.execute_read_query(query, [self.test_user.id])
            self.assertEqual(result[0]['username'], 'testuser')
        except Exception as e:
            self.fail(f"Read query failed: {str(e)}")

if __name__ == '__main__':
    import django
    django.setup()
    from django.test.runner import DiscoverRunner
    test_runner = DiscoverRunner(verbosity=2)
    failures = test_runner.run_tests(['forum.tests'])
    if failures:
        sys.exit(1)