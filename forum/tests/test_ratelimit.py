from django.test import TestCase, Client
from django.urls import reverse
from django_ratelimit.decorators import ratelimit

class RateLimitTests(TestCase):
    """Test cases for rate limiting"""

    def setUp(self):
        self.client = Client()

    def test_rate_limit(self):

        url = reverse('forum:home')
        # S'assurer que les 10 premieres requettes sont acceptees
        for _ in range(10):
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200)

        # Faire en sorte que la 11eme soit bloquée
        response = self.client.get(url)
        self.assertEqual(response.status_code, 429)  # 429 Too Many Requests
