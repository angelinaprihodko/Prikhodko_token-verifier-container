"""
============================================
ТЕСТЫ: Модифицированный контейнер верификации (HTTPS)
ВЕРСИЯ: 2.0 | АВТОР: Приходько А.Р., КП-23-17
============================================
"""
import os
import time
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')
django.setup()

from django.test import TestCase, Client
from verifier.views import generate_token, verify_token

# ============================================
# ТЕСТ 1: Конфигурация HTTPS
# ============================================
class TestConfig(TestCase):

    def test_sslserver_installed(self):
        """s'sslserver' в INSTALLED_APPS"""
        from django.conf import settings
        self.assertIn('sslserver', settings.INSTALLED_APPS)

    def test_hsts_set(self):
        """HSTS включён"""
        from django.conf import settings
        self.assertGreater(settings.SECURE_HSTS_SECONDS, 0)

# ============================================
# ТЕСТ 2: Генерация маркеров
# ============================================
class TestGenerate(TestCase):

    def test_returns_tuple(self):
        """generate_token возвращает кортеж (token, timestamp)"""
        result = generate_token("user_001", "analyst", 0)
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)

    def test_token_is_string(self):
        """Первый элемент кортежа — строка с точкой"""
        token, ts = generate_token("user_001", "analyst", 0)
        self.assertIsInstance(token, str)
        self.assertIn('.', token)

    def test_different_timestamps(self):
        """Два вызова дают разные timestamp"""
        _, ts1 = generate_token("user_001", "analyst", 0)
        time.sleep(1)
        _, ts2 = generate_token("user_001", "analyst", 0)
        self.assertNotEqual(ts1, ts2)

# ============================================
# ТЕСТ 3: Верификация
# ============================================
class TestVerify(TestCase):

    def test_valid_token(self):
        """Легитимный маркер проходит проверку"""
        token, ts = generate_token("user_001", "analyst", 0)
        # Передаём строку токена в verify_token
        result = verify_token(token)
        self.assertTrue(result['valid'])
        self.assertTrue(result['level1_pass'])
        self.assertTrue(result['level2_pass'])
        self.assertTrue(result['level3_pass'])

    def test_broken_structure(self):
        """Нарушенная структура отклоняется на уровне 1"""
        result = verify_token("broken_token_without_dot")
        self.assertFalse(result['valid'])
        self.assertFalse(result['level1_pass'])

    def test_tampered_signature(self):
        """Подделанная подпись отклоняется на уровне 2"""
        token, ts = generate_token("user_001", "analyst", 0)
        parts = token.split('.')
        tampered = parts[0] + '.badsignature123'
        result = verify_token(tampered)
        self.assertFalse(result['valid'])
        self.assertTrue(result['level1_pass'])
        self.assertFalse(result['level2_pass'])

# ============================================
# ТЕСТ 4: HTTPS-доступ
# ============================================
class TestAccess(TestCase):

    def test_page_returns_200(self):
        """Главная страница открывается"""
        client = Client()
        response = client.get('/')
        self.assertEqual(response.status_code, 200)

    def test_page_contains_html(self):
        """Ответ содержит HTML"""
        client = Client()
        response = client.get('/')
        self.assertContains(response, '<html', status_code=200)

# ============================================
# ЗАПУСК
# ============================================
if __name__ == '__main__':
    import unittest
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(TestConfig))
    suite.addTests(loader.loadTestsFromTestCase(TestGenerate))
    suite.addTests(loader.loadTestsFromTestCase(TestVerify))
    suite.addTests(loader.loadTestsFromTestCase(TestAccess))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "="*50)
    print("ИТОГИ ТЕСТИРОВАНИЯ")
    print(f"Всего тестов: {result.testsRun}")
    print(f"Успешно: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Провалено: {len(result.failures)}")
    print(f"Ошибок: {len(result.errors)}")

    if result.wasSuccessful():
        print("\n✅ ВСЕ ТЕСТЫ ПРОЙДЕНЫ!")
    else:
        print("\n❌ ЕСТЬ ПРОБЛЕМЫ")