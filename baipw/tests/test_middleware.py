from unittest.mock import MagicMock

from django.core.exceptions import PermissionDenied
from django.test import RequestFactory, TestCase, override_settings

from baipw.middleware import BasicAuthIPWhitelistMiddleware


class TestMiddleware(TestCase):
    def setUp(self):
        self.get_response_mock = MagicMock()
        self.middleware = BasicAuthIPWhitelistMiddleware(
            self.get_response_mock
        )
        self.request = RequestFactory().get('/')

    def test_no_settings_returns_permission_denied(self):
        with self.assertRaises(PermissionDenied):
            self.middleware(self.request)

    @override_settings(
        BASIC_AUTH_LOGIN='testlogin',
        BASIC_AUTH_PASSWORD='testpassword',
    )
    def test_basic_auth_returns_401(self):
        response = self.middleware(self.request)
        self.assertEqual(response.status_code, 401)

    @override_settings(
        BASIC_AUTH_LOGIN='testlogin',
    )
    def test_is_basic_auth_configured_if_only_login_set(self):
        self.assertFalse(self.middleware._is_basic_auth_configured())

    @override_settings(
        BASIC_AUTH_PASSWORD='testpassword',
    )
    def test_is_basic_auth_configured_if_only_password_set(self):
        self.assertFalse(self.middleware._is_basic_auth_configured())

    @override_settings(
        BASIC_AUTH_LOGIN='testlogin',
        BASIC_AUTH_PASSWORD='testpassword',
    )
    def test_is_basic_auth_configured_if_login_and_password_set(self):
        self.assertTrue(self.middleware._is_basic_auth_configured())

    def test_get_whitelisted_networks_when_none_set(self):
        networks = list(self.middleware._get_whitelisted_networks())
        self.assertEqual(len(networks), 0)

    @override_settings(
        BASIC_AUTH_WHITELISTED_IP_NETWORKS=[
            '192.168.0.0/24',
            '2001:db00::0/24',
        ]
    )
    def test_whitelisted_networks_when_set(self):
        networks = list(self.middleware._get_whitelisted_networks())
        self.assertEqual(len(networks), 2)

    @override_settings(
        BASIC_AUTH_WHITELISTED_IP_NETWORKS=[
            '192.168.0.0/24',
            '2001:db00::0/24',
        ]
    )
    def test_is_ip_whitelisted(self):
        self.request.META['REMOTE_ADDR'] = '192.168.0.25'
        self.assertTrue(self.middleware._is_ip_whitelisted(self.request))
        self.request.META['REMOTE_ADDR'] = '2001:db00::33'
        self.assertTrue(self.middleware._is_ip_whitelisted(self.request))

    @override_settings(
        BASIC_AUTH_WHITELISTED_IP_NETWORKS=[
            '192.168.0.0/24',
            '2001:db00::0/24',
        ]
    )
    def test_is_ip_whitelisted_invalid_ip(self):
        self.request.META['REMOTE_ADDR'] = '192.168.1.25'
        self.assertFalse(self.middleware._is_ip_whitelisted(self.request))
        self.request.META['REMOTE_ADDR'] = '2002:eb00::33'
        self.assertFalse(self.middleware._is_ip_whitelisted(self.request))

    @override_settings(
        BASIC_AUTH_LOGIN='randomlogin',
        BASIC_AUTH_PASSWORD='somepassword',
    )
    def test_basic_auth_credentials_settings(self):
        self.assertEqual(self.middleware.basic_auth_login, 'randomlogin')
        self.assertEqual(self.middleware.basic_auth_password, 'somepassword')
