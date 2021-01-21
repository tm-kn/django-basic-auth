import django
from django.test import RequestFactory, TestCase, override_settings

from baipw.response import DEFAULT_AUTH_TEMPLATE, HttpUnauthorizedResponse


class TestHttpUnauthorizedResponse(TestCase):
    def setUp(self):
        self.request = RequestFactory().get("/")

    def test_default_realm(self):
        response = HttpUnauthorizedResponse(request=self.request)
        self.assertEqual(response["WWW-Authenticate"], "Basic")

    @override_settings(BASIC_AUTH_REALM="Custom realm")
    def test_custom_realm(self):
        response = HttpUnauthorizedResponse(request=self.request)
        self.assertEqual(response["WWW-Authenticate"], 'Basic realm="Custom realm"')

    @override_settings(BASIC_AUTH_REALM='"Custom realm"')
    def test_custom_realm_with_doublequotes(self):
        response = HttpUnauthorizedResponse(request=self.request)
        self.assertEqual(
            response["WWW-Authenticate"], 'Basic realm="\\"Custom realm\\""'
        )

    def test_default_template(self):
        response = HttpUnauthorizedResponse(request=self.request)
        self.assertEqual(response.get_response_content(), DEFAULT_AUTH_TEMPLATE)

    @override_settings(BASIC_AUTH_RESPONSE_TEMPLATE="test_template.html",)
    def test_custom_template(self):
        response = HttpUnauthorizedResponse(request=self.request)
        self.assertEqual(
            response.get_response_content().strip(), "This is a test template."
        )
        self.assertEqual(response["Content-Type"], "text/html")

    def test_never_cache_headers_set(self):
        response = HttpUnauthorizedResponse(request=self.request)
        cache_control_args = [v.strip() for v in response["cache-control"].split(",")]
        if django.VERSION >= (3, 0):
            self.assertCountEqual(
                cache_control_args,
                ["max-age=0", "no-cache", "no-store", "must-revalidate", "private"],
            )
        else:
            self.assertCountEqual(
                cache_control_args,
                ["max-age=0", "no-cache", "no-store", "must-revalidate"],
            )
