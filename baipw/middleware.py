import ipaddress

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.utils.module_loading import import_string

from .exceptions import Unauthorized
from .response import HttpUnauthorizedResponse
from .utils import authorize, get_client_ip


class BasicAuthIPWhitelistMiddleware:
    def __init__(self, get_response=None):
        self.get_response = get_response

    def __call__(self, request):
        response = None
        response = self.process_request(request)
        response = response or self.get_response(request)
        return response

    def process_request(self, request):
        # If this attribute is set, skip the check.
        if getattr(request, "_skip_basic_auth_ip_whitelist_middleware_check", False):
            return self.get_response(request)

        setattr(request, "_skip_basic_auth_ip_whitelist_middleware_check", True)
        # Check if http host is whitelisted.
        if self._is_http_host_whitelisted(request):
            return
        # Check if path is whitelisted
        if self._is_path_whitelisted(request):
            return
        # Check if IP is whitelisted
        if self._is_ip_whitelisted(request):
            return
        # Skip basic auth for health probes.
        if self._is_health_probe(request):
            return
        # Fallback to basic auth if configured.
        if self._is_basic_auth_configured():
            return self._basic_auth_response(request)
        # Otherwise just deny the access to the website
        raise PermissionDenied

    @property
    def basic_auth_login(self):
        return getattr(settings, "BASIC_AUTH_LOGIN", None)

    @property
    def basic_auth_password(self):
        return getattr(settings, "BASIC_AUTH_PASSWORD", None)

    def get_response_class(self):
        try:
            return import_string(settings.BASIC_AUTH_RESPONSE_CLASS)
        except AttributeError:
            return HttpUnauthorizedResponse

    def _basic_auth_response(self, request):
        try:
            authorize(request, self.basic_auth_login, self.basic_auth_password)
        except Unauthorized:
            return self.get_response_class()(request=request)

    def _get_client_ip(self, request):
        function_path = getattr(settings, "BASIC_AUTH_GET_CLIENT_IP_FUNCTION", None)
        func = get_client_ip
        if function_path is not None:
            func = import_string(function_path)
        return func(request)

    def _get_whitelisted_networks(self):
        networks = getattr(settings, "BASIC_AUTH_WHITELISTED_IP_NETWORKS", [])
        # If we get a list, users probably passed a list of strings in
        #  the settings, probably from the environment.
        if isinstance(networks, str):
            networks = networks.split(",")
        # Otherwise assume that the list is iterable.
        for network in networks:
            network = network.strip()
            if not network:
                continue
            yield ipaddress.ip_network(network)

    def _get_whitelisted_http_hosts(self):
        http_hosts = getattr(settings, "BASIC_AUTH_WHITELISTED_HTTP_HOSTS", [])
        # If we get a list, users probably passed a list of strings in
        #  the settings, probably from the environment.
        if isinstance(http_hosts, str):
            http_hosts = http_hosts.split(",")
        # Otherwise assume that the list is iterable.
        for http_host in http_hosts:
            http_host = http_host.strip()
            if not http_host:
                continue
            yield http_host

    def _get_whitelisted_paths(self):
        paths = getattr(settings, "BASIC_AUTH_WHITELISTED_PATHS", [])
        # If we get a list, users probably passed a list of strings in
        #  the settings, probably from the environment.
        if isinstance(paths, str):
            paths = paths.split(",")
        # Otherwise assume that the list is iterable.
        for path in paths:
            path = path.strip()
            if not path:
                continue
            yield path

    def _is_http_host_whitelisted(self, request):
        request_host = request.get_host()
        if not request_host:
            return False
        return request_host in self._get_whitelisted_http_hosts()

    def _is_path_whitelisted(self, request):
        """
        Check if request.path is whitelisted. Subpaths are included.
        """
        for path in self._get_whitelisted_paths():
            if request.path.startswith(path):
                return True
        return False

    def _is_ip_whitelisted(self, request):
        """
        Check if IP is on the whitelisted network.
        """
        ip_address = ipaddress.ip_address(self._get_client_ip(request))
        for network in self._get_whitelisted_networks():
            if ip_address in network:
                return True
        return False

    def _is_basic_auth_configured(self):
        """
        Check basic authentication username and password are
        configured.
        """
        return self.basic_auth_login and self.basic_auth_password

    def _is_health_probe(self, request):
        """
        Check if request is a health probe.
        """
        azure_health_probe_enabled = getattr(
            settings, "BASIC_AUTH_AZURE_FRONT_DOOR_HEALTH_PROBE_ENABLED", False
        )
        if azure_health_probe_enabled:
            # https://docs.microsoft.com/en-us/azure/frontdoor/front-door-http-headers-protocol
            return request.META.get("HTTP_X_FD_HEALTHPROBE", "") == "1"
