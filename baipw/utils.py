import base64

from .exceptions import Unauthorized


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if not x_forwarded_for:
        return request.META.get('REMOTE_ADDR')
    # If there is a list of IPs provided, use the last one.
    # This may not work on Google Cloud.
    return x_forwarded_for.split(',')[-1].strip()


def authorize(request, configured_username, configured_password):
    """
    Match authorization header present in the request against
    configured username and password.
    """
    if 'HTTP_AUTHORIZATION' not in request.META:
        raise Unauthorized(
            '"HTTP_AUTHORIZATION" is not present in the request object.'
        )
    authentication = request.META['HTTP_AUTHORIZATION']
    auth_method, auth = authentication.split(' ', 1)
    if 'basic' != auth_method.lower():
        raise Unauthorized('"Basic" is not an authorization method')
    auth = base64.b64decode(auth.strip()).decode('utf-8')
    username, password = auth.split(':', 1)
    if username == configured_username and password == configured_password:
        return True
    raise Unauthorized('Basic authentication credentials are invalid.')
