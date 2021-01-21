django-basic-auth-ip-whitelist
==============================

.. image:: https://github.com/tm-kn/django-basic-auth-ip-whitelist/workflows/Test/badge.svg
   :alt: GitHub actions CI status
   :target: https://github.com/tm-kn/django-basic-auth-ip-whitelist/actions/
.. image:: https://img.shields.io/pypi/v/django-basic-auth-ip-whitelist.svg
   :target: https://pypi.org/project/django-basic-auth-ip-whitelist/
.. image:: https://img.shields.io/pypi/dm/django-basic-auth-ip-whitelist.svg
   :target: https://pypi.org/project/django-basic-auth-ip-whitelist/

This simple package ships middleware that lets you to set basic authentication
and IP whitelisting via Django settings.

Use case
--------

This package has been created for staging and demo sites that need to be
completely hidden from the Internet behind a password or accessible only to
certain IP networks.

Do not depend on this package to protect highly valuable information. This
package is at a good way to disable staging sites being discovered by
search engines and Internet users trying to access staging sites. It is
advised that any sensitive information is protected using `Django authentication
system <https://docs.djangoproject.com/en/stable/topics/auth/>`_.

Requirements
------------

-  Django 1.8, 1.9, 1.10, 1.11, 2.0, 2.1, 2.2 or 3.0.
-  Python 3.4, 3.5, 3.6, 3.7 or 3.8.

Installation
------------

The package is on
`PyPI <https://pypi.org/project/django-basic-auth-ip-whitelist/>`__ so you can
just install it with pip.

.. code:: sh

   pip install django-basic-auth-ip-whitelist

Configuration
-------------

In your Django settings you can configure the following settings:

``BASIC_AUTH_LOGIN`` and ``BASIC_AUTH_PASSWORD``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Credentials that you want to use with your basic authentication.

``BASIC_AUTH_WHITELISTED_IP_NETWORKS``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Set a list of network ranges (strings) compatible with Python’s
`ipaddress.ip_network <https://docs.python.org/3.6/library/ipaddress.html#ipaddress.ip_network>`__
that you want to be able to access the website without authentication
from. It must be either a string with networks separated by comma or
Python iterable.

``BASIC_AUTH_REALM``
~~~~~~~~~~~~~~~~~~~~

String specifying the realm of the default response.

Example settings
~~~~~~~~~~~~~~~~

.. code:: python

   MIDDLEWARE += [
       'baipw.middleware.BasicAuthIPWhitelistMiddleware'
   ]
   BASIC_AUTH_LOGIN = 'somelogin'
   BASIC_AUTH_PASSWORD = 'greatpassword'
   BASIC_AUTH_WHITELISTED_IP_NETWORKS = [
       '192.168.0.0/28',
       '2001:db00::0/24',
   ]

Advanced customisation
----------------------

Getting IP
~~~~~~~~~~

If you want to have a custom behaviour when getting IP, you can create a
custom function that takes request as a parameter and specify path to it
in the ``BASIC_AUTH_GET_CLIENT_IP_FUNCTION`` settings, e.g.

.. code:: python

   BASIC_AUTH_GET_CLIENT_IP_FUNCTION = 'utils.ip.get_client_ip'


``BASIC_AUTH_WHITELISTED_HTTP_HOSTS``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Set a list of hosts that your website will be open to without basic
authentication. This is useful if your website is hosted under multiple domains
and you want only one of them to be publicly visible, e.g. by search engines.

**This is by no means a security feature. Please do not use to secure your
site.**

.. code:: python

   BASIC_AUTH_WHITELISTED_HTTP_HOSTS = [
       'your-public-domain.com',
   ]


``BASIC_AUTH_WHITELISTED_PATHS``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Set a list of paths that your website will serve without basic authentication.
This can be used to support API integrations for example with third-party
services which don't support basic authentication.

Paths listed in the setting ``BASIC_AUTH_WHITELISTED_PATHS`` are treated as roots, and any subpath will be whitelisted too. For example:

.. code:: python

    BASIC_AUTH_WHITELISTED_PATHS = [
        '/api',
    ]

This will open up the path https://mydomain.com/api/, as well as anything
below it, e.g. https://mydomain.com/api/document/1/.


``BASIC_AUTH_RESPONSE_TEMPLATE``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you want to display a different template on the 401 page, please use this
setting to point at the template.

.. code:: python

   BASIC_AUTH_RESPONSE_TEMPLATE = '401.html'


``BASIC_AUTH_RESPONSE_CLASS``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you want to specify custom response class, you can do so with this setting.
Provide the path as a string.

.. code:: python

   BASIC_AUTH_RESPONSE_CLASS = 'yourmodule.response.CustomUnathorisedResponse'


``BASIC_AUTH_DISABLE_CONSUMING_AUTHORIZATION_HEADER``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Set this setting to True if you want the Authorization HTTP header to not be deleted from the request object after it has been used by this package's middleware.

.. code:: python

   BASIC_AUTH_DISABLE_CONSUMING_AUTHORIZATION_HEADER = True


Skip middleware
~~~~~~~~~~~~~~~

You can skip the middleware by setting
`_skip_basic_auth_ip_whitelist_middleware_check` attribute on the request to
`True`.

.. code:: python

   setattr(request, '_skip_basic_auth_ip_whitelist_middleware_check', True)


This may be handy if you have other middleware that you want to have

``BASIC_AUTH_AZURE_FRONT_DOOR_HEALTH_PROBE_ENABLED``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can disable basic authentication for `Azure Front Door health probes
<https://docs.microsoft.com/en-us/azure/frontdoor/front-door-health-probes>`_.
It is strongly discouraged having this setting enabled if your server won't
strip this header if it was inserted by users manually into their request.

.. code:: python

   BASIC_AUTH_AZURE_FRONT_DOOR_HEALTH_PROBE_ENABLED = True
