=============
Configuration
=============

Django OpenStack Auth is configured through Django ``settings.py`` file.
In most cases it is used combined with the OpenStack Dashboard,
so the settings file will be ``local/local_settings.py`` file
in your OpenStack Dashboard deployment.

This page covers the configuration options referred by Django OpenStack Auth.

:ref:`Some settings <settings-shared-with-horizon>` are also referred to
by Horizon. Configure them carefully.

General settings
================

``AUTHENTICATION_PLUGINS``
--------------------------

Default: ``['openstack_auth.plugin.password.PasswordPlugin', 'openstack_auth.plugin.token.TokenPlugin']``

A list of authentication plugins to be used.
In most cases, there is no need to configure this.

``AVAILABLE_REGIONS``
---------------------

Default: ``None``

A list of tuples which define multiple regions. The tuple format is
``('http://{{ keystone_host }}:5000/v2.0', '{{ region_name }}')``. If any regions
are specified the login form will have a dropdown selector for authenticating
to the appropriate region, and there will be a region switcher dropdown in
the site header when logged in.

You should also define ``OPENSTACK_KEYSTONE_URL`` to indicate which of
the regions is the default one.


``DEFAULT_SERVICE_REGIONS``
---------------------------

Default: ``{}``

The default service region is set on a per-endpoint basis, meaning that once
the user logs into some Keystone endpoint, if a default service region is
defined for it in this setting and exists within Keystone catalog, it will be
set as the initial service region in this endpoint. By default it is an empty
dictionary because upstream can neither predict service region names in a
specific deployment, nor tell whether this behavior is desired. The key of the
dictionary is a full url of a Keystone endpoint with version suffix, the value
is a region name.

Example::

    DEFAULT_SERVICE_REGIONS = {
        OPENSTACK_KEYSTONE_URL: 'RegionOne'
    }


``OPENSTACK_API_VERSIONS``
--------------------------

Default::

    {
        "identity": 2.0,
        ...,
    }

Overrides for OpenStack API versions. Use this setting to force the
OpenStack dashboard to use a specific API version for a given service API.
Django OpenStack Auth refers to only the ``"identity"`` entry.
The current valid values are "2.0" or "3".

.. note::

   See `Horizon settings
   <https://docs.openstack.org/developer/horizon/install/settings.html#openstack-api-versions>`__
   for the full description of this setting.

``OPENSTACK_ENDPOINT_TYPE``
---------------------------

Default: ``"publicURL"``

A string which specifies the endpoint type to use for the endpoints in the
Keystone service catalog. The default value for all services except for
identity is ``"publicURL"``. The default value for the identity service is
``"internalURL"``.

``OPENSTACK_KEYSTONE_ADMIN_ROLES``
----------------------------------

Default: ``["admin"]``

The list of roles that have administrator privileges in this OpenStack
installation. This check is very basic and essentially only works with
keystone v2.0 and v3 with the default policy file. The setting assumes there
is a common ``admin`` like role(s) across services. Example uses of this
setting are:

* to rename the ``admin`` role to ``cloud-admin``
* allowing multiple roles to have administrative privileges, like
  ``["admin", "cloud-admin", "net-op"]``

``OPENSTACK_KEYSTONE_DEFAULT_DOMAIN``
-------------------------------------

Default: ``"Default"``

Overrides the default domain used when running on single-domain model
with Keystone V3. All entities will be created in the default domain.

.. note::

   This value must be the name of the default domain, NOT the ID.
   Also, you will most likely have a value in the keystone policy file like
   ``"cloud_admin": "rule:admin_required and domain_id:<your domain id>"``.
   This value must be the name of the domain whose ID is specified there.

``OPENSTACK_KEYSTONE_DOMAIN_CHOICES``
-------------------------------------

.. versionadded:: 12.0.0(Pike)

Default::

        (
          ('Default', 'Default'),
        )

If OPENSTACK_KEYSTONE_DOMAIN_DROPDOWN is enabled, this option can be used to
set the available domains to choose from. This is a list of pairs whose first
value is the domain name and the second is the display name.

``OPENSTACK_KEYSTONE_DOMAIN_DROPDOWN``
--------------------------------------

.. versionadded:: 12.0.0(Pike)

Default: ``False``
Set this to True if you want available domains displayed as a dropdown menu on
the login screen. It is strongly advised NOT to enable this for public clouds,
as advertising enabled domains to unauthenticated customers irresponsibly
exposes private information. This should only be used for private clouds where
the dashboard sits behind a corporate firewall.

``OPENSTACK_KEYSTONE_MULTIDOMAIN_SUPPORT``
------------------------------------------

Default: ``False``

Set this to True if running on multi-domain model. When this is enabled, it
will require user to enter the Domain name in addition to username for login.

``OPENSTACK_KEYSTONE_URL``
--------------------------

Default: ``"http://%s:5000/v2.0" % OPENSTACK_HOST``

The full URL for the Keystone endpoint used for authentication. Unless you
are using HTTPS, running your Keystone server on a nonstandard port, or using
a nonstandard URL scheme you shouldn't need to touch this setting.

``OPENSTACK_SSL_CACERT``
------------------------

Default: ``None``

When unset or set to ``None`` the default CA certificate on the system is used
for SSL verification.

When set with the path to a custom CA certificate file, this overrides use of
the default system CA certificate. This custom certificate is used to verify all
connections to openstack services when making API calls.

``OPENSTACK_SSL_NO_VERIFY``
---------------------------

Default: ``False``

Disable SSL certificate checks in the OpenStack clients (useful for self-signed
certificates).

``OPENSTACK_TOKEN_HASH_ALGORITHM``
----------------------------------

Default: ``"md5"``

The hash algorithm to use for authentication tokens. This must match the hash
algorithm that the identity (Keystone) server and the auth_token middleware
are using. Allowed values are the algorithms supported by Python's hashlib
library.

``OPENSTACK_TOKEN_HASH_ENABLED``
--------------------------------

(Deprecated)

Default: ``True``

Hashing tokens from Keystone keeps the Horizon session data smaller, but it
doesn't work in some cases when using PKI tokens.  Uncomment this value and
set it to False if using PKI tokens and there are 401 errors due to token
hashing.

This option is now marked as "deprecated" and will be removed in Ocata or a
later release. PKI tokens currently work with hashing, and Keystone will soon
deprecate usage of PKI tokens.

``PASSWORD_EXPIRES_WARNING_THRESHOLD_DAYS``
-------------------------------------------

Default: ``-1``

Password will have an expiration date when using keystone v3 and enabling the
feature. This setting allows you to set the number of days that the user will
be alerted prior to the password expiration. Once the password expires keystone
will deny the access and users must contact an admin to change their password.
Setting this value to ``N`` days means the user will be alerted when the
password expires in less than ``N+1`` days. ``-1`` disables the feature.

``POLICY_FILES``
----------------

Default: ``{'identity': 'keystone_policy.json', 'compute': 'nova_policy.json'}``

This should essentially be the mapping of the contents of ``POLICY_FILES_PATH``
to service types.  When policy.json files are added to ``POLICY_FILES_PATH``,
they should be included here too.

``POLICY_FILES_PATH``
---------------------

Default:  ``os.path.join(ROOT_PATH, "conf")``

Specifies where service based policy files are located. These are used to
define the policy rules actions are verified against.

``SECURE_PROXY_ADDR_HEADER``
----------------------------

Default: ``False``

If horizon is behind a proxy server and the proxy is configured, the IP address
from request is passed using header variables inside the request. The header
name depends on a proxy or a load-balancer. This setting specifies the name of
the header with remote IP address. The main use is for authentication log
(success or fail) displaing the IP address of the user.
The commom value for this setting is ``HTTP_X_REAL_IP`` or
``HTTP_X_FORWARDED_FOR``.
If not present, then ``REMOTE_ADDR`` header is used. (``REMOTE_ADDR`` is the
field of Django HttpRequest object which contains IP address of the client.)

``SESSION_TIMEOUT``
-------------------

Default: ``"3600"``

This ``SESSION_TIMEOUT`` is a method to supercede the token timeout with a
shorter horizon session timeout (in seconds).  So if your token expires in
60 minutes, a value of 1800 will log users out after 30 minutes.

``TOKEN_DELETION_DISABLED``
---------------------------

Default: ``False``

This setting allows deployers to control whether a token is deleted on log out.
This can be helpful when there are often long running processes being run
in the Horizon environment.

``TOKEN_TIMEOUT_MARGIN``
------------------------

Default: ``0``

A time margin in seconds to subtract from the real token's validity.
An example usage is that the token can be valid once the middleware
passed, and invalid (timed-out) during a view rendering and this
generates authorization errors during the view rendering.
By setting this value to some smaller seconds, you can avoid token
expiration during a view rendering.

``WEBROOT``
-----------

Default: ``"/"``

Specifies the location where the access to the dashboard is configured in
the web server.

For example, if you're accessing the Dashboard via
https://<your server>/dashboard, you would set this to ``"/dashboard/"``.

.. note::

    Additional settings may be required in the config files of your webserver
    of choice. For example to make ``"/dashboard/"`` the web root in Apache,
    the ``"sites-available/horizon.conf"`` requires a couple of additional
    aliases set::

        Alias /dashboard/static %HORIZON_DIR%/static

        Alias /dashboard/media %HORIZON_DIR%/openstack_dashboard/static

    Apache also requires changing your WSGIScriptAlias to reflect the desired
    path.  For example, you'd replace ``/`` with ``/dashboard`` for the
    alias.

Web SSO (Single Sign On) settings
=================================

``WEBSSO_ENABLED``
------------------

Default: ``False``

Enables keystone web single-sign-on if set to True. For this feature to work,
make sure that you are using Keystone V3 and Django OpenStack Auth V1.2.0 or
later.

``WEBSSO_INITIAL_CHOICE``
-------------------------

Default: ``"credentials"``

Determines the default authentication mechanism. When user lands on the login
page, this is the first choice they will see.

``WEBSSO_CHOICES``
------------------

Default::

        (
          ("credentials", _("Keystone Credentials")),
          ("oidc", _("OpenID Connect")),
          ("saml2", _("Security Assertion Markup Language"))
        )

This is the list of authentication mechanisms available to the user. It
includes Keystone federation protocols such as OpenID Connect and SAML, and
also keys that map to specific identity provider and federation protocol
combinations (as defined in ``WEBSSO_IDP_MAPPING``). The list of choices is
completely configurable, so as long as the id remains intact. Do not remove
the credentials mechanism unless you are sure. Once removed, even admins will
have no way to log into the system via the dashboard.

``WEBSSO_IDP_MAPPING``
----------------------

Default: ``{}``

A dictionary of specific identity provider and federation protocol combinations.
From the selected authentication mechanism, the value will be looked up as keys
in the dictionary. If a match is found, it will redirect the user to a identity
provider and federation protocol specific WebSSO endpoint in keystone, otherwise
it will use the value as the protocol_id when redirecting to the WebSSO by
protocol endpoint.

Example::

        WEBSSO_CHOICES =  (
            ("credentials", _("Keystone Credentials")),
            ("oidc", _("OpenID Connect")),
            ("saml2", _("Security Assertion Markup Language")),
            ("acme_oidc", "ACME - OpenID Connect"),
            ("acme_saml2", "ACME - SAML2")
        )

        WEBSSO_IDP_MAPPING = {
            "acme_oidc": ("acme", "oidc"),
            "acme_saml2": ("acme", "saml2")
        }

.. note::
  The value is expected to be a tuple formatted as: (<idp_id>, <protocol_id>).

K2K (Keystone to Keystone) Federation settings
==============================================

``KEYSTONE_PROVIDER_IDP_NAME``
------------------------------

Default: ``Local Keystone``

The Keystone Provider drop down uses Keystone to Keystone federation
to switch between Keystone service providers.
This sets display name for Identity Provider (dropdown display name).

``KEYSTONE_PROVIDER_IDP_ID``
----------------------------

Default:: ``localkeystone``

This ID is used for only for comparison with the service provider IDs.
This ID should not match any service provider IDs.

.. _settings-shared-with-horizon:

Settings shared with Horizon
============================

The following settings in Django OpenStack Auth are also used by Horizon.

* ``AVAILABLE_REGIONS``
* ``OPENSTACK_API_VERSIONS``
* ``OPENSTACK_KEYSTONE_URL``
* ``OPENSTACK_ENDPOINT_TYPE``
* ``OPENSTACK_SSL_CACERT``
* ``OPENSTACK_SSL_NO_VERIFY``
* ``WEBROOT``

Django OpenStack Auth also refers to the following Django settings.
For more detail, see `Django settings documentation
<https://docs.djangoproject.com/en/1.11/ref/settings/#auth>`__.
They are usually configured as part of Horizon settings.

* ``LOGIN_REDIRECT_URL``
* ``LOGIN_URL``
* ``SESSION_ENGINE``
* ``USE_TZ``
