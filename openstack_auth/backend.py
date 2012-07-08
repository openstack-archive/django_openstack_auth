""" Module defining the Django auth backend class for the Keystone API. """

import logging

from django.utils.translation import ugettext as _

from keystoneclient.v2_0 import client as keystone_client
from keystoneclient import exceptions as keystone_exceptions
from keystoneclient.v2_0.tokens import Token, TokenManager

from .exceptions import KeystoneAuthException
from .user import create_user_from_token
from .utils import check_token_expiration


LOG = logging.getLogger(__name__)


KEYSTONE_CLIENT_ATTR = "_keystoneclient"


class KeystoneBackend(object):
    """
    Django authentication backend class for use with ``django.contrib.auth``.
    """
    def check_auth_expiry(self, token):
        if not check_token_expiration(token):
            msg = _("The authentication token issued by the Identity service "
                    "has expired.")
            LOG.warning("The authentication token issued by the Identity "
                        "service appears to have expired before it was "
                        "issued. This may indicate a problem with either your "
                        "server or client configuration.")
            raise KeystoneAuthException(msg)
        return True

    def get_user(self, user_id):
        """
        Returns the current user (if authenticated) based on the user ID
        and session data.

        Note: this required monkey-patching the ``contrib.auth`` middleware
        to make the ``request`` object available to the auth backend class.
        """
        if user_id == self.request.session["user_id"]:
            token = Token(TokenManager(None),
                          self.request.session['token'],
                          loaded=True)
            endpoint = self.request.session['region_endpoint']
            return create_user_from_token(self.request, token, endpoint)
        else:
            return None

    def authenticate(self, request=None, username=None, password=None,
                     tenant=None, auth_url=None):
        """ Authenticates a user via the Keystone Identity API. """
        LOG.debug('Beginning user authentication for user "%s".' % username)

        try:
            client = keystone_client.Client(username=username,
                                            password=password,
                                            tenant_id=tenant,
                                            auth_url=auth_url)
            unscoped_token_data = {"token": client.service_catalog.get_token()}
            unscoped_token = Token(TokenManager(None),
                                   unscoped_token_data,
                                   loaded=True)
        except keystone_exceptions.Unauthorized:
            msg = _('Invalid user name or password.')
            raise KeystoneAuthException(msg)
        except keystone_exceptions.ClientException:
            msg = _("An error occurred authenticating. "
                    "Please try again later.")
            raise KeystoneAuthException(msg)

        # Check expiry for our unscoped token.
        self.check_auth_expiry(unscoped_token)

        # FIXME: Log in to default tenant when the Keystone API returns it...
        # For now we list all the user's tenants and iterate through.
        try:
            tenants = client.tenants.list()
        except keystone_exceptions.ClientException:
            msg = _('Unable to retrieve authorized projects.')
            raise KeystoneAuthException(msg)

        # Abort if there are no tenants for this user
        if not tenants:
            msg = _('You are not authorized for any projects.')
            raise KeystoneAuthException(msg)

        while tenants:
            tenant = tenants.pop()
            try:
                token = client.tokens.authenticate(username=username,
                                                   token=unscoped_token.id,
                                                   tenant_id=tenant.id)
                break
            except keystone_exceptions.ClientException:
                token = None

        if token is None:
            msg = _("Unable to authenticate to any available projects.")
            raise KeystoneAuthException(msg)

        # Check expiry for our new scoped token.
        self.check_auth_expiry(token)

        # If we made it here we succeeded. Create our User!
        user = create_user_from_token(request, token, client.management_url)

        if request is not None:
            request.session['unscoped_token'] = unscoped_token.id
            request.user = user

            # Support client caching to save on auth calls.
            setattr(request, KEYSTONE_CLIENT_ATTR, client)

        LOG.debug('Authentication completed for user "%s".' % username)
        return user
