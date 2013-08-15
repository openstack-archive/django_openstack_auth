""" Module defining the Django auth backend class for the Keystone API. """

import logging

from django.conf import settings
from django.utils.translation import ugettext_lazy as _

from keystoneclient import exceptions as keystone_exceptions

from .exceptions import KeystoneAuthException
from .user import create_user_from_token
from .user import Token
from .utils import check_token_expiration
from .utils import get_keystone_client
from .utils import get_keystone_version


LOG = logging.getLogger(__name__)


KEYSTONE_CLIENT_ATTR = "_keystoneclient"


class KeystoneBackend(object):
    """Django authentication backend class for use with
      ``django.contrib.auth``.
    """

    def check_auth_expiry(self, auth_ref):
        if not check_token_expiration(auth_ref):
            msg = _("The authentication token issued by the Identity service "
                    "has expired.")
            LOG.warning("The authentication token issued by the Identity "
                        "service appears to have expired before it was "
                        "issued. This may indicate a problem with either your "
                        "server or client configuration.")
            raise KeystoneAuthException(msg)
        return True

    def get_user(self, user_id):
        """Returns the current user (if authenticated) based on the user ID
        and session data.

        Note: this required monkey-patching the ``contrib.auth`` middleware
        to make the ``request`` object available to the auth backend class.
        """
        if user_id == self.request.session["user_id"]:
            token = self.request.session['token']
            endpoint = self.request.session['region_endpoint']
            services_region = self.request.session['services_region']
            user = create_user_from_token(self.request, token, endpoint,
                                          services_region)
            return user
        else:
            return None

    def authenticate(self, request=None, username=None, password=None,
                     user_domain_name=None, auth_url=None):
        """Authenticates a user via the Keystone Identity API. """
        LOG.debug('Beginning user authentication for user "%s".' % username)

        insecure = getattr(settings, 'OPENSTACK_SSL_NO_VERIFY', False)

        keystone_client = get_keystone_client()
        try:
            client = keystone_client.Client(
                user_domain_name=user_domain_name,
                username=username,
                password=password,
                auth_url=auth_url,
                insecure=insecure,
                debug=settings.DEBUG)

            unscoped_auth_ref = client.auth_ref
            unscoped_token = Token(auth_ref=unscoped_auth_ref)
        except (keystone_exceptions.Unauthorized,
                keystone_exceptions.Forbidden,
                keystone_exceptions.NotFound) as exc:
            msg = _('Invalid user name or password.')
            LOG.debug(exc.message)
            raise KeystoneAuthException(msg)
        except (keystone_exceptions.ClientException,
                keystone_exceptions.AuthorizationFailure) as exc:
            msg = _("An error occurred authenticating. "
                    "Please try again later.")
            LOG.debug(exc.message)
            raise KeystoneAuthException(msg)

        # Check expiry for our unscoped auth ref.
        self.check_auth_expiry(unscoped_auth_ref)

        # Check if token is automatically scoped to default_project
        if unscoped_auth_ref.project_scoped:
            auth_ref = unscoped_auth_ref
        else:
            # For now we list all the user's projects and iterate through.
            try:
                if get_keystone_version() < 3:
                    projects = client.tenants.list()
                else:
                    client.management_url = auth_url
                    projects = client.projects.list(
                        user=unscoped_auth_ref.user_id)
            except (keystone_exceptions.ClientException,
                    keystone_exceptions.AuthorizationFailure) as exc:
                msg = _('Unable to retrieve authorized projects.')
                raise KeystoneAuthException(msg)

            # Abort if there are no projects for this user
            if not projects:
                msg = _('You are not authorized for any projects.')
                raise KeystoneAuthException(msg)

            while projects:
                project = projects.pop()
                try:
                    client = keystone_client.Client(
                        tenant_id=project.id,
                        token=unscoped_auth_ref.auth_token,
                        auth_url=auth_url,
                        insecure=insecure,
                        debug=settings.DEBUG)
                    auth_ref = client.auth_ref
                    break
                except (keystone_exceptions.ClientException,
                        keystone_exceptions.AuthorizationFailure):
                    auth_ref = None

            if auth_ref is None:
                msg = _("Unable to authenticate to any available projects.")
                raise KeystoneAuthException(msg)

        # Check expiry for our new scoped token.
        self.check_auth_expiry(auth_ref)

        # If we made it here we succeeded. Create our User!
        user = create_user_from_token(request,
                                      Token(auth_ref),
                                      client.service_catalog.url_for())

        if request is not None:
            request.session['unscoped_token'] = unscoped_token.id
            request.user = user

            # Support client caching to save on auth calls.
            setattr(request, KEYSTONE_CLIENT_ATTR, client)

        LOG.debug('Authentication completed for user "%s".' % username)
        return user

    def get_group_permissions(self, user, obj=None):
        """Returns an empty set since Keystone doesn't support "groups". """
        # Keystone V3 added "groups". The Auth token response includes the
        # roles from the user's Group assignment. It should be fine just
        # returning an empty set here.
        return set()

    def get_all_permissions(self, user, obj=None):
        """Returns a set of permission strings that this user has through
           his/her Keystone "roles".

          The permissions are returned as ``"openstack.{{ role.name }}"``.
        """
        if user.is_anonymous() or obj is not None:
            return set()
        # TODO(gabrielhurley): Integrate policy-driven RBAC
        #                      when supported by Keystone.
        role_perms = set(["openstack.roles.%s" % role['name'].lower()
                          for role in user.roles])
        service_perms = set(["openstack.services.%s" % service['type'].lower()
                          for service in user.service_catalog])
        return role_perms | service_perms

    def has_perm(self, user, perm, obj=None):
        """Returns True if the given user has the specified permission. """
        if not user.is_active:
            return False
        return perm in self.get_all_permissions(user, obj)

    def has_module_perms(self, user, app_label):
        """Returns True if user has any permissions in the given app_label.

           Currently this matches for the app_label ``"openstack"``.
        """
        if not user.is_active:
            return False
        for perm in self.get_all_permissions(user):
            if perm[:perm.index('.')] == app_label:
                return True
        return False
