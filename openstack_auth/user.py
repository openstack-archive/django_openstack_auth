import hashlib
import logging

from django.contrib.auth.models import AnonymousUser
from django.conf import settings

from keystoneclient.v2_0 import client as keystone_client
from keystoneclient import exceptions as keystone_exceptions

from .utils import check_token_expiration, is_ans1_token


LOG = logging.getLogger(__name__)


def set_session_from_user(request, user):
    if is_ans1_token(user.token.id):
        hashed_token = hashlib.md5(user.token.id).hexdigest()
        user.token._info['token']['id'] = hashed_token
    if 'token_list' not in request.session:
        request.session['token_list'] = []
    token_tuple = (user.endpoint, user.token.id)
    request.session['token_list'].append(token_tuple)
    request.session['token'] = user.token._info
    request.session['user_id'] = user.id
    request.session['region_endpoint'] = user.endpoint


def create_user_from_token(request, token, endpoint):
    return User(id=token.user['id'],
                token=token,
                user=token.user['name'],
                tenant_id=token.tenant['id'],
                tenant_name=token.tenant['name'],
                enabled=True,
                service_catalog=token.serviceCatalog,
                roles=token.user['roles'],
                endpoint=endpoint)


class User(AnonymousUser):
    """ A User class with some extra special sauce for Keystone.

    In addition to the standard Django user attributes, this class also has
    the following:

    .. attribute:: token

        The Keystone token object associated with the current user/tenant.

    .. attribute:: tenant_id

        The id of the Keystone tenant for the current user/token.

    .. attribute:: tenant_name

        The name of the Keystone tenant for the current user/token.

    .. attribute:: service_catalog

        The ``ServiceCatalog`` data returned by Keystone.

    .. attribute:: roles

        A list of dictionaries containing role names and ids as returned
        by Keystone.
    """
    def __init__(self, id=None, token=None, user=None, tenant_id=None,
                    service_catalog=None, tenant_name=None, roles=None,
                    authorized_tenants=None, endpoint=None, enabled=False):
        self.id = id
        self.pk = id
        self.token = token
        self.username = user
        self.tenant_id = tenant_id
        self.tenant_name = tenant_name
        self.service_catalog = service_catalog
        self.roles = roles or []
        self.endpoint = endpoint
        self.enabled = enabled
        self._authorized_tenants = authorized_tenants

    def __unicode__(self):
        return self.username

    def __repr__(self):
        return "<%s: %s>" % (self.__class__.__name__, self.username)

    def is_token_expired(self):
        """
        Returns ``True`` if the token is expired, ``False`` if not, and
        ``None`` if there is no token set.
        """
        if self.token is None:
            return None
        return not check_token_expiration(self.token)

    def is_authenticated(self):
        """ Checks for a valid token that has not yet expired. """
        return self.token is not None and check_token_expiration(self.token)

    def is_anonymous(self):
        """
        Returns ``True`` if the user is not authenticated,``False`` otherwise.
        """
        return not self.is_authenticated()

    @property
    def is_active(self):
        return self.enabled

    @property
    def is_superuser(self):
        """
        Evaluates whether this user has admin privileges. Returns
        ``True`` or ``False``.
        """
        return 'admin' in [role['name'].lower() for role in self.roles]

    @property
    def authorized_tenants(self):
        """ Returns a memoized list of tenants this user may access. """
        insecure = getattr(settings, 'OPENSTACK_SSL_NO_VERIFY', False)

        if self.is_authenticated() and self._authorized_tenants is None:
            endpoint = self.endpoint
            token = self.token
            try:
                client = keystone_client.Client(username=self.username,
                                                auth_url=endpoint,
                                                token=token.id,
                                                insecure=insecure)
                self._authorized_tenants = client.tenants.list()
            except (keystone_exceptions.ClientException,
                    keystone_exceptions.AuthorizationFailure):
                LOG.exception('Unable to retrieve tenant list.')
        return self._authorized_tenants or []

    @authorized_tenants.setter
    def authorized_tenants(self, tenant_list):
        self._authorized_tenants = tenant_list

    def save(*args, **kwargs):
        # Presume we can't write to Keystone.
        pass

    def delete(*args, **kwargs):
        # Presume we can't write to Keystone.
        pass

    # Check for OR'd permission rules, check that user has one of the
    # required permission.
    def has_a_matching_perm(self, perm_list, obj=None):
        """
        Returns True if the user has one of the specified permissions. If
        object is passed, it checks if the user has any of the required perms
        for this object.
        """
        # If there are no permissions to check, just return true
        if not perm_list:
            return True
        # Check that user has at least one of the required permissions.
        for perm in perm_list:
            if self.has_perm(perm, obj):
                return True
        return False

    # Override the default has_perms method. Allowing for more
    # complex combinations of permissions.  Will check for logical AND of
    # all top level permissions.  Will use logical OR for all first level
    # tuples (check that use has one permissions in the tuple)
    #
    # Examples:
    #   Checks for all required permissions
    #   ('openstack.roles.admin', 'openstack.roles.L3-support')
    #
    #   Checks for admin AND (L2 or L3)
    #   ('openstack.roles.admin', ('openstack.roles.L3-support',
    #                              'openstack.roles.L2-support'),)
    def has_perms(self, perm_list, obj=None):
        """
        Returns True if the user has all of the specified permissions.
        Tuples in the list will possess the required permissions if
        the user has a permissions matching one of the elements of
        that tuple
        """
        # If there are no permissions to check, just return true
        if not perm_list:
            return True
        for perm in perm_list:
            if isinstance(perm, basestring):
                # check that the permission matches
                if not self.has_perm(perm, obj):
                    return False
            else:
                # check that a permission in the tuple matches
                if not self.has_a_matching_perm(perm, obj):
                    return False
        return True
