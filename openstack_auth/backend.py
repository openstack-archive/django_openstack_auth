# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

""" Module defining the Django auth backend class for the Keystone API. """

import logging

from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from keystoneclient import exceptions as keystone_exceptions

from openstack_auth import exceptions
from openstack_auth import user as auth_user
from openstack_auth import utils


LOG = logging.getLogger(__name__)


KEYSTONE_CLIENT_ATTR = "_keystoneclient"


class KeystoneBackend(object):
    """Django authentication backend class for use with
      ``django.contrib.auth``.
    """

    def check_auth_expiry(self, auth_ref, margin=None):
        if not utils.is_token_valid(auth_ref, margin):
            msg = _("The authentication token issued by the Identity service "
                    "has expired.")
            LOG.warning("The authentication token issued by the Identity "
                        "service appears to have expired before it was "
                        "issued. This may indicate a problem with either your "
                        "server or client configuration.")
            raise exceptions.KeystoneAuthException(msg)
        return True

    def get_user(self, user_id):
        """Returns the current user (if authenticated) based on the user ID
        and session data.

        Note: this required monkey-patching the ``contrib.auth`` middleware
        to make the ``request`` object available to the auth backend class.
        """
        if (hasattr(self, 'request') and
                user_id == self.request.session["user_id"]):
            token = self.request.session['token']
            endpoint = self.request.session['region_endpoint']
            services_region = self.request.session['services_region']
            user = auth_user.create_user_from_token(self.request, token,
                                                    endpoint, services_region)
            return user
        else:
            return None

    def authenticate(self, request=None, username=None, password=None,
                     user_domain_name=None, auth_url=None):
        """Authenticates a user via the Keystone Identity API."""
        LOG.debug('Beginning user authentication for user "%s".' % username)

        interface = getattr(settings, 'OPENSTACK_ENDPOINT_TYPE', 'public')

        if auth_url is None:
            auth_url = settings.OPENSTACK_KEYSTONE_URL

        session = utils.get_session()
        keystone_client_class = utils.get_keystone_client().Client

        auth_url = utils.fix_auth_url_version(auth_url)
        unscoped_auth = utils.get_password_auth_plugin(auth_url,
                                                       username,
                                                       password,
                                                       user_domain_name)

        try:
            unscoped_auth_ref = unscoped_auth.get_access(session)
        except (keystone_exceptions.Unauthorized,
                keystone_exceptions.Forbidden,
                keystone_exceptions.NotFound) as exc:
            msg = _('Invalid user name or password.')
            LOG.debug(str(exc))
            raise exceptions.KeystoneAuthException(msg)
        except (keystone_exceptions.ClientException,
                keystone_exceptions.AuthorizationFailure) as exc:
            msg = _("An error occurred authenticating. "
                    "Please try again later.")
            LOG.debug(str(exc))
            raise exceptions.KeystoneAuthException(msg)

        # Check expiry for our unscoped auth ref.
        self.check_auth_expiry(unscoped_auth_ref)

        unscoped_client = keystone_client_class(session=session,
                                                auth=unscoped_auth)

        # We list all the user's projects
        try:
            if utils.get_keystone_version() >= 3:
                projects = unscoped_client.projects.list(
                    user=unscoped_auth_ref.user_id)
            else:
                projects = unscoped_client.tenants.list()
        except (keystone_exceptions.ClientException,
                keystone_exceptions.AuthorizationFailure) as exc:
            msg = _('Unable to retrieve authorized projects.')
            raise exceptions.KeystoneAuthException(msg)

        # Abort if there are no projects for this user
        if not projects:
            msg = _('You are not authorized for any projects.')
            raise exceptions.KeystoneAuthException(msg)

        # the recent project id a user might have set in a cookie
        recent_project = None
        if request:
            # Check if token is automatically scoped to default_project
            # grab the project from this token, to use as a default
            # if no recent_project is found in the cookie
            recent_project = request.COOKIES.get('recent_project',
                                                 unscoped_auth_ref.project_id)

        # if a most recent project was found, try using it first
        if recent_project:
            for pos, project in enumerate(projects):
                if project.id == recent_project:
                    # move recent project to the beginning
                    projects.pop(pos)
                    projects.insert(0, project)
                    break

        for project in projects:
            token = unscoped_auth_ref.auth_token
            scoped_auth = utils.get_token_auth_plugin(auth_url,
                                                      token=token,
                                                      project_id=project.id)

            try:
                scoped_auth_ref = scoped_auth.get_access(session)
            except (keystone_exceptions.ClientException,
                    keystone_exceptions.AuthorizationFailure):
                pass
            else:
                break
        else:
            msg = _("Unable to authenticate to any available projects.")
            raise exceptions.KeystoneAuthException(msg)

        # Check expiry for our new scoped token.
        self.check_auth_expiry(scoped_auth_ref)

        # If we made it here we succeeded. Create our User!
        user = auth_user.create_user_from_token(
            request,
            auth_user.Token(scoped_auth_ref),
            scoped_auth_ref.service_catalog.url_for(endpoint_type=interface))

        if request is not None:
            request.session['unscoped_token'] = unscoped_auth_ref.auth_token
            request.user = user
            scoped_client = keystone_client_class(session=session,
                                                  auth=scoped_auth)

            # Support client caching to save on auth calls.
            setattr(request, KEYSTONE_CLIENT_ATTR, scoped_client)

        LOG.debug('Authentication completed for user "%s".' % username)
        return user

    def get_group_permissions(self, user, obj=None):
        """Returns an empty set since Keystone doesn't support "groups"."""
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
                             for service in user.service_catalog
                             if user.services_region in
                             [endpoint.get('region', None) for endpoint
                              in service.get('endpoints', [])]])
        return role_perms | service_perms

    def has_perm(self, user, perm, obj=None):
        """Returns True if the given user has the specified permission."""
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
