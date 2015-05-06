# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import abc

from django.utils.translation import ugettext_lazy as _
from keystoneclient import exceptions as keystone_exceptions
from keystoneclient.v2_0 import client as v2_client
from keystoneclient.v3 import client as v3_client
import six

from openstack_auth import exceptions
from openstack_auth import utils

__all__ = ['BasePlugin']


@six.add_metaclass(abc.ABCMeta)
class BasePlugin(object):
    """Base plugin to provide ways to log in to dashboard.

    Provides a framework for keystoneclient plugins that can be used with the
    information provided to return an unscoped token.
    """

    @abc.abstractmethod
    def get_plugin(self, auth_url=None, **kwargs):
        """Create a new plugin to attempt to authenticate.

        Given the information provided by the login providers attempt to create
        an authentication plugin that can be used to authenticate the user.

        If the provided login information does not contain enough information
        for this plugin to proceed then it should return None.

        :param str auth_url: The URL to authenticate against.

        :returns: A plugin that will be used to authenticate or None if the
                  plugin cannot authenticate with the data provided.
        :rtype: keystoneclient.auth.BaseAuthPlugin
        """
        return None

    @property
    def keystone_version(self):
        """The Identity API version as specified in the settings file."""
        return utils.get_keystone_version()

    def list_projects(self, session, auth_plugin, auth_ref=None):
        """List the projects that are accessible to this plugin.

        Query the keystone server for all projects that this authentication
        token can be rescoped to.

        This function is overrideable by plugins if they use a non-standard
        mechanism to determine projects.

        :param session: A session object for communication:
        :type session: keystoneclient.session.Session
        :param auth_plugin: The auth plugin returned by :py:meth:`get_plugin`.
        :type auth_plugin: keystoneclient.auth.BaseAuthPlugin
        :param auth_ref: The current authentication data. This is optional as
                         future auth plugins may not have auth_ref data and all
                         the required information should be available via the
                         auth_plugin.
        :type auth_ref: keystoneclient.access.AccessInfo` or None.

        :raises: exceptions.KeystoneAuthException on lookup failure.

        :returns: A list of projects. This currently accepts returning both v2
                  or v3 keystoneclient projects objects.
        """
        try:
            if self.keystone_version >= 3:
                client = v3_client.Client(session=session, auth=auth_plugin)
                if auth_ref.is_federated:
                    return client.federation.projects.list()
                else:
                    return client.projects.list(user=auth_ref.user_id)

            else:
                client = v2_client.Client(session=session, auth=auth_plugin)
                return client.tenants.list()

        except (keystone_exceptions.ClientException,
                keystone_exceptions.AuthorizationFailure):
            msg = _('Unable to retrieve authorized projects.')
            raise exceptions.KeystoneAuthException(msg)
