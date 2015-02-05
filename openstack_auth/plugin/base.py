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

import six

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
