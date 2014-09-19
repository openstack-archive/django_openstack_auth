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

import logging

from django.conf import settings
from django.contrib.auth import authenticate  # noqa
from django.contrib.auth import forms as django_auth_forms
from django import forms
from django.utils.translation import ugettext_lazy as _
from django.views.decorators.debug import sensitive_variables  # noqa

from openstack_auth import exceptions


LOG = logging.getLogger(__name__)


class Login(django_auth_forms.AuthenticationForm):
    """Form used for logging in a user.

    Handles authentication with Keystone by providing the domain name, username
    and password. A scoped token is fetched after successful authentication.

    A domain name is required if authenticating with Keystone V3 running
    multi-domain configuration.

    If the user authenticated has a default project set, the token will be
    automatically scoped to their default project.

    If the user authenticated has no default project set, the authentication
    backend will try to scope to the projects returned from the user's assigned
    projects. The first successful project scoped will be returned.

    Inherits from the base ``django.contrib.auth.forms.AuthenticationForm``
    class for added security features.
    """
    region = forms.ChoiceField(label=_("Region"), required=False)
    username = forms.CharField(
        label=_("User Name"),
        widget=forms.TextInput(attrs={"autofocus": "autofocus"}))
    password = forms.CharField(label=_("Password"),
                               widget=forms.PasswordInput(render_value=False))

    def __init__(self, *args, **kwargs):
        super(Login, self).__init__(*args, **kwargs)
        self.fields.keyOrder = ['username', 'password', 'region']
        if getattr(settings,
                   'OPENSTACK_KEYSTONE_MULTIDOMAIN_SUPPORT',
                   False):
            self.fields['domain'] = forms.CharField(label=_("Domain"),
                                                    required=True)
            self.fields.keyOrder = ['domain', 'username', 'password', 'region']
        self.fields['region'].choices = self.get_region_choices()
        if len(self.fields['region'].choices) == 1:
            self.fields['region'].initial = self.fields['region'].choices[0][0]
            self.fields['region'].widget = forms.widgets.HiddenInput()

    @staticmethod
    def get_region_choices():
        default_region = (settings.OPENSTACK_KEYSTONE_URL, "Default Region")
        return getattr(settings, 'AVAILABLE_REGIONS', [default_region])

    @sensitive_variables()
    def clean(self):
        default_domain = getattr(settings,
                                 'OPENSTACK_KEYSTONE_DEFAULT_DOMAIN',
                                 'Default')
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')
        region = self.cleaned_data.get('region')
        domain = self.cleaned_data.get('domain', default_domain)

        if not (username and password):
            # Don't authenticate, just let the other validators handle it.
            return self.cleaned_data

        try:
            self.user_cache = authenticate(request=self.request,
                                           username=username,
                                           password=password,
                                           user_domain_name=domain,
                                           auth_url=region)
            msg = 'Login successful for user "%(username)s".' % \
                {'username': username}
            LOG.info(msg)
        except exceptions.KeystoneAuthException as exc:
            msg = 'Login failed for user "%(username)s".' % \
                {'username': username}
            LOG.warning(msg)
            self.request.session.flush()
            raise forms.ValidationError(exc)
        if hasattr(self, 'check_for_test_cookie'):  # Dropped in django 1.7
            self.check_for_test_cookie()
        return self.cleaned_data
