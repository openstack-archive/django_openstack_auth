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

import copy

from mox3 import mox

from django.conf import settings
from django.contrib import auth
from django.core.urlresolvers import reverse
from django import test

from keystoneclient import exceptions as keystone_exceptions
from keystoneclient.v2_0 import client as client_v2
from keystoneclient.v3 import client as client_v3

from openstack_auth.tests import data_v2
from openstack_auth.tests import data_v3
from openstack_auth import utils


DEFAULT_DOMAIN = settings.OPENSTACK_KEYSTONE_DEFAULT_DOMAIN


class OpenStackAuthTestsV2(test.TestCase):
    def setUp(self):
        super(OpenStackAuthTestsV2, self).setUp()
        self.mox = mox.Mox()
        self.data = data_v2.generate_test_data()
        self.ks_client_module = client_v2
        endpoint = settings.OPENSTACK_KEYSTONE_URL
        self.keystone_client_unscoped = self.ks_client_module.Client(
            endpoint=endpoint,
            auth_ref=self.data.unscoped_access_info)
        self.keystone_client_scoped = self.ks_client_module.Client(
            endpoint=endpoint,
            auth_ref=self.data.scoped_access_info)
        settings.OPENSTACK_API_VERSIONS['identity'] = 2.0
        settings.OPENSTACK_KEYSTONE_URL = "http://localhost:5000/v2.0"

    def tearDown(self):
        self.mox.UnsetStubs()
        self.mox.VerifyAll()

    def _login(self):
        tenants = [self.data.tenant_one, self.data.tenant_two]
        user = self.data.user
        unscoped = self.data.unscoped_access_info

        form_data = {'region': settings.OPENSTACK_KEYSTONE_URL,
                     'domain': DEFAULT_DOMAIN,
                     'password': user.password,
                     'username': user.name}

        self.mox.StubOutWithMock(self.ks_client_module, "Client")
        self.mox.StubOutWithMock(self.keystone_client_unscoped.tenants, "list")

        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     password=user.password,
                                     username=user.name,
                                     user_domain_name=DEFAULT_DOMAIN,
                                     insecure=False,
                                     cacert=None,
                                     debug=False)\
            .AndReturn(self.keystone_client_unscoped)
        self.keystone_client_unscoped.tenants.list().AndReturn(tenants)
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     tenant_id=self.data.tenant_two.id,
                                     insecure=False,
                                     cacert=None,
                                     token=unscoped.auth_token,
                                     debug=False) \
            .AndReturn(self.keystone_client_scoped)

        self.mox.ReplayAll()

        url = reverse('login')

        # GET the page to set the test cookie.
        response = self.client.get(url, form_data)
        self.assertEqual(response.status_code, 200)

        # POST to the page to log in.
        response = self.client.post(url, form_data)
        self.assertRedirects(response, settings.LOGIN_REDIRECT_URL)

    def test_login(self):
        self._login()

    def test_login_with_disabled_tenants(self):
        # Test to validate that authentication will try to get
        # scoped token if the first project is disabled.
        tenants = [self.data.tenant_one, self.data.tenant_two]
        user = self.data.user
        unscoped = self.data.unscoped_access_info

        form_data = {'region': settings.OPENSTACK_KEYSTONE_URL,
                     'domain': DEFAULT_DOMAIN,
                     'password': user.password,
                     'username': user.name}

        self.mox.StubOutWithMock(self.ks_client_module, "Client")
        self.mox.StubOutWithMock(self.keystone_client_unscoped.tenants, "list")

        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     password=user.password,
                                     username=user.name,
                                     user_domain_name=DEFAULT_DOMAIN,
                                     insecure=False,
                                     cacert=None,
                                     debug=False)\
            .AndReturn(self.keystone_client_unscoped)
        self.keystone_client_unscoped.tenants.list().AndReturn(tenants)
        exc = keystone_exceptions.AuthorizationFailure
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     tenant_id=self.data.tenant_two.id,
                                     insecure=False,
                                     cacert=None,
                                     token=unscoped.auth_token,
                                     debug=False) \
            .AndRaise(exc)
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     tenant_id=self.data.tenant_one.id,
                                     insecure=False,
                                     cacert=None,
                                     token=unscoped.auth_token,
                                     debug=False) \
            .AndReturn(self.keystone_client_scoped)

        self.mox.ReplayAll()

        url = reverse('login')

        # GET the page to set the test cookie.
        response = self.client.get(url, form_data)
        self.assertEqual(response.status_code, 200)

        # POST to the page to log in.
        response = self.client.post(url, form_data)
        self.assertRedirects(response, settings.LOGIN_REDIRECT_URL)

    def test_no_enabled_tenants(self):
        tenants = [self.data.tenant_one, self.data.tenant_two]
        user = self.data.user
        unscoped = self.data.unscoped_access_info

        form_data = {'region': settings.OPENSTACK_KEYSTONE_URL,
                     'domain': DEFAULT_DOMAIN,
                     'password': user.password,
                     'username': user.name}

        self.mox.StubOutWithMock(self.ks_client_module, "Client")
        self.mox.StubOutWithMock(self.keystone_client_unscoped.tenants, "list")

        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     password=user.password,
                                     username=user.name,
                                     user_domain_name=DEFAULT_DOMAIN,
                                     insecure=False,
                                     cacert=None,
                                     debug=False)\
            .AndReturn(self.keystone_client_unscoped)
        self.keystone_client_unscoped.tenants.list().AndReturn(tenants)
        exc = keystone_exceptions.AuthorizationFailure
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     tenant_id=self.data.tenant_two.id,
                                     insecure=False,
                                     cacert=None,
                                     token=unscoped.auth_token,
                                     debug=False) \
            .AndRaise(exc)
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     tenant_id=self.data.tenant_one.id,
                                     insecure=False,
                                     cacert=None,
                                     token=unscoped.auth_token,
                                     debug=False) \
            .AndRaise(exc)

        self.mox.ReplayAll()

        url = reverse('login')

        # GET the page to set the test cookie.
        response = self.client.get(url, form_data)
        self.assertEqual(response.status_code, 200)

        # POST to the page to log in.
        response = self.client.post(url, form_data)
        self.assertTemplateUsed(response, 'auth/login.html')
        self.assertContains(response,
                            'Unable to authenticate to any available'
                            ' projects.')

    def test_no_tenants(self):
        user = self.data.user

        form_data = {'region': settings.OPENSTACK_KEYSTONE_URL,
                     'domain': DEFAULT_DOMAIN,
                     'password': user.password,
                     'username': user.name}

        self.mox.StubOutWithMock(self.ks_client_module, "Client")
        self.mox.StubOutWithMock(self.keystone_client_unscoped.tenants, "list")

        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     password=user.password,
                                     username=user.name,
                                     user_domain_name=DEFAULT_DOMAIN,
                                     insecure=False,
                                     cacert=None,
                                     debug=False)\
            .AndReturn(self.keystone_client_unscoped)
        self.keystone_client_unscoped.tenants.list().AndReturn([])

        self.mox.ReplayAll()

        url = reverse('login')

        # GET the page to set the test cookie.
        response = self.client.get(url, form_data)
        self.assertEqual(response.status_code, 200)

        # POST to the page to log in.
        response = self.client.post(url, form_data)
        self.assertTemplateUsed(response, 'auth/login.html')
        self.assertContains(response,
                            'You are not authorized for any projects.')

    def test_invalid_credentials(self):
        user = self.data.user

        form_data = {'region': settings.OPENSTACK_KEYSTONE_URL,
                     'domain': DEFAULT_DOMAIN,
                     'password': "invalid",
                     'username': user.name}

        self.mox.StubOutWithMock(self.ks_client_module, "Client")

        exc = keystone_exceptions.Unauthorized(401)
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     password="invalid",
                                     username=user.name,
                                     user_domain_name=DEFAULT_DOMAIN,
                                     insecure=False,
                                     cacert=None,
                                     debug=False).AndRaise(exc)

        self.mox.ReplayAll()

        url = reverse('login')

        # GET the page to set the test cookie.
        response = self.client.get(url, form_data)
        self.assertEqual(response.status_code, 200)

        # POST to the page to log in.
        response = self.client.post(url, form_data)
        self.assertTemplateUsed(response, 'auth/login.html')
        self.assertContains(response, "Invalid user name or password.")

    def test_exception(self):
        user = self.data.user

        form_data = {'region': settings.OPENSTACK_KEYSTONE_URL,
                     'domain': DEFAULT_DOMAIN,
                     'password': user.password,
                     'username': user.name}

        self.mox.StubOutWithMock(self.ks_client_module, "Client")

        exc = keystone_exceptions.ClientException(500)
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     password=user.password,
                                     username=user.name,
                                     user_domain_name=DEFAULT_DOMAIN,
                                     insecure=False,
                                     cacert=None,
                                     debug=False).AndRaise(exc)

        self.mox.ReplayAll()

        url = reverse('login')

        # GET the page to set the test cookie.
        response = self.client.get(url, form_data)
        self.assertEqual(response.status_code, 200)

        # POST to the page to log in.
        response = self.client.post(url, form_data)

        self.assertTemplateUsed(response, 'auth/login.html')
        self.assertContains(response,
                            ("An error occurred authenticating. Please try "
                             "again later."))

    def test_redirect_when_already_logged_in(self):
        self._login()

        response = self.client.get(reverse('login'))
        self.assertEqual(response.status_code, 302)
        self.assertNotIn(reverse('login'), response['location'])

    def test_dont_redirect_when_already_logged_in_if_next_is_set(self):
        self._login()

        expected_url = "%s?%s=/%s/" % (reverse('login'),
                                       auth.REDIRECT_FIELD_NAME,
                                       'special')

        response = self.client.get(expected_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'auth/login.html')

    def test_switch(self, next=None):
        tenant = self.data.tenant_two
        tenants = [self.data.tenant_one, self.data.tenant_two]
        user = self.data.user
        unscoped = self.data.unscoped_access_info
        scoped = self.data.scoped_access_info
        sc = self.data.service_catalog
        et = getattr(settings, 'OPENSTACK_ENDPOINT_TYPE', 'publicURL')

        form_data = {'region': settings.OPENSTACK_KEYSTONE_URL,
                     'domain': DEFAULT_DOMAIN,
                     'username': user.name,
                     'password': user.password}

        self.mox.StubOutWithMock(self.ks_client_module, "Client")
        self.mox.StubOutWithMock(self.keystone_client_unscoped.tenants, "list")

        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     password=user.password,
                                     username=user.name,
                                     user_domain_name=DEFAULT_DOMAIN,
                                     insecure=False,
                                     cacert=None,
                                     debug=False) \
            .AndReturn(self.keystone_client_unscoped)
        self.keystone_client_unscoped.tenants.list().AndReturn(tenants)
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     tenant_id=self.data.tenant_two.id,
                                     insecure=False,
                                     cacert=None,
                                     token=unscoped.auth_token,
                                     debug=False) \
            .AndReturn(self.keystone_client_scoped)

        self.ks_client_module.Client(auth_url=sc.url_for(endpoint_type=et),
                                     tenant_id=tenant.id,
                                     token=scoped.auth_token,
                                     insecure=False,
                                     cacert=None,
                                     debug=False) \
            .AndReturn(self.keystone_client_scoped)

        self.mox.ReplayAll()

        url = reverse('login')

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

        response = self.client.post(url, form_data)
        self.assertRedirects(response, settings.LOGIN_REDIRECT_URL)

        url = reverse('switch_tenants', args=[tenant.id])

        scoped['token']['tenant']['id'] = self.data.tenant_two.id

        if next:
            form_data.update({auth.REDIRECT_FIELD_NAME: next})

        response = self.client.get(url, form_data)

        if next:
            expected_url = 'http://testserver%s' % next
            self.assertEqual(response['location'], expected_url)
        else:
            self.assertRedirects(response, settings.LOGIN_REDIRECT_URL)

        self.assertEqual(self.client.session['token'].tenant['id'],
                         scoped.tenant_id)

    def test_switch_with_next(self):
        self.test_switch(next='/next_url')

    def test_switch_region(self, next=None):
        tenants = [self.data.tenant_one, self.data.tenant_two]
        user = self.data.user
        unscoped = self.data.unscoped_access_info
        sc = self.data.service_catalog

        form_data = {'region': settings.OPENSTACK_KEYSTONE_URL,
                     'domain': DEFAULT_DOMAIN,
                     'username': user.name,
                     'password': user.password}

        self.mox.StubOutWithMock(self.ks_client_module, "Client")
        self.mox.StubOutWithMock(self.keystone_client_unscoped.tenants, "list")

        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     password=user.password,
                                     username=user.name,
                                     user_domain_name=DEFAULT_DOMAIN,
                                     insecure=False,
                                     cacert=None,
                                     debug=False) \
            .AndReturn(self.keystone_client_unscoped)
        self.keystone_client_unscoped.tenants.list().AndReturn(tenants)
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     tenant_id=self.data.tenant_two.id,
                                     insecure=False,
                                     cacert=None,
                                     token=unscoped.auth_token,
                                     debug=False) \
            .AndReturn(self.keystone_client_scoped)

        self.mox.ReplayAll()

        url = reverse('login')

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

        response = self.client.post(url, form_data)
        self.assertRedirects(response, settings.LOGIN_REDIRECT_URL)

        old_region = sc.get_endpoints()['compute'][0]['region']
        self.assertEqual(self.client.session['services_region'], old_region)

        region = sc.get_endpoints()['compute'][1]['region']
        url = reverse('switch_services_region', args=[region])

        form_data['region_name'] = region

        if next:
            form_data.update({auth.REDIRECT_FIELD_NAME: next})

        response = self.client.get(url, form_data)

        if next:
            expected_url = 'http://testserver%s' % next
            self.assertEqual(response['location'], expected_url)
        else:
            self.assertRedirects(response, settings.LOGIN_REDIRECT_URL)

        self.assertEqual(self.client.session['services_region'], region)

    def test_switch_region_with_next(self, next=None):
        self.test_switch_region(next='/next_url')

    def test_tenant_sorting(self):
        tenants = [self.data.tenant_two, self.data.tenant_one]
        expected_tenants = [self.data.tenant_one, self.data.tenant_two]
        user = self.data.user
        unscoped = self.data.unscoped_access_info

        self.mox.StubOutWithMock(self.ks_client_module, "Client")
        self.mox.StubOutWithMock(self.keystone_client_unscoped.tenants, "list")

        self.ks_client_module.Client(user_id=user.id,
                                     auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     token=unscoped.auth_token,
                                     insecure=False,
                                     cacert=None,
                                     debug=False)\
            .AndReturn(self.keystone_client_unscoped)
        self.keystone_client_unscoped.tenants.list().AndReturn(tenants)

        self.mox.ReplayAll()

        tenant_list = utils.get_project_list(
            user_id=user.id,
            auth_url=settings.OPENSTACK_KEYSTONE_URL,
            token=unscoped.auth_token,
            insecure=False,
            cacert=None,
            debug=False)
        self.assertEqual(tenant_list, expected_tenants)


def EndpointMetaFactory(endpoint_type):
    def endpoint_wrapper(func):
        def new_func(*args, **kwargs):
            _endpoint_type = getattr(settings, 'OPENSTACK_ENDPOINT_TYPE', None)
            # set settings.OPENSTACK_ENDPOINT_TYPE to given value
            setattr(settings, 'OPENSTACK_ENDPOINT_TYPE', endpoint_type)
            # ensure that ret won't be touched by del/setattr below
            ret = copy.deepcopy(func(*args, **kwargs))
            # and restore it
            if _endpoint_type is None:
                del settings.OPENSTACK_ENDPOINT_TYPE
            else:
                setattr(settings, 'OPENSTACK_ENDPOINT_TYPE', _endpoint_type)
            return ret
        return new_func

    class EndPointMeta(type):
        # wrap each test with OPENSTACK_ENDPOINT_TYPE parameter set/restore
        def __new__(cls, name, bases, attrs):
            base, = bases
            for k, v in base.__dict__.iteritems():
                if not k.startswith('__') and getattr(v, '__call__', None):
                    attrs[k] = endpoint_wrapper(v)
            return super(EndPointMeta, cls).__new__(cls, name, bases, attrs)
    return EndPointMeta


class OpenStackAuthTestsV2WithPublicURL(OpenStackAuthTestsV2):
    """Test V2 with settings.OPENSTACK_ENDPOINT_TYPE = 'publicURL'."""
    __metaclass__ = EndpointMetaFactory('publicURL')


class OpenStackAuthTestsV2WithInternalURL(OpenStackAuthTestsV2):
    """Test V2 with settings.OPENSTACK_ENDPOINT_TYPE = 'internalURL'."""
    __metaclass__ = EndpointMetaFactory('internalURL')


class OpenStackAuthTestsV2WithAdminURL(OpenStackAuthTestsV2):
    """Test V2 with settings.OPENSTACK_ENDPOINT_TYPE = 'adminURL'."""
    __metaclass__ = EndpointMetaFactory('adminURL')


class OpenStackAuthTestsV3(test.TestCase):
    def setUp(self):
        super(OpenStackAuthTestsV3, self).setUp()
        self.mox = mox.Mox()
        self.data = data_v3.generate_test_data()
        self.ks_client_module = client_v3
        endpoint = settings.OPENSTACK_KEYSTONE_URL
        self.keystone_client_unscoped = self.ks_client_module.Client(
            endpoint=endpoint,
            auth_ref=self.data.unscoped_access_info)
        self.keystone_client_scoped = self.ks_client_module.Client(
            endpoint=endpoint,
            auth_ref=self.data.scoped_access_info)
        settings.OPENSTACK_API_VERSIONS['identity'] = 3
        settings.OPENSTACK_KEYSTONE_URL = "http://localhost:5000/v3"

    def tearDown(self):
        self.mox.UnsetStubs()
        self.mox.VerifyAll()

    def test_login(self):
        projects = [self.data.project_one, self.data.project_two]
        user = self.data.user
        unscoped = self.data.unscoped_access_info

        form_data = {'region': settings.OPENSTACK_KEYSTONE_URL,
                     'domain': DEFAULT_DOMAIN,
                     'password': user.password,
                     'username': user.name}

        self.mox.StubOutWithMock(self.ks_client_module, "Client")
        self.mox.StubOutWithMock(self.keystone_client_unscoped.projects,
                                 "list")

        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     password=user.password,
                                     username=user.name,
                                     user_domain_name=DEFAULT_DOMAIN,
                                     insecure=False,
                                     cacert=None,
                                     debug=False)\
            .AndReturn(self.keystone_client_unscoped)
        self.keystone_client_unscoped.projects.list(user=user.id) \
            .AndReturn(projects)
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     tenant_id=self.data.project_two.id,
                                     insecure=False,
                                     cacert=None,
                                     token=unscoped.auth_token,
                                     debug=False) \
            .AndReturn(self.keystone_client_scoped)

        self.mox.ReplayAll()

        url = reverse('login')

        # GET the page to set the test cookie.
        response = self.client.get(url, form_data)
        self.assertEqual(response.status_code, 200)

        # POST to the page to log in.
        response = self.client.post(url, form_data)
        self.assertRedirects(response, settings.LOGIN_REDIRECT_URL)

    def test_login_with_disabled_projects(self):
        projects = [self.data.project_one, self.data.project_two]
        user = self.data.user
        unscoped = self.data.unscoped_access_info

        form_data = {'region': settings.OPENSTACK_KEYSTONE_URL,
                     'domain': DEFAULT_DOMAIN,
                     'password': user.password,
                     'username': user.name}

        self.mox.StubOutWithMock(self.ks_client_module, "Client")
        self.mox.StubOutWithMock(self.keystone_client_unscoped.projects,
                                 "list")

        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     password=user.password,
                                     username=user.name,
                                     user_domain_name=DEFAULT_DOMAIN,
                                     insecure=False,
                                     cacert=None,
                                     debug=False)\
            .AndReturn(self.keystone_client_unscoped)
        self.keystone_client_unscoped.projects.list(user=user.id) \
            .AndReturn(projects)
        exc = keystone_exceptions.AuthorizationFailure
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     tenant_id=self.data.project_two.id,
                                     insecure=False,
                                     cacert=None,
                                     token=unscoped.auth_token,
                                     debug=False) \
            .AndRaise(exc)
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     tenant_id=self.data.project_one.id,
                                     insecure=False,
                                     cacert=None,
                                     token=unscoped.auth_token,
                                     debug=False) \
            .AndReturn(self.keystone_client_scoped)

        self.mox.ReplayAll()

        url = reverse('login')

        # GET the page to set the test cookie.
        response = self.client.get(url, form_data)
        self.assertEqual(response.status_code, 200)

        # POST to the page to log in.
        response = self.client.post(url, form_data)
        self.assertRedirects(response, settings.LOGIN_REDIRECT_URL)

    def test_no_enabled_projects(self):
        projects = [self.data.project_one, self.data.project_two]
        user = self.data.user
        unscoped = self.data.unscoped_access_info

        form_data = {'region': settings.OPENSTACK_KEYSTONE_URL,
                     'domain': DEFAULT_DOMAIN,
                     'password': user.password,
                     'username': user.name}

        self.mox.StubOutWithMock(self.ks_client_module, "Client")
        self.mox.StubOutWithMock(self.keystone_client_unscoped.projects,
                                 "list")

        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     password=user.password,
                                     username=user.name,
                                     user_domain_name=DEFAULT_DOMAIN,
                                     insecure=False,
                                     cacert=None,
                                     debug=False)\
            .AndReturn(self.keystone_client_unscoped)
        self.keystone_client_unscoped.projects.list(user=user.id) \
            .AndReturn(projects)
        exc = keystone_exceptions.AuthorizationFailure
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     tenant_id=self.data.project_two.id,
                                     insecure=False,
                                     cacert=None,
                                     token=unscoped.auth_token,
                                     debug=False) \
            .AndRaise(exc)
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     tenant_id=self.data.project_one.id,
                                     insecure=False,
                                     cacert=None,
                                     token=unscoped.auth_token,
                                     debug=False) \
            .AndRaise(exc)

        self.mox.ReplayAll()

        url = reverse('login')

        # GET the page to set the test cookie.
        response = self.client.get(url, form_data)
        self.assertEqual(response.status_code, 200)

        # POST to the page to log in.
        response = self.client.post(url, form_data)
        self.assertTemplateUsed(response, 'auth/login.html')
        self.assertContains(response,
                            'Unable to authenticate to any available'
                            ' projects.')

    def test_no_projects(self):
        user = self.data.user

        form_data = {'region': settings.OPENSTACK_KEYSTONE_URL,
                     'domain': DEFAULT_DOMAIN,
                     'password': user.password,
                     'username': user.name}

        self.mox.StubOutWithMock(self.ks_client_module, "Client")
        self.mox.StubOutWithMock(self.keystone_client_unscoped.projects,
                                 "list")

        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     password=user.password,
                                     username=user.name,
                                     user_domain_name=DEFAULT_DOMAIN,
                                     insecure=False,
                                     cacert=None,
                                     debug=False)\
            .AndReturn(self.keystone_client_unscoped)
        self.keystone_client_unscoped.projects.list(user=user.id) \
            .AndReturn([])

        self.mox.ReplayAll()

        url = reverse('login')

        # GET the page to set the test cookie.
        response = self.client.get(url, form_data)
        self.assertEqual(response.status_code, 200)

        # POST to the page to log in.
        response = self.client.post(url, form_data)
        self.assertTemplateUsed(response, 'auth/login.html')
        self.assertContains(response,
                            'You are not authorized for any projects.')

    def test_invalid_credentials(self):
        user = self.data.user

        form_data = {'region': settings.OPENSTACK_KEYSTONE_URL,
                     'domain': DEFAULT_DOMAIN,
                     'password': "invalid",
                     'username': user.name}

        self.mox.StubOutWithMock(self.ks_client_module, "Client")

        exc = keystone_exceptions.Unauthorized(401)
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     password="invalid",
                                     username=user.name,
                                     user_domain_name=DEFAULT_DOMAIN,
                                     insecure=False,
                                     cacert=None,
                                     debug=False).AndRaise(exc)

        self.mox.ReplayAll()

        url = reverse('login')

        # GET the page to set the test cookie.
        response = self.client.get(url, form_data)
        self.assertEqual(response.status_code, 200)

        # POST to the page to log in.
        response = self.client.post(url, form_data)
        self.assertTemplateUsed(response, 'auth/login.html')
        self.assertContains(response, "Invalid user name or password.")

    def test_exception(self):
        user = self.data.user

        form_data = {'region': settings.OPENSTACK_KEYSTONE_URL,
                     'domain': DEFAULT_DOMAIN,
                     'password': user.password,
                     'username': user.name}

        self.mox.StubOutWithMock(self.ks_client_module, "Client")

        exc = keystone_exceptions.ClientException(500)
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     password=user.password,
                                     username=user.name,
                                     user_domain_name=DEFAULT_DOMAIN,
                                     insecure=False,
                                     cacert=None,
                                     debug=False).AndRaise(exc)

        self.mox.ReplayAll()

        url = reverse('login')

        # GET the page to set the test cookie.
        response = self.client.get(url, form_data)
        self.assertEqual(response.status_code, 200)

        # POST to the page to log in.
        response = self.client.post(url, form_data)

        self.assertTemplateUsed(response, 'auth/login.html')
        self.assertContains(response,
                            ("An error occurred authenticating. Please try "
                             "again later."))

    def test_switch(self, next=None):
        project = self.data.project_two
        projects = [self.data.project_one, self.data.project_two]
        user = self.data.user
        unscoped = self.data.unscoped_access_info
        scoped = self.data.scoped_access_info
        sc = self.data.service_catalog
        et = getattr(settings, 'OPENSTACK_ENDPOINT_TYPE', 'publicURL')

        form_data = {'region': settings.OPENSTACK_KEYSTONE_URL,
                     'domain': DEFAULT_DOMAIN,
                     'username': user.name,
                     'password': user.password}

        self.mox.StubOutWithMock(self.ks_client_module, "Client")
        self.mox.StubOutWithMock(self.keystone_client_unscoped.projects,
                                 "list")

        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     password=user.password,
                                     username=user.name,
                                     user_domain_name=DEFAULT_DOMAIN,
                                     insecure=False,
                                     cacert=None,
                                     debug=False) \
            .AndReturn(self.keystone_client_unscoped)
        self.keystone_client_unscoped.projects.list(user=user.id) \
            .AndReturn(projects)
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     tenant_id=self.data.project_two.id,
                                     insecure=False,
                                     cacert=None,
                                     token=unscoped.auth_token,
                                     debug=False) \
            .AndReturn(self.keystone_client_scoped)
        self.ks_client_module.Client(auth_url=sc.url_for(endpoint_type=et),
                                     tenant_id=project.id,
                                     token=scoped.auth_token,
                                     insecure=False,
                                     cacert=None,
                                     debug=False) \
            .AndReturn(self.keystone_client_scoped)

        self.mox.ReplayAll()

        url = reverse('login')

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

        response = self.client.post(url, form_data)
        self.assertRedirects(response, settings.LOGIN_REDIRECT_URL)

        url = reverse('switch_tenants', args=[project.id])

        scoped['project']['id'] = self.data.project_two.id

        if next:
            form_data.update({auth.REDIRECT_FIELD_NAME: next})

        response = self.client.get(url, form_data)

        if next:
            expected_url = 'http://testserver%s' % next
            self.assertEqual(response['location'], expected_url)
        else:
            self.assertRedirects(response, settings.LOGIN_REDIRECT_URL)

        self.assertEqual(self.client.session['token'].project['id'],
                         scoped.project_id)

    def test_switch_with_next(self):
        self.test_switch(next='/next_url')

    def test_switch_region(self, next=None):
        projects = [self.data.project_one, self.data.project_two]
        user = self.data.user
        unscoped = self.data.unscoped_access_info
        sc = self.data.service_catalog

        form_data = {'region': settings.OPENSTACK_KEYSTONE_URL,
                     'domain': DEFAULT_DOMAIN,
                     'username': user.name,
                     'password': user.password}

        self.mox.StubOutWithMock(self.ks_client_module, "Client")
        self.mox.StubOutWithMock(self.keystone_client_unscoped.projects,
                                 "list")

        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     password=user.password,
                                     username=user.name,
                                     user_domain_name=DEFAULT_DOMAIN,
                                     insecure=False,
                                     cacert=None,
                                     debug=False) \
            .AndReturn(self.keystone_client_unscoped)
        self.keystone_client_unscoped.projects.list(user=user.id) \
            .AndReturn(projects)
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     tenant_id=self.data.project_two.id,
                                     insecure=False,
                                     cacert=None,
                                     token=unscoped.auth_token,
                                     debug=False) \
            .AndReturn(self.keystone_client_scoped)

        self.mox.ReplayAll()

        url = reverse('login')

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

        response = self.client.post(url, form_data)
        self.assertRedirects(response, settings.LOGIN_REDIRECT_URL)

        old_region = sc.get_endpoints()['compute'][0]['region']
        self.assertEqual(self.client.session['services_region'], old_region)

        region = sc.get_endpoints()['compute'][1]['region']
        url = reverse('switch_services_region', args=[region])

        form_data['region_name'] = region

        if next:
            form_data.update({auth.REDIRECT_FIELD_NAME: next})

        response = self.client.get(url, form_data)

        if next:
            expected_url = 'http://testserver%s' % next
            self.assertEqual(response['location'], expected_url)
        else:
            self.assertRedirects(response, settings.LOGIN_REDIRECT_URL)

        self.assertEqual(self.client.session['services_region'], region)

    def test_switch_region_with_next(self, next=None):
        self.test_switch_region(next='/next_url')

    def test_tenant_sorting(self):
        projects = [self.data.project_two, self.data.project_one]
        expected_projects = [self.data.project_one, self.data.project_two]
        user = self.data.user
        unscoped = self.data.unscoped_access_info

        self.mox.StubOutWithMock(self.ks_client_module, "Client")
        self.mox.StubOutWithMock(self.keystone_client_unscoped.projects,
                                 "list")

        self.ks_client_module.Client(user_id=user.id,
                                     auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     token=unscoped.auth_token,
                                     insecure=False,
                                     cacert=None,
                                     debug=False)\
            .AndReturn(self.keystone_client_unscoped)
        self.keystone_client_unscoped.projects.list(user=user.id) \
            .AndReturn(projects)

        self.mox.ReplayAll()

        project_list = utils.get_project_list(
            user_id=user.id,
            auth_url=settings.OPENSTACK_KEYSTONE_URL,
            token=unscoped.auth_token,
            insecure=False,
            cacert=None,
            debug=False)
        self.assertEqual(project_list, expected_projects)


class OpenStackAuthTestsV3WithPublicURL(OpenStackAuthTestsV3):
    """Test V3 with settings.OPENSTACK_ENDPOINT_TYPE = 'publicURL'."""
    __metaclass__ = EndpointMetaFactory('publicURL')


class OpenStackAuthTestsV3WithInternalURL(OpenStackAuthTestsV3):
    """Test V3 with settings.OPENSTACK_ENDPOINT_TYPE = 'internalURL'."""
    __metaclass__ = EndpointMetaFactory('internalURL')


class OpenStackAuthTestsV3WithAdminURL(OpenStackAuthTestsV3):
    """Test V3 with settings.OPENSTACK_ENDPOINT_TYPE = 'adminURL'."""
    __metaclass__ = EndpointMetaFactory('adminURL')
