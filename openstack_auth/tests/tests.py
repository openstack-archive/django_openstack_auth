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

import uuid

from django.conf import settings
from django.contrib import auth
from django.core.urlresolvers import reverse
from django import http
from django import test
from keystoneclient.auth.identity import v2 as auth_v2
from keystoneclient.auth.identity import v3 as auth_v3
from keystoneclient.auth import token_endpoint
from keystoneclient import exceptions as keystone_exceptions
from keystoneclient import session
from keystoneclient.v2_0 import client as client_v2
from keystoneclient.v3 import client as client_v3
import mock
from mox3 import mox
from testscenarios import load_tests_apply_scenarios  # noqa

from openstack_auth import policy
from openstack_auth.tests import data_v2
from openstack_auth.tests import data_v3
from openstack_auth import user
from openstack_auth import utils


DEFAULT_DOMAIN = settings.OPENSTACK_KEYSTONE_DEFAULT_DOMAIN


class OpenStackAuthTestsMixin(object):
    '''Common functions for version specific tests.'''

    scenarios = [
        ('pure', {'interface': None}),
        ('public', {'interface': 'publicURL'}),
        ('internal', {'interface': 'internalURL'}),
        ('admin', {'interface': 'adminURL'})
    ]

    def _mock_unscoped_client(self, user):
        plugin = self._create_password_auth()
        plugin.get_access(mox.IsA(session.Session)). \
            AndReturn(self.data.unscoped_access_info)
        return self.ks_client_module.Client(session=mox.IsA(session.Session),
                                            auth=plugin)

    def _mock_unscoped_client_with_token(self, user, unscoped):
        plugin = token_endpoint.Token(settings.OPENSTACK_KEYSTONE_URL,
                                      unscoped.auth_token)
        return self.ks_client_module.Client(session=mox.IsA(session.Session),
                                            auth=plugin)

    def _mock_client_token_auth_failure(self, unscoped, tenant_id):
        plugin = self._create_token_auth(tenant_id, unscoped.auth_token)
        plugin.get_access(mox.IsA(session.Session)). \
            AndRaise(keystone_exceptions.AuthorizationFailure)

    def _mock_client_password_auth_failure(self, username, password, exc):
        plugin = self._create_password_auth(username=username,
                                            password=password)
        plugin.get_access(mox.IsA(session.Session)).AndRaise(exc)

    def _mock_scoped_client_for_tenant(self, auth_ref, tenant_id, url=None,
                                       client=True):
        if url is None:
            url = settings.OPENSTACK_KEYSTONE_URL

        plugin = self._create_token_auth(
            tenant_id,
            token=self.data.unscoped_access_info.auth_token,
            url=url)

        plugin.get_access(mox.IsA(session.Session)).AndReturn(auth_ref)
        if client:
            return self.ks_client_module.Client(
                session=mox.IsA(session.Session),
                auth=plugin)

    def get_form_data(self, user):
        return {'region': settings.OPENSTACK_KEYSTONE_URL,
                'domain': DEFAULT_DOMAIN,
                'password': user.password,
                'username': user.name}


class OpenStackAuthTestsV2(OpenStackAuthTestsMixin, test.TestCase):

    def setUp(self):
        super(OpenStackAuthTestsV2, self).setUp()

        if self.interface:
            override = self.settings(OPENSTACK_ENDPOINT_TYPE=self.interface)
            override.enable()
            self.addCleanup(override.disable)

        self.mox = mox.Mox()
        self.addCleanup(self.mox.VerifyAll)
        self.addCleanup(self.mox.UnsetStubs)

        self.data = data_v2.generate_test_data()
        self.ks_client_module = client_v2

        settings.OPENSTACK_API_VERSIONS['identity'] = 2.0
        settings.OPENSTACK_KEYSTONE_URL = "http://localhost:5000/v2.0"

        self.mox.StubOutClassWithMocks(token_endpoint, 'Token')
        self.mox.StubOutClassWithMocks(auth_v2, 'Token')
        self.mox.StubOutClassWithMocks(auth_v2, 'Password')
        self.mox.StubOutClassWithMocks(client_v2, 'Client')

    def _mock_unscoped_list_tenants(self, client, tenants):
        client.tenants = self.mox.CreateMockAnything()
        client.tenants.list().AndReturn(tenants)

    def _mock_unscoped_client_list_tenants(self, user, tenants):
        client = self._mock_unscoped_client(user)
        self._mock_unscoped_list_tenants(client, tenants)

    def _mock_client_delete_token(self, user, token, url=None):
        if not url:
            url = settings.OPENSTACK_KEYSTONE_URL

        plugin = token_endpoint.Token(
            endpoint=url,
            token=self.data.unscoped_access_info.auth_token)

        client = self.ks_client_module.Client(session=mox.IsA(session.Session),
                                              auth=plugin)
        client.tokens = self.mox.CreateMockAnything()
        client.tokens.delete(token=token)
        return client

    def _create_password_auth(self, username=None, password=None, url=None):
        if not username:
            username = self.data.user.name

        if not password:
            password = self.data.user.password

        if not url:
            url = settings.OPENSTACK_KEYSTONE_URL

        return auth_v2.Password(auth_url=url,
                                password=password,
                                username=username)

    def _create_token_auth(self, project_id, token=None, url=None):
        if not token:
            token = self.data.unscoped_access_info.auth_token

        if not url:
            url = settings.OPENSTACK_KEYSTONE_URL

        return auth_v2.Token(auth_url=url,
                             token=token,
                             tenant_id=project_id,
                             reauthenticate=False)

    def _login(self):
        tenants = [self.data.tenant_one, self.data.tenant_two]
        user = self.data.user
        unscoped = self.data.unscoped_access_info

        form_data = self.get_form_data(user)
        self._mock_unscoped_client_list_tenants(user, tenants)
        self._mock_scoped_client_for_tenant(unscoped, self.data.tenant_one.id)

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

    def test_login_with_disabled_tenant(self):
        # Test to validate that authentication will not try to get
        # scoped token for disabled project.
        tenants = [self.data.tenant_two, self.data.tenant_one]
        user = self.data.user
        unscoped = self.data.unscoped_access_info

        form_data = self.get_form_data(user)
        self._mock_unscoped_client_list_tenants(user, tenants)
        self._mock_scoped_client_for_tenant(unscoped, self.data.tenant_one.id)
        self.mox.ReplayAll()

        url = reverse('login')

        # GET the page to set the test cookie.
        response = self.client.get(url, form_data)
        self.assertEqual(response.status_code, 200)

        # POST to the page to log in.
        response = self.client.post(url, form_data)
        self.assertRedirects(response, settings.LOGIN_REDIRECT_URL)

    def test_login_w_bad_region_cookie(self):
        self.client.cookies['services_region'] = "bad_region"
        self._login()
        self.assertNotEqual("bad_region",
                            self.client.session['services_region'])
        self.assertEqual("RegionOne",
                         self.client.session['services_region'])

    def test_no_enabled_tenants(self):
        tenants = [self.data.tenant_two]
        user = self.data.user

        form_data = self.get_form_data(user)
        self._mock_unscoped_client_list_tenants(user, tenants)
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

    def test_no_tenants(self):
        user = self.data.user

        form_data = self.get_form_data(user)
        self._mock_unscoped_client_list_tenants(user, [])

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

        form_data = self.get_form_data(user)
        form_data['password'] = "invalid"

        exc = keystone_exceptions.Unauthorized(401)
        self._mock_client_password_auth_failure(user.name, "invalid", exc)

        self.mox.ReplayAll()

        url = reverse('login')

        # GET the page to set the test cookie.
        response = self.client.get(url, form_data)
        self.assertEqual(response.status_code, 200)

        # POST to the page to log in.
        response = self.client.post(url, form_data)
        self.assertTemplateUsed(response, 'auth/login.html')
        self.assertContains(response, "Invalid credentials.")

    def test_exception(self):
        user = self.data.user

        form_data = self.get_form_data(user)
        exc = keystone_exceptions.ClientException(500)
        self._mock_client_password_auth_failure(user.name, user.password, exc)
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
        endpoint = sc.url_for(endpoint_type=et)

        form_data = self.get_form_data(user)

        self._mock_unscoped_client_list_tenants(user, tenants)
        self._mock_scoped_client_for_tenant(unscoped, self.data.tenant_one.id)
        self._mock_client_delete_token(user, unscoped.auth_token, endpoint)
        self._mock_scoped_client_for_tenant(scoped, tenant.id, url=endpoint,
                                            client=False)

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
        scoped = self.data.scoped_access_info
        sc = self.data.service_catalog

        form_data = self.get_form_data(user)

        self._mock_unscoped_client_list_tenants(user, tenants)
        self._mock_scoped_client_for_tenant(scoped, self.data.tenant_one.id)

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
        self.assertEqual(self.client.cookies['services_region'].value, region)

    def test_switch_region_with_next(self, next=None):
        self.test_switch_region(next='/next_url')

    def test_tenant_sorting(self):
        tenants = [self.data.tenant_two, self.data.tenant_one]
        expected_tenants = [self.data.tenant_one, self.data.tenant_two]
        user = self.data.user
        unscoped = self.data.unscoped_access_info

        client = self._mock_unscoped_client_with_token(user, unscoped)
        self._mock_unscoped_list_tenants(client, tenants)

        self.mox.ReplayAll()

        tenant_list = utils.get_project_list(
            user_id=user.id,
            auth_url=settings.OPENSTACK_KEYSTONE_URL,
            token=unscoped.auth_token)
        self.assertEqual(tenant_list, expected_tenants)

    def test_tenant_list_caching(self):
        tenants = [self.data.tenant_two, self.data.tenant_one]
        expected_tenants = [self.data.tenant_one, self.data.tenant_two]
        user = self.data.user
        unscoped = self.data.unscoped_access_info

        client = self._mock_unscoped_client_with_token(user, unscoped)
        self._mock_unscoped_list_tenants(client, tenants)
        self.mox.ReplayAll()

        tenant_list = utils.get_project_list(
            user_id=user.id,
            auth_url=settings.OPENSTACK_KEYSTONE_URL,
            token=unscoped.auth_token)
        self.assertEqual(tenant_list, expected_tenants)

        # Test to validate that requesting the project list again results
        # to using the cache and will not make a Keystone call.
        self.assertEqual(utils._PROJECT_CACHE.get(unscoped.auth_token),
                         expected_tenants)
        tenant_list = utils.get_project_list(
            user_id=user.id,
            auth_url=settings.OPENSTACK_KEYSTONE_URL,
            token=unscoped.auth_token)
        self.assertEqual(tenant_list, expected_tenants)

        utils.remove_project_cache(unscoped.auth_token)
        self.assertIsNone(utils._PROJECT_CACHE.get(unscoped.auth_token))


class OpenStackAuthTestsV3(OpenStackAuthTestsMixin, test.TestCase):

    def _mock_unscoped_client_list_projects(self, user, projects):
        client = self._mock_unscoped_client(user)
        self._mock_unscoped_list_projects(client, user, projects)

    def _mock_unscoped_list_projects(self, client, user, projects):
        client.projects = self.mox.CreateMockAnything()
        client.projects.list(user=user.id).AndReturn(projects)

    def _mock_unscoped_client_list_projects_fail(self, user):
        client = self._mock_unscoped_client(user)
        self._mock_unscoped_list_projects_fail(client, user)

    def _mock_unscoped_list_projects_fail(self, client, user):
        client.projects = self.mox.CreateMockAnything()
        client.projects.list(user=user.id).AndRaise(
            keystone_exceptions.AuthorizationFailure)

    def _create_password_auth(self, username=None, password=None, url=None):
        if not username:
            username = self.data.user.name

        if not password:
            password = self.data.user.password

        if not url:
            url = settings.OPENSTACK_KEYSTONE_URL

        return auth_v3.Password(auth_url=url,
                                password=password,
                                username=username,
                                user_domain_name=DEFAULT_DOMAIN,
                                unscoped=True)

    def _create_token_auth(self, project_id, token=None, url=None):
        if not token:
            token = self.data.unscoped_access_info.auth_token

        if not url:
            url = settings.OPENSTACK_KEYSTONE_URL

        return auth_v3.Token(auth_url=url,
                             token=token,
                             project_id=project_id,
                             reauthenticate=False)

    def setUp(self):
        super(OpenStackAuthTestsV3, self).setUp()

        if getattr(self, 'interface', None):
            override = self.settings(OPENSTACK_ENDPOINT_TYPE=self.interface)
            override.enable()
            self.addCleanup(override.disable)

        self.mox = mox.Mox()
        self.addCleanup(self.mox.VerifyAll)
        self.addCleanup(self.mox.UnsetStubs)

        self.data = data_v3.generate_test_data()
        self.ks_client_module = client_v3

        settings.OPENSTACK_API_VERSIONS['identity'] = 3
        settings.OPENSTACK_KEYSTONE_URL = "http://localhost:5000/v3"

        self.mox.StubOutClassWithMocks(token_endpoint, 'Token')
        self.mox.StubOutClassWithMocks(auth_v3, 'Token')
        self.mox.StubOutClassWithMocks(auth_v3, 'Password')
        self.mox.StubOutClassWithMocks(client_v3, 'Client')

    def test_login(self):
        projects = [self.data.project_one, self.data.project_two]
        user = self.data.user
        unscoped = self.data.unscoped_access_info

        form_data = self.get_form_data(user)
        self._mock_unscoped_client_list_projects(user, projects)
        self._mock_scoped_client_for_tenant(unscoped, self.data.project_one.id)

        self.mox.ReplayAll()

        url = reverse('login')

        # GET the page to set the test cookie.
        response = self.client.get(url, form_data)
        self.assertEqual(response.status_code, 200)

        # POST to the page to log in.
        response = self.client.post(url, form_data)
        self.assertRedirects(response, settings.LOGIN_REDIRECT_URL)

    def test_login_with_disabled_project(self):
        # Test to validate that authentication will not try to get
        # scoped token for disabled project.
        projects = [self.data.project_two, self.data.project_one]
        user = self.data.user
        unscoped = self.data.unscoped_access_info

        form_data = self.get_form_data(user)
        self._mock_unscoped_client_list_projects(user, projects)
        self._mock_scoped_client_for_tenant(unscoped, self.data.project_one.id)
        self.mox.ReplayAll()

        url = reverse('login')

        # GET the page to set the test cookie.
        response = self.client.get(url, form_data)
        self.assertEqual(response.status_code, 200)

        # POST to the page to log in.
        response = self.client.post(url, form_data)
        self.assertRedirects(response, settings.LOGIN_REDIRECT_URL)

    def test_no_enabled_projects(self):
        projects = [self.data.project_two]
        user = self.data.user

        form_data = self.get_form_data(user)

        self._mock_unscoped_client_list_projects(user, projects)
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

    def test_no_projects(self):
        user = self.data.user

        form_data = self.get_form_data(user)
        self._mock_unscoped_client_list_projects(user, [])
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

    def test_fail_projects(self):
        user = self.data.user

        form_data = self.get_form_data(user)
        self._mock_unscoped_client_list_projects_fail(user)
        self.mox.ReplayAll()

        url = reverse('login')

        # GET the page to set the test cookie.
        response = self.client.get(url, form_data)
        self.assertEqual(response.status_code, 200)

        # POST to the page to log in.
        response = self.client.post(url, form_data)
        self.assertTemplateUsed(response, 'auth/login.html')
        self.assertContains(response,
                            'Unable to retrieve authorized projects.')

    def test_invalid_credentials(self):
        user = self.data.user

        form_data = self.get_form_data(user)

        form_data['password'] = "invalid"

        exc = keystone_exceptions.Unauthorized(401)
        self._mock_client_password_auth_failure(user.name, "invalid", exc)

        self.mox.ReplayAll()

        url = reverse('login')

        # GET the page to set the test cookie.
        response = self.client.get(url, form_data)
        self.assertEqual(response.status_code, 200)

        # POST to the page to log in.
        response = self.client.post(url, form_data)
        self.assertTemplateUsed(response, 'auth/login.html')
        self.assertContains(response, "Invalid credentials.")

    def test_exception(self):
        user = self.data.user
        form_data = self.get_form_data(user)
        exc = keystone_exceptions.ClientException(500)
        self._mock_client_password_auth_failure(user.name, user.password, exc)
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
        scoped = self.data.scoped_access_info
        sc = self.data.service_catalog
        et = getattr(settings, 'OPENSTACK_ENDPOINT_TYPE', 'publicURL')

        form_data = self.get_form_data(user)

        self._mock_unscoped_client_list_projects(user, projects)
        self._mock_scoped_client_for_tenant(scoped, self.data.project_one.id)
        self._mock_scoped_client_for_tenant(
            scoped,
            project.id,
            url=sc.url_for(endpoint_type=et),
            client=False)

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
        scoped = self.data.unscoped_access_info
        sc = self.data.service_catalog

        form_data = self.get_form_data(user)
        self._mock_unscoped_client_list_projects(user, projects)
        self._mock_scoped_client_for_tenant(scoped, self.data.project_one.id)

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

        client = self._mock_unscoped_client_with_token(user, unscoped)
        self._mock_unscoped_list_projects(client, user, projects)
        self.mox.ReplayAll()

        project_list = utils.get_project_list(
            user_id=user.id,
            auth_url=settings.OPENSTACK_KEYSTONE_URL,
            token=unscoped.auth_token)
        self.assertEqual(project_list, expected_projects)

    def test_tenant_list_caching(self):
        projects = [self.data.project_two, self.data.project_one]
        expected_projects = [self.data.project_one, self.data.project_two]
        user = self.data.user
        unscoped = self.data.unscoped_access_info

        client = self._mock_unscoped_client_with_token(user, unscoped)
        self._mock_unscoped_list_projects(client, user, projects)

        self.mox.ReplayAll()

        project_list = utils.get_project_list(
            user_id=user.id,
            auth_url=settings.OPENSTACK_KEYSTONE_URL,
            token=unscoped.auth_token)
        self.assertEqual(project_list, expected_projects)

        # Test to validate that requesting the project list again results
        # to using the cache and will not make a Keystone call.
        self.assertEqual(utils._PROJECT_CACHE.get(unscoped.auth_token),
                         expected_projects)
        project_list = utils.get_project_list(
            user_id=user.id,
            auth_url=settings.OPENSTACK_KEYSTONE_URL,
            token=unscoped.auth_token)
        self.assertEqual(project_list, expected_projects)

        utils.remove_project_cache(unscoped.auth_token)
        self.assertIsNone(utils._PROJECT_CACHE.get(unscoped.auth_token))


class OpenStackAuthTestsWebSSO(OpenStackAuthTestsMixin, test.TestCase):

    def _create_token_auth(self, project_id=None, token=None, url=None):
        if not token:
            token = self.data.federated_unscoped_access_info.auth_token

        if not url:
            url = settings.OPENSTACK_KEYSTONE_URL

        return auth_v3.Token(auth_url=url,
                             token=token,
                             project_id=project_id,
                             reauthenticate=False)

    def _mock_unscoped_client(self, unscoped):
        plugin = self._create_token_auth(
            None,
            token=unscoped.auth_token,
            url=settings.OPENSTACK_KEYSTONE_URL)
        plugin.get_access(mox.IsA(session.Session)).AndReturn(unscoped)

        return self.ks_client_module.Client(session=mox.IsA(session.Session),
                                            auth=plugin)

    def _mock_unscoped_federated_list_projects(self, client, projects):
        client.federation = self.mox.CreateMockAnything()
        client.federation.projects = self.mox.CreateMockAnything()
        client.federation.projects.list().AndReturn(projects)

    def _mock_unscoped_client_list_projects(self, unscoped, projects):
        client = self._mock_unscoped_client(unscoped)
        self._mock_unscoped_federated_list_projects(client, projects)

    def setUp(self):
        super(OpenStackAuthTestsWebSSO, self).setUp()

        self.mox = mox.Mox()
        self.addCleanup(self.mox.VerifyAll)
        self.addCleanup(self.mox.UnsetStubs)

        self.data = data_v3.generate_test_data()
        self.ks_client_module = client_v3

        self.idp_id = uuid.uuid4().hex
        self.idp_oidc_id = uuid.uuid4().hex
        self.idp_saml2_id = uuid.uuid4().hex

        settings.OPENSTACK_API_VERSIONS['identity'] = 3
        settings.OPENSTACK_KEYSTONE_URL = 'http://localhost:5000/v3'
        settings.WEBSSO_ENABLED = True
        settings.WEBSSO_CHOICES = (
            ('credentials', 'Keystone Credentials'),
            ('oidc', 'OpenID Connect'),
            ('saml2', 'Security Assertion Markup Language'),
            (self.idp_oidc_id, 'IDP OIDC'),
            (self.idp_saml2_id, 'IDP SAML2')
        )
        settings.WEBSSO_IDP_MAPPING = {
            self.idp_oidc_id: (self.idp_id, 'oidc'),
            self.idp_saml2_id: (self.idp_id, 'saml2')
        }

        self.mox.StubOutClassWithMocks(token_endpoint, 'Token')
        self.mox.StubOutClassWithMocks(auth_v3, 'Token')
        self.mox.StubOutClassWithMocks(auth_v3, 'Password')
        self.mox.StubOutClassWithMocks(client_v3, 'Client')

    def test_login_form(self):
        url = reverse('login')

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'credentials')
        self.assertContains(response, 'oidc')
        self.assertContains(response, 'saml2')
        self.assertContains(response, self.idp_oidc_id)
        self.assertContains(response, self.idp_saml2_id)

    def test_websso_redirect_by_protocol(self):
        origin = 'http://testserver/auth/websso/'
        protocol = 'oidc'
        redirect_url = ('%s/auth/OS-FEDERATION/websso/%s?origin=%s' %
                        (settings.OPENSTACK_KEYSTONE_URL, protocol, origin))

        form_data = {'auth_type': protocol,
                     'region': settings.OPENSTACK_KEYSTONE_URL}
        url = reverse('login')

        # POST to the page and redirect to keystone.
        response = self.client.post(url, form_data)
        self.assertRedirects(response, redirect_url, status_code=302,
                             target_status_code=404)

    def test_websso_redirect_by_idp(self):
        origin = 'http://testserver/auth/websso/'
        protocol = 'oidc'
        redirect_url = ('%s/auth/OS-FEDERATION/identity_providers/%s'
                        '/protocols/%s/websso?origin=%s' %
                        (settings.OPENSTACK_KEYSTONE_URL, self.idp_id,
                         protocol, origin))

        form_data = {'auth_type': self.idp_oidc_id,
                     'region': settings.OPENSTACK_KEYSTONE_URL}
        url = reverse('login')

        # POST to the page and redirect to keystone.
        response = self.client.post(url, form_data)
        self.assertRedirects(response, redirect_url, status_code=302,
                             target_status_code=404)

    def test_websso_login(self):
        projects = [self.data.project_one, self.data.project_two]
        unscoped = self.data.federated_unscoped_access_info
        token = unscoped.auth_token

        form_data = {'token': token}
        self._mock_unscoped_client_list_projects(unscoped, projects)
        self._mock_scoped_client_for_tenant(unscoped, self.data.project_one.id)

        self.mox.ReplayAll()

        url = reverse('websso')

        # POST to the page to log in.
        response = self.client.post(url, form_data)
        self.assertRedirects(response, settings.LOGIN_REDIRECT_URL)

load_tests = load_tests_apply_scenarios


class PolicyLoaderTestCase(test.TestCase):
    def test_policy_file_load(self):
        policy.reset()
        enforcer = policy._get_enforcer()
        self.assertEqual(2, len(enforcer))
        self.assertTrue('identity' in enforcer)
        self.assertTrue('compute' in enforcer)

    def test_policy_reset(self):
        policy._get_enforcer()
        self.assertEqual(2, len(policy._ENFORCER))
        policy.reset()
        self.assertIsNone(policy._ENFORCER)


class PermTestCase(test.TestCase):
    def test_has_perms(self):
        testuser = user.User(id=1, roles=[])

        def has_perm(perm, obj=None):
            return perm in ('perm1', 'perm3')

        with mock.patch.object(testuser, 'has_perm', side_effect=has_perm):
            self.assertFalse(testuser.has_perms(['perm2']))

            # perm1 AND perm3
            self.assertFalse(testuser.has_perms(['perm1', 'perm2']))

            # perm1 AND perm3
            self.assertTrue(testuser.has_perms(['perm1', 'perm3']))

            # perm1 AND (perm2 OR perm3)
            perm_list = ['perm1', ('perm2', 'perm3')]
            self.assertTrue(testuser.has_perms(perm_list))


class PolicyTestCase(test.TestCase):
    _roles = []

    def setUp(self):
        mock_user = user.User(id=1, roles=self._roles)
        patcher = mock.patch('openstack_auth.utils.get_user',
                             return_value=mock_user)
        self.MockClass = patcher.start()
        self.addCleanup(patcher.stop)
        self.request = http.HttpRequest()


class PolicyTestCaseNonAdmin(PolicyTestCase):
    _roles = [{'id': '1', 'name': 'member'}]

    def test_check_admin_required_false(self):
        policy.reset()
        value = policy.check((("identity", "admin_required"),),
                             request=self.request)
        self.assertFalse(value)

    def test_check_identity_rule_not_found_false(self):
        policy.reset()
        value = policy.check((("identity", "i_dont_exist"),),
                             request=self.request)
        # this should fail because the default check for
        # identity is admin_required
        self.assertFalse(value)

    def test_check_nova_context_is_admin_false(self):
        policy.reset()
        value = policy.check((("compute", "context_is_admin"),),
                             request=self.request)
        self.assertFalse(value)

    def test_compound_check_false(self):
        policy.reset()
        value = policy.check((("identity", "admin_required"),
                              ("identity", "identity:default"),),
                             request=self.request)
        self.assertFalse(value)

    def test_scope_not_found(self):
        policy.reset()
        value = policy.check((("dummy", "default"),),
                             request=self.request)
        self.assertTrue(value)


class PolicyTestCaseAdmin(PolicyTestCase):
    _roles = [{'id': '1', 'name': 'admin'}]

    def test_check_admin_required_true(self):
        policy.reset()
        value = policy.check((("identity", "admin_required"),),
                             request=self.request)
        self.assertTrue(value)

    def test_check_identity_rule_not_found_true(self):
        policy.reset()
        value = policy.check((("identity", "i_dont_exist"),),
                             request=self.request)
        # this should succeed because the default check for
        # identity is admin_required
        self.assertTrue(value)

    def test_compound_check_true(self):
        policy.reset()
        value = policy.check((("identity", "admin_required"),
                              ("identity", "identity:default"),),
                             request=self.request)
        self.assertTrue(value)

    def test_check_nova_context_is_admin_true(self):
        policy.reset()
        value = policy.check((("compute", "context_is_admin"),),
                             request=self.request)
        self.assertTrue(value)
