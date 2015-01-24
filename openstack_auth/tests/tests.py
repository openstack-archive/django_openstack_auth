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

from django.conf import settings
from django.contrib import auth
from django.core.urlresolvers import reverse
from django import http
from django import test
from keystoneclient import exceptions as keystone_exceptions
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

    def tearDown(self):
        self.mox.UnsetStubs()
        self.mox.VerifyAll()

    def _mock_unscoped_client(self, user):
        self.mox.StubOutWithMock(self.ks_client_module, "Client")
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     password=user.password,
                                     username=user.name,
                                     user_domain_name=DEFAULT_DOMAIN,
                                     insecure=False,
                                     cacert=None,
                                     debug=False)\
            .AndReturn(self.keystone_client_unscoped)

    def _mock_unscoped_client_with_token(self, user, unscoped):
        self.mox.StubOutWithMock(self.ks_client_module, "Client")
        url = settings.OPENSTACK_KEYSTONE_URL
        self.ks_client_module.Client(user_id=user.id,
                                     auth_url=url,
                                     token=unscoped.auth_token,
                                     insecure=False,
                                     cacert=None,
                                     debug=False)\
            .AndReturn(self.keystone_client_unscoped)

    def _mock_client_token_auth_failure(self, unscoped, tenant_id):
        exc = keystone_exceptions.AuthorizationFailure
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     tenant_id=tenant_id,
                                     insecure=False,
                                     cacert=None,
                                     token=unscoped.auth_token,
                                     debug=False) \
            .AndRaise(exc)

    def _mock_client_password_auth_failure(self, username, password, exc):
        self.mox.StubOutWithMock(self.ks_client_module, "Client")
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     password=password,
                                     username=username,
                                     user_domain_name=DEFAULT_DOMAIN,
                                     insecure=False,
                                     cacert=None,
                                     debug=False).AndRaise(exc)

    def _mock_scoped_client_for_tenant(self, auth_ref, tenant_id, url=None):
        if url is None:
            auth_url = settings.OPENSTACK_KEYSTONE_URL
        else:
            auth_url = url
        self.ks_client_module.Client(auth_url=auth_url,
                                     tenant_id=tenant_id,
                                     insecure=False,
                                     cacert=None,
                                     token=auth_ref.auth_token,
                                     debug=False) \
            .AndReturn(self.keystone_client_scoped)

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

    def _mock_unscoped_list_tenants(self, tenants):
        self.mox.StubOutWithMock(self.keystone_client_unscoped.tenants, "list")
        self.keystone_client_unscoped.tenants.list().AndReturn(tenants)

    def _mock_unscoped_client_list_tenants(self, user, tenants):
        self._mock_unscoped_client(user)
        self._mock_unscoped_list_tenants(tenants)

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

    def test_login_with_disabled_tenants(self):
        # Test to validate that authentication will try to get
        # scoped token if the first project is disabled.
        tenants = [self.data.tenant_one, self.data.tenant_two]
        user = self.data.user
        unscoped = self.data.unscoped_access_info

        form_data = self.get_form_data(user)
        self._mock_unscoped_client_list_tenants(user, tenants)
        self._mock_client_token_auth_failure(unscoped, self.data.tenant_one.id)
        self._mock_scoped_client_for_tenant(unscoped, self.data.tenant_two.id)
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
        tenants = [self.data.tenant_one, self.data.tenant_two]
        user = self.data.user
        unscoped = self.data.unscoped_access_info

        form_data = self.get_form_data(user)
        self._mock_unscoped_client_list_tenants(user, tenants)
        self._mock_client_token_auth_failure(unscoped, self.data.tenant_one.id)
        self._mock_client_token_auth_failure(unscoped, self.data.tenant_two.id)
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
        self.assertContains(response, "Invalid user name or password.")

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

        form_data = self.get_form_data(user)

        self._mock_unscoped_client_list_tenants(user, tenants)
        self._mock_scoped_client_for_tenant(unscoped, self.data.tenant_one.id)
        self._mock_scoped_client_for_tenant(scoped, tenant.id,
                                            url=sc.url_for(endpoint_type=et))
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

        form_data = self.get_form_data(user)

        self._mock_unscoped_client_list_tenants(user, tenants)
        self._mock_scoped_client_for_tenant(unscoped, self.data.tenant_one.id)

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

        self._mock_unscoped_client_with_token(user, unscoped)
        self._mock_unscoped_list_tenants(tenants)

        self.mox.ReplayAll()

        tenant_list = utils.get_project_list(
            user_id=user.id,
            auth_url=settings.OPENSTACK_KEYSTONE_URL,
            token=unscoped.auth_token,
            insecure=False,
            cacert=None,
            debug=False)
        self.assertEqual(tenant_list, expected_tenants)

    def test_tenant_list_caching(self):
        tenants = [self.data.tenant_two, self.data.tenant_one]
        expected_tenants = [self.data.tenant_one, self.data.tenant_two]
        user = self.data.user
        unscoped = self.data.unscoped_access_info

        self._mock_unscoped_list_tenants(tenants)
        self._mock_unscoped_client_with_token(user, unscoped)
        self.mox.ReplayAll()

        tenant_list = utils.get_project_list(
            user_id=user.id,
            auth_url=settings.OPENSTACK_KEYSTONE_URL,
            token=unscoped.auth_token,
            insecure=False,
            cacert=None,
            debug=False)
        self.assertEqual(tenant_list, expected_tenants)

        # Test to validate that requesting the project list again results
        # to using the cache and will not make a Keystone call.
        self.assertEqual(utils._PROJECT_CACHE.get(unscoped.auth_token),
                         expected_tenants)
        tenant_list = utils.get_project_list(
            user_id=user.id,
            auth_url=settings.OPENSTACK_KEYSTONE_URL,
            token=unscoped.auth_token,
            insecure=False,
            cacert=None,
            debug=False)
        self.assertEqual(tenant_list, expected_tenants)

        utils.remove_project_cache(unscoped.auth_token)
        self.assertIsNone(utils._PROJECT_CACHE.get(unscoped.auth_token))


class OpenStackAuthTestsV3(OpenStackAuthTestsMixin, test.TestCase):

    def _mock_unscoped_client_list_projects(self, user, projects):
        self._mock_unscoped_client(user)
        self._mock_unscoped_list_projects(user, projects)

    def _mock_unscoped_list_projects(self, user, projects):
        self.mox.StubOutWithMock(self.keystone_client_unscoped.projects,
                                 "list")
        self.keystone_client_unscoped.projects.list(user=user.id) \
            .AndReturn(projects)

    def setUp(self):
        super(OpenStackAuthTestsV3, self).setUp()

        if self.interface:
            override = self.settings(OPENSTACK_ENDPOINT_TYPE=self.interface)
            override.enable()
            self.addCleanup(override.disable)

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

    def test_login_with_disabled_projects(self):
        projects = [self.data.project_one, self.data.project_two]
        user = self.data.user
        unscoped = self.data.unscoped_access_info

        form_data = self.get_form_data(user)
        self._mock_unscoped_client_list_projects(user, projects)
        self._mock_client_token_auth_failure(unscoped,
                                             self.data.project_one.id)
        self._mock_scoped_client_for_tenant(unscoped, self.data.project_two.id)
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

        form_data = self.get_form_data(user)

        self._mock_unscoped_client_list_projects(user, projects)
        self._mock_client_token_auth_failure(unscoped,
                                             self.data.project_one.id)
        self._mock_client_token_auth_failure(unscoped,
                                             self.data.project_two.id)
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
        self.assertContains(response, "Invalid user name or password.")

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
        unscoped = self.data.unscoped_access_info
        scoped = self.data.scoped_access_info
        sc = self.data.service_catalog
        et = getattr(settings, 'OPENSTACK_ENDPOINT_TYPE', 'publicURL')

        form_data = self.get_form_data(user)

        self._mock_unscoped_client_list_projects(user, projects)
        self._mock_scoped_client_for_tenant(unscoped, self.data.project_one.id)
        self._mock_scoped_client_for_tenant(
            unscoped,
            project.id,
            url=sc.url_for(endpoint_type=et))

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

        form_data = self.get_form_data(user)
        self._mock_unscoped_client_list_projects(user, projects)
        self._mock_scoped_client_for_tenant(unscoped, self.data.project_one.id)

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

        self._mock_unscoped_client_with_token(user, unscoped)
        self._mock_unscoped_list_projects(user, projects)
        self.mox.ReplayAll()

        project_list = utils.get_project_list(
            user_id=user.id,
            auth_url=settings.OPENSTACK_KEYSTONE_URL,
            token=unscoped.auth_token,
            insecure=False,
            cacert=None,
            debug=False)
        self.assertEqual(project_list, expected_projects)

    def test_tenant_list_caching(self):
        projects = [self.data.project_two, self.data.project_one]
        expected_projects = [self.data.project_one, self.data.project_two]
        user = self.data.user
        unscoped = self.data.unscoped_access_info

        self._mock_unscoped_client_with_token(user, unscoped)
        self._mock_unscoped_list_projects(user, projects)

        self.mox.ReplayAll()

        project_list = utils.get_project_list(
            user_id=user.id,
            auth_url=settings.OPENSTACK_KEYSTONE_URL,
            token=unscoped.auth_token,
            insecure=False,
            cacert=None,
            debug=False)
        self.assertEqual(project_list, expected_projects)

        # Test to validate that requesting the project list again results
        # to using the cache and will not make a Keystone call.
        self.assertEqual(utils._PROJECT_CACHE.get(unscoped.auth_token),
                         expected_projects)
        project_list = utils.get_project_list(
            user_id=user.id,
            auth_url=settings.OPENSTACK_KEYSTONE_URL,
            token=unscoped.auth_token,
            insecure=False,
            cacert=None,
            debug=False)
        self.assertEqual(project_list, expected_projects)

        utils.remove_project_cache(unscoped.auth_token)
        self.assertIsNone(utils._PROJECT_CACHE.get(unscoped.auth_token))


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
