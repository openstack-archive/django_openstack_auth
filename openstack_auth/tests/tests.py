import mox

from django import test
from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.core.urlresolvers import reverse

from keystoneclient import exceptions as keystone_exceptions
from keystoneclient.v2_0 import client as client_v2
from keystoneclient.v3 import client as client_v3

from .data_v2 import generate_test_data as data_v2
from .data_v3 import generate_test_data as data_v3


DEFAULT_DOMAIN = settings.OPENSTACK_KEYSTONE_DEFAULT_DOMAIN


class OpenStackAuthTestsV2(test.TestCase):
    def setUp(self):
        super(OpenStackAuthTestsV2, self).setUp()
        self.mox = mox.Mox()
        self.data = data_v2()
        self.ks_client_module = client_v2
        endpoint = settings.OPENSTACK_KEYSTONE_URL
        self.keystone_client_unscoped = self.ks_client_module.Client(
            endpoint=endpoint,
            auth_ref=self.data.unscoped_access_info)
        self.keystone_client_scoped = self.ks_client_module.Client(
            endpoint=endpoint,
            auth_ref=self.data.scoped_access_info)

    def tearDown(self):
        self.mox.UnsetStubs()
        self.mox.VerifyAll()

    def test_login(self):
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
                                     debug=False)\
                .AndReturn(self.keystone_client_unscoped)
        self.keystone_client_unscoped.tenants.list().AndReturn(tenants)
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     tenant_id=self.data.tenant_two.id,
                                     insecure=False,
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
                                     debug=False)\
                .AndReturn(self.keystone_client_unscoped)
        self.keystone_client_unscoped.tenants.list().AndReturn(tenants)
        exc = keystone_exceptions.AuthorizationFailure
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     tenant_id=self.data.tenant_two.id,
                                     insecure=False,
                                     token=unscoped.auth_token,
                                     debug=False) \
                .AndRaise(exc)
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     tenant_id=self.data.tenant_one.id,
                                     insecure=False,
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
                                     debug=False)\
                .AndReturn(self.keystone_client_unscoped)
        self.keystone_client_unscoped.tenants.list().AndReturn(tenants)
        exc = keystone_exceptions.AuthorizationFailure
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     tenant_id=self.data.tenant_two.id,
                                     insecure=False,
                                     token=unscoped.auth_token,
                                     debug=False) \
                .AndRaise(exc)
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     tenant_id=self.data.tenant_one.id,
                                     insecure=False,
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
        tenant = self.data.tenant_two
        tenants = [self.data.tenant_one, self.data.tenant_two]
        user = self.data.user
        unscoped = self.data.unscoped_access_info
        scoped = self.data.scoped_access_info
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
                                     debug=False) \
                .AndReturn(self.keystone_client_unscoped)
        self.keystone_client_unscoped.tenants.list().AndReturn(tenants)
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     tenant_id=self.data.tenant_two.id,
                                     insecure=False,
                                     token=unscoped.auth_token,
                                     debug=False) \
                .AndReturn(self.keystone_client_scoped)

        self.ks_client_module.Client(auth_url=sc.url_for(),
                                     tenant_id=tenant.id,
                                     token=scoped.auth_token,
                                     insecure=False,
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
            form_data.update({REDIRECT_FIELD_NAME: next})

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
                                     debug=False) \
                .AndReturn(self.keystone_client_unscoped)
        self.keystone_client_unscoped.tenants.list().AndReturn(tenants)
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     tenant_id=self.data.tenant_two.id,
                                     insecure=False,
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
            form_data.update({REDIRECT_FIELD_NAME: next})

        response = self.client.get(url, form_data)

        if next:
            expected_url = 'http://testserver%s' % next
            self.assertEqual(response['location'], expected_url)
        else:
            self.assertRedirects(response, settings.LOGIN_REDIRECT_URL)

        self.assertEqual(self.client.session['services_region'], region)

    def test_switch_region_with_next(self, next=None):
        self.test_switch_region(next='/next_url')


class OpenStackAuthTestsV3(test.TestCase):
    def setUp(self):
        super(OpenStackAuthTestsV3, self).setUp()
        self.mox = mox.Mox()
        self.data = data_v3()
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
                                     debug=False)\
                .AndReturn(self.keystone_client_unscoped)
        self.keystone_client_unscoped.projects.list(user=user.id) \
                .AndReturn(projects)
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     tenant_id=self.data.project_two.id,
                                     insecure=False,
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
                                     debug=False)\
                .AndReturn(self.keystone_client_unscoped)
        self.keystone_client_unscoped.projects.list(user=user.id) \
                .AndReturn(projects)
        exc = keystone_exceptions.AuthorizationFailure
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     tenant_id=self.data.project_two.id,
                                     insecure=False,
                                     token=unscoped.auth_token,
                                     debug=False) \
                .AndRaise(exc)
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     tenant_id=self.data.project_one.id,
                                     insecure=False,
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
                                     debug=False)\
                .AndReturn(self.keystone_client_unscoped)
        self.keystone_client_unscoped.projects.list(user=user.id) \
                .AndReturn(projects)
        exc = keystone_exceptions.AuthorizationFailure
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     tenant_id=self.data.project_two.id,
                                     insecure=False,
                                     token=unscoped.auth_token,
                                     debug=False) \
                .AndRaise(exc)
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     tenant_id=self.data.project_one.id,
                                     insecure=False,
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
                                     debug=False) \
                .AndReturn(self.keystone_client_unscoped)
        self.keystone_client_unscoped.projects.list(user=user.id) \
                .AndReturn(projects)
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     tenant_id=self.data.project_two.id,
                                     insecure=False,
                                     token=unscoped.auth_token,
                                     debug=False) \
                .AndReturn(self.keystone_client_scoped)
        self.ks_client_module.Client(auth_url=sc.url_for(),
                                     tenant_id=project.id,
                                     token=scoped.auth_token,
                                     insecure=False,
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
            form_data.update({REDIRECT_FIELD_NAME: next})

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
                                     debug=False) \
                .AndReturn(self.keystone_client_unscoped)
        self.keystone_client_unscoped.projects.list(user=user.id) \
                .AndReturn(projects)
        self.ks_client_module.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                                     tenant_id=self.data.project_two.id,
                                     insecure=False,
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
            form_data.update({REDIRECT_FIELD_NAME: next})

        response = self.client.get(url, form_data)

        if next:
            expected_url = 'http://testserver%s' % next
            self.assertEqual(response['location'], expected_url)
        else:
            self.assertRedirects(response, settings.LOGIN_REDIRECT_URL)

        self.assertEqual(self.client.session['services_region'], region)

    def test_switch_region_with_next(self, next=None):
        self.test_switch_region(next='/next_url')
