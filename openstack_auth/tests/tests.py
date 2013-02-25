from django import test
from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.core.urlresolvers import reverse

from keystoneclient import exceptions as keystone_exceptions
from keystoneclient.v2_0 import client

import mox

from .data import generate_test_data


class OpenStackAuthTests(test.TestCase):
    def setUp(self):
        super(OpenStackAuthTests, self).setUp()
        self.mox = mox.Mox()
        self.data = generate_test_data()
        endpoint = settings.OPENSTACK_KEYSTONE_URL
        self.keystone_client = client.Client(endpoint=endpoint)
        self.keystone_client.service_catalog = self.data.service_catalog

    def tearDown(self):
        self.mox.UnsetStubs()
        self.mox.VerifyAll()

    def test_login(self):
        tenants = [self.data.tenant_one, self.data.tenant_two]
        user = self.data.user
        sc = self.data.service_catalog

        form_data = {'region': settings.OPENSTACK_KEYSTONE_URL,
                     'password': user.password,
                     'username': user.name}

        self.mox.StubOutWithMock(client, "Client")
        self.mox.StubOutWithMock(self.keystone_client.tenants, "list")
        self.mox.StubOutWithMock(self.keystone_client.tokens, "authenticate")

        client.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                      password=user.password,
                      username=user.name,
                      insecure=False,
                      tenant_id=None).AndReturn(self.keystone_client)
        self.keystone_client.tenants.list().AndReturn(tenants)
        client.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                      tenant_id=self.data.tenant_two.id,
                      insecure=False,
                      token=sc.get_token()['id']) \
                .AndReturn(self.keystone_client)
        self.keystone_client.tokens.authenticate(tenant_id=tenants[1].id,
                                                 token=sc.get_token()['id'],
                                                 username=user.name) \
                            .AndReturn(self.data.scoped_token)

        self.mox.ReplayAll()

        url = reverse('login')

        # GET the page to set the test cookie.
        response = self.client.get(url, form_data)
        self.assertEqual(response.status_code, 200)

        # POST to the page to log in.
        response = self.client.post(url, form_data)
        self.assertRedirects(response, settings.LOGIN_REDIRECT_URL)

    def test_no_tenants(self):
        user = self.data.user

        form_data = {'region': settings.OPENSTACK_KEYSTONE_URL,
                     'password': user.password,
                     'username': user.name}

        self.mox.StubOutWithMock(client, "Client")
        self.mox.StubOutWithMock(self.keystone_client.tenants, "list")

        client.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                      password=user.password,
                      username=user.name,
                      insecure=False,
                      tenant_id=None).AndReturn(self.keystone_client)
        self.keystone_client.tenants.list().AndReturn([])

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
                     'password': "invalid",
                     'username': user.name}

        self.mox.StubOutWithMock(client, "Client")

        exc = keystone_exceptions.Unauthorized(401)
        client.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                      password="invalid",
                      username=user.name,
                      insecure=False,
                      tenant_id=None).AndRaise(exc)

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
                     'password': user.password,
                     'username': user.name}

        self.mox.StubOutWithMock(client, "Client")

        exc = keystone_exceptions.ClientException(500)
        client.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                      password=user.password,
                      username=user.name,
                      insecure=False,
                      tenant_id=None).AndRaise(exc)

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
        scoped = self.data.scoped_token
        sc = self.data.service_catalog

        form_data = {'region': settings.OPENSTACK_KEYSTONE_URL,
                     'username': user.name,
                     'password': user.password}

        self.mox.StubOutWithMock(client, "Client")
        self.mox.StubOutWithMock(self.keystone_client.tenants, "list")
        self.mox.StubOutWithMock(self.keystone_client.tokens, "authenticate")

        client.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                      password=user.password,
                      username=user.name,
                      insecure=False,
                      tenant_id=None).AndReturn(self.keystone_client)
        self.keystone_client.tenants.list().AndReturn(tenants)
        self.keystone_client.tokens.authenticate(tenant_id=tenants[1].id,
                                                 token=sc.get_token()['id'],
                                                 username=user.name) \
                            .AndReturn(scoped)

        client.Client(auth_url=settings.OPENSTACK_KEYSTONE_URL,
                      tenant_id=self.data.tenant_two.id,
                      insecure=False,
                      token=sc.get_token()['id']) \
                .AndReturn(self.keystone_client)

        client.Client(endpoint=sc.url_for()) \
                .AndReturn(self.keystone_client)

        self.keystone_client.tokens.authenticate(tenant_id=tenant.id,
                                                 token=sc.get_token()['id']) \
                            .AndReturn(scoped)

        self.mox.ReplayAll()

        url = reverse('login')

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

        response = self.client.post(url, form_data)
        self.assertRedirects(response, settings.LOGIN_REDIRECT_URL)

        url = reverse('switch_tenants', args=[tenant.id])

        scoped.tenant['id'] = self.data.tenant_two._info
        sc.catalog['token']['id'] = self.data.tenant_two.id

        form_data['tenant_id'] = tenant.id

        if next:
            form_data.update({REDIRECT_FIELD_NAME: next})

        response = self.client.get(url, form_data)

        if next:
            expected_url = 'http://testserver%s' % next
            self.assertEqual(response['location'], expected_url)
        else:
            self.assertRedirects(response, settings.LOGIN_REDIRECT_URL)
        self.assertEqual(self.client.session['token']['token']['tenant']['id'],
                         scoped.tenant['id'])

    def test_switch_with_next(self):
        self.test_switch(next='/next_url')
