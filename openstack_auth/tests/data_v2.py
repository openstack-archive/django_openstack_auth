import uuid

from datetime import timedelta

from django.utils import datetime_safe

from keystoneclient.access import AccessInfo
from keystoneclient.service_catalog import ServiceCatalog
from keystoneclient.v2_0.roles import Role, RoleManager
from keystoneclient.v2_0.tenants import Tenant, TenantManager
from keystoneclient.v2_0.users import User, UserManager


class TestDataContainer(object):
    """ Arbitrary holder for test data in an object-oriented fashion. """
    pass


def generate_test_data():
    ''' Builds a set of test_data data as returned by Keystone V2. '''
    test_data = TestDataContainer()

    keystone_service = {
        'type': 'identity',
        'name': 'keystone',
        'endpoints_links': [],
        'endpoints': [
            {
                'region': 'RegionOne',
                'adminURL': 'http://admin.localhost:35357/v2.0',
                'internalURL': 'http://internal.localhost:5000/v2.0',
                'publicURL': 'http://public.localhost:5000/v2.0'
            }
        ]
    }

    # Users
    user_dict = {'id': uuid.uuid4().hex,
                 'name': 'gabriel',
                 'email': 'gabriel@example.com',
                 'password': 'swordfish',
                 'token': '',
                 'enabled': True}
    test_data.user = User(UserManager(None), user_dict, loaded=True)

    # Tenants
    tenant_dict_1 = {'id': uuid.uuid4().hex,
                     'name': 'tenant_one',
                     'description': '',
                     'enabled': True}
    tenant_dict_2 = {'id': uuid.uuid4().hex,
                     'name': '',
                     'description': '',
                     'enabled': False}
    test_data.tenant_one = Tenant(TenantManager(None),
                                  tenant_dict_1,
                                  loaded=True)
    test_data.tenant_two = Tenant(TenantManager(None),
                                  tenant_dict_2,
                                  loaded=True)

    nova_service = {
        'type': 'compute',
        'name': 'nova',
        'endpoint_links': [],
        'endpoints': [
            {
                'region': 'RegionOne',
                'adminURL': 'http://nova-admin.localhost:8774/v2.0/%s' \
                            % (tenant_dict_1['id']),
                'internalURL': 'http://nova-internal.localhost:8774/v2.0/%s' \
                               % (tenant_dict_1['id']),
                'publicURL': 'http://nova-public.localhost:8774/v2.0/%s' \
                             % (tenant_dict_1['id'])
            },
            {
                'region': 'RegionTwo',
                'adminURL': 'http://nova2-admin.localhost:8774/v2.0/%s' \
                            % (tenant_dict_1['id']),
                'internalURL': 'http://nova2-internal.localhost:8774/v2.0/%s' \
                               % (tenant_dict_1['id']),
                'publicURL': 'http://nova2-public.localhost:8774/v2.0/%s' \
                             % (tenant_dict_1['id'])
            }
        ]
    }

    # Roles
    role_dict = {'id': uuid.uuid4().hex,
                 'name': 'Member'}
    test_data.role = Role(RoleManager, role_dict)

    # Tokens
    tomorrow = datetime_safe.datetime.now() + timedelta(days=1)
    expiration = datetime_safe.datetime.isoformat(tomorrow)

    scoped_token_dict = {
        'access': {
            'token': {
                'id': uuid.uuid4().hex,
                'expires': expiration,
                'tenant': tenant_dict_1,
                'tenants': [tenant_dict_1, tenant_dict_2]},
            'user': {
                'id': user_dict['id'],
                'name': user_dict['name'],
                'roles': [role_dict]},
            'serviceCatalog': [keystone_service, nova_service]
        }
    }

    test_data.scoped_access_info = AccessInfo.factory(
        resp=None,
        body=scoped_token_dict)

    unscoped_token_dict = {
        'access': {
            'token': {
                'id': uuid.uuid4().hex,
                'expires': expiration},
            'user': {
                     'id': user_dict['id'],
                     'name': user_dict['name'],
                     'roles': [role_dict]},
            'serviceCatalog': [keystone_service]
        }
    }
    test_data.unscoped_access_info = AccessInfo.factory(
        resp=None,
        body=unscoped_token_dict)

    # Service Catalog
    test_data.service_catalog = ServiceCatalog.factory({
        'serviceCatalog': [keystone_service, nova_service],
        'token': {
            'id': scoped_token_dict['access']['token']['id'],
            'expires': scoped_token_dict['access']['token']['expires'],
            'user_id': user_dict['id'],
            'tenant_id': tenant_dict_1['id']
        }
    })

    return test_data
