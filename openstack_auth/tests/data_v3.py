import requests
import uuid

from datetime import timedelta

from django.utils import datetime_safe

from keystoneclient.access import AccessInfo
from keystoneclient.service_catalog import ServiceCatalog
from keystoneclient.v3.domains import Domain, DomainManager
from keystoneclient.v3.roles import Role, RoleManager
from keystoneclient.v3.projects import Project, ProjectManager
from keystoneclient.v3.users import User, UserManager


class TestDataContainer(object):
    """ Arbitrary holder for test data in an object-oriented fashion. """
    pass


class TestResponse(requests.Response):
    """ Class used to wrap requests.Response and provide some
        convenience to initialize with a dict """

    def __init__(self, data):
        self._text = None
        super(TestResponse, self)
        if isinstance(data, dict):
            self.status_code = data.get('status_code', None)
            self.headers = data.get('headers', None)
            # Fake the text attribute to streamline Response creation
            self._text = data.get('text', None)
        else:
            self.status_code = data

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    @property
    def text(self):
        return self._text


def generate_test_data():
    ''' Builds a set of test_data data as returned by Keystone V2. '''
    test_data = TestDataContainer()

    keystone_service = {
        'type': 'identity',
        'id': uuid.uuid4().hex,
        'endpoints': [
            {
                'url': 'http://admin.localhost:35357/v3',
                'region': 'RegionOne',
                'interface': 'admin',
                'id': uuid.uuid4().hex,
            },
            {
                'url': 'http://internal.localhost:5000/v3',
                'region': 'RegionOne',
                'interface': 'internal',
                'id': uuid.uuid4().hex
            },
            {
                'url': 'http://public.localhost:5000/v3',
                'region': 'RegionOne',
                'interface': 'public',
                 'id': uuid.uuid4().hex
            }
        ]
    }

    # Domains
    domain_dict = {'id': uuid.uuid4().hex,
                   'name': 'domain',
                   'description': '',
                   'enabled': True}
    test_data.domain = Domain(DomainManager(None), domain_dict, loaded=True)

    # Users
    user_dict = {'id': uuid.uuid4().hex,
                 'name': 'gabriel',
                 'email': 'gabriel@example.com',
                 'password': 'swordfish',
                 'domain_id': domain_dict['id'],
                 'token': '',
                 'enabled': True}
    test_data.user = User(UserManager(None), user_dict, loaded=True)

    # Projects
    project_dict_1 = {'id': uuid.uuid4().hex,
                     'name': 'tenant_one',
                     'description': '',
                     'domain_id': domain_dict['id'],
                     'enabled': True}
    project_dict_2 = {'id': uuid.uuid4().hex,
                     'name': '',
                     'description': '',
                     'domain_id': domain_dict['id'],
                     'enabled': False}
    test_data.project_one = Project(ProjectManager(None),
                                  project_dict_1,
                                  loaded=True)
    test_data.project_two = Project(ProjectManager(None),
                                  project_dict_2,
                                  loaded=True)

    # Roles
    role_dict = {'id': uuid.uuid4().hex,
                 'name': 'Member'}
    test_data.role = Role(RoleManager, role_dict)

    nova_service = {
        'type': 'compute',
        'id': uuid.uuid4().hex,
        'endpoints': [
            {
                'url': 'http://nova-admin.localhost:8774/v2.0/%s' \
                       % (project_dict_1['id']),
                'region': 'RegionOne',
                'interface': 'admin',
                'id': uuid.uuid4().hex,
            },
            {
                'url': 'http://nova-internal.localhost:8774/v2.0/%s' \
                       % (project_dict_1['id']),
                'region': 'RegionOne',
                'interface': 'internal',
                'id': uuid.uuid4().hex
            },
            {
                'url': 'http://nova-public.localhost:8774/v2.0/%s' \
                       % (project_dict_1['id']),
                'region': 'RegionOne',
                'interface': 'public',
                 'id': uuid.uuid4().hex
            },
            {
                'url': 'http://nova2-admin.localhost:8774/v2.0/%s' \
                       % (project_dict_1['id']),
                'region': 'RegionTwo',
                'interface': 'admin',
                'id': uuid.uuid4().hex,
            },
            {
                'url': 'http://nova2-internal.localhost:8774/v2.0/%s' \
                       % (project_dict_1['id']),
                'region': 'RegionTwo',
                'interface': 'internal',
                'id': uuid.uuid4().hex
            },
            {
                'url': 'http://nova2-public.localhost:8774/v2.0/%s' \
                       % (project_dict_1['id']),
                'region': 'RegionTwo',
                'interface': 'public',
                 'id': uuid.uuid4().hex
            }
        ]
    }

    # Tokens
    tomorrow = datetime_safe.datetime.now() + timedelta(days=1)
    expiration = datetime_safe.datetime.isoformat(tomorrow)
    auth_token = uuid.uuid4().hex
    auth_response_headers = {
        'X-Subject-Token': auth_token
    }

    auth_response = TestResponse({
        "headers": auth_response_headers
    })

    scoped_token_dict = {
        'token': {
            'methods': ['password'],
            'expires_at': expiration,
            'project': {
                'id': project_dict_1['id'],
                'name': project_dict_1['name'],
                'domain': {
                    'id': domain_dict['id'],
                    'name': domain_dict['name']
                }
            },
            'user': {
                'id': user_dict['id'],
                'name': user_dict['name'],
                'domain': {
                    'id': domain_dict['id'],
                    'name': domain_dict['name']
                }
            },
            'roles': [role_dict],
            'catalog': [keystone_service, nova_service]
        }
    }

    test_data.scoped_access_info = AccessInfo.factory(
        resp=auth_response,
        body=scoped_token_dict
    )

    unscoped_token_dict = {
        'token': {
            'methods': ['password'],
            'expires_at': expiration,
            'user': {
                'id': user_dict['id'],
                'name': user_dict['name'],
                'domain': {
                    'id': domain_dict['id'],
                    'name': domain_dict['name']
                }
            },
            'catalog': [keystone_service]
        }
    }

    test_data.unscoped_access_info = AccessInfo.factory(
        resp=auth_response,
        body=unscoped_token_dict
    )

    # Service Catalog
    test_data.service_catalog = ServiceCatalog.factory({
        'methods': ['password'],
        'user': {},
        'catalog': [keystone_service, nova_service],
    }, token=auth_token)

    return test_data
