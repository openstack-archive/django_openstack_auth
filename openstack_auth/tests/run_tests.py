#!/usr/bin/env python
import os
import sys

from django.conf import settings

if not settings.configured:
    settings.configure(
        DATABASES={'default': {'ENGINE': 'django.db.backends.sqlite3'}},
        INSTALLED_APPS=[
            'django',
            'django.contrib.contenttypes',
            'django.contrib.auth',
            'django.contrib.sessions',
            'openstack_auth',
            'openstack_auth.tests'
        ],
        MIDDLEWARE_CLASSES=[
            'django.middleware.common.CommonMiddleware',
            'django.middleware.csrf.CsrfViewMiddleware',
            'django.contrib.sessions.middleware.SessionMiddleware',
            'django.contrib.auth.middleware.AuthenticationMiddleware'
        ],
        AUTHENTICATION_BACKENDS=['openstack_auth.backend.KeystoneBackend'],
        OPENSTACK_KEYSTONE_URL="http://localhost:5000/v2.0",
        ROOT_URLCONF='openstack_auth.tests.urls',
        LOGIN_REDIRECT_URL='/'
    )

from django.test.simple import DjangoTestSuiteRunner


def run(*test_args):
    if not test_args:
        test_args = ['tests']
    parent = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..",
        "..",
    )
    sys.path.insert(0, parent)
    failures = DjangoTestSuiteRunner().run_tests(test_args)
    sys.exit(failures)


if __name__ == '__main__':
    run(*sys.argv[1:])
