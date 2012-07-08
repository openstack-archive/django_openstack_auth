#!/usr/bin/env python
import os
import sys


os.environ['DJANGO_SETTINGS_MODULE'] = 'openstack_auth.tests.settings'

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
