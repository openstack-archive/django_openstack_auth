import os
import re
import codecs
from setuptools import setup, find_packages


def read(*parts):
    return codecs.open(os.path.join(os.path.dirname(__file__), *parts)).read()


def find_version(*file_paths):
    version_file = read(*file_paths)
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                              version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")


setup(
    name="django_openstack_auth",
    version=find_version("openstack_auth", "__init__.py"),
    url='http://django_openstack_auth.readthedocs.org/',
    license='BSD',
    description=("A Django authentication backend for use with the "
                 "OpenStack Keystone Identity backend."),
    long_description=read('README.rst'),
    author='Gabriel Hurley',
    author_email='gabriel@strikeawe.com',
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet :: WWW/HTTP',
    ],
    zip_safe=False,
    install_requires=[
        'django >= 1.4',
        'python-keystoneclient >= 0.3'
    ],
    tests_require=[
        'mox',
    ],
    test_suite='openstack_auth.tests.run_tests.run'
)
