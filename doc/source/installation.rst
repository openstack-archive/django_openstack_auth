===============
Getting Started
===============

Installation
============

Installing is quick and easy:

#. Run ``pip install django_openstack_auth``.

#. Add ``openstack_auth`` to ``settings.INSTALLED_APPS``.

#. Add ``'openstack_auth.backend.KeystoneBackend'`` to your
   ``settings.AUTHENTICATION_BACKENDS``, e.g.::

        AUTHENTICATION_BACKENDS = ('openstack_auth.backend.KeystoneBackend',)

#. Configure your API endpoint(s) in ``settings.py``::

        OPENSTACK_KEYSTONE_URL = "http://example.com:5000/v3"

#. Include ``'openstack_auth.urls'`` somewhere in your ``urls.py`` file.

#. Use it as you would any other Django auth backend.

Running The Tests
=================

Download the repository and run::

    python setup.py test
