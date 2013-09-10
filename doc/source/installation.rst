===============
Getting Started
===============

Installation
============

Installing is quick and easy:

#. Run ``pip install django_openstack_auth``.

#. Add ``openstack_auth`` to ``settings.INSTALLED_APPS``.

#. Add ``'keystone_auth.backend.KeystoneBackend'`` to your
   ``settings.AUTHENTICATION_BACKENDS``, e.g.::

        AUTHENTICATION_BACKENDS = ('keystone_auth.backend.KeystoneBackend',)

#. Configure your API endpoint(s) in ``settings.py``::

        OPENSTACK_KEYSTONE_URL = "http://example.com:5000/v2.0"

#. Include ``'keystone_auth.urls'`` somewhere in your ``urls.py`` file.

#. Use it as you would any other Django auth backend.

Running The Tests
=================

Download the repository and run::

    python setup.py test