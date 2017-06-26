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

Running Tests
=============

Before running tests, you should have ``tox`` installed and available in your
environment:

.. code-block:: bash

    $ pip install tox

.. NOTE::

    You may need to perform both the above operation and the next inside a
    python virtualenv, or prefix the above command with ``sudo``, depending on
    your preference.

To execute the full suite of tests maintained within the project, simply run:

.. code-block:: bash

    $ tox

.. NOTE::

    The first time you run ``tox``, it will take additional time to build
    virtualenvs. You can later use the ``-r`` option with ``tox`` to rebuild
    your virtualenv in a similar manner.

To run tests for one or more specific test environments (for example, the most
common configuration of Python 2.7 and PEP-8), list the environments with the
``-e`` option, separated by spaces:

.. code-block:: bash

    $ tox -e py27,pep8

See ``tox.ini`` for the full list of available test environments.
