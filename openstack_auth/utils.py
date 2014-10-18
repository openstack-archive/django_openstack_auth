# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import datetime
import functools

from django.conf import settings
from django.contrib import auth
from django.contrib.auth import middleware
from django.contrib.auth import models
from django.utils import decorators
from django.utils import timezone
from keystoneclient.v2_0 import client as client_v2
from keystoneclient.v3 import client as client_v3
from six.moves.urllib import parse as urlparse


_PROJECT_CACHE = {}

_TOKEN_TIMEOUT_MARGIN = getattr(settings, 'TOKEN_TIMEOUT_MARGIN', 0)

"""
We need the request object to get the user, so we'll slightly modify the
existing django.contrib.auth.get_user method. To do so we update the
auth middleware to point to our overridden method.

Calling the "patch_middleware_get_user" method somewhere like our urls.py
file takes care of hooking it in appropriately.
"""


def middleware_get_user(request):
    if not hasattr(request, '_cached_user'):
        request._cached_user = get_user(request)
    return request._cached_user


def get_user(request):
    try:
        user_id = request.session[auth.SESSION_KEY]
        backend_path = request.session[auth.BACKEND_SESSION_KEY]
        backend = auth.load_backend(backend_path)
        backend.request = request
        user = backend.get_user(user_id) or models.AnonymousUser()
    except KeyError:
        user = models.AnonymousUser()
    return user


def patch_middleware_get_user():
    middleware.get_user = middleware_get_user
    auth.get_user = get_user


""" End Monkey-Patching. """


def is_token_valid(token, margin=None):
    """Timezone-aware checking of the auth token's expiration timestamp.

    Returns ``True`` if the token has not yet expired, otherwise ``False``.

    .. param:: token

       The openstack_auth.user.Token instance to check

    .. param:: margin

       A time margin in seconds to subtract from the real token's validity.
       An example usage is that the token can be valid once the middleware
       passed, and invalid (timed-out) during a view rendering and this
       generates authorization errors during the view rendering.
       A default margin can be set by the TOKEN_TIMEOUT_MARGIN in the
       django settings.
    """
    expiration = token.expires
    # In case we get an unparseable expiration timestamp, return False
    # so you can't have a "forever" token just by breaking the expires param.
    if expiration is None:
        return False
    if margin is None:
        margin = getattr(settings, 'TOKEN_TIMEOUT_MARGIN', 0)
    expiration = expiration - datetime.timedelta(seconds=margin)
    if settings.USE_TZ and timezone.is_naive(expiration):
        # Presumes that the Keystone is using UTC.
        expiration = timezone.make_aware(expiration, timezone.utc)
    return expiration > timezone.now()


# From django.contrib.auth.views
# Added in Django 1.4.3, 1.5b2
# Vendored here for compatibility with old Django versions.
def is_safe_url(url, host=None):
    """Return ``True`` if the url is a safe redirection.

    The safe redirection means that it doesn't point to a different host.
    Always returns ``False`` on an empty url.
    """
    if not url:
        return False
    netloc = urlparse.urlparse(url)[1]
    return not netloc or netloc == host


def memoize_by_keyword_arg(cache, kw_keys):
    """Memoize a function using the list of keyword argument name as its key.

    Wrap a function so that results for any keyword argument tuple are stored
    in 'cache'. Note that the keyword args to the function must be usable as
    dictionary keys.

    :param cache: Dictionary object to store the results.
    :param kw_keys: List of keyword arguments names. The values are used
                    for generating the key in the cache.
    """
    def _decorator(func):
        @functools.wraps(func, assigned=decorators.available_attrs(func))
        def wrapper(*args, **kwargs):
            mem_args = [kwargs[key] for key in kw_keys if key in kwargs]
            mem_args = '__'.join(str(mem_arg) for mem_arg in mem_args)
            if not mem_args:
                return func(*args, **kwargs)
            if mem_args in cache:
                return cache[mem_args]
            result = func(*args, **kwargs)
            cache[mem_args] = result
            return result
        return wrapper
    return _decorator


def remove_project_cache(token):
    _PROJECT_CACHE.pop(token, None)


# Helper for figuring out keystone version
# Implementation will change when API version discovery is available
def get_keystone_version():
    return getattr(settings, 'OPENSTACK_API_VERSIONS', {}).get('identity', 2.0)


def get_keystone_client():
    if get_keystone_version() < 3:
        return client_v2
    else:
        return client_v3


def has_in_url_path(url, sub):
    """Test if the `sub` string is in the `url` path."""
    scheme, netloc, path, query, fragment = urlparse.urlsplit(url)
    return sub in path


def url_path_replace(url, old, new, count=None):
    """Return a copy of url with replaced path.

    Return a copy of url with all occurrences of old replaced by new in the url
    path.  If the optional argument count is given, only the first count
    occurrences are replaced.
    """
    args = []
    scheme, netloc, path, query, fragment = urlparse.urlsplit(url)
    if count is not None:
        args.append(count)
    return urlparse.urlunsplit((
        scheme, netloc, path.replace(old, new, *args), query, fragment))


@memoize_by_keyword_arg(_PROJECT_CACHE, ('token', ))
def get_project_list(*args, **kwargs):
    if get_keystone_version() < 3:
        auth_url = url_path_replace(
            kwargs.get('auth_url', ''), '/v3', '/v2.0', 1)
        kwargs['auth_url'] = auth_url
        client = get_keystone_client().Client(*args, **kwargs)
        projects = client.tenants.list()
    else:
        auth_url = url_path_replace(
            kwargs.get('auth_url', ''), '/v2.0', '/v3', 1)
        kwargs['auth_url'] = auth_url
        client = get_keystone_client().Client(*args, **kwargs)
        client.management_url = auth_url
        projects = client.projects.list(user=kwargs.get('user_id'))

    projects.sort(key=lambda project: project.name.lower())
    return projects
