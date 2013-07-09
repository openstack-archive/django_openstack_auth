import logging

from threading import Thread

from django import shortcuts
from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.views import (login as django_login,
                                       logout_then_login as django_logout)
from django.contrib.auth.decorators import login_required
from django.views.decorators.debug import sensitive_post_parameters
from django.utils.functional import curry
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect

try:
    from django.utils.http import is_safe_url
except ImportError:
    from .utils import is_safe_url

from keystoneclient.v2_0 import client as keystone_client_v2
from keystoneclient import exceptions as keystone_exceptions

from .forms import Login
from .user import set_session_from_user, create_user_from_token, Token
from .utils import get_keystone_client
from .utils import get_keystone_version


LOG = logging.getLogger(__name__)


@sensitive_post_parameters()
@csrf_protect
@never_cache
def login(request):
    """ Logs a user in using the :class:`~openstack_auth.forms.Login` form. """
    # Get our initial region for the form.
    initial = {}
    current_region = request.session.get('region_endpoint', None)
    requested_region = request.GET.get('region', None)
    regions = dict(getattr(settings, "AVAILABLE_REGIONS", []))
    if requested_region in regions and requested_region != current_region:
        initial.update({'region': requested_region})

    if request.method == "POST":
        form = curry(Login, request)
    else:
        form = curry(Login, initial=initial)

    extra_context = {'redirect_field_name': REDIRECT_FIELD_NAME}

    if request.is_ajax():
        template_name = 'auth/_login.html'
        extra_context['hide'] = True
    else:
        template_name = 'auth/login.html'

    res = django_login(request,
                       template_name=template_name,
                       authentication_form=form,
                       extra_context=extra_context)
    # Set the session data here because django's session key rotation
    # will erase it if we set it earlier.
    if request.user.is_authenticated():
        set_session_from_user(request, request.user)
        regions = dict(Login.get_region_choices())
        region = request.user.endpoint
        region_name = regions.get(region)
        request.session['region_endpoint'] = region
        request.session['region_name'] = region_name
    return res


def logout(request):
    msg = 'Logging out user "%(username)s".' % \
        {'username': request.user.username}
    LOG.info(msg)
    if 'token_list' in request.session:
        t = Thread(target=delete_all_tokens,
                   args=(list(request.session['token_list']),))
        t.start()
    """ Securely logs a user out. """
    return django_logout(request)


def delete_all_tokens(token_list):
    insecure = getattr(settings, 'OPENSTACK_SSL_NO_VERIFY', False)
    for token_tuple in token_list:
        try:
            endpoint = token_tuple[0]
            token = token_tuple[1]
            if get_keystone_version() < 3:
                client = keystone_client_v2.Client(endpoint=endpoint,
                                                token=token,
                                                insecure=insecure,
                                                debug=settings.DEBUG)
                client.tokens.delete(token=token)
            else:
                # FIXME: KS-client does not have delete token available
                # Need to add this later when it is exposed.
                pass
        except keystone_exceptions.ClientException as e:
            LOG.info('Could not delete token')


@login_required
def switch(request, tenant_id, redirect_field_name=REDIRECT_FIELD_NAME):
    """ Switches an authenticated user from one project to another. """
    LOG.debug('Switching to tenant %s for user "%s".'
              % (tenant_id, request.user.username))
    insecure = getattr(settings, 'OPENSTACK_SSL_NO_VERIFY', False)
    endpoint = request.user.endpoint
    try:
        if get_keystone_version() >= 3:
            endpoint = endpoint.replace('v2.0', 'v3')

        client = get_keystone_client().Client(tenant_id=tenant_id,
                                              token=request.user.token.id,
                                              auth_url=endpoint,
                                              insecure=insecure,
                                              debug=settings.DEBUG)
        auth_ref = client.auth_ref
        msg = 'Project switch successful for user "%(username)s".' % \
            {'username': request.user.username}
        LOG.info(msg)
    except keystone_exceptions.ClientException:
        msg = 'Project switch failed for user "%(username)s".' % \
            {'username': request.user.username}
        LOG.warning(msg)
        auth_ref = None
        LOG.exception('An error occurred while switching sessions.')

    # Ensure the user-originating redirection url is safe.
    # Taken from django.contrib.auth.views.login()
    redirect_to = request.REQUEST.get(redirect_field_name, '')
    if not is_safe_url(url=redirect_to, host=request.get_host()):
        redirect_to = settings.LOGIN_REDIRECT_URL

    if auth_ref:
        user = create_user_from_token(request, Token(auth_ref), endpoint)
        set_session_from_user(request, user)
    return shortcuts.redirect(redirect_to)


def switch_region(request, region_name,
                  redirect_field_name=REDIRECT_FIELD_NAME):
    """
    Switches the non-identity services region that is being managed
    for the scoped project.
    """
    if region_name in request.user.available_services_regions:
        request.session['services_region'] = region_name
        LOG.debug('Switching services region to %s for user "%s".'
                  % (region_name, request.user.username))

    redirect_to = request.REQUEST.get(redirect_field_name, '')
    if not is_safe_url(url=redirect_to, host=request.get_host()):
        redirect_to = settings.LOGIN_REDIRECT_URL

    return shortcuts.redirect(redirect_to)
