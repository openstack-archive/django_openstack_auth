from django.conf.urls.defaults import patterns, include, url
from django.views.generic import TemplateView

from openstack_auth.utils import patch_middleware_get_user


patch_middleware_get_user()


urlpatterns = patterns('',
    url(r"", include('openstack_auth.urls')),
    url(r"^$", TemplateView.as_view(template_name="auth/blank.html"))
)
