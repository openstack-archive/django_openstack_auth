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

from django.conf.urls.defaults import patterns, include, url
from django.views.generic import TemplateView

from openstack_auth.utils import patch_middleware_get_user


patch_middleware_get_user()


urlpatterns = patterns('',
    url(r"", include('openstack_auth.urls')),
    url(r"^$", TemplateView.as_view(template_name="auth/blank.html"))
)
