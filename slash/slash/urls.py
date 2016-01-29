from django.conf.urls import include,url
from django.contrib import admin

from . import views

handler404 = 'base.views.handle_404'
handler500 = 'base.views.handle_500'

urlpatterns = [
	url(r'^diablo2/', include('diablo2.urls')),
	url(r'^admin/', admin.site.urls),
	url(r'^', include('base.urls')),
]
