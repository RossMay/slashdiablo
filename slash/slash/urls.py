from django.conf.urls import include,url
from django.contrib import admin

urlpatterns = [
	url(r'^diablo2/', include('diablo2.urls')),
	url(r'^admin/', admin.site.urls),
]
