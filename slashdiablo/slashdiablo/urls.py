from django.conf.urls import include,url
from django.contrib import admin

urlpatterns = [
	url(r'^account/', include('accounts.urls')),
	url(r'^admin/', admin.site.urls),
]
