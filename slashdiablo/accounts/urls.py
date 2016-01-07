from django.conf.urls import url

from . import views

urlpatterns = [
	url(r'^sync', views.sync, name='sync'),
	url(r'^$', views.index, name='index'),
]
