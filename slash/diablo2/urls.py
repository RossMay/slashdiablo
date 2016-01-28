from django.conf.urls import url

from . import views

urlpatterns = [
	url(r'^sync-accounts', views.account_sync_all, name='account_sync_all'),
	url(r'^sync-characters', views.character_sync, name='character_sync'),
	url(r'^$', views.index, name='index'),
]
