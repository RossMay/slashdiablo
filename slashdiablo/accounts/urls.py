from django.conf.urls import url

from . import views

urlpatterns = [
	url(r'^sync-accounts', views.sync_all_accounts, name='sync_all_accounts'),
	url(r'^sync-characters', views.sync_characters, name='sync_characters'),
	url(r'^$', views.index, name='index'),
]
