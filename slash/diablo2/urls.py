from django.conf.urls import url

from . import views

urlpatterns = [
	url(r'^moderation/search/?$', views.moderation_search, name='moderation_search'),
	url(r'^log_sync/?$', views.log_sync, name='log_sync'),
	url(r'^accounts/?$', views.accounts, name='accounts'),
	url(r'^characters/?$', views.characters, name='characters'),
	url(r'^moderation/?$', views.moderation, name='moderation'),
	url(r'^premium/?$', views.premium, name='premium'),
]
