from django.conf.urls import url

from . import views

urlpatterns = [
	url(r'moderation/report/(?P<reportid>[0-9]+)/?$', views.moderation_report, name='moderation_report'),
	url(r'moderation/lookup/(?P<lookupid>[0-9]+)/?$', views.moderation_lookup, name='moderation_lookup'),
	url(r'moderation/action/(?P<actionid>[0-9]+)/?$', views.moderation_action, name='moderation_action'),
	url(r'^moderation/search/?$', views.moderation_search, name='moderation_search'),
	url(r'^log_sync/?$', views.log_sync, name='log_sync'),
	url(r'^accounts/?$', views.accounts, name='accounts'),
	url(r'^characters/?$', views.characters, name='characters'),
	url(r'^moderation/?$', views.moderation, name='moderation'),
	url(r'^premium/?$', views.premium, name='premium'),
]
