from django.conf.urls import url

from . import views

urlpatterns = [
	url(r'^update_logs/?$', views.update_logs, name='update_logs'),
	url(r'^accounts/?$', views.accounts, name='accounts'),
	url(r'^characters/?$', views.characters, name='characters'),
	url(r'^moderation/?$', views.moderation, name='moderation'),
	url(r'^premium/?$', views.premium, name='premium'),
]
