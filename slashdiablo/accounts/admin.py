from django.contrib import admin

from .models import Diablo2

class Diablo2Admin(admin.ModelAdmin):
	list_display = ('name','owner','admin','locked','commandgroups','lastlogin','lastlogin_ip','status')

admin.site.register(Diablo2,Diablo2Admin)
