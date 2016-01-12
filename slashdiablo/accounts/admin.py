from django.contrib import admin

from .models import Diablo2,Diablo2Character

class Diablo2Admin(admin.ModelAdmin):
	list_display = ('name','owner','admin','locked','commandgroups','lastlogin','lastlogin_ip','status')

class Diablo2CharacterAdmin(admin.ModelAdmin):
	list_display = ('name','account','level','cclass','hardcore','created','last_update')

admin.site.register(Diablo2,Diablo2Admin)
admin.site.register(Diablo2Character,Diablo2CharacterAdmin)
