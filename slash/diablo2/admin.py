from django.contrib import admin

from .models import Account,Character

class AccountAdmin(admin.ModelAdmin):
	list_display = ('name','owner','admin','locked','commandgroups','lastlogin','lastlogin_ip','status')

class CharacterAdmin(admin.ModelAdmin):
	list_display = ('name','account','level','cclass','hardcore','created','last_update')

admin.site.register(Account,AccountAdmin)
admin.site.register(Character,CharacterAdmin)
