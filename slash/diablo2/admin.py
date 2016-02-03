from django.contrib import admin

from .models import Account,Character,FailedLog,GameserverLog

class AccountAdmin(admin.ModelAdmin):
	list_display = ('name','owner','admin','locked','commandgroups','lastlogin','lastlogin_ip','status')

class CharacterAdmin(admin.ModelAdmin):
	list_display = ('name','account','level','cclass','hardcore','created','last_update')

class FailedLogAdmin(admin.ModelAdmin):
	list_display = ('message',)

class GameserverLogAdmin(admin.ModelAdmin):
	list_display = ('date','type','account_name','character_name','ip','name','password','difficulty')

admin.site.register(Account,AccountAdmin)
admin.site.register(Character,CharacterAdmin)
admin.site.register(FailedLog,FailedLogAdmin)
admin.site.register(GameserverLog,GameserverLogAdmin)
