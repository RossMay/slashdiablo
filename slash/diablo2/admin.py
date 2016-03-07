from django.contrib import admin

from .models import Account,Character,FailedLog,GameserverLog,LookupLog,ActionLog,Report,Stat

class AccountAdmin(admin.ModelAdmin):
	list_display = ('name','owner','admin','locked','commandgroups','lastlogin','lastlogin_ip','status')

class LookupLogAdmin(admin.ModelAdmin):
	list_display = ('user','type','target','query','parsed_query','date','num_results')

class CharacterAdmin(admin.ModelAdmin):
	list_display = ('name','account','level','cclass','hardcore','created','last_update')

class FailedLogAdmin(admin.ModelAdmin):
	list_display = ('message',)

class GameserverLogAdmin(admin.ModelAdmin):
	list_display = ('date','type','account_name','character_name','ip','name','password','difficulty')

class ActionLogAdmin(admin.ModelAdmin):
	list_display = ('action','target','user','date')

class ReportAdmin(admin.ModelAdmin):
	list_display = ('date','target','user','active')

class StatAdmin(admin.ModelAdmin):
	list_display = ('date','type','value','data')

admin.site.register(Account,AccountAdmin)
admin.site.register(LookupLog,LookupLogAdmin)
admin.site.register(Character,CharacterAdmin)
admin.site.register(FailedLog,FailedLogAdmin)
admin.site.register(GameserverLog,GameserverLogAdmin)
admin.site.register(ActionLog,ActionLogAdmin)
admin.site.register(Report,ReportAdmin)
admin.site.register(Stat,StatAdmin)
