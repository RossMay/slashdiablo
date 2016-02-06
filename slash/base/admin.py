from django.contrib import admin

from .models import Variable

class VariableAdmin(admin.ModelAdmin):
	list_display = ('name','value','json_value')

admin.site.register(Variable,VariableAdmin)
