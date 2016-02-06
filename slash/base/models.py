from __future__ import unicode_literals

from django.db import models

class Variable(models.Model):
        name = models.CharField(blank=False,null=False,max_length=128,help_text='Variable name')
        value = models.CharField(blank=True,null=True,max_length=255,help_text='Value')
        json = models.TextField(blank=True,null=True,help_text='Json value')

        class Meta:
                verbose_name = "Variable"

        def __unicode__(self):
                return self.name

	def json_value(self):
		if len(self.json) <= 30:
			return self.json
		else:
			return "%s..." % self.json[0:27]
