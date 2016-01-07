from __future__ import unicode_literals

from django.contrib.auth.models import User

from django.db import models

class Diablo2(models.Model):
	STATUS = (
		('A', 'Active'),
		('B', 'Banned')
	)
	
	name = models.CharField(max_length=25,help_text='Diablo 2 Account Name')
	owner = models.ForeignKey(User,blank=True,null=True,help_text='Owner of this account, blank if unknown')
	user_id = models.IntegerField(default=-1,help_text='Diablo 2 Account User ID')
	admin = models.BooleanField(default=False,help_text='Account is admin flagged')
	operator = models.BooleanField(default=False,help_text='Account is operator flagged')
	locked = models.BooleanField(default=False,help_text='Account is locked')
	commandgroups = models.IntegerField(default=1,help_text='Diablo 2 command groups (1 is Default)')
	lastlogin = models.DateTimeField(blank=True,null=True,help_text='Last time logged in by this account in game')
	lastlogin_ip = models.CharField(max_length=15,blank=True,null=True,help_text='Last ip logged in from by this account in game')
	status = models.CharField(default='A',choices=STATUS,max_length=1,help_text='Account status (Active/Banned)')
	email = models.EmailField(blank=True,null=True,help_text='Diablo 2 registered email address')
	class Meta:
		permissions = (
			("diablo2.sync_all", "Can resync all Diablo 2 account data"),
		)
