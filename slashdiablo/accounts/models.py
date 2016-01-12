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
	last_update = models.DateTimeField(blank=True,null=True,help_text='Last time the account was updated from the database')
	last_character_update = models.DateTimeField(blank=True,null=True,help_text='Last time character data was updated')

	class Meta:
		verbose_name = "Diablo2 Account"
		permissions = (
			("diablo2.sync.account", 	"Can resync Diablo 2 accounts"),
			("diablo2.sync.account.all", 	"Can resync all Diablo 2 accounts at once"),
			("diablo2.sync.char", 		"Can resync Diablo 2 characters"),
			("diablo2.sync.char.all", 	"Can resync all Diablo 2 characters at once"),
		)

	def __unicode__(self):
		return self.name

class Diablo2Character(models.Model):
	CLASS = (
		('SO', 'Sorceress'),
		('PA', 'Paladin'),
		('AM', 'Amazon'),
		('NE', 'Necromancer'),
		('BA', 'Barbarian'),
		('AS', 'Assassin'),
		('DR', 'Druid'),
		('UN', 'Unknown')
	)

	name = models.CharField(max_length=25,help_text='Character Name')
	account = models.ForeignKey(Diablo2,help_text='Diablo2 Account')
	level = models.IntegerField(default=1,help_text='Character Level')
	cclass = models.CharField(default='UN',choices=CLASS,max_length=2,help_text='Character Class')
	hardcore = models.BooleanField(default=False,help_text='Character is hardcore')
	has_died = models.BooleanField(default=False,help_text='Character has died')
	created = models.DateTimeField(help_text='Date created (Determines ladder)')
	last_update = models.DateTimeField(blank=True,null=True,help_text='Last time the character was updated')
	info = models.TextField(blank=True)
	
	class Meta:
		verbose_name = "Diablo2 Character"

	def __unicode__(self):
		return self.name
