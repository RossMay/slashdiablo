from __future__ import unicode_literals

from django.contrib.auth.models import User

from django.db import models

class Account(models.Model):
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
	characters = models.IntegerField(default=0,help_text='Number of characters as of last update')

	class Meta:
		verbose_name = "Account"
		permissions = (
			("diablo2.account_sync", 	"Can resync Diablo 2 accounts"),
			("diablo2.account_sync_all", 	"Can resync all Diablo 2 accounts at once"),
			("diablo2.character_sync", 	"Can resync Diablo 2 characters"),
			("diablo2.character_sync_all", 	"Can resync all Diablo 2 characters at once"),
			("diablo2.moderation_enabled", 	"Can access moderation tools"),
			("diablo2.log_parse", 		"Can parse the gameserver logs"),
		)

	def __unicode__(self):
		return self.name

class Character(models.Model):
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
	account = models.ForeignKey(Account,help_text='Diablo2 Account')
	level = models.IntegerField(default=1,help_text='Character Level')
	cclass = models.CharField(default='UN',choices=CLASS,max_length=2,help_text='Character Class')
	hardcore = models.BooleanField(default=False,help_text='Character is hardcore')
	has_died = models.BooleanField(default=False,help_text='Character has died')
	created = models.DateTimeField(help_text='Date created (Determines ladder)')
	last_update = models.DateTimeField(blank=True,null=True,help_text='Last time the character was updated')
	info = models.TextField(blank=True)
	expansion = models.BooleanField(default=True,help_text='Character is expansion')

	class Meta:
		verbose_name = "Character"

	def __unicode__(self):
		return self.name


class FailedLog(models.Model):
	message = models.CharField(blank=False,null=False,max_length=255,help_text='Log message')

	class Meta:
		verbose_name = "Failed Log"

	def __unicode__(self):
		return self.message

class GameserverLog(models.Model):
	TYPE = (
		('D2CSCreateEmptyGame','Create Game'),
		('D2GSCBEnterGame','Join Game'),
		('D2GSCBLeaveGame','Leave Game'),
	)

	date = models.DateTimeField(blank=False,null=False,help_text='Date and time the log entry was generated')
	type = models.CharField(blank=False,null=False,choices=TYPE,max_length=25,help_text='Log type')

	ip = models.CharField(blank=True,null=True,max_length=16,help_text='Player IP address')
	character = models.ForeignKey(Character,blank=True,null=True,help_text="Link to Diablo2 character")
	character_name = models.CharField(blank=True,null=True,max_length=40,help_text='Diablo2 character name')
	account = models.ForeignKey(Account,blank=True,null=True,help_text="Link to Diablo2 account")
	account_name = models.CharField(blank=True,null=True,max_length=40,help_text='Diablo2 account name')

	game_id = models.IntegerField(blank=True,null=True,default=0,help_text='Game ID')
	name = models.CharField(blank=True,null=True,max_length=40,help_text='Game name')
	password = models.CharField(blank=True,null=True,max_length=40,help_text='Game password')
	description = models.CharField(blank=True,null=True,max_length=75,help_text='Game Description')

	ladder = models.BooleanField(default=False,help_text='Game is ladder')
	difficulty = models.CharField(blank=True,null=True,max_length=10,help_text='Game Difficulty')
	hardcore = models.BooleanField(default=False,help_text='Game is hardcore')
	expansion = models.BooleanField(default=True,help_text='Game is expansion')

	cclass = models.CharField(blank=True,null=True,max_length=10,help_text='Character class')
	level = models.IntegerField(blank=True,null=True,default=1,help_text='Character Level')

	class Meta:
		verbose_name = "Gameserver Log"

	def __unicode__(self):
		return self.type
