from __future__ import unicode_literals

from django.contrib.auth.models import User
from django.core.cache import cache

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
			("account_sync", 				"Can resync Diablo 2 accounts"),
			("account_sync_all", 				"Can resync all Diablo 2 accounts at once"),
			("character_sync", 				"Can resync Diablo 2 characters"),
			("character_sync_all", 				"Can resync all Diablo 2 characters at once"),
			("moderation_enabled", 				"Can access moderation tools"),
			("log_sync", 					"Can sync the gameserver logs"),
			("log_parse", 					"Can parse the gameserver logs"),
			("moderation_investigate", 			"Can access the investigate section"),
			("moderation_action", 				"Can access the actions section"),
			("moderation_gamelist", 			"Can access the game info section"),
			("moderation_history", 				"Can access the history section"),
			("moderation_system", 				"Can access the system secton"),
			("moderation_investigate_charname", 		"Can investigate character account names"),
			("moderation_investigate_database", 		"Can investigate using the database"),
			("moderation_investigate_database_password", 	"Can investigate using the database and lookup matching passwords"),
			("moderation_investigate_logs", 		"Can investigate using the logs"),
			("moderation_investigate_report", 		"Can generate reports"),
			("moderation_investigate_account", 		"Can investigate via account model "),
			("moderation_investigate_character", 		"Can investigate via character model"),
			("moderation_investigate_characterlist", 	"Can investigate character list from account"),
			("moderation_action_lock", 			"Can preform account lock"),
			("moderation_action_unlock", 			"Can preform account unlock"),
			("moderation_action_ban", 			"Can preform ip ban"),
			("moderation_action_unban", 		"Can preform ip unban"),
			("moderation_action_kick", 		"Can preform kick"),
			("moderation_action_announce", 		"Can preform announcement"),
			("moderation_action_chpass", 		"Can preform password change"),
			("moderation_history_gs", 		"Can view history for gameserver"),
			("moderation_history_report", 		"Can view history for reports"),
			("moderation_history_lookup", 		"Can view history for lookups"),
			("moderation_history_lookup_all",	"Can view history for lookups by everyone"),
			("moderation_history_action", 		"Can view history for actions"),
			("moderation_history_action_all",	"Can view history for actions by everyone"),
			("moderation_system_pvpgn_start",	"Can manage pvpgn and start processes"),
			("moderation_system_pvpgn_stop",	"Can manage pvpgn and stop processes"),
			("moderation_system_pvpgn_restart",	"Can manage pvpgn and restart processes"),
			("moderation_system_d2gs_start",	"Can manage d2gs and start processes"),
			("moderation_system_d2gs_stop",		"Can manage d2gs and stop processes"),
			("moderation_system_d2gs_restart",	"Can manage d2gs and restart processes"),
			("moderation_system_status",		"Can view system status"),
			("moderation_gamelist_list",		"Can view gamelist"),
			("moderation_gamelist_detail",		"Can view game details"),
			("moderation_passwords",		"Can view various passwords"),
			("moderation_passwords_discord",	"Can view discord password"),
			("moderation_passwords_subreddit",	"Can view subreddit password"),
			("moderation_passwords_telnet",		"Can view telnet password"),
			("moderation_passwords_game",		"Can view in game moderator password"),
		)

	def save(self, *args, **kwargs):
		cache.delete('diablo2_accounts_all')
		cache.delete('diablo2_accounts_%s' % self.owner.id)
		print "deleting cache for accounts"
		super(Account, self).save(*args, **kwargs)

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
	checksum = models.CharField(max_length=25,help_text='Character Checksum')

	def save(self, *args, **kwargs):
		cache.delete('diablo2_characters_all')
		cache.delete('diablo2_characters_%s' % self.account.owner.id)
		print "deleting chartacter cache"
		super(Character, self).save(*args, **kwargs)

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

	def save(self, *args, **kwargs):
		cache.delete('diablo2_gameserver_log')
		super(GameserverLog, self).save(*args, **kwargs)

	class Meta:
		verbose_name = "Gameserver Log"

	def __unicode__(self):
		return self.type

class LookupLog(models.Model):
	user = models.ForeignKey(User,blank=False,null=False,help_text='User who ran the query')
	type = models.CharField(blank=False,null=False,max_length=20,help_text='Type of lookup')
	target = models.CharField(blank=False,null=False,max_length=20,help_text='Target of lookup')
	query = models.CharField(blank=False,null=False,max_length=255,help_text='User provided query')
	parsed_query = models.CharField(blank=False,null=False,max_length=255,help_text='Actual query run')
	num_results = models.IntegerField(help_text='Number of results')
	date = models.DateTimeField(auto_now_add=True,help_text='When the lookup was preformed')
	results = models.TextField(blank=True,null=True,help_text='Lookup results')
	
	def save(self, *args, **kwargs):
		cache.delete('diablo2_lookup_log')
		super(LookupLog, self).save(*args, **kwargs)

	class Meta:
		verbose_name = "Lookup Log"

	def __unicode__(self):
		return "%s - %s" % (self.user,self.parsed_query)

class ActionLog(models.Model):
	user = models.ForeignKey(User,blank=True,null=True,help_text='User who performed the action')
	action = models.CharField(blank=False,null=False,max_length=20,help_text='Which action was done')
	target = models.CharField(blank=False,null=False,max_length=255,help_text='Target of action')
	date = models.DateTimeField(auto_now_add=True,help_text='When the action was preformed')

	def save(self, *args, **kwargs):
		cache.delete('diablo2_action_log')
		super(ActionLog, self).save(*args, **kwargs)

	class Meta:
		verbose_name = "Action Log"

	def __unicode__(self):
		return "%s - %s" % (self.user if self.user else 'Command Line',self.action)

class Report(models.Model):
	user = models.ForeignKey(User,blank=False,null=False,help_text='User who generated this report')
	target = models.CharField(blank=False,null=False,max_length=25,help_text='Account the report was generated for')
	date = models.DateTimeField(auto_now_add=True,help_text='When the report was started')
	active = models.BooleanField(default=False,help_text='Report is currently being generated')
	results = models.TextField(blank=True,null=True,help_text='Report contents')
	results_full = models.TextField(blank=True,null=True,help_text='Full report contents')
	summary = models.TextField(blank=True,null=True,help_text='Report Summary')
	ignores = models.TextField(blank=True,null=True,help_text='List of entries ignored by this report')
	processed = models.TextField(blank=True,null=True,help_text='List of accounts and ips that were processed')
	next = models.TextField(blank=True,null=True,help_text='List of accounts and ips to search next')
	depth = models.IntegerField(default=1,help_text='Depth of search')


	def save(self, *args, **kwargs):
		cache.delete('diablo2_report_log')
		super(Report, self).save(*args, **kwargs)

	class Meta:
		verbose_name = "Report"

	def __unicode__(self):
		return self.target

class Stat(models.Model):
	TYPE = (
		('activity','Player Activity'),
	)

	date = models.DateTimeField(help_text='Stat recorded time')
	type = models.CharField(choices=TYPE,max_length=25,help_text='Stat type')

	value = models.IntegerField(blank=True,null=True)
	data = models.TextField(blank=True,null=True, default='{}')


	def save(self, *args, **kwargs):
		cache.delete('diablo2_stats_%s' % self.type)
		super(Stat, self).save(*args, **kwargs)

	class Meta:
		verbose_name = "Statistics"

	def __unicode__(self):
		return self.type
