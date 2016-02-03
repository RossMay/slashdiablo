from django.shortcuts import render
from django.contrib.auth.decorators import login_required,permission_required
from django.contrib.auth.models import User
from django.http import HttpResponse, HttpResponseRedirect
from django.conf import settings
from django.utils import timezone

from .models import Account,Character,FailedLog,GameserverLog

import MySQLdb,pytz,os,json,datetime,re

#ssh slash@gs.slashdiablo.net 'cmd /c echo|set /p=>c:\D2GS\Testlog.log'

def premium(request):
	return render(request,'diablo2/premium.html',{})

@login_required
def accounts(request):
	account_sync_owner(request.user)
	accounts = Account.objects.filter(owner=request.user)
	return render(request,'diablo2/accounts.html',{'accounts':accounts})

@login_required
def characters(request):
	sync_character_user(request.user)
	characters = Character.objects.filter(account__owner=request.user)
	return render(request,'diablo2/characters.html',{'characters':characters})

@permission_required('diablo2.moderation_enabled')
def moderation(request):
	return render(request,'diablo2/moderation.html',{})

def account_sync(query):
	db = MySQLdb.connect(host=settings.DIABLO2DB['HOST'],user=settings.DIABLO2DB['USER'],passwd=settings.DIABLO2DB['PASSWORD'],db=settings.DIABLO2DB['NAME'])
	cur = db.cursor()
	cur.execute("SELECT acct_username,acct_email,acct_userid,auth_admin,auth_operator,auth_lockk,auth_command_groups,acct_lastlogin_time,acct_lastlogin_ip FROM BNET where %s" % query)

	for row in cur.fetchall():
		if not row[0]:
			continue
		entry = {
			'name': row[0],
			'email': row[1],
			'id': row[2],
			'admin': True if row[3].lower() == "true" else False,
			'operator': True if row[4].lower() == "true" else False,
			'locked': True if row[5].lower() == "true" else False,
			'commandgroups': row[6],
			'time': datetime.datetime.fromtimestamp(row[7]),
			'ip': row[8]
		}

		if not entry['email']:
			user = False
		else:
			try:
				user = User.objects.get(email=entry['email'])
				#Check verified user status
			except User.DoesNotExist:
				print "No user match!"
				user = False

		try:
			account = Account.objects.get(name=entry['name'])
			#update the account
			print "Exists! - %s" % entry['name']
		except Account.DoesNotExist:
			account = Account(name=entry['name'],owner=user if user else None,user_id=entry['id'],admin=entry['admin'],operator=entry['operator'],locked=entry['locked'],commandgroups=entry['commandgroups'],lastlogin=timezone.make_aware(entry['time'],pytz.timezone('UTC')),lastlogin_ip=entry['ip'],status='B' if entry['locked'] else 'A',email=entry['email'])
			account.save()
			print "Doesnt exist! - %s" % entry['name']
	db.close()
	return True

def account_sync_owner(user):
	for account in Account.objects.filter(owner=user).filter(email=""):
		account_sync("acct_userid = '%d'" % account.user_id)
	account_sync("acct_email = '%s'" % user.email.replace(';',''))
	return HttpResponseRedirect('/diablo2/accounts/')
	
@permission_required('diablo2.account_sync_all')
def account_sync_all(request):
	return HttpResponse("Sync")


def parse_bytes_to_hex(values,start,size):
	hex = "0x"
	for x in reversed(values[start:start+size]):
        	hex = "%s%s" % (hex,x.encode('hex'))
	return hex

def parse_bytes_to_string(values,start,size):
	s = ""
	for x in reversed(values[start:start+size]):
		if not x or x == u'\u0000':
			continue
                s = "%s%s" % (s,x)

	return s[::-1]

def parse_bytes_to_int(values,start,size):
	return int(parse_bytes_to_hex(values,start,size),16)

def parse_bytes_to_bin(values,start,size):
	return bin(parse_bytes_to_int(values,start,size))

def parse_char_progress(val,expansion):
	if val < 4:
		return "None"
	elif (not expansion and val < 8) or (expansion and val < 9):
		return "Normal"
	elif (not expansion and val < 12) or (expansion and val < 15):
		return "Nightmare"
	else:
		return "Hell"

def parse_char_status(byte):
	expansion = byte & 32 > 0
	died = byte & 8 > 0
	hardcore = byte & 4 > 0
	return (expansion,died,hardcore)

def parse_char_class(byte):
	return {
		u'0x00': 'AM',
		u'0x01': 'SO',
		u'0x02': 'NE',
		u'0x03': 'PA',
		u'0x04': 'BA',
		u'0x05': 'DR',
		u'0x06': 'AS',
	}.get(byte,'UN')

def parse_character(owner,bytes):
	expansion, died, hardcore = parse_char_status(parse_bytes_to_int(bytes,36,1))
	info = {
		'expansion': expansion,
		'died': died,
		'hardcore': hardcore,
		'checksum': parse_bytes_to_hex(bytes,12,4),
		'name': parse_bytes_to_string(bytes,20,16),
		'progress': parse_char_progress(parse_bytes_to_int(bytes,37,1),expansion),
		'class': parse_char_class(parse_bytes_to_hex(bytes,40,1)),
		'level': parse_bytes_to_int(bytes,43,1),
		'timestamp': parse_bytes_to_hex(bytes,48,4),
		'merc_name': parse_bytes_to_hex(bytes,183,2),
		'merc_code': parse_bytes_to_hex(bytes,185,2),
#		'merc_exp': parse_bytes_to_int(bytes,187,4),

	}

	try:
		character = Character.objects.get(name=info['name'])
		if character.account != owner:
			print "New owner"
			character.delete()
			raise Character.DoesNotExist
		character.level = info['level']
		character.cclass = info['class']
		character.hardcore = info['hardcore']
		character.has_died = info['died']
		character.created = timezone.make_aware(datetime.datetime.fromtimestamp(int(info['timestamp'],16)),pytz.timezone('UTC'))
		character.last_update = timezone.make_aware(datetime.datetime.now(),pytz.timezone('UTC'))
		character.info = json.dumps(info)

	except Character.DoesNotExist:
		print "New Character %s" % info['name']
		character = Character(
				name=info['name'],
				account = owner,
				level = info['level'],
				cclass = info['class'],
				hardcore = info['hardcore'],
				has_died = info['died'],
				created = timezone.make_aware(datetime.datetime.fromtimestamp(int(info['timestamp'],16)),pytz.timezone('UTC')),
				last_update = timezone.make_aware(datetime.datetime.now(),pytz.timezone('UTC')),
				info = json.dumps(info)
			)
	character.save()

def sync_character(char,account):
	charfile = open("/home/slashdiablo/pvpgn/var/charsave/%s" % char, 'rb')
	byte = charfile.read(1)
	bytes = [byte]
	while byte != "":
		byte = charfile.read(1)
		bytes.append(byte)

	charfile.close()

	try:
		parse_character(account,bytes)
	except Exception, e:
		print "Failed to parse %s on %s - Probably hasn't logged in" % (char,account.name.lower())
		return False
	return True

def sync_character_account(account):
	characters = {}
	if not os.path.exists("/home/slashdiablo/pvpgn/var/charinfo/%s" % account.name.lower()):
		return False
	for char in os.listdir("/home/slashdiablo/pvpgn/var/charinfo/%s" % account.name.lower()):
		sync_character(char,account)

	return True

def sync_character_user(user):
	for account in Account.objects.filter(owner=user):
		sync_character_account(account)
	return True

def sync_character_all():
	for account in Account.objects.all():
		sync_character_account(account)

	return True

@permission_required('diablo2.log_parse')
def update_logs(request):
	parse_log("/srv/slashdiablo/www/logs/d2gs.log")
	return HttpResponse("Done")

def parse_log(file):
	ignored = []
	prev_created_game = {'parsed':{},'message':''}
	with open(file,'r') as f:
		for line in f:
			parsed = re.match(r'(?P<date>\d\d/\d\d) (?P<time>\d\d:\d\d:\d\d\.\d\d\d) (?P<type>\w+): (?P<message>.*)', line)
			if parsed:
				event = parsed.groupdict()
				if event['type'] == 'D2CSCreateEmptyGame':
					details = re.match(r'Created game \'(?P<game>.*?)\', (?P<id>\d+),(?P<exp>\w+),(?P<difficulty>\w+),(?P<mode>\w+),(?P<ladder>[\w\-]+).*', event['message'].replace('\r',''))
					if details:
						prev_created_game['parsed'] = details.groupdict().copy()
						prev_created_game['message'] = event['message'].replace('\r','')
						continue
					else:
						details = re.match(r'GameInfo: \'(?P<game>.*?)\',\'(?P<password>.*?)\',\'(?P<description>.*?)\', By (?P<character>[\w\-]+)\((?P<account>\*[\w\-]+)\)@(?P<ip>[\d\.]+)', event['message'].replace('\r',''))
						if details:
							log = details.groupdict()
							if log['game'] == prev_created_game['parsed']['game']:
								log.update(prev_created_game['parsed'])
								log['type'] = 'D2CSCreateEmptyGame'
							else:
								FailedLog(message="%s %s - Failed to merge \'D2CSCreateEmptyGame\' - %s - %s" % (event['date'],event['time'],event['message'].replace('\r',''),prev_created_game['message'])).save()
							
						else:
							FailedLog(message="Failed to parse \'D2CSCreateEmptyGame\' - %s" % event['message'].replace('\r','')).save()
	
				elif event['type'] == 'D2GSCBEnterGame':
					details = re.match(r'(?P<character>[\w\-]+)\((?P<account>\*[\w\-]+)\)\[L=(?P<level>\d+),C=(?P<cclass>\w+)\]@(?P<ip>[\d\.]+) enter game \'(?P<game>.*?)\', id=(?P<id>\d+)\((?P<exp>\w+),(?P<difficulty>\w+),(?P<mode>\w+),(?P<ladder>[\w\-]+)\)', event['message'].replace('\r',''))
					if details:
						log = details.groupdict()
						log['type'] = 'D2GSCBEnterGame'
					else:
						FailedLog(message="Failed to parse \'D2GSCBEnterGame\' - %s" % event['message'].replace('\r','')).save()
	
				elif event['type'] == 'D2GSCBLeaveGame':
					details = re.match(r'(?P<character>[\w\-]+)\((?P<account>\*[\w\-]+)\)\[L=(?P<level>\d+),C=(?P<cclass>\w+)\] leave game \'(?P<game>.*?)\', id=(?P<id>\d+)\((?P<exp>\w+),(?P<difficulty>\w+),(?P<mode>\w+),(?P<ladder>[\w\-]+)\)', event['message'].replace('\r',''))
					if details:
						log = details.groupdict()
						log['type'] = 'D2GSCBLeaveGame'
					else:
						FailedLog(message="Failed to parse \'D2GSCBLeaveGame\' - %s" % event['message'].replace('\r','')).save()
	
				else:
					continue
			else:
				continue

			today = datetime.date.today() 
			dt = datetime.datetime.strptime("%s/%s %s" % (event['date'], today.year if int(event['date'].split('/')[0]) <= today.month else today.year - 1,event['time'].split('.')[0]), "%m/%d/%Y %H:%M:%S")

			GameserverLog(	date = dt,
					type = log['type'],
			
					ip = log.get('ip',None),
					character = None,
					character_name = log.get('character',None),
					account = None,
					account_name = log.get('account',None),

					game_id = log.get('id',None),
					name = log.get('game',None),
					password = log.get('password',''),
					description = log.get('description',''),

					ladder = True if log.get('ladder','non-ladder') == 'ladder' else False,
					difficulty = log.get('difficulty','Unknown'),					
					hardcore = True if log.get('mode','softcore') == 'hardcore' else False,
					expansion = True if log.get('exp','cl') == 'exp' else False,
			
					cclass = log.get('cclass','Unknown'),
					level = int(log.get('level',0))).save()
					
