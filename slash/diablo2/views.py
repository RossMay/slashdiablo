from django.shortcuts import render
from django.contrib.auth.decorators import login_required,permission_required
from django.http import HttpResponse
from django.conf import settings
from django.utils import timezone
import datetime

from .models import Account,Character
from django.contrib.auth.models import User

import MySQLdb,pytz,os,json

def index(request):
	return HttpResponse("Working")


@permission_required('diablo2.account.sync.all')
def account_sync_all(request):
	db = MySQLdb.connect(host=settings.DIABLO2DB['HOST'],user=settings.DIABLO2DB['USER'],passwd=settings.DIABLO2DB['PASSWORD'],db=settings.DIABLO2DB['NAME'])
	cur = db.cursor()
	cur.execute("SELECT acct_username,acct_email,acct_userid,auth_admin,auth_operator,auth_lockk,auth_command_groups,acct_lastlogin_time,acct_lastlogin_ip FROM BNET where acct_username like 'verris%'")

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
			#update
			print "Exists! - %s" % entry['name']
		except Account.DoesNotExist:
			#create
			account = Account(name=entry['name'],owner=user if user else None,user_id=entry['id'],admin=entry['admin'],operator=entry['operator'],locked=entry['locked'],commandgroups=entry['commandgroups'],lastlogin=timezone.make_aware(entry['time'],pytz.timezone('UTC')),lastlogin_ip=entry['ip'],status='B' if entry['locked'] else 'A',email=entry['email'])
			account.save()
			print "Doesnt exist! - %s" % entry['name']

		
	db.close()
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

@permission_required('diablo2.character.sync')
def character_sync(request):

	for account in Account.objects.all():
	#account = Diablo2.objects.get(name='Verris')

		characters = {}
		if not os.path.exists("/home/slashdiablo/pvpgn/var/charinfo/%s" % account.name.lower()):
			continue
		for char in os.listdir("/home/slashdiablo/pvpgn/var/charinfo/%s" % account.name.lower()):

			charfile = open("/home/slashdiablo/pvpgn/var/charsave/%s" % char, 'rb')
			#charfile = open("/srv/slashdiablo/%s" % char, 'rb')
	
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


	return HttpResponse("Sync chars")
