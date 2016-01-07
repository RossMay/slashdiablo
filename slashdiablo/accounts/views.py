from django.shortcuts import render
from django.contrib.auth.decorators import login_required,permission_required
from django.http import HttpResponse
from django.conf import settings
from django.utils import timezone
import datetime

from .models import Diablo2
from django.contrib.auth.models import User

import MySQLdb,pytz

def index(request):
	return HttpResponse("Working")


@permission_required('accounts.diablo2.sync_all')
def sync(request):
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
			account = Diablo2.objects.get(name=entry['name'])
			#update
			print "Exists! - %s" % entry['name']
		except Diablo2.DoesNotExist:
			#create
			account = Diablo2(name=entry['name'],owner=user if user else None,user_id=entry['id'],admin=entry['admin'],operator=entry['operator'],locked=entry['locked'],commandgroups=entry['commandgroups'],lastlogin=timezone.make_aware(entry['time'],pytz.timezone('UTC')),lastlogin_ip=entry['ip'],status='B' if entry['locked'] else 'A',email=entry['email'])
			account.save()
			print "Doesnt exist! - %s" % entry['name']

		
	db.close()
	return HttpResponse("Sync")
