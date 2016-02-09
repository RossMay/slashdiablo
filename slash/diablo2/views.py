from django.db.models.query import QuerySet
from django.shortcuts import render
from django.contrib.auth.decorators import login_required,permission_required
from django.contrib.auth.models import User
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse, Http404
from django.conf import settings
from django.utils import timezone
from django.views.decorators.csrf import ensure_csrf_cookie

from .models import Account,Character,FailedLog,GameserverLog,LookupLog,Report

from base.models import Variable

from . import tasks

import MySQLdb,pytz,os,json,datetime,re,pysftp,subprocess,random

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
@ensure_csrf_cookie
def moderation(request):
	context = {}

	#GS Log Syncing
	last_sync = Variable.objects.get(name='diablo2_log_sync_time')
	context['log_sync_time'] = datetime.datetime.strptime(last_sync.value,'%Y-%m-%d %H:%M:%S.%f')
	context['log_sync_mins'] = int((datetime.datetime.now() - context['log_sync_time']).seconds) / 60
	context['log_sync_user'] = json.loads(last_sync.json).get('user','Unknown')

	context['report_ignore'] = ['HCSlash']

	return render(request,'diablo2/moderation.html',context)

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

@permission_required('diablo2.log_sync')
def log_sync(request):
	variable = Variable.objects.get(name='diablo2_log_sync_time')
	last_update = datetime.datetime.strptime(variable.value,'%Y-%m-%d %H:%M:%S.%f')
	minutes = int((datetime.datetime.now() - last_update).seconds) / 60
	print minutes
	if minutes > 5:
		variable = Variable.objects.get(name='diablo2_log_sync_time')
		variable.value = datetime.datetime.now()
		variable.json = json.dumps({'user': request.user.username})
		variable.save()
		tasks.logs_sync.delay(username=request.user.username)
		return JsonResponse({'success': True, 'message': 'Log sync was sent to queue'})
	return JsonResponse({'success':False, 'message': 'Please wait, the log was synced %s minutes ago by %s' % (int(minutes),json.loads(variable.json).get('user','Unknown'))})

def logs_parse_all():
	for log in os.listdir("/srv/slashdiablo/www/logs/"):
		if log.endswith('.log'):
			tasks.logs_parse("/srv/slashdiablo/www/logs/%s" % log)


@permission_required('diablo2.moderation_enabled')
def moderation_search(request):
	if request.method == 'POST':
		action = request.POST.get('action',False)
		if action == 'search':
			source = request.POST.get('source',False)
			if source == 'database':
				if not request.user.has_perm('diablo2.moderation_investigate_database'):
					return JsonResponse({'success': False, 'message': 'You do not have the required permission to do that.', 'type': 'error', 'title': 'Permission Denied'})
				target = request.POST.get('target',False)
				terms = request.POST.get('terms',False)

				if not terms or not len(terms):
					return JsonResponse({'success':False,'message':'A search term is required', 'type': 'warn', 'title': 'Search Failed'})

				if not target in ['ip','email','account','password']:
					return JsonResponse({'success':False,'message':'Invalid target for database search', 'type': 'error', 'title': 'Error'})

				parsed_terms = re.sub('[^\w_\-@\.\*]','',terms)
				if not parsed_terms or not len(parsed_terms) or not len(parsed_terms.replace('*','')):
					return JsonResponse({'success':False,'message':'Invalid search term', 'type': 'warn', 'title': 'Search Failed'})

				
				target_map = { 'account': 'acct_username', 'email': 'acct_email', 'ip': 'acct_lastlogin_ip', 'password': 'acct_passhash1'}
				if target == 'password':
					if not request.user.has_perm('diablo2.moderation_investigate_database_password'):
						return JsonResponse({'success': False, 'message': 'You do not have the required permission to do that.', 'type': 'error', 'title': 'Permission Denied'})
					query = 'acct_passhash1 = (SELECT acct_passhash1 from BNET where acct_username = \'%s\');' % parsed_terms.replace('*','%')
				else:
					query = '%s like \'%s\';' % (target_map[target], parsed_terms.replace('*','%'))

				short_query = '%s = %s' % (target_map[target],parsed_terms)

				log = LookupLog(user=request.user,type=source,target=target_map[target],query=terms,parsed_query=query,results=0)
				log.save()
				
				db = MySQLdb.connect(host=settings.DIABLO2DB['HOST'],user=settings.DIABLO2DB['USER'],passwd=settings.DIABLO2DB['PASSWORD'],db=settings.DIABLO2DB['NAME'])
				cur = db.cursor()
				cur.execute("SELECT acct_username,acct_email,acct_userid,auth_admin,auth_operator,auth_lockk,auth_command_groups,acct_lastlogin_time,acct_lastlogin_ip FROM BNET where %s" % query)


				results = ''
				count = 0

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
						'ip': row[8],
					}

					results = results + "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" %(
								entry['name'],
								entry['email'],
								entry['id'],
								entry['admin'],
								entry['operator'],
								entry['locked'],
								entry['commandgroups'],
								entry['time'],
								entry['ip']
							)
					count = count +1
				db.close()

				if results == '':
					results = '<tr><td colspan=9>No Results</td></tr>'

				result = '''	<table class='table table-bordered'>
							<thead>
								<tr>
									<th>Account</th>
									<th>Email</th>
									<th>User ID</th>
									<th>Admin</th>
									<th>Operator</th>
									<th>Locked</th>
									<th>Command Groups</th>
									<th>Last Login</th>
									<th>Last IP</th>
								</tr>
							</thead>
							<tbody>
								%s
							</tbody>
						</table>''' % results

				log.results = count
				log.save()

				return JsonResponse({'success': True, 'query': short_query, 'result': result, 'count': count})
			elif source == 'logs':
				if not request.user.has_perm('diablo2.moderation_investigate_logs'):
					return JsonResponse({'success': False, 'message': 'You do not have the required permission to do that.', 'type': 'error', 'title': 'Permission Denied'})
				target = request.POST.get('target',False)
				terms = request.POST.get('terms',False)

				if not terms or not len(terms):
					return JsonResponse({'success':False,'message':'A search term is required', 'type': 'warn', 'title': 'Search Failed'})

				if not target in ['activity-ip','activity-account','activity-character','ip-account','ip-character','ip-ip','gamelist-ip','gamelist-account','gamelist-character','gameinfo','account-ip']:
					return JsonResponse({'success':False,'message':'Invalid target for log search', 'type': 'error', 'title': 'Error'})

				parsed_terms = re.sub('[^\w_\-\[\]\'\*\.]','',terms)
				if not parsed_terms or not len(parsed_terms) or not len(parsed_terms.replace('*','')):
					return JsonResponse({'success':False,'message':'Invalid search term', 'type': 'warn', 'title': 'Search Failed'})

				log = LookupLog(user=request.user,type=source,target=target,query=terms,parsed_query=parsed_terms,results=0)
				log.save()

				if target == 'gameinfo':

					short_query = "Gameinfo where gamename = %s" % terms
					entries = GameserverLog.objects.filter(name=parsed_terms).order_by('-date')

					results = ''
					count = 0
					for entry in entries:
						results = results + "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" %(
								datetime.datetime.strftime(entry.date,'%b %d %H:%M:%S'),
								entry.name,
								entry.password,
								entry.get_type_display().replace(' Game',''),
								entry.account_name,
								entry.character_name,
								entry.ip if entry.ip else '',
								entry.game_id,
								entry.cclass if not entry.cclass == "Unknown" else '',
								entry.level if entry.level else '',
								entry.difficulty.capitalize(),
							)
						count = count + 1

					if not count:
						results = '<tr><td colspan=8>No Results</td></tr>'

					result = '''	<table class='table table-bordered'>
								<thead>
									<tr>
										<th>Date</th>
										<th>Game</th>
										<th>Password</th>
										<th>Event</th>
										<th>Account</th>
										<th>Character</th>
										<th>IP</th>
										<th>ID</th>
										<th>Class</th>
										<th>Level</th>
										<th>Difficulty</th>
									</tr>
								</thead>
								<tbody>
									%s
								</tbody>
							</table>
						''' % results

					log.results = count
					log.save()

				else:
					t,s = target.split('-')
					if s == 'account':
						entries = GameserverLog.objects.filter(account_name=parsed_terms).order_by('-date')
					elif s == 'character':
						entries = GameserverLog.objects.filter(character_name=parsed_terms).order_by('-date')
					elif s == 'ip':
						entries = GameserverLog.objects.filter(ip=parsed_terms).order_by('-date')
					else:
						return JsonResponse({'success':False,'message':'Invalid target for log search', 'type': 'error', 'title': 'Error'})

					if t == 'activity':

						short_query = "Activity where %s = %s" % (s,terms)

						results = ''
						count = 0
						for entry in entries:
							results = results + "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" %(
									datetime.datetime.strftime(entry.date,'%b %d %H:%M:%S'),
									entry.name,
									entry.password,
									entry.get_type_display().replace(' Game',''),
									entry.account_name,
									entry.character_name,
									entry.ip if entry.ip else '',
									entry.game_id,
									entry.cclass if not entry.cclass == "Unknown" else '',
									entry.level if entry.level else '',
									entry.difficulty.capitalize(),
								)
							count = count + 1 
	
						if not count:
							results = '<tr><td colspan=8>No Results</td></tr>'
	
						result = '''	<table class='table table-bordered'>
									<thead>
										<tr>
											<th>Date</th>
											<th>Game</th>
											<th>Password</th>
											<th>Event</th>
											<th>Account</th>
											<th>Character</th>
											<th>IP</th>
											<th>ID</th>
											<th>Class</th>
											<th>Level</th>
											<th>Difficulty</th>
										</tr>
									</thead>
									<tbody>
										%s
									</tbody>
								</table>
							''' % results
	
						log.results = count
						log.save()

					elif t == 'ip':

						short_query = "IP List where %s = %s" % (s,terms)

						results = ''
						ips = []
						for entry in entries:
							if entry.ip and len(entry.ip) and not entry.ip in ips:
								results = results + "%s%s" % ('<br/>' if len(results) else '',entry.ip)
								ips.append(entry.ip)
	
						if not len(ips):
							results = 'No Results'
	
						result = '''	<table class='table table-bordered'>
									<thead>
										<tr>
											<th>IPs</th>
										</tr>
									</thead>
									<tbody>
										<tr>
											<td>
										%s
											</td>
										</tr>
									</tbody>
								</table>
							''' % results
	
						log.results = len(ips)
						log.save()
					elif t == 'gamelist':

						short_query = "Game List where %s = %s" % (s,terms)

						results = ''
						count = 0
						for entry in entries:
								if not entry.type == 'D2GSCBEnterGame':
									continue
								results = results + "%s%s" % ('<br/>' if len(results) else '',entry.name)
								count = count + 1
	
						if not count:
							results = 'No Results'
	
						result = '''	<table class='table table-bordered'>
									<thead>
										<tr>
											<th>Games</th>
										</tr>
									</thead>
									<tbody>
										<tr>
											<td>
										%s
											</td>
										</tr>
									</tbody>
								</table>
							''' % results
	
						log.results = count
						log.save()
					elif t == 'account':

						short_query = "Account List where %s = %s" % (s,terms)

						results = ''
						accounts = []
						for entry in entries:
								if not entry.account_name or entry.account_name in accounts:
									continue
								results = results + "%s%s" % ('<br/>' if len(results) else '',entry.account_name)
								accounts.append(entry.account_name)
	
						if not len(accounts):
							results = 'No Results'
	
						result = '''	<table class='table table-bordered'>
									<thead>
										<tr>
											<th>Accounts</th>
										</tr>
									</thead>
									<tbody>
										<tr>
											<td>
										%s
											</td>
										</tr>
									</tbody>
								</table>
							''' % results
	
						log.results = len(accounts)
						log.save()
					else:
						result = 'Not implemented'
						short_query = '%s = %s' % (target,terms)

				return JsonResponse({'success': True, 'query': short_query, 'result': result, 'count': log.results})
			elif source == 'report':
				if not request.user.has_perm('diablo2.moderation_investigate_report'):
					return JsonResponse({'success': False, 'message': 'You do not have the required permission to do that.', 'type': 'error', 'title': 'Permission Denied'})

				report_status = Variable.objects.get_or_create(name = 'diablo2_report_%s' % request.user.username)
				rs_json = json.loads(report_status.json)
				if rs_json.get('report_active',False):
					return JsonResponse({'success': False, 'message': 'You already have a running report, please wait.', 'type': 'error', 'title': 'Error'})

				report_id = request.POST.get('reportid',False)
		

				ignore_accounts = []
				ignore_ips = []

				accounts = []
				ips = []
				new_ips = []

				ignore = re.sub('[^\w_\-\[\]\,\.]','',request.POST.get('ignore',''))

				if report_id:
					report = Report.objects.get(id=int(report_id))
					log = LookupLog(user=request.user,type='report-continue',target=report_id,query='',parsed_query='',results=0)
					
					new_accounts = []
					for term in report.processed.split(','):
						if re.match('\d+\.\d+\.\d+\.\d+',term):
							ips.append(term)
						else:
							accounts.append(term)

					for term in report.next.split(','):
						if re.match('\d+\.\d+\.\d+\.\d+',term):
							new_ips.append(term)
						else:
							new_accounts.append(term)

				else:
					terms = request.POST.get('terms',False)
					new_accounts = ['%s' % terms]

					if not terms or not len(terms):
						return JsonResponse({'success':False,'message':'A search term is required', 'type': 'warn', 'title': 'Search Failed'})

					log = LookupLog(user=request.user,type=source,target='account',query=terms,parsed_query='',results=0)




				for term in ignore.split(','):
					if re.match('\d+\.\d+\.\d+\.\d+',term):
						ignore_ips.append(term)
					else:
						ignore_accounts.append(term)

				log.save()


				if not report_id:
					content =     '''=====================================================================<br/>
							Generating list of accounts and IPs associated with *%s<br/>
							=====================================================================<br/><br/>
							Ignoring IPs<br/>%s<br/><br/>Ignoring Accounts<br/>%s<br/><br/>''' % (terms,'<br/>'.join(ignore_ips),'<br/>'.join(ignore_accounts))

				else:
					content = report.results +  '''=====================================================================<br/>
								Checking again for all new IPs and Accounts</br>
								=====================================================================<br/>'''
				for account in new_accounts:
					if account in ignore_accounts:
						print "Ignoring account %s" % account
						continue
					if account in accounts:
						print "Already searched account %s" % account
						continue
					print "Searching for IPs by account %s" % account

					entries = GameserverLog.objects.filter(account_name=account).exclude(ip=None).only('ip')
					current_ips = []
					for entry in entries:
						if entry.ip in current_ips:
							continue
						elif entry.ip not in ips:
							if entry.ip not in new_ips:
								new_ips.append(entry.ip)
								current_ips.append(entry.ip)
								print "New IP %s" % entry.ip
							else:
								current_ips.append(entry.ip)
								print 'Already checked %s' % entry.ip
						elif entry.ip not in current_ips:
							current_ips.append(entry.ip)
							print 'Already checked %s' % entry.ip
	
					accounts.append(account)

				new_accounts = []
				for ip in new_ips:
					if ip in ignore_ips:
						print "Ignoring IP %s" % ip
						continue
					if ip in ips:
						print "Already Searched %s" % ip
						continue
					print "Searching for accounts by IP %s" % ip
					entries = GameserverLog.objects.filter(ip=ip).only('account_name')
					current_accounts = []
					for entry in entries:
						if entry.account_name in current_accounts:
							continue
						elif entry.account_name not in accounts:
							if entry.account_name not in new_accounts:
								new_accounts.append(entry.account_name)
								current_accounts.append(entry.account_name)
								print "New account %s" % entry.account_name
							else:
								current_accounts.append(entry.account_name)
								print "Already searched %s" % entry.account_name
						elif entry.account_name not in current_accounts:
							current_accounts.append(entry.account_name)
							print "Already searched %s" % entry.account_name
					ips.append(ip)

				final = len(new_accounts) == 0
				if final:
					print "No new accounts, ending"
					content = content +  '''=====================================================================<br/>
								No additional IPs or accounts</br>
								=====================================================================<br/>'''
				else:
					content = content +  '''=====================================================================<br/>
								New IP and Account Summary<br/>
								=====================================================================<br/>
								New IPs tied to accounts<br/><br/>
								%s<br/><br/>
								New Accounts tied to ips<br/><br/>
								%s<br/>''' % ('<br/>'.join(new_ips),'<br/>'.join(new_accounts))

				new_ips = []

				summary = 	     '''=====================================================================<br/>
							Final IP and Account Summary<br/>
							=====================================================================<br/>
							IPs tied to accounts<br/><br/>
							%s<br/><br/>
							Accounts tied to ips<br/><br/>
							%s<br/><br/>''' % ('<br/>'.join(ips),'<br/>'.join(accounts+new_accounts))

				if final:
					#Print db results for each account username,pass,email,ip, logintime, lock
					#Print list of accounts with matching lastlogin ip
					#Print list of accounts with matching passhash
					#print list of accounts with matching emails
					pass

				if not report_id:
					report = Report(user = request.user,
						target = terms,
						depth = 0,
						ignores = re.sub('[^\w_\-\[\]\,\.]','',request.POST.get('ignore','')))
				report.depth += 1
				report.active = final
				report.summary = summary
				report.results = content
				report.processed = ','.join(accounts+ips)
				report.next = ','.join(new_accounts+new_ips)
	
				report.save()

				return JsonResponse({'success': True, 'query': report.target, 'result': summary + content, 'reportid': report.id, 'final': final, 'depth': '%s' % report.depth})
		return JsonResponse({'success': True})
	else:
		raise Http404


def kill_multibox():
	tn = telnetlib.Telnet(settings.DIABLO2GS,8888)
	tn.read_until('Password:')
	tn.write('%s\n' % settings.DIABLO2GSPW)
	tn.read_until('D2GS>')
	tn.write('gl\n')
	gl = tn.read_until('D2GS>')

	gids = []
	ips = {}
	games = re.findall(r'\|(.*)\|',gl)
	for game in games:
		parsed = re.match(r' (?P<line>\d+)  (?P<game>.{15})  (?P<password>.{15})\s+(?P<gid>\d+).*',game)
		if parsed:
			gids.append(parsed.groupdict()['gid'])

	for gid in gids:
		tn.write('cl %s\n' % gid)
		cl =tn.read_until('D2GS>')

		chars = re.findall(r'\|(.*)\|',cl)
		for char in chars:
			parsed = re.match(r' (?P<line>\d+)  (?P<account>.{15})  (?P<char>.{15})\s+(?P<ip>[\d\.]+)\s+(?P<class>\w+)\s+(?P<level>\d+)\s+(?P<joined>[\w:]+).*',char)
			if parsed:
				if not parsed.groupdict()['ip'] in ips.keys():
					ips[parsed.groupdict()['ip']] = {'count': 0, 'accounts': []}
				ips[parsed.groupdict()['ip']]['count'] += 1
				ips[parsed.groupdict()['ip']]['accounts'].append((parsed.groupdict()['account'].rstrip(),parsed.groupdict()['char'].rstrip()))
				

	for ip in ips.keys():		
		kick = False
		print '\n%s\t%d\t' % (ip,ips[ip]['count']),
		if ips[ip]['count'] > int(Variable.objects.get(name='diablo2_max_connections').value):
			print '\n\tMore connections than allowed from ip %s, kicking chars' % (settings.DIABLO2MAXCONN,ip)
			kick = True
		for acct,char in ips[ip]['accounts']:
			if kick:
				tn.write('kick %s\n' % char)
				tn.read_until('D2GS>')
				print '\n\t\tKicking *%s on %s' % (acct, char),
			else:
				print '*%s on %s, ' % (acct, char),
		if kick:
			ActionLog(action='Kill Multibox',target='%s - %s - %s' % (ip,ips[ip]['count'],','.join('*%s on %s' % (x[0],x[1]) for x in ips[ip]['accounts'])))			



	tn.write('exit\n')

	return True
