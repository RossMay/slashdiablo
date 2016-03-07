from __future__ import absolute_import

from django.conf import settings
from django.utils import timezone

from .models import FailedLog,GameserverLog,ActionLog,Stat

from base.models import Variable

import pytz,os,datetime,re,pysftp,subprocess

from celery import shared_task

import json, random, telnetlib

@shared_task()
def log_cleanup():
	before = datetime.datetime.now() - datetime.timedelta(days=20)
	GameserverLog.objects.filter(date__lte=before).delete()

@shared_task()
def stats_serverinfo():
	serverdat = open('/home/slashdiablo/pvpgn/var/status/server.dat','r').read()
	info = {
		'users': int(re.findall(r'Users=(\d+)',serverdat)[0]),
		'games': int(re.findall(r'Games=(\d+)',serverdat)[0]),
		'channels': int(re.findall(r'Channels=(\d+)',serverdat)[0])
	}
	Stat(date=timezone.make_aware(datetime.datetime.now(),pytz.timezone('UTC')),type='activity',data=json.dumps(info)).save()

@shared_task
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
		if ips[ip]['count'] > int(Variable.objects.get(name='diablo2_max_connections').value):
			kick = True
		for acct,char in ips[ip]['accounts']:
			if kick:
				tn.write('kick %s\n' % char)
				tn.read_until('D2GS>')
		if kick:
			ActionLog(action='Kill Multibox',target='%s - %s - %s' % (ip,ips[ip]['count'],','.join('*%s on %s' % (x[0],x[1]) for x in ips[ip]['accounts']))).save()

	tn.write('exit\n')

	return True

@shared_task
def logs_parse(file,remove=False):
	ignored = []
	prev_created_game = {'parsed':{},'message':''}
	with open(file,'r') as f:
		for line in f:
			parsed = re.match(r'(?P<date>\d\d/\d\d) (?P<time>\d\d:\d\d:\d\d\.\d\d\d) (?P<type>\w+): (?P<message>.*)', line)
			event = {}
			if parsed:
				event = parsed.groupdict().copy()
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
								continue
							
						else:
							FailedLog(message="Failed to parse \'D2CSCreateEmptyGame\' - %s" % event['message'].replace('\r','')).save()
							continue
	
				elif event['type'] == 'D2GSCBEnterGame':
					details = re.match(r'(?P<character>[\w\-]+)\((?P<account>\*[\w\-]+)\)\[L=(?P<level>\d+),C=(?P<cclass>\w+)\]@(?P<ip>[\d\.]+) enter game \'(?P<game>.*?)\', id=(?P<id>\d+)\((?P<exp>\w+),(?P<difficulty>\w+),(?P<mode>\w+),(?P<ladder>[\w\-]+)\)', event['message'].replace('\r',''))
					if details:
						log = details.groupdict()
						log['type'] = 'D2GSCBEnterGame'
					else:
						FailedLog(message="Failed to parse \'D2GSCBEnterGame\' - %s" % event['message'].replace('\r','')).save()
						continue
	
				elif event['type'] == 'D2GSCBLeaveGame':
					details = re.match(r'(?P<character>[\w\-]+)\((?P<account>\*[\w\-]+)\)\[L=(?P<level>\d+),C=(?P<cclass>\w+)\] leave game \'(?P<game>.*?)\', id=(?P<id>\d+)\((?P<exp>\w+),(?P<difficulty>\w+),(?P<mode>\w+),(?P<ladder>[\w\-]+)\)', event['message'].replace('\r',''))
					if details:
						log = details.groupdict()
						log['type'] = 'D2GSCBLeaveGame'
					else:
						if re.match(r'\d\d/\d\d \d\d:\d\d:\d\d\.\d\d\d D2DBSSaveDataReply: .*',event['message'].replace('\r','')):
							continue
						if re.match(r'phantom user .*',event['message'].replace('\r','')):
							continue
						FailedLog(message="Failed to parse \'D2GSCBLeaveGame\' - %s" % event['message'].replace('\r','')).save()
						continue
	
				else:
					continue
			else:
				continue

			today = datetime.date.today() 
			dt = datetime.datetime.strptime("%s/%s %s" % (event['date'], today.year if int(event['date'].split('/')[0]) <= today.month else today.year - 1,event['time'].split('.')[0]), "%m/%d/%Y %H:%M:%S")
			
			try:
				GameserverLog(	date = timezone.make_aware(dt,pytz.timezone('UTC')),
					type = log['type'],
			
					ip = log.get('ip',None),
					character = None,
					character_name = log.get('character',None),
					account = None,
					account_name = log.get('account','').replace('*',''),

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
			except Exception, e:
				print e
				print line
				print event
	if remove:
		os.remove(file)
					
def sftp_progress(done,total):
	if not total:
		return
	print "%s/%s %s%%\r" % (done, total,int((done/float(total))*100)),

@shared_task
def logs_sync(username='Unknown'):
	with pysftp.Connection('74.91.124.236',username='slash',private_key='/home/slashdiablo/.ssh/id_rsa') as sftp:
		with sftp.cd('log'):
			for dir in sftp.listdir():
				r = random.randint(0,100000)
				if (not sftp.isdir(dir) and not dir.find('.log')) or dir == "Parsed":
					continue
				if sftp.isdir(dir):
					file = "%s\\d2gs.log" % dir
				else:
					file = dir
				sftp.get('%s' % file,localpath='/srv/slashdiablo/www/logs/%s-d2gs-%s.log' % (dir,r),callback=sftp_progress,preserve_mtime=True)
				logs_parse.delay('/srv/slashdiablo/www/logs/%s-d2gs-%s.log' % (dir,r),remove=True)
				subprocess.call("ssh slash@gs.slashdiablo.net 'cmd /c move C:\\D2GS\\log\\%s C:\\D2GS\\log\\Parsed\\%s-d2gs-%s.log'" % (dir,dir,r), shell=True)

		if sftp.isfile('d2gs.log'):
			dt = datetime.datetime.now()
			fname = "%s-%s.log" % (datetime.datetime.now().strftime("%Y-%m-%d--%H.%M-d2gs"),r)
			subprocess.call("ssh slash@gs.slashdiablo.net 'cmd /c copy C:\\D2GS\\d2gs.log C:\\D2GS\\log\\%s'" % fname, shell=True)
			subprocess.call("ssh slash@gs.slashdiablo.net 'powershell -inputformat none -command \"& {Clear-Content C:\D2GS\d2gs.log}\"'", shell=True)
			sftp.get('log/%s' % fname,localpath='/srv/slashdiablo/www/logs/%s' % fname,callback=sftp_progress,preserve_mtime=True)
			logs_parse.delay('/srv/slashdiablo/www/logs/%s' % fname,remove=True)
			subprocess.call("ssh slash@gs.slashdiablo.net 'cmd /c move C:\\D2GS\\log\\%s C:\\D2GS\\log\\Parsed\\%s'" % (fname,fname), shell=True)

	
		
		variable = Variable.objects.get(name='diablo2_log_sync_time')
		variable.value = datetime.datetime.now()
		variable.json = json.dumps({'user': username})
		variable.save()
