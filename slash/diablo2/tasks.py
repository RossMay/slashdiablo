from django.conf import settings
from django.utils import timezone

from .models import FailedLog,GameserverLog

import pytz,os,datetime,re,pysftp,subprocess

from __future__ import absolute_import

from celery import shared_task


@shared_task
def logs_parse(file,remove=False):
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

			GameserverLog(	date = timezone.make_aware(dt,pytz.timezone('UTC')),
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
	if remove:
		os.remove(file)
					
def sftp_progress(done,total):
	print "%s/%s %s%%\r" % (done, total,int((done/float(total))*100)),

@shared_task
def logs_sync():
	with pysftp.Connection('74.91.124.236',username='slash',private_key='/home/slashdiablo/.ssh/id_rsa') as sftp:
		with sftp.cd('log'):
			for dir in sftp.listdir():
				if (not sftp.isdir(dir) and not dir.find('.log')) or dir == "Parsed":
					continue
				if sftp.isdir(dir):
					file = "%s\\d2gs.log" % dir
				else:
					file = dir
				sftp.get('%s' % file,localpath='/srv/slashdiablo/www/logs/%s-d2gs.log' % dir,callback=sftp_progress,preserve_mtime=True)
				logs_parse('/srv/slashdiablo/www/logs/%s-d2gs.log' % dir,remove=True)
				subprocess.call("ssh slash@gs.slashdiablo.net 'cmd /c move C:\\D2GS\\log\\%s C:\\D2GS\\log\\Parsed\\'" % dir, shell=True)

		if sftp.isfile('d2gs.log'):
			dt = datetime.datetime.now()
			fname = datetime.datetime.now().strftime("%Y-%m-%d--%H.%M-d2gs.log")
			subprocess.call("ssh slash@gs.slashdiablo.net 'cmd /c copy C:\\D2GS\\d2gs.log C:\\D2GS\\log\\%s'" % fname, shell=True)
			subprocess.call("ssh slash@gs.slashdiablo.net 'powershell -inputformat none -command \"& {Clear-Content C:\D2GS\d2gs.log}\"'", shell=True)
			sftp.get('log/%s' % fname,localpath='/srv/slashdiablo/www/logs/%s' % fname,callback=sftp_progress,preserve_mtime=True)
			subprocess.call("ssh slash@gs.slashdiablo.net 'cmd /c move C:\\D2GS\\log\\%s C:\\D2GS\\log\\Parsed\\%s'" % (fname,fname), shell=True)
		
