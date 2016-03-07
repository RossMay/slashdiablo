from django.shortcuts import render

from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponseRedirect, HttpResponse
from django.utils import timezone
from django.contrib.auth.decorators import login_required

import json,pytz,datetime

from diablo2.models import Stat

@login_required
def index(request):
	activity = Stat.objects.filter(type='activity').filter(date__gt=timezone.make_aware(datetime.datetime.now()-datetime.timedelta(seconds=604800),pytz.timezone('UTC')))
	games = []
	users = []
	channels = []
	for a in activity:
		info = json.loads(a.data)
		games.append({'date': a.date,'value': info.get('games',0)})
		users.append({'date': a.date,'value': info.get('users',0)})
		channels.append({'date': a.date,'value': info.get('channels',0)})

	return render(request, 'base.html', {'games':games,'users':users,'channels':channels})

def user_login(request):
	if request.method == 'POST':
		username = request.POST.get('username', False)
		password = request.POST.get('password', False)
		next = request.POST.get('next', '/')

		if '@' in username:
			try:
				u = User.objects.get(email=username)
				username = u.username
			except User.DoesNotExist:
				pass
	
		user = authenticate(username=username, password=password)

		if username and password and user:
			if user.is_active:
				login(request,user)
				return HttpResponseRedirect(next)
			else:
				return render(request, 'login.html', {'error': 'Your account is not active'})
		else:
			return render(request, 'login.html', {'error': 'Invalid login information'})
	else:
		return render(request, 'login.html', {'next':request.GET.get('next','/')})


def user_logout(request):
	logout(request)
	return HttpResponseRedirect('/login/')

def handle_404(request):
	return render(request,'404.html',{})

def handle_500(request):
	return render(request,'500.html',{})
