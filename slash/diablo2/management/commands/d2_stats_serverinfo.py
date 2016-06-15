from django.core.management.base import BaseCommand, CommandError
from diablo2.tasks import stats_serverinfo

class Command(BaseCommand):
	help = 'Parse the serverinfo file'

	def handle(self, *args, **options):
		stats_serverinfo()
