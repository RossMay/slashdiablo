from django.core.management.base import BaseCommand, CommandError
from diablo2.tasks import logs_sync

class Command(BaseCommand):
	help = 'Sync the gameserver logs'

	def handle(self, *args, **options):
		logs_sync.delay()
