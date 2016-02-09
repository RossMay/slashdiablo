from django.core.management.base import BaseCommand, CommandError
from diablo2.tasks import log_cleanup

class Command(BaseCommand):
	help = 'Cleanup the gamserverlog'

	def handle(self, *args, **options):
		log_cleanup.delay()
