from django.core.management.base import BaseCommand, CommandError
from diablo2.tasks import kill_multibox

class Command(BaseCommand):
	help = 'Kill any connections with more than variables.diablo2_max_connections connections to the GS'

	def handle(self, *args, **options):
		kill_multibox.delay()
