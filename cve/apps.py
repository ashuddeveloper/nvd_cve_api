import logging
from django.apps import AppConfig
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from .utils import synchronize_cve_data
import atexit

logger = logging.getLogger('cve')


class CveConfig(AppConfig):
    """
    Configuration class for the CVE application.

    Sets up the application configuration and initializes
    a background scheduler to periodically synchronize CVE data.
    """
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'cve'

    def ready(self):
        """
        Perform application setup once the Django application is ready.

        Initializes the background scheduler to run the CVE data
        synchronization job every 24 hours and registers a shutdown
        hook to gracefully stop the scheduler when the application exits.
        """
        logger.info("CveConfig is being initialized.")

        # Initialize the background scheduler
        scheduler = BackgroundScheduler()
        scheduler.start()

        # Add a job to synchronize CVE data every 24 hours
        scheduler.add_job(
            func=synchronize_cve_data,
            trigger=IntervalTrigger(hours=24),  # Adjust the interval as needed
            id='synchronize_cve_data',
            name='Synchronize CVE data every 24 hours',
            replace_existing=True
        )

        logger.info("Scheduler job for CVE data synchronization added.")

        # Register a shutdown hook to stop the scheduler when the application exits
        atexit.register(lambda: scheduler.shutdown())
        logger.info("Scheduler shutdown registered.")
