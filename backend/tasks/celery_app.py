"""
ReconXploit - Celery Task Queue Configuration
"""

from celery import Celery
from backend.core.config import settings

celery_app = Celery(
    "reconxploit",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["backend.tasks.scan_tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=settings.default_scan_timeout + 600,
    task_soft_time_limit=settings.default_scan_timeout,
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=50,
    # Eager mode: honoured when CELERY_TASK_ALWAYS_EAGER env var is set (e.g. tests)
    task_always_eager=bool(int(__import__("os").environ.get("CELERY_TASK_ALWAYS_EAGER", "0"))),
    task_eager_propagates=bool(int(__import__("os").environ.get("CELERY_TASK_EAGER_PROPAGATES", "0"))),
    beat_schedule={
        "check-scheduled-scans": {
            "task": "backend.tasks.scan_tasks.check_scheduled_scans",
            "schedule": 60.0,  # Every minute
        },
    },
)
