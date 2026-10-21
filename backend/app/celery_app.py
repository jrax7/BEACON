import logging

from celery import Celery
from kombu import Queue

from app.config import settings


# Avoid logging scanner API request URLs at INFO level.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)


celery_app = Celery(
    "beacon",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=[
        "app.tasks",
        "app.tasks_v2",
        "app.reporting.tasks",
        "app.auth.mail_tasks",
    ],
)

celery_app.conf.update(
    task_track_started=True,
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="Asia/Amman",
    enable_utc=True,
    broker_connection_retry_on_startup=True,
    worker_prefetch_multiplier=1,
    task_default_queue="control",
    task_queues=(
        Queue("control"),
        Queue("discovery"),
        Queue("scanner"),
        Queue("report"),
    ),
    task_routes={
        "beacon.test_task": {
            "queue": "control",
        },
        "beacon.send_auth_email": {
            "queue": "control",
        },
        "beacon.send_organization_invitation_email": {
            "queue": "control",
        },
        "beacon.run_basic_scan": {
            "queue": "scanner",
        },
        "beacon.run_assessment_v2": {
            "queue": "scanner",
        },
        "beacon.generate_scan_report": {
            "queue": "report",
        },
    },
)
