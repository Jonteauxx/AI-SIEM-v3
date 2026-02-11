# Celery application configuration for SOC Agent
# Provides distributed task processing for log analysis and maintenance

import os
from celery import Celery
from celery.schedules import crontab
from kombu import Queue, Exchange

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Redis configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", REDIS_URL)
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", REDIS_URL)

# Create Celery application
celery_app = Celery(
    "soc_agent",
    broker=CELERY_BROKER_URL,
    backend=CELERY_RESULT_BACKEND,
    include=[
        "tasks.log_analysis",
        "tasks.retention",
        "tasks.metrics",
    ]
)

# Define exchanges
default_exchange = Exchange("default", type="direct")
log_analysis_exchange = Exchange("log_analysis", type="direct")
maintenance_exchange = Exchange("maintenance", type="direct")

# Celery configuration
celery_app.conf.update(
    # Task serialization
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",

    # Timezone
    timezone="UTC",
    enable_utc=True,

    # Task routing with dedicated queues
    task_queues=(
        Queue("default", default_exchange, routing_key="default"),
        Queue("log_analysis", log_analysis_exchange, routing_key="log_analysis"),
        Queue("log_analysis_priority", log_analysis_exchange, routing_key="log_analysis_priority"),
        Queue("maintenance", maintenance_exchange, routing_key="maintenance"),
        Queue("retention", maintenance_exchange, routing_key="retention"),
    ),

    task_default_queue="default",
    task_default_exchange="default",
    task_default_routing_key="default",

    # Route tasks to appropriate queues
    task_routes={
        "tasks.log_analysis.analyze_log_task": {"queue": "log_analysis"},
        "tasks.log_analysis.analyze_log_batch_task": {"queue": "log_analysis"},
        "tasks.log_analysis.analyze_log_priority_task": {"queue": "log_analysis_priority"},
        "tasks.retention.cleanup_old_logs": {"queue": "retention"},
        "tasks.retention.archive_logs": {"queue": "retention"},
        "tasks.metrics.update_metrics_task": {"queue": "maintenance"},
        "tasks.metrics.sync_metrics_from_db": {"queue": "maintenance"},
    },

    # Task execution settings
    task_acks_late=True,  # Acknowledge after task completion (ensures no loss)
    task_reject_on_worker_lost=True,
    task_time_limit=300,  # 5 minute hard limit
    task_soft_time_limit=240,  # 4 minute soft limit (raises SoftTimeLimitExceeded)

    # Worker settings
    worker_prefetch_multiplier=1,  # One task at a time per worker for LLM tasks
    worker_concurrency=int(os.getenv("CELERY_CONCURRENCY", "4")),
    worker_max_tasks_per_child=100,  # Restart worker after 100 tasks (memory cleanup)

    # Result backend settings
    result_expires=3600,  # Results expire after 1 hour
    result_extended=True,

    # Broker settings
    broker_connection_retry_on_startup=True,
    broker_connection_retry=True,
    broker_connection_max_retries=10,

    # Rate limiting (optional, per-task override available)
    task_annotations={
        "tasks.log_analysis.analyze_log_task": {
            "rate_limit": os.getenv("LOG_ANALYSIS_RATE_LIMIT", "10/s"),
        },
    },

    # Beat schedule for periodic tasks
    beat_schedule={
        # Cleanup old logs based on retention policy
        "cleanup-old-logs-hourly": {
            "task": "tasks.retention.cleanup_old_logs",
            "schedule": crontab(minute=0),  # Every hour
            "options": {"queue": "retention"},
        },
        # Sync metrics from database
        "sync-metrics-every-minute": {
            "task": "tasks.metrics.sync_metrics_from_db",
            "schedule": 60.0,  # Every minute
            "options": {"queue": "maintenance"},
        },
        # Archive old logs (if enabled)
        "archive-logs-daily": {
            "task": "tasks.retention.archive_logs",
            "schedule": crontab(hour=2, minute=0),  # 2 AM daily
            "options": {"queue": "retention"},
        },
    },

    # Beat scheduler settings
    beat_scheduler="celery.beat:PersistentScheduler",
    beat_schedule_filename="/app/data/celerybeat-schedule" if os.path.exists("/app/data") else "celerybeat-schedule",
)


# Optional: Flower monitoring configuration
FLOWER_PORT = int(os.getenv("FLOWER_PORT", "5555"))
FLOWER_BASIC_AUTH = os.getenv("FLOWER_BASIC_AUTH", "")  # Format: user:password


def get_celery_app():
    """Get the Celery application instance."""
    return celery_app


if __name__ == "__main__":
    celery_app.start()
