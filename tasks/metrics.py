# Metrics aggregation Celery tasks
# Handles metrics syncing and aggregation for distributed workers

import logging
from typing import Dict, Any

from celery import shared_task

from core.database import get_db
from core.shared_state import get_shared_state

logger = logging.getLogger(__name__)


@shared_task
def update_metrics_task(metric_name: str, value: int) -> Dict[str, Any]:
    """
    Update a specific metric value.

    Args:
        metric_name: Name of the metric to update
        value: New value for the metric
    """
    shared_state = get_shared_state()
    shared_state.set_metric(metric_name, value)

    return {
        "metric": metric_name,
        "value": value,
        "status": "updated"
    }


@shared_task
def increment_metric_task(metric_name: str, amount: int = 1) -> Dict[str, Any]:
    """
    Increment a metric atomically.

    Args:
        metric_name: Name of the metric to increment
        amount: Amount to increment by (default: 1)
    """
    shared_state = get_shared_state()
    new_value = shared_state.increment_metric(metric_name, amount)

    return {
        "metric": metric_name,
        "new_value": new_value,
        "status": "incremented"
    }


@shared_task
def sync_metrics_from_db() -> Dict[str, Any]:
    """
    Sync metrics from database to Redis.

    This task runs periodically to ensure Redis metrics stay in sync
    with the actual database state. Useful for recovery after Redis
    restarts or for ensuring consistency.
    """
    shared_state = get_shared_state()

    try:
        with get_db() as conn:
            cursor = conn.cursor()

            # Get total logs count
            cursor.execute("SELECT COUNT(*) FROM raw_logs")
            total = cursor.fetchone()[0]

            # Get pending logs count
            cursor.execute("SELECT COUNT(*) FROM raw_logs WHERE status='PENDING'")
            pending = cursor.fetchone()[0]

            # Get processed logs count
            cursor.execute("SELECT COUNT(*) FROM raw_logs WHERE status='PROCESSED'")
            processed = cursor.fetchone()[0]

            # Get info logs count
            cursor.execute("SELECT COUNT(*) FROM raw_logs WHERE status='INFO'")
            info = cursor.fetchone()[0]

            # Get error logs count
            cursor.execute("SELECT COUNT(*) FROM raw_logs WHERE status='ERROR'")
            error = cursor.fetchone()[0]

            # Sync to Redis
            shared_state.sync_metrics_from_db(
                total=total,
                pending=pending,
                processed=processed,
                info=info,
                error=error
            )

            metrics = {
                "total_logs": total,
                "pending_logs": pending,
                "processed_logs": processed,
                "info_logs": info,
                "error_logs": error,
            }

            logger.debug(f"Metrics synced from DB: {metrics}")

            return {
                "status": "synced",
                "metrics": metrics
            }

    except Exception as e:
        logger.error(f"Failed to sync metrics from DB: {e}")
        return {
            "status": "error",
            "error": str(e)
        }


@shared_task
def get_all_metrics() -> Dict[str, Any]:
    """
    Get all current metrics from Redis.
    """
    shared_state = get_shared_state()
    return shared_state.get_all_metrics()


@shared_task
def get_worker_stats() -> Dict[str, Any]:
    """
    Get statistics about active Celery workers.
    """
    shared_state = get_shared_state()

    stats = {
        "workers": shared_state.get_active_workers(),
        "queue_stats": shared_state.get_queue_stats(),
        "redis_available": shared_state.is_redis_available(),
    }

    return stats


@shared_task
def get_processing_stats() -> Dict[str, Any]:
    """
    Get detailed processing statistics from the database.
    """
    stats = {
        "by_status": {},
        "by_severity": {},
        "by_analyzer": {},
        "processing_times": {},
    }

    try:
        with get_db() as conn:
            cursor = conn.cursor()

            # Counts by status
            cursor.execute("""
                SELECT status, COUNT(*) as count
                FROM raw_logs
                GROUP BY status
            """)
            for row in cursor.fetchall():
                status = row[0] if isinstance(row, tuple) else row['status']
                count = row[1] if isinstance(row, tuple) else row['count']
                stats["by_status"][status or "null"] = count

            # Counts by severity
            cursor.execute("""
                SELECT severity, COUNT(*) as count
                FROM raw_logs
                WHERE status = 'PROCESSED'
                GROUP BY severity
            """)
            for row in cursor.fetchall():
                severity = row[0] if isinstance(row, tuple) else row['severity']
                count = row[1] if isinstance(row, tuple) else row['count']
                stats["by_severity"][severity or "null"] = count

            # Counts by analyzer type
            cursor.execute("""
                SELECT analyzed_by, COUNT(*) as count
                FROM raw_logs
                WHERE status = 'PROCESSED'
                GROUP BY analyzed_by
            """)
            for row in cursor.fetchall():
                analyzer = row[0] if isinstance(row, tuple) else row['analyzed_by']
                count = row[1] if isinstance(row, tuple) else row['count']
                stats["by_analyzer"][analyzer or "null"] = count

            # Average processing times by analyzer (if column exists)
            try:
                cursor.execute("""
                    SELECT analyzed_by, AVG(processing_time_ms) as avg_time
                    FROM raw_logs
                    WHERE status = 'PROCESSED' AND processing_time_ms IS NOT NULL
                    GROUP BY analyzed_by
                """)
                for row in cursor.fetchall():
                    analyzer = row[0] if isinstance(row, tuple) else row['analyzed_by']
                    avg_time = row[1] if isinstance(row, tuple) else row['avg_time']
                    if avg_time:
                        stats["processing_times"][analyzer or "null"] = round(float(avg_time), 2)
            except Exception:
                # Column might not exist
                pass

    except Exception as e:
        logger.error(f"Failed to get processing stats: {e}")
        stats["error"] = str(e)

    return stats
