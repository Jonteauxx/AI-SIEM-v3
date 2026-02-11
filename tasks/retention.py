# Log retention Celery tasks
# Handles cleanup of old logs based on retention policies

import logging
import datetime
from typing import Dict, Any

from celery import shared_task

from core.config import Config
from core.database import get_db
from core.shared_state import get_shared_state

logger = logging.getLogger(__name__)


def get_cutoff_date(days: int) -> str:
    """Calculate cutoff date for retention."""
    cutoff = datetime.datetime.now() - datetime.timedelta(days=days)
    return cutoff.isoformat()


@shared_task(bind=True, max_retries=1)
def cleanup_old_logs(self):
    """
    Celery task to clean up old logs based on retention policy.

    Runs hourly via Celery Beat. Uses distributed locking to prevent
    concurrent execution across multiple workers.
    """
    if not Config.RETENTION_ENABLED:
        logger.info("Retention cleanup disabled")
        return {"status": "disabled"}

    shared_state = get_shared_state()

    # Try to acquire distributed lock
    with shared_state.distributed_lock("retention_cleanup", timeout=3600, blocking=False) as acquired:
        if not acquired:
            logger.info("Retention cleanup already running on another worker")
            return {"status": "skipped", "reason": "lock_not_acquired"}

        logger.info("Starting retention cleanup...")
        cleanup_stats = {
            "total_deleted": 0,
            "total_archived": 0,
            "by_severity": {},
            "errors": [],
        }

        # Define retention periods by severity
        retention_policies = [
            ("Critical", Config.RETENTION_CRITICAL_DAYS),
            ("High", Config.RETENTION_HIGH_DAYS),
            ("Medium", Config.RETENTION_MEDIUM_DAYS),
            ("Low", Config.RETENTION_LOW_DAYS),
            ("Info", Config.RETENTION_INFO_DAYS),
        ]

        try:
            with get_db() as conn:
                cursor = conn.cursor()
                param = "%s" if conn.db_type == "postgresql" else "?"

                for severity, days in retention_policies:
                    if days <= 0:
                        continue

                    cutoff_date = get_cutoff_date(days)

                    # Count logs to be deleted
                    cursor.execute(f"""
                        SELECT COUNT(*) FROM raw_logs
                        WHERE severity = {param}
                        AND created_at < {param}
                        AND status = 'PROCESSED'
                    """, (severity, cutoff_date))

                    count = cursor.fetchone()[0]

                    if count > 0:
                        # Archive if enabled
                        if Config.RETENTION_ARCHIVE_ENABLED:
                            try:
                                cursor.execute(f"""
                                    INSERT INTO raw_logs_archive
                                    (id, timestamp, raw_log, status, severity, event_type, ai_summary, archived_at)
                                    SELECT id, timestamp, raw_log, status, severity, event_type, ai_summary,
                                           {'NOW()' if conn.db_type == 'postgresql' else 'CURRENT_TIMESTAMP'}
                                    FROM raw_logs
                                    WHERE severity = {param}
                                    AND created_at < {param}
                                    AND status = 'PROCESSED'
                                """, (severity, cutoff_date))
                                cleanup_stats["total_archived"] += count
                            except Exception as e:
                                logger.error(f"Archive failed for {severity}: {e}")
                                cleanup_stats["errors"].append(f"Archive {severity}: {str(e)}")

                        # Delete old logs
                        cursor.execute(f"""
                            DELETE FROM raw_logs
                            WHERE severity = {param}
                            AND created_at < {param}
                            AND status = 'PROCESSED'
                        """, (severity, cutoff_date))

                        cleanup_stats["total_deleted"] += count
                        cleanup_stats["by_severity"][severity] = {
                            "deleted": count,
                            "retention_days": days,
                            "cutoff_date": cutoff_date,
                        }

                        logger.info(f"Deleted {count} {severity} logs older than {days} days")

                conn.commit()

                # Record audit log
                try:
                    cursor.execute(f"""
                        INSERT INTO audit_log (action, entity_type, details, created_at)
                        VALUES ({param}, {param}, {param}, {'NOW()' if conn.db_type == 'postgresql' else 'CURRENT_TIMESTAMP'})
                    """, (
                        'retention_cleanup',
                        'raw_logs',
                        f"Deleted {cleanup_stats['total_deleted']} logs, archived {cleanup_stats['total_archived']}"
                    ))
                    conn.commit()
                except Exception as e:
                    # Audit log table might not exist
                    logger.debug(f"Audit log not recorded: {e}")

        except Exception as e:
            logger.error(f"Retention cleanup error: {e}")
            cleanup_stats["errors"].append(str(e))
            raise self.retry(exc=e, countdown=300)

        logger.info(f"Retention cleanup completed: {cleanup_stats['total_deleted']} logs deleted")
        return cleanup_stats


@shared_task(bind=True)
def archive_logs(self):
    """
    Celery task to archive old logs before deletion.

    Runs daily via Celery Beat. Archives logs that will be deleted
    by the retention policy within the next day.
    """
    if not Config.RETENTION_ENABLED or not Config.RETENTION_ARCHIVE_ENABLED:
        logger.info("Log archiving disabled")
        return {"status": "disabled"}

    shared_state = get_shared_state()

    with shared_state.distributed_lock("log_archive", timeout=7200, blocking=False) as acquired:
        if not acquired:
            logger.info("Log archiving already running on another worker")
            return {"status": "skipped", "reason": "lock_not_acquired"}

        logger.info("Starting log archiving...")
        archive_stats = {
            "total_archived": 0,
            "by_severity": {},
        }

        try:
            with get_db() as conn:
                cursor = conn.cursor()
                param = "%s" if conn.db_type == "postgresql" else "?"

                # Ensure archive table exists
                if conn.db_type == "postgresql":
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS raw_logs_archive (
                            id INTEGER PRIMARY KEY,
                            timestamp TEXT,
                            raw_log TEXT,
                            status TEXT,
                            severity TEXT,
                            event_type TEXT,
                            ai_summary TEXT,
                            archived_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """)
                else:
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS raw_logs_archive (
                            id INTEGER PRIMARY KEY,
                            timestamp TEXT,
                            raw_log TEXT,
                            status TEXT,
                            severity TEXT,
                            event_type TEXT,
                            ai_summary TEXT,
                            archived_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """)
                conn.commit()

                # Archive logs that will be deleted in the next cleanup
                retention_policies = [
                    ("Critical", Config.RETENTION_CRITICAL_DAYS),
                    ("High", Config.RETENTION_HIGH_DAYS),
                    ("Medium", Config.RETENTION_MEDIUM_DAYS),
                    ("Low", Config.RETENTION_LOW_DAYS),
                    ("Info", Config.RETENTION_INFO_DAYS),
                ]

                for severity, days in retention_policies:
                    if days <= 0:
                        continue

                    # Archive logs that will be deleted in the next day
                    cutoff_date = get_cutoff_date(days - 1)

                    cursor.execute(f"""
                        INSERT INTO raw_logs_archive
                        (id, timestamp, raw_log, status, severity, event_type, ai_summary, archived_at)
                        SELECT id, timestamp, raw_log, status, severity, event_type, ai_summary,
                               {'NOW()' if conn.db_type == 'postgresql' else 'CURRENT_TIMESTAMP'}
                        FROM raw_logs
                        WHERE severity = {param}
                        AND created_at < {param}
                        AND status = 'PROCESSED'
                        AND id NOT IN (SELECT id FROM raw_logs_archive)
                    """, (severity, cutoff_date))

                    archived = cursor.rowcount
                    if archived > 0:
                        archive_stats["total_archived"] += archived
                        archive_stats["by_severity"][severity] = archived
                        logger.info(f"Archived {archived} {severity} logs")

                conn.commit()

        except Exception as e:
            logger.error(f"Log archiving error: {e}")
            raise

        logger.info(f"Log archiving completed: {archive_stats['total_archived']} logs archived")
        return archive_stats


@shared_task
def get_retention_status() -> Dict[str, Any]:
    """
    Get current retention policy status and statistics.
    """
    status = {
        "enabled": Config.RETENTION_ENABLED,
        "archive_enabled": Config.RETENTION_ARCHIVE_ENABLED,
        "policies": {
            "Critical": {"days": Config.RETENTION_CRITICAL_DAYS},
            "High": {"days": Config.RETENTION_HIGH_DAYS},
            "Medium": {"days": Config.RETENTION_MEDIUM_DAYS},
            "Low": {"days": Config.RETENTION_LOW_DAYS},
            "Info": {"days": Config.RETENTION_INFO_DAYS},
        },
        "counts": {},
    }

    try:
        with get_db() as conn:
            cursor = conn.cursor()

            # Get counts by severity
            cursor.execute("""
                SELECT severity, COUNT(*) as count
                FROM raw_logs
                WHERE status = 'PROCESSED'
                GROUP BY severity
            """)

            for row in cursor.fetchall():
                severity = row[0] if isinstance(row, tuple) else row['severity']
                count = row[1] if isinstance(row, tuple) else row['count']
                if severity:
                    status["counts"][severity] = count

            # Get archive count if table exists
            try:
                cursor.execute("SELECT COUNT(*) FROM raw_logs_archive")
                status["archived_count"] = cursor.fetchone()[0]
            except Exception:
                status["archived_count"] = 0

    except Exception as e:
        logger.error(f"Error getting retention status: {e}")
        status["error"] = str(e)

    return status
