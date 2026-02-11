# Redis-backed shared state for distributed metrics and coordination
# Provides thread-safe access to global counters and distributed locking

import json
import time
import logging
import threading
from typing import Optional, Dict, Any
from contextlib import contextmanager

from .config import Config

logger = logging.getLogger(__name__)

# Redis support
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


class SharedState:
    """Redis-backed shared state for distributed metrics and coordination."""

    _instance: Optional['SharedState'] = None
    _lock = threading.Lock()

    # Redis key prefixes
    PREFIX = "soc_agent:"
    METRICS_KEY = f"{PREFIX}metrics"
    LOCK_PREFIX = f"{PREFIX}lock:"
    WORKER_PREFIX = f"{PREFIX}worker:"
    QUEUE_STATS_KEY = f"{PREFIX}queue_stats"

    def __init__(self):
        self._redis: Optional[redis.Redis] = None
        self._local_metrics = {
            "total_logs": 0,
            "pending_logs": 0,
            "processed_logs": 0,
            "info_logs": 0,
            "error_logs": 0,
        }
        self._local_lock = threading.Lock()
        self._redis_available = False
        self._init_redis()

    def _init_redis(self):
        """Initialize Redis connection."""
        if not REDIS_AVAILABLE:
            logger.warning("Redis not available. Using local-only metrics.")
            return

        try:
            self._redis = redis.Redis.from_url(
                Config.REDIS_URL,
                max_connections=Config.REDIS_MAX_CONNECTIONS,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
            )
            # Test connection
            self._redis.ping()
            self._redis_available = True
            logger.info(f"Redis connected: {Config.REDIS_URL}")
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}. Using local-only metrics.")
            self._redis = None
            self._redis_available = False

    @classmethod
    def get_instance(cls) -> 'SharedState':
        """Get singleton instance of SharedState."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def is_redis_available(self) -> bool:
        """Check if Redis is available."""
        return self._redis_available

    # Metrics operations
    def set_metric(self, name: str, value: int) -> None:
        """Set a metric value."""
        with self._local_lock:
            self._local_metrics[name] = value

        if self._redis_available:
            try:
                self._redis.hset(self.METRICS_KEY, name, value)
            except Exception as e:
                logger.debug(f"Redis metric set failed: {e}")

    def get_metric(self, name: str) -> int:
        """Get a metric value."""
        if self._redis_available:
            try:
                value = self._redis.hget(self.METRICS_KEY, name)
                if value is not None:
                    return int(value)
            except Exception as e:
                logger.debug(f"Redis metric get failed: {e}")

        with self._local_lock:
            return self._local_metrics.get(name, 0)

    def increment_metric(self, name: str, amount: int = 1) -> int:
        """Increment a metric atomically."""
        with self._local_lock:
            self._local_metrics[name] = self._local_metrics.get(name, 0) + amount
            local_value = self._local_metrics[name]

        if self._redis_available:
            try:
                return self._redis.hincrby(self.METRICS_KEY, name, amount)
            except Exception as e:
                logger.debug(f"Redis metric increment failed: {e}")

        return local_value

    def decrement_metric(self, name: str, amount: int = 1) -> int:
        """Decrement a metric atomically."""
        return self.increment_metric(name, -amount)

    def get_all_metrics(self) -> Dict[str, int]:
        """Get all metrics."""
        if self._redis_available:
            try:
                metrics = self._redis.hgetall(self.METRICS_KEY)
                return {k: int(v) for k, v in metrics.items()}
            except Exception as e:
                logger.debug(f"Redis metrics get failed: {e}")

        with self._local_lock:
            return self._local_metrics.copy()

    def sync_metrics_from_db(self, total: int, pending: int, processed: int,
                             info: int = 0, error: int = 0) -> None:
        """Sync metrics from database counts."""
        metrics = {
            "total_logs": total,
            "pending_logs": pending,
            "processed_logs": processed,
            "info_logs": info,
            "error_logs": error,
        }

        with self._local_lock:
            self._local_metrics.update(metrics)

        if self._redis_available:
            try:
                self._redis.hset(self.METRICS_KEY, mapping=metrics)
            except Exception as e:
                logger.debug(f"Redis metrics sync failed: {e}")

    # Distributed locking
    @contextmanager
    def distributed_lock(self, name: str, timeout: int = 60, blocking: bool = True):
        """Acquire a distributed lock using Redis."""
        lock_key = f"{self.LOCK_PREFIX}{name}"
        lock_value = f"{threading.current_thread().name}:{time.time()}"
        acquired = False

        if self._redis_available:
            try:
                lock = self._redis.lock(lock_key, timeout=timeout)
                acquired = lock.acquire(blocking=blocking)
                if acquired:
                    try:
                        yield True
                    finally:
                        try:
                            lock.release()
                        except Exception:
                            pass
                else:
                    yield False
                return
            except Exception as e:
                logger.debug(f"Redis lock failed: {e}")

        # Fallback to local lock (no distributed coordination)
        yield True

    # Worker registration and heartbeat
    def register_worker(self, worker_id: str, worker_type: str) -> None:
        """Register a worker with heartbeat."""
        if not self._redis_available:
            return

        try:
            worker_key = f"{self.WORKER_PREFIX}{worker_id}"
            worker_data = {
                "id": worker_id,
                "type": worker_type,
                "registered_at": time.time(),
                "last_heartbeat": time.time(),
                "status": "active",
            }
            self._redis.hset(worker_key, mapping={
                k: json.dumps(v) if isinstance(v, (dict, list)) else str(v)
                for k, v in worker_data.items()
            })
            self._redis.expire(worker_key, 300)  # 5 minute TTL
        except Exception as e:
            logger.debug(f"Worker registration failed: {e}")

    def worker_heartbeat(self, worker_id: str) -> None:
        """Update worker heartbeat."""
        if not self._redis_available:
            return

        try:
            worker_key = f"{self.WORKER_PREFIX}{worker_id}"
            self._redis.hset(worker_key, "last_heartbeat", str(time.time()))
            self._redis.expire(worker_key, 300)
        except Exception as e:
            logger.debug(f"Worker heartbeat failed: {e}")

    def get_active_workers(self) -> list:
        """Get list of active workers."""
        workers = []
        if not self._redis_available:
            return workers

        try:
            pattern = f"{self.WORKER_PREFIX}*"
            for key in self._redis.scan_iter(pattern):
                worker_data = self._redis.hgetall(key)
                if worker_data:
                    workers.append({
                        k: v for k, v in worker_data.items()
                    })
        except Exception as e:
            logger.debug(f"Get workers failed: {e}")

        return workers

    # Queue statistics
    def update_queue_stats(self, queue_name: str, pending: int, processing: int = 0) -> None:
        """Update queue statistics."""
        if not self._redis_available:
            return

        try:
            stats = {
                f"{queue_name}:pending": pending,
                f"{queue_name}:processing": processing,
                f"{queue_name}:updated_at": time.time(),
            }
            self._redis.hset(self.QUEUE_STATS_KEY, mapping={
                k: str(v) for k, v in stats.items()
            })
        except Exception as e:
            logger.debug(f"Queue stats update failed: {e}")

    def get_queue_stats(self) -> Dict[str, Any]:
        """Get all queue statistics."""
        if not self._redis_available:
            return {}

        try:
            stats = self._redis.hgetall(self.QUEUE_STATS_KEY)
            return {k: v for k, v in stats.items()}
        except Exception as e:
            logger.debug(f"Get queue stats failed: {e}")
            return {}

    def close(self):
        """Close Redis connection."""
        if self._redis:
            try:
                self._redis.close()
            except Exception:
                pass


# Module-level convenience function
def get_shared_state() -> SharedState:
    """Get the shared state singleton."""
    return SharedState.get_instance()
