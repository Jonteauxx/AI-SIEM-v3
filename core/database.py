# Database connection management with improved pooling
# Supports both SQLite and PostgreSQL with configurable connection pools

import sqlite3
import threading
import time
import logging
from contextlib import contextmanager
from typing import Optional, Any, Dict

from .config import Config

logger = logging.getLogger(__name__)

# PostgreSQL support
try:
    import psycopg2
    import psycopg2.extras
    from psycopg2 import pool
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False


class DatabaseConnection:
    """Unified database connection wrapper for SQLite and PostgreSQL."""

    def __init__(self, conn, db_type: str):
        self.conn = conn
        self.db_type = db_type

    def cursor(self):
        if self.db_type == "postgresql":
            return self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        return self.conn.cursor()

    def commit(self):
        self.conn.commit()

    def rollback(self):
        self.conn.rollback()

    def close(self):
        self.conn.close()


class DatabaseManager:
    """Manages database connections with connection pooling."""

    _instance: Optional['DatabaseManager'] = None
    _lock = threading.Lock()

    def __init__(self):
        self.db_type = Config.get_db_type()
        self.db_config = Config.get_db_config()
        self._pool = None
        self._sqlite_lock = threading.Lock()
        self._health_check_thread: Optional[threading.Thread] = None
        self._running = threading.Event()
        self._last_health_check = 0
        self._pool_stats = {
            "connections_created": 0,
            "connections_reused": 0,
            "connections_failed": 0,
            "health_checks_passed": 0,
            "health_checks_failed": 0,
        }

        self._init_pool()

    def _init_pool(self):
        """Initialize the connection pool."""
        if self.db_type == "postgresql" and POSTGRES_AVAILABLE:
            try:
                self._pool = pool.ThreadedConnectionPool(
                    minconn=Config.DB_POOL_MIN,
                    maxconn=Config.DB_POOL_MAX,
                    host=self.db_config["host"],
                    port=self.db_config["port"],
                    database=self.db_config["database"],
                    user=self.db_config["user"],
                    password=self.db_config["password"],
                    connect_timeout=Config.DB_CONNECT_TIMEOUT,
                )
                logger.info(
                    f"PostgreSQL connection pool initialized: "
                    f"min={Config.DB_POOL_MIN}, max={Config.DB_POOL_MAX}"
                )
            except Exception as e:
                logger.error(f"Failed to create PostgreSQL pool: {e}")
                self._pool = None
                self._pool_stats["connections_failed"] += 1
        else:
            if self.db_type == "postgresql" and not POSTGRES_AVAILABLE:
                logger.warning("PostgreSQL requested but psycopg2 not available. Using SQLite.")
                self.db_type = "sqlite"
            logger.info(f"Using SQLite database: {self.db_config.get('database', Config.DB_NAME)}")

    @classmethod
    def get_instance(cls) -> 'DatabaseManager':
        """Get singleton instance of DatabaseManager."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @contextmanager
    def get_connection(self):
        """Get a database connection from the pool."""
        if self.db_type == "postgresql" and self._pool:
            conn = None
            try:
                conn = self._pool.getconn()
                self._pool_stats["connections_reused"] += 1
                yield DatabaseConnection(conn, "postgresql")
            except Exception as e:
                self._pool_stats["connections_failed"] += 1
                logger.error(f"PostgreSQL connection error: {e}")
                raise
            finally:
                if conn:
                    self._pool.putconn(conn)
        else:
            # SQLite with thread-safe access
            with self._sqlite_lock:
                conn = sqlite3.connect(
                    Config.DB_NAME,
                    timeout=Config.DB_CONNECT_TIMEOUT,
                    check_same_thread=False
                )
                conn.row_factory = sqlite3.Row
                try:
                    self._pool_stats["connections_created"] += 1
                    yield DatabaseConnection(conn, "sqlite")
                finally:
                    conn.close()

    def health_check(self) -> bool:
        """Perform a health check on the database connection."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                if self.db_type == "postgresql":
                    cursor.execute("SELECT 1")
                else:
                    cursor.execute("SELECT 1")
                result = cursor.fetchone()
                if result:
                    self._pool_stats["health_checks_passed"] += 1
                    self._last_health_check = time.time()
                    return True
        except Exception as e:
            self._pool_stats["health_checks_failed"] += 1
            logger.error(f"Database health check failed: {e}")
        return False

    def start_health_checks(self):
        """Start periodic health check thread."""
        if self._health_check_thread is not None:
            return

        self._running.set()

        def health_check_loop():
            while self._running.is_set():
                try:
                    self.health_check()
                except Exception as e:
                    logger.error(f"Health check error: {e}")
                time.sleep(Config.DB_HEALTH_CHECK_INTERVAL)

        self._health_check_thread = threading.Thread(
            target=health_check_loop,
            daemon=True,
            name="DB-HealthCheck"
        )
        self._health_check_thread.start()
        logger.info("Database health check thread started")

    def stop_health_checks(self):
        """Stop periodic health check thread."""
        self._running.clear()
        if self._health_check_thread:
            self._health_check_thread.join(timeout=5)
            self._health_check_thread = None
        logger.info("Database health check thread stopped")

    def get_pool_status(self) -> Dict[str, Any]:
        """Get current pool status and statistics."""
        status = {
            "db_type": self.db_type,
            "pool_active": self._pool is not None if self.db_type == "postgresql" else True,
            "last_health_check": self._last_health_check,
            "stats": self._pool_stats.copy(),
            "config": {
                "pool_min": Config.DB_POOL_MIN,
                "pool_max": Config.DB_POOL_MAX,
                "connect_timeout": Config.DB_CONNECT_TIMEOUT,
                "health_check_interval": Config.DB_HEALTH_CHECK_INTERVAL,
            }
        }

        if self.db_type == "postgresql" and self._pool:
            # Get pool-specific stats if available
            try:
                status["pool_size"] = {
                    "min": self._pool.minconn,
                    "max": self._pool.maxconn,
                }
            except Exception:
                pass

        return status

    def close(self):
        """Close all connections and clean up."""
        self.stop_health_checks()
        if self._pool:
            try:
                self._pool.closeall()
                logger.info("PostgreSQL connection pool closed")
            except Exception as e:
                logger.error(f"Error closing connection pool: {e}")

    # SQL helper methods for database-agnostic queries
    def sql_param(self, index: int = None) -> str:
        """Return the correct parameter placeholder."""
        if self.db_type == "postgresql":
            return "%s"
        return "?"

    def sql_now(self) -> str:
        """Return the correct NOW() function."""
        if self.db_type == "postgresql":
            return "NOW()"
        return "datetime('now')"

    def sql_autoincrement(self) -> str:
        """Return the correct auto-increment syntax."""
        if self.db_type == "postgresql":
            return "SERIAL PRIMARY KEY"
        return "INTEGER PRIMARY KEY AUTOINCREMENT"

    def sql_boolean(self, val: bool) -> str:
        """Return boolean for current database."""
        if self.db_type == "postgresql":
            return "TRUE" if val else "FALSE"
        return "1" if val else "0"


# Module-level convenience function
def get_db_manager() -> DatabaseManager:
    """Get the database manager singleton."""
    return DatabaseManager.get_instance()


# Context manager for backward compatibility
@contextmanager
def get_db():
    """Backward-compatible context manager for database connections."""
    manager = get_db_manager()
    with manager.get_connection() as conn:
        yield conn
