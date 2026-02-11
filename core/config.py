# Configuration management for SOC Agent
# Centralizes environment variable loading and validation

import os
from typing import Optional
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Centralized configuration management."""

    # Database Configuration
    DATABASE_URL: Optional[str] = os.getenv("DATABASE_URL")
    DB_NAME: str = os.getenv("DB_NAME", "ai_agent_logs.db")

    # Database Pool Configuration
    DB_POOL_MIN: int = int(os.getenv("DB_POOL_MIN", "2"))
    DB_POOL_MAX: int = int(os.getenv("DB_POOL_MAX", "20"))
    DB_POOL_OVERFLOW: int = int(os.getenv("DB_POOL_OVERFLOW", "10"))
    DB_CONNECT_TIMEOUT: int = int(os.getenv("DB_CONNECT_TIMEOUT", "10"))
    DB_COMMAND_TIMEOUT: int = int(os.getenv("DB_COMMAND_TIMEOUT", "30"))
    DB_HEALTH_CHECK_INTERVAL: int = int(os.getenv("DB_HEALTH_CHECK_INTERVAL", "30"))

    # Redis Configuration
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    REDIS_MAX_CONNECTIONS: int = int(os.getenv("REDIS_MAX_CONNECTIONS", "20"))

    # Celery Configuration
    CELERY_BROKER_URL: str = os.getenv("CELERY_BROKER_URL", os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    CELERY_RESULT_BACKEND: str = os.getenv("CELERY_RESULT_BACKEND", os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    CELERY_TASK_QUEUE: str = os.getenv("CELERY_TASK_QUEUE", "log_analysis")
    CELERY_CONCURRENCY: int = int(os.getenv("CELERY_CONCURRENCY", "4"))

    # Retention Policy Configuration
    RETENTION_ENABLED: bool = os.getenv("RETENTION_ENABLED", "true").lower() == "true"
    RETENTION_CRITICAL_DAYS: int = int(os.getenv("RETENTION_CRITICAL_DAYS", "365"))
    RETENTION_HIGH_DAYS: int = int(os.getenv("RETENTION_HIGH_DAYS", "180"))
    RETENTION_MEDIUM_DAYS: int = int(os.getenv("RETENTION_MEDIUM_DAYS", "90"))
    RETENTION_LOW_DAYS: int = int(os.getenv("RETENTION_LOW_DAYS", "30"))
    RETENTION_INFO_DAYS: int = int(os.getenv("RETENTION_INFO_DAYS", "14"))
    RETENTION_ARCHIVE_ENABLED: bool = os.getenv("RETENTION_ARCHIVE_ENABLED", "false").lower() == "true"

    # Elasticsearch/OpenSearch Configuration
    ES_HOSTS: str = os.getenv("ES_HOSTS", "http://localhost:9200")
    ES_INDEX: str = os.getenv("ES_INDEX", "ai-analyzed-logs")

    # Ollama LLM Configuration
    OLLAMA_URL: str = os.getenv("OLLAMA_URL", "http://localhost:11434")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "mistral:7b")

    # Network Configuration
    LISTEN_PORT: int = int(os.getenv("LISTEN_PORT", "5046"))
    HOST_IP: str = os.getenv("HOST_IP", "0.0.0.0")
    API_PORT: int = int(os.getenv("API_PORT", "8000"))

    # Syslog Configuration
    SYSLOG_ENABLED: bool = os.getenv("SYSLOG_ENABLED", "true").lower() == "true"
    SYSLOG_UDP_PORT: int = int(os.getenv("SYSLOG_UDP_PORT", "514"))
    SYSLOG_TCP_PORT: int = int(os.getenv("SYSLOG_TCP_PORT", "1514"))
    SYSLOG_TCP_ENABLED: bool = os.getenv("SYSLOG_TCP_ENABLED", "false").lower() == "true"

    # Processing Configuration
    MAX_RETRIES: int = int(os.getenv("MAX_RETRIES", "3"))
    BATCH_SIZE: int = int(os.getenv("BATCH_SIZE", "5"))
    SLEEP_WHEN_EMPTY: int = int(os.getenv("SLEEP_WHEN_EMPTY", "3"))

    # Feature Flags
    CELERY_ENABLED: bool = os.getenv("CELERY_ENABLED", "true").lower() == "true"
    LEGACY_PROCESSOR_ENABLED: bool = os.getenv("LEGACY_PROCESSOR_ENABLED", "false").lower() == "true"

    @classmethod
    def get_db_type(cls) -> str:
        """Determine database type from configuration."""
        if cls.DATABASE_URL:
            return "postgresql"
        return "sqlite"

    @classmethod
    def get_db_config(cls) -> dict:
        """Parse DATABASE_URL into connection parameters."""
        if not cls.DATABASE_URL:
            return {"database": cls.DB_NAME}

        parsed = urlparse(cls.DATABASE_URL)
        return {
            "host": parsed.hostname,
            "port": parsed.port or 5432,
            "database": parsed.path.lstrip('/'),
            "user": parsed.username,
            "password": parsed.password
        }

    @classmethod
    def get_retention_days(cls, severity: str) -> int:
        """Get retention days for a given severity level."""
        severity_map = {
            "Critical": cls.RETENTION_CRITICAL_DAYS,
            "High": cls.RETENTION_HIGH_DAYS,
            "Medium": cls.RETENTION_MEDIUM_DAYS,
            "Low": cls.RETENTION_LOW_DAYS,
            "Info": cls.RETENTION_INFO_DAYS,
        }
        return severity_map.get(severity, cls.RETENTION_MEDIUM_DAYS)

    @classmethod
    def validate(cls) -> None:
        """Validate required configuration."""
        if not cls.ES_HOSTS:
            raise ValueError("ES_HOSTS is required")
        if not cls.OLLAMA_URL:
            raise ValueError("OLLAMA_URL is required")


# Singleton instance
config = Config()
