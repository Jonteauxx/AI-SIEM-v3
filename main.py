import os
import json
import sqlite3
import socket
import threading
import msgpack
import datetime
import io
import uvicorn
import re
import hashlib
import time
import signal
import sys
import logging
import psutil
import asyncio
from logging.handlers import RotatingFileHandler
from contextlib import contextmanager
from typing import Optional, Dict, Any, List
from dotenv import load_dotenv
from urllib.parse import urlparse

# PostgreSQL support
try:
    import psycopg2
    import psycopg2.extras
    from psycopg2 import pool
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False
from ollama import Client
from elasticsearch import Elasticsearch
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import timedelta
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Depends, status

# ==============================================================================
# 1. Logging Configuration with Rotation
# ==============================================================================
LOG_FILE = os.getenv("LOG_FILE", "soc_agent.log")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_MAX_BYTES = int(os.getenv("LOG_MAX_BYTES", "10485760"))  # 10MB default
LOG_BACKUP_COUNT = int(os.getenv("LOG_BACKUP_COUNT", "5"))

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler(
            LOG_FILE,
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUP_COUNT
        ),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ==============================================================================
# 2. Configuration & Setup
# ==============================================================================
load_dotenv()

ES_HOSTS = os.getenv("ES_HOSTS", 'http://localhost:9200')
ES_INDEX = os.getenv("ES_INDEX", 'ai-analyzed-logs')
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mistral:7b")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "5046"))
HOST_IP = os.getenv("HOST_IP", '0.0.0.0')
API_PORT = int(os.getenv("API_PORT", "8000"))

# Syslog Configuration (for UniFi and other syslog sources)
SYSLOG_ENABLED = os.getenv("SYSLOG_ENABLED", "true").lower() == "true"
SYSLOG_UDP_PORT = int(os.getenv("SYSLOG_UDP_PORT", "514"))
SYSLOG_TCP_PORT = int(os.getenv("SYSLOG_TCP_PORT", "1514"))
SYSLOG_TCP_ENABLED = os.getenv("SYSLOG_TCP_ENABLED", "false").lower() == "true"
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))

# Database Configuration - PostgreSQL or SQLite
DATABASE_URL = os.getenv("DATABASE_URL")  # PostgreSQL connection string
DB_NAME = os.getenv("DB_NAME", 'ai_agent_logs.db')  # SQLite fallback

# Determine database type
if DATABASE_URL and POSTGRES_AVAILABLE:
    DB_TYPE = "postgresql"
    # Parse DATABASE_URL for connection pool
    parsed = urlparse(DATABASE_URL)
    DB_CONFIG = {
        "host": parsed.hostname,
        "port": parsed.port or 5432,
        "database": parsed.path.lstrip('/'),
        "user": parsed.username,
        "password": parsed.password
    }
    # Create connection pool
    DB_POOL = pool.ThreadedConnectionPool(
        minconn=2,
        maxconn=20,
        **DB_CONFIG
    )
    logger.info(f"Using PostgreSQL database: {DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}")
elif DATABASE_URL and not POSTGRES_AVAILABLE:
    logger.warning("DATABASE_URL provided but psycopg2 not installed. Falling back to SQLite.")
    DB_TYPE = "sqlite"
    DB_POOL = None
else:
    DB_TYPE = "sqlite"
    DB_POOL = None
    logger.info(f"Using SQLite database: {DB_NAME}")

# Authentication Configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not JWT_SECRET_KEY or JWT_SECRET_KEY == "CHANGE-THIS-SECRET-KEY-IN-PRODUCTION-MIN-32-CHARS":
    raise ValueError("CRITICAL: JWT_SECRET_KEY environment variable must be set with a secure random key. "
                     "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(32))\"")
if len(JWT_SECRET_KEY) < 32:
    raise ValueError("CRITICAL: JWT_SECRET_KEY must be at least 32 characters long")

JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
JWT_REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", "7"))
API_KEY_HEADER = os.getenv("API_KEY_HEADER", "X-API-Key")

# CORS Configuration
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "").split(",") if os.getenv("CORS_ORIGINS") else []
CORS_ALLOW_ALL = os.getenv("CORS_ALLOW_ALL", "false").lower() == "true"

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Password Policy Configuration
PASSWORD_MIN_LENGTH = int(os.getenv("PASSWORD_MIN_LENGTH", "12"))
PASSWORD_REQUIRE_UPPERCASE = os.getenv("PASSWORD_REQUIRE_UPPERCASE", "true").lower() == "true"
PASSWORD_REQUIRE_LOWERCASE = os.getenv("PASSWORD_REQUIRE_LOWERCASE", "true").lower() == "true"
PASSWORD_REQUIRE_DIGIT = os.getenv("PASSWORD_REQUIRE_DIGIT", "true").lower() == "true"
PASSWORD_REQUIRE_SPECIAL = os.getenv("PASSWORD_REQUIRE_SPECIAL", "true").lower() == "true"
PASSWORD_EXPIRY_DAYS = int(os.getenv("PASSWORD_EXPIRY_DAYS", "90"))

# Account Lockout Configuration
ACCOUNT_LOCKOUT_THRESHOLD = int(os.getenv("ACCOUNT_LOCKOUT_THRESHOLD", "5"))
ACCOUNT_LOCKOUT_DURATION_MINUTES = int(os.getenv("ACCOUNT_LOCKOUT_DURATION_MINUTES", "30"))

# Session Management Configuration
MAX_CONCURRENT_SESSIONS = int(os.getenv("MAX_CONCURRENT_SESSIONS", "5"))
SESSION_INACTIVITY_TIMEOUT_MINUTES = int(os.getenv("SESSION_INACTIVITY_TIMEOUT_MINUTES", "60"))

INGESTOR_RUNNING = threading.Event()
INGESTOR_RUNNING.set()

TOTAL_LOGS_COUNT = 0
PENDING_LOGS_COUNT = 0
PROCESSED_LOGS_COUNT = 0
PROCESSOR_ACTIVE = False
metrics_lock = threading.Lock()

def set_processor_active(active):
    """Helper function to set PROCESSOR_ACTIVE global variable"""
    global PROCESSOR_ACTIVE
    PROCESSOR_ACTIVE = active

# ==============================================================================
# 3. FastAPI App Configuration
# ==============================================================================
app = FastAPI(
    title="AXS ICT Hybrid SOC Agent",
    description="AI-Powered Security Log Analysis Platform",
    version="2.0.0"
)

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS Middleware - Restrict in production!
if CORS_ALLOW_ALL:
    logger.warning("SECURITY WARNING: CORS is set to allow all origins. This should only be used in development!")
    cors_origins = ["*"]
elif CORS_ORIGINS:
    cors_origins = [origin.strip() for origin in CORS_ORIGINS if origin.strip()]
    logger.info(f"CORS restricted to origins: {cors_origins}")
else:
    cors_origins = ["http://localhost:8080", "http://127.0.0.1:8080"]
    logger.info("CORS using default localhost origins")

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)

# ==============================================================================
# 3.5. Security Headers Middleware
# ==============================================================================
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://unpkg.com; "
        "img-src 'self' data: https: https://*.tile.openstreetmap.org; "
        "font-src 'self' data:; "
        "connect-src 'self'"
    )
    return response

# ==============================================================================
# 4. Configuration Validation
# ==============================================================================
def validate_config():
    required_vars = {
        "ES_HOSTS": ES_HOSTS,
        "OLLAMA_URL": OLLAMA_URL,
        "OLLAMA_MODEL": OLLAMA_MODEL,
    }

    for var, value in required_vars.items():
        if not value:
            raise ValueError(f"Missing required configuration: {var}")

    logger.info("Configuration validated successfully")

# ==============================================================================
# 5. Database Management
# ==============================================================================

class DatabaseConnection:
    """Unified database connection wrapper for SQLite and PostgreSQL"""
    def __init__(self, conn, db_type):
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

@contextmanager
def get_db():
    """Get database connection - PostgreSQL or SQLite"""
    if DB_TYPE == "postgresql" and DB_POOL:
        conn = DB_POOL.getconn()
        try:
            yield DatabaseConnection(conn, "postgresql")
        finally:
            DB_POOL.putconn(conn)
    else:
        conn = sqlite3.connect(DB_NAME, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield DatabaseConnection(conn, "sqlite")
        finally:
            conn.close()

def sql_param(index: int = None) -> str:
    """Return the correct parameter placeholder for the current database type"""
    if DB_TYPE == "postgresql":
        return "%s"
    return "?"

def sql_now() -> str:
    """Return the correct NOW() function for the current database type"""
    if DB_TYPE == "postgresql":
        return "NOW()"
    return "datetime('now')"

def sql_autoincrement() -> str:
    """Return the correct auto-increment syntax"""
    if DB_TYPE == "postgresql":
        return "SERIAL PRIMARY KEY"
    return "INTEGER PRIMARY KEY AUTOINCREMENT"

def sql_insert_ignore() -> str:
    """Return the correct INSERT OR IGNORE syntax"""
    if DB_TYPE == "postgresql":
        return "INSERT INTO"  # Will use ON CONFLICT separately
    return "INSERT OR IGNORE INTO"

def sql_on_conflict_ignore() -> str:
    """Return ON CONFLICT clause for PostgreSQL"""
    if DB_TYPE == "postgresql":
        return "ON CONFLICT DO NOTHING"
    return ""

def sql_boolean(val: bool) -> str:
    """Return boolean for current database"""
    if DB_TYPE == "postgresql":
        return "TRUE" if val else "FALSE"
    return "1" if val else "0"

def table_exists(cursor, table_name: str) -> bool:
    """Check if a table exists in the database"""
    if DB_TYPE == "postgresql":
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_schema = 'public' AND table_name = %s
            )
        """, (table_name,))
        return cursor.fetchone()[0]
    else:
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
        return cursor.fetchone() is not None

def column_exists(cursor, table_name: str, column_name: str) -> bool:
    """Check if a column exists in a table"""
    if DB_TYPE == "postgresql":
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.columns
                WHERE table_name = %s AND column_name = %s
            )
        """, (table_name, column_name))
        return cursor.fetchone()[0]
    else:
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = [col[1] for col in cursor.fetchall()]
        return column_name in columns

def add_column_if_not_exists(cursor, table_name: str, column_name: str, column_type: str, default: str = None):
    """Add a column to a table if it doesn't exist"""
    if not column_exists(cursor, table_name, column_name):
        if DB_TYPE == "postgresql":
            default_clause = f" DEFAULT {default}" if default else ""
            cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}{default_clause}")
        else:
            # SQLite doesn't allow non-constant defaults in ALTER TABLE ADD COLUMN
            # For CURRENT_TIMESTAMP or similar, add without default then update
            if default and default.upper() in ('CURRENT_TIMESTAMP', 'NOW()'):
                cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")
                cursor.execute(f"UPDATE {table_name} SET {column_name} = CURRENT_TIMESTAMP WHERE {column_name} IS NULL")
            else:
                default_clause = f" DEFAULT {default}" if default else ""
                cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}{default_clause}")

def init_db():
    with get_db() as conn:
        cursor = conn.cursor()

        # Use database-specific syntax
        if DB_TYPE == "postgresql":
            auto_id = "SERIAL PRIMARY KEY"
            param = "%s"
            bool_true = "TRUE"
            bool_false = "FALSE"
        else:
            auto_id = "INTEGER PRIMARY KEY AUTOINCREMENT"
            param = "?"
            bool_true = "1"
            bool_false = "0"

        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS raw_logs (
                id {auto_id},
                timestamp TEXT NOT NULL,
                raw_log TEXT NOT NULL,
                status TEXT DEFAULT 'PENDING',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                processed_at TIMESTAMP,
                severity TEXT,
                event_type TEXT,
                ai_summary TEXT,
                analyzed_by TEXT,
                host TEXT
            )
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_status ON raw_logs(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON raw_logs(timestamp)")

        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS ai_knowledge (
                pattern_hash TEXT PRIMARY KEY,
                corrected_severity TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Severity Adjustments - Track all severity changes with conditions
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS severity_adjustments (
                id {auto_id},
                log_id INTEGER,
                pattern_hash TEXT,
                original_severity TEXT NOT NULL,
                new_severity TEXT NOT NULL,
                reason TEXT NOT NULL,
                adjusted_by TEXT DEFAULT 'user',
                host_filter TEXT,
                ip_filter TEXT,
                expires_at TEXT,
                exclude_hosts TEXT,
                is_active BOOLEAN DEFAULT 1,
                times_applied INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (log_id) REFERENCES raw_logs(id)
            )
        """)

        # Extended AI Knowledge with conditions
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ai_knowledge_conditions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_hash TEXT NOT NULL,
                original_severity TEXT,
                corrected_severity TEXT NOT NULL,
                reason TEXT NOT NULL,
                host_filter TEXT,
                ip_filter TEXT,
                expires_at TEXT,
                exclude_hosts TEXT,
                is_active BOOLEAN DEFAULT 1,
                times_applied INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(pattern_hash, host_filter, ip_filter)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS processing_errors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_id INTEGER,
                error_message TEXT,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (log_id) REFERENCES raw_logs(id)
            )
        """)

        # NEW: Alert Enrichment Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alert_enrichment (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_id INTEGER UNIQUE,
                threat_score INTEGER DEFAULT 0,
                mitre_attack_tactic TEXT,
                mitre_attack_technique TEXT,
                geo_country TEXT,
                geo_city TEXT,
                source_ip TEXT,
                is_known_threat BOOLEAN DEFAULT 0,
                threat_intel_source TEXT,
                similar_incidents_count INTEGER DEFAULT 0,
                time_to_detection_seconds INTEGER,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (log_id) REFERENCES raw_logs(id)
            )
        """)

        # NEW: Host/Asset Management Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT UNIQUE NOT NULL,
                ip_address TEXT,
                asset_classification TEXT DEFAULT 'Unknown',
                criticality TEXT DEFAULT 'Medium',
                risk_score INTEGER DEFAULT 50,
                total_alerts INTEGER DEFAULT 0,
                last_seen TEXT,
                first_seen TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # NEW: Threat Intelligence Cache Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_intel_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT UNIQUE NOT NULL,
                indicator_type TEXT NOT NULL,
                threat_score INTEGER DEFAULT 0,
                is_malicious BOOLEAN DEFAULT 0,
                threat_type TEXT,
                source TEXT,
                last_checked TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # NEW: Incident Tracking Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT DEFAULT 'Open',
                assigned_to TEXT,
                primary_log_id INTEGER,
                related_log_ids TEXT,
                mitre_tactics TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                resolved_at TEXT,
                FOREIGN KEY (primary_log_id) REFERENCES raw_logs(id)
            )
        """)

        # NEW: Response Actions/Playbooks Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS response_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_id INTEGER,
                incident_id INTEGER,
                action_type TEXT NOT NULL,
                action_description TEXT,
                status TEXT DEFAULT 'Pending',
                executed_at TEXT,
                result TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (log_id) REFERENCES raw_logs(id),
                FOREIGN KEY (incident_id) REFERENCES incidents(id)
            )
        """)

        # NEW: Correlation Rules Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS correlation_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT UNIQUE NOT NULL,
                rule_description TEXT,
                rule_pattern TEXT NOT NULL,
                time_window_seconds INTEGER DEFAULT 3600,
                threshold INTEGER DEFAULT 5,
                severity TEXT DEFAULT 'Medium',
                enabled BOOLEAN DEFAULT 1,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # NEW: Correlated Events Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS correlated_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                correlation_rule_id INTEGER,
                log_ids TEXT NOT NULL,
                event_count INTEGER,
                first_event_time TEXT,
                last_event_time TEXT,
                severity TEXT,
                description TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (correlation_rule_id) REFERENCES correlation_rules(id)
            )
        """)

        # NEW: Compliance Reports Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS compliance_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_type TEXT NOT NULL,
                report_period_start TEXT,
                report_period_end TEXT,
                total_events INTEGER,
                critical_events INTEGER,
                high_events INTEGER,
                medium_events INTEGER,
                low_events INTEGER,
                compliance_score INTEGER,
                generated_by TEXT,
                file_path TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Add processing_time_ms column to raw_logs if not exists
        cursor.execute("PRAGMA table_info(raw_logs)")
        columns = [col[1] for col in cursor.fetchall()]
        if 'processing_time_ms' not in columns:
            cursor.execute("ALTER TABLE raw_logs ADD COLUMN processing_time_ms INTEGER")
        if 'original_severity' not in columns:
            cursor.execute("ALTER TABLE raw_logs ADD COLUMN original_severity TEXT")

        # Create indexes for new tables
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alert_enrichment_log_id ON alert_enrichment(log_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alert_enrichment_threat_score ON alert_enrichment(threat_score)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_hosts_hostname ON hosts(hostname)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_hosts_risk_score ON hosts(risk_score)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_intel_indicator ON threat_intel_cache(indicator)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_response_actions_status ON response_actions(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_correlated_events_rule_id ON correlated_events(correlation_rule_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_severity_adjustments_pattern ON severity_adjustments(pattern_hash)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_severity_adjustments_active ON severity_adjustments(is_active)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ai_knowledge_conditions_pattern ON ai_knowledge_conditions(pattern_hash)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ai_knowledge_conditions_active ON ai_knowledge_conditions(is_active)")

        # Authentication Tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT,
                email TEXT,
                is_active BOOLEAN DEFAULT 1,
                is_admin BOOLEAN DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                last_login TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_hash TEXT UNIQUE NOT NULL,
                key_name TEXT NOT NULL,
                user_id INTEGER,
                is_active BOOLEAN DEFAULT 1,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                expires_at TEXT,
                last_used TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                ip_address TEXT,
                success BOOLEAN DEFAULT 0,
                attempted_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_time ON login_attempts(attempted_at)")

        # Add role column to users if not exists
        # Add columns to users table if not exists (database-agnostic)
        add_column_if_not_exists(cursor, 'users', 'role', 'TEXT', "'analyst'")
        add_column_if_not_exists(cursor, 'users', 'password_changed_at', 'TIMESTAMP', 'CURRENT_TIMESTAMP')
        add_column_if_not_exists(cursor, 'users', 'must_change_password', 'BOOLEAN', '0')
        add_column_if_not_exists(cursor, 'users', 'failed_login_count', 'INTEGER', '0')
        add_column_if_not_exists(cursor, 'users', 'locked_until', 'TIMESTAMP', 'NULL')

        # Update existing admin users
        if DB_TYPE == "postgresql":
            cursor.execute("UPDATE users SET role = 'admin' WHERE is_admin = TRUE AND role IS NULL")
        else:
            cursor.execute("UPDATE users SET role = 'admin' WHERE is_admin = 1 AND role IS NULL")

        # NEW: Audit Log Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT,
                action TEXT NOT NULL,
                entity_type TEXT,
                entity_id TEXT,
                details TEXT,
                ip_address TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_time ON audit_log(created_at)")

        # NEW: Alert Triage Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alert_triage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_id INTEGER UNIQUE,
                triage_status TEXT DEFAULT 'new',
                assigned_to TEXT,
                notes TEXT,
                triaged_by TEXT,
                triaged_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (log_id) REFERENCES raw_logs(id)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alert_triage_status ON alert_triage(triage_status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alert_triage_log ON alert_triage(log_id)")

        # NEW: Shift Notes Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS shift_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                author TEXT NOT NULL,
                shift_date TEXT NOT NULL,
                shift_period TEXT DEFAULT 'day',
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                priority TEXT DEFAULT 'normal',
                acknowledged_by TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_shift_notes_date ON shift_notes(shift_date)")

        # NEW: SLA Config Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sla_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                severity TEXT UNIQUE NOT NULL,
                response_minutes INTEGER NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            INSERT OR IGNORE INTO sla_config (severity, response_minutes) VALUES
            ('Critical', 15),
            ('High', 60),
            ('Medium', 240),
            ('Low', 1440)
        """)

        # NEW: Saved Searches Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS saved_searches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                name TEXT NOT NULL,
                filters TEXT NOT NULL,
                is_shared BOOLEAN DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        # NEW: User Sessions Table for session management
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS user_sessions (
                id {auto_id},
                user_id INTEGER NOT NULL,
                session_token_hash TEXT UNIQUE NOT NULL,
                refresh_token_hash TEXT UNIQUE,
                ip_address TEXT,
                user_agent TEXT,
                is_active BOOLEAN DEFAULT {bool_true},
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                revoked_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(session_token_hash)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_active ON user_sessions(is_active)")

        # Create default admin user if not exists (with forced password change)
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
        if cursor.fetchone()[0] == 0:
            admin_password_hash = pwd_context.hash("changeme")
            if DB_TYPE == "postgresql":
                cursor.execute("""
                    INSERT INTO users (username, password_hash, full_name, is_admin, must_change_password, role)
                    VALUES (%s, %s, %s, TRUE, TRUE, 'admin')
                """, ("admin", admin_password_hash, "System Administrator"))
            else:
                cursor.execute("""
                    INSERT INTO users (username, password_hash, full_name, is_admin, must_change_password, role)
                    VALUES (?, ?, ?, 1, 1, 'admin')
                """, ("admin", admin_password_hash, "System Administrator"))
            logger.warning("Default admin user created (username: admin, password: changeme) - PASSWORD CHANGE REQUIRED ON FIRST LOGIN")

        # Insert default correlation rules
        cursor.execute("""
            INSERT OR IGNORE INTO correlation_rules
            (rule_name, rule_description, rule_pattern, time_window_seconds, threshold, severity)
            VALUES
            ('Brute Force Detection', 'Multiple failed login attempts followed by success', 'failed.*login', 300, 5, 'High'),
            ('Port Scan Detection', 'Multiple port connection attempts from same IP', 'port.*scan|connection.*refused', 60, 10, 'Medium'),
            ('Data Exfiltration Pattern', 'Large data transfer to unusual destination', 'transfer|upload|exfiltration', 600, 3, 'Critical'),
            ('Privilege Escalation Chain', 'User privilege changes followed by suspicious activity', 'privilege|escalation|sudo|root', 1800, 3, 'Critical'),
            ('Malware Propagation', 'Similar malware detections across multiple hosts', 'malware|virus|trojan', 3600, 3, 'High')
        """)

        conn.commit()
        logger.info("Database initialized successfully with all feature tables")

def check_db_health() -> bool:
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            return True
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return False

# ==============================================================================
# 5.5. Authentication Helper Functions
# ==============================================================================
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a hashed password"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Hash a password for storing"""
    return pwd_context.hash(password)

def validate_password_policy(password: str) -> tuple[bool, str]:
    """
    Validate password against policy requirements.
    Returns (is_valid, error_message)
    """
    errors = []

    if len(password) < PASSWORD_MIN_LENGTH:
        errors.append(f"Password must be at least {PASSWORD_MIN_LENGTH} characters")

    if PASSWORD_REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")

    if PASSWORD_REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")

    if PASSWORD_REQUIRE_DIGIT and not re.search(r'\d', password):
        errors.append("Password must contain at least one digit")

    if PASSWORD_REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append("Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>)")

    if errors:
        return False, "; ".join(errors)
    return True, ""

def is_account_locked(username: str) -> tuple[bool, int]:
    """
    Check if account is locked due to failed login attempts.
    Returns (is_locked, remaining_minutes)
    """
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            lockout_window = datetime.datetime.utcnow() - timedelta(minutes=ACCOUNT_LOCKOUT_DURATION_MINUTES)

            if DB_TYPE == "postgresql":
                cursor.execute("""
                    SELECT COUNT(*) as failed_count, MAX(attempted_at) as last_attempt
                    FROM login_attempts
                    WHERE username = %s AND success = FALSE AND attempted_at > %s
                """, (username, lockout_window.isoformat()))
            else:
                cursor.execute("""
                    SELECT COUNT(*) as failed_count, MAX(attempted_at) as last_attempt
                    FROM login_attempts
                    WHERE username = ? AND success = 0 AND attempted_at > ?
                """, (username, lockout_window.isoformat()))

            result = cursor.fetchone()
            if result:
                failed_count = result['failed_count'] if isinstance(result, dict) else result[0]
                if failed_count >= ACCOUNT_LOCKOUT_THRESHOLD:
                    last_attempt = result['last_attempt'] if isinstance(result, dict) else result[1]
                    if last_attempt:
                        try:
                            last_attempt_dt = datetime.datetime.fromisoformat(last_attempt.replace('Z', '+00:00'))
                        except:
                            last_attempt_dt = datetime.datetime.strptime(last_attempt, '%Y-%m-%d %H:%M:%S')
                        unlock_time = last_attempt_dt + timedelta(minutes=ACCOUNT_LOCKOUT_DURATION_MINUTES)
                        remaining = (unlock_time - datetime.datetime.utcnow()).total_seconds() / 60
                        if remaining > 0:
                            return True, int(remaining)
            return False, 0
    except Exception as e:
        logger.error(f"Error checking account lockout: {e}")
        return False, 0

def check_password_expired(user_id: int) -> bool:
    """Check if user's password has expired"""
    if PASSWORD_EXPIRY_DAYS <= 0:
        return False
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            if DB_TYPE == "postgresql":
                cursor.execute("""
                    SELECT password_changed_at FROM users WHERE id = %s
                """, (user_id,))
            else:
                cursor.execute("""
                    SELECT password_changed_at FROM users WHERE id = ?
                """, (user_id,))
            result = cursor.fetchone()
            if result and result[0]:
                try:
                    changed_at = datetime.datetime.fromisoformat(result[0].replace('Z', '+00:00'))
                except:
                    changed_at = datetime.datetime.strptime(result[0], '%Y-%m-%d %H:%M:%S')
                expiry_date = changed_at + timedelta(days=PASSWORD_EXPIRY_DAYS)
                return datetime.datetime.utcnow() > expiry_date
    except Exception as e:
        logger.error(f"Error checking password expiry: {e}")
    return False

def create_session(user_id: int, access_token: str, refresh_token: str,
                   ip_address: str = None, user_agent: str = None) -> int:
    """Create a new session record and enforce concurrent session limits"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            param = "%s" if DB_TYPE == "postgresql" else "?"
            bool_false = "FALSE" if DB_TYPE == "postgresql" else "0"

            # Enforce max concurrent sessions - revoke oldest if limit exceeded
            cursor.execute(f"""
                SELECT id FROM user_sessions
                WHERE user_id = {param} AND is_active = {'TRUE' if DB_TYPE == 'postgresql' else '1'}
                ORDER BY created_at ASC
            """, (user_id,))
            active_sessions = cursor.fetchall()

            if len(active_sessions) >= MAX_CONCURRENT_SESSIONS:
                # Revoke oldest sessions
                sessions_to_revoke = len(active_sessions) - MAX_CONCURRENT_SESSIONS + 1
                for i in range(sessions_to_revoke):
                    session_id = active_sessions[i][0] if isinstance(active_sessions[i], tuple) else active_sessions[i]['id']
                    cursor.execute(f"""
                        UPDATE user_sessions SET is_active = {bool_false},
                               revoked_at = {'NOW()' if DB_TYPE == 'postgresql' else 'CURRENT_TIMESTAMP'}
                        WHERE id = {param}
                    """, (session_id,))
                logger.info(f"Revoked {sessions_to_revoke} old session(s) for user {user_id} due to concurrent session limit")

            # Create new session
            access_hash = hashlib.sha256(access_token.encode()).hexdigest()
            refresh_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
            expires_at = datetime.datetime.utcnow() + timedelta(days=JWT_REFRESH_TOKEN_EXPIRE_DAYS)

            cursor.execute(f"""
                INSERT INTO user_sessions (user_id, session_token_hash, refresh_token_hash,
                                          ip_address, user_agent, expires_at)
                VALUES ({param}, {param}, {param}, {param}, {param}, {param})
            """, (user_id, access_hash, refresh_hash, ip_address, user_agent, expires_at.isoformat()))
            conn.commit()

            return cursor.lastrowid
    except Exception as e:
        logger.error(f"Error creating session: {e}")
        return None

def revoke_session(session_token: str) -> bool:
    """Revoke a specific session by its access token"""
    try:
        token_hash = hashlib.sha256(session_token.encode()).hexdigest()
        with get_db() as conn:
            cursor = conn.cursor()
            param = "%s" if DB_TYPE == "postgresql" else "?"
            bool_false = "FALSE" if DB_TYPE == "postgresql" else "0"
            cursor.execute(f"""
                UPDATE user_sessions SET is_active = {bool_false},
                       revoked_at = {'NOW()' if DB_TYPE == 'postgresql' else 'CURRENT_TIMESTAMP'}
                WHERE session_token_hash = {param}
            """, (token_hash,))
            conn.commit()
            return cursor.rowcount > 0
    except Exception as e:
        logger.error(f"Error revoking session: {e}")
        return False

def revoke_all_user_sessions(user_id: int, except_current: str = None) -> int:
    """Revoke all sessions for a user, optionally except the current one"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            param = "%s" if DB_TYPE == "postgresql" else "?"
            bool_false = "FALSE" if DB_TYPE == "postgresql" else "0"

            if except_current:
                current_hash = hashlib.sha256(except_current.encode()).hexdigest()
                cursor.execute(f"""
                    UPDATE user_sessions SET is_active = {bool_false},
                           revoked_at = {'NOW()' if DB_TYPE == 'postgresql' else 'CURRENT_TIMESTAMP'}
                    WHERE user_id = {param} AND session_token_hash != {param}
                """, (user_id, current_hash))
            else:
                cursor.execute(f"""
                    UPDATE user_sessions SET is_active = {bool_false},
                           revoked_at = {'NOW()' if DB_TYPE == 'postgresql' else 'CURRENT_TIMESTAMP'}
                    WHERE user_id = {param}
                """, (user_id,))
            conn.commit()
            return cursor.rowcount
    except Exception as e:
        logger.error(f"Error revoking user sessions: {e}")
        return 0

def get_active_sessions(user_id: int) -> List[Dict[str, Any]]:
    """Get all active sessions for a user"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            param = "%s" if DB_TYPE == "postgresql" else "?"
            cursor.execute(f"""
                SELECT id, ip_address, user_agent, created_at, last_activity
                FROM user_sessions
                WHERE user_id = {param} AND is_active = {'TRUE' if DB_TYPE == 'postgresql' else '1'}
                ORDER BY last_activity DESC
            """, (user_id,))
            sessions = cursor.fetchall()
            return [dict(s) if hasattr(s, 'keys') else {
                'id': s[0], 'ip_address': s[1], 'user_agent': s[2],
                'created_at': s[3], 'last_activity': s[4]
            } for s in sessions]
    except Exception as e:
        logger.error(f"Error getting sessions: {e}")
        return []

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict) -> str:
    """Create a JWT refresh token"""
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + timedelta(days=JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def authenticate_user(username: str, password: str) -> Dict[str, Any]:
    """
    Authenticate a user by username and password.
    Returns dict with user info or error details.
    """
    # Check account lockout first
    is_locked, remaining_mins = is_account_locked(username)
    if is_locked:
        return {"error": "account_locked", "message": f"Account locked. Try again in {remaining_mins} minutes."}

    try:
        with get_db() as conn:
            cursor = conn.cursor()
            param = "%s" if DB_TYPE == "postgresql" else "?"
            cursor.execute(f"""
                SELECT id, username, password_hash, full_name, email, is_active, is_admin, role,
                       must_change_password, password_changed_at
                FROM users WHERE username = {param}
            """, (username,))
            user = cursor.fetchone()

            if not user:
                return {"error": "invalid_credentials", "message": "Invalid username or password"}

            # Convert row to dict if needed
            if hasattr(user, 'keys'):
                user_dict = dict(user)
            else:
                user_dict = {
                    'id': user[0], 'username': user[1], 'password_hash': user[2],
                    'full_name': user[3], 'email': user[4], 'is_active': user[5],
                    'is_admin': user[6], 'role': user[7], 'must_change_password': user[8],
                    'password_changed_at': user[9]
                }

            if not user_dict['is_active']:
                return {"error": "account_disabled", "message": "Account is disabled"}

            if not verify_password(password, user_dict['password_hash']):
                return {"error": "invalid_credentials", "message": "Invalid username or password"}

            # Check if password must be changed
            must_change = user_dict.get('must_change_password', False)
            password_expired = check_password_expired(user_dict['id'])

            # Update last login and reset failed count
            cursor.execute(f"""
                UPDATE users SET last_login = CURRENT_TIMESTAMP, failed_login_count = 0
                WHERE id = {param}
            """, (user_dict['id'],))
            conn.commit()

            return {
                "id": user_dict['id'],
                "username": user_dict['username'],
                "full_name": user_dict['full_name'],
                "email": user_dict['email'],
                "is_admin": bool(user_dict['is_admin']),
                "role": user_dict['role'] or ('admin' if user_dict['is_admin'] else 'analyst'),
                "must_change_password": bool(must_change) or password_expired,
                "password_expired": password_expired
            }
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        return {"error": "server_error", "message": "Authentication service error"}

def verify_api_key(api_key: str) -> Optional[Dict[str, Any]]:
    """Verify an API key and return associated user"""
    try:
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT u.id, u.username, u.full_name, u.is_admin, a.id as key_id
                FROM api_keys a
                JOIN users u ON a.user_id = u.id
                WHERE a.key_hash = ? AND a.is_active = 1 AND u.is_active = 1
                AND (a.expires_at IS NULL OR a.expires_at > datetime('now'))
            """, (key_hash,))
            result = cursor.fetchone()

            if result:
                # Update last used timestamp
                cursor.execute("""
                    UPDATE api_keys SET last_used = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (result['key_id'],))
                conn.commit()

                return {
                    "id": result['id'],
                    "username": result['username'],
                    "full_name": result['full_name'],
                    "is_admin": bool(result['is_admin'])
                }
            return None
    except Exception as e:
        logger.error(f"API key verification error: {e}")
        return None

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    api_key: Optional[str] = None
) -> Dict[str, Any]:
    """Get current user from JWT token or API key"""
    # Try API key first (from header)
    if api_key:
        user = verify_api_key(api_key)
        if user:
            return user

    # Try JWT token
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        token_type: str = payload.get("type")

        if username is None or token_type != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, username, full_name, email, is_admin, role
                FROM users WHERE username = ? AND is_active = 1
            """, (username,))
            user = cursor.fetchone()

            if user is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            return {
                "id": user['id'],
                "username": user['username'],
                "full_name": user['full_name'],
                "email": user['email'],
                "is_admin": bool(user['is_admin']),
                "role": user['role'] or ('admin' if user['is_admin'] else 'analyst')
            }
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

def record_login_attempt(username: str, ip_address: str, success: bool):
    """Record a login attempt for security monitoring"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO login_attempts (username, ip_address, success)
                VALUES (?, ?, ?)
            """, (username, ip_address, success))
            conn.commit()
    except Exception as e:
        logger.error(f"Failed to record login attempt: {e}")

def record_audit(user_id: int, username: str, action: str, entity_type: str = None,
                 entity_id: str = None, details: str = None, ip_address: str = None):
    """Record an action in the audit log"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit_log (user_id, username, action, entity_type, entity_id, details, ip_address)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (user_id, username, action, entity_type, entity_id, details, ip_address))
            conn.commit()
    except Exception as e:
        logger.error(f"Failed to record audit log: {e}")

def is_info_level_log(raw_log: str) -> bool:
    """Detect routine/informational logs that bypass AI analysis"""
    info_patterns = [
        r'health[\s_-]?check',
        r'heartbeat',
        r'keepalive',
        r'service\s+(started|running|active|status)',
        r'cron.*completed',
        r'logrotate',
        r'session\s+opened\s+for\s+user\s+root\s+by',
        r'systemd.*started',
        r'dhcp(discover|request|ack)',
        r'ntp.*synchronized',
        r'kernel.*loaded',
    ]
    log_lower = raw_log.lower()
    for pattern in info_patterns:
        if re.search(pattern, log_lower):
            return True
    return False

# ==============================================================================
# 6. Elasticsearch/OpenSearch Management
# ==============================================================================
def get_es_client() -> Elasticsearch:
    return Elasticsearch(
        hosts=[ES_HOSTS],
        sniff_on_start=False,
        request_timeout=30
    )

def ensure_index_exists():
    try:
        es = get_es_client()

        if not es.indices.exists(index=ES_INDEX):
            mappings = {
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "severity": {"type": "keyword"},
                        "event_type": {"type": "keyword"},
                        "raw_log": {"type": "text"},
                        "summary": {"type": "text"},
                        "db_id": {"type": "integer"},
                        "host": {"type": "keyword"},
                        "analyzed_by": {"type": "keyword"}
                    }
                }
            }
            es.indices.create(index=ES_INDEX, body=mappings)
            logger.info(f"Created index: {ES_INDEX}")
        else:
            logger.info(f"Index {ES_INDEX} already exists")
    except Exception as e:
        logger.warning(f"Could not create OpenSearch index (continuing without it): {e}")

def check_opensearch_health() -> bool:
    try:
        es = get_es_client()
        result = es.ping()
        if result:
            logger.debug("OpenSearch is online")
        return result
    except Exception as e:
        logger.debug(f"OpenSearch health check failed: {e}")
        return False

def index_to_opensearch(analysis: Dict[str, Any], max_retries: int = 1) -> bool:
    try:
        es = get_es_client()
        es.index(index=ES_INDEX, document=analysis)
        return True
    except Exception as e:
        logger.debug(f"OpenSearch indexing skipped: {str(e)[:100]}")
        return False

# ==============================================================================
# 7. Ollama LLM Integration
# ==============================================================================
def check_ollama_health() -> bool:
    try:
        ollama_client = Client(host=OLLAMA_URL)
        ollama_client.list()
        return True
    except Exception as e:
        logger.error(f"Ollama health check failed: {e}")
        return False

LLM_SYSTEM_PROMPT = """You are a Security Operations Center (SOC) analyst specializing in network security and UniFi infrastructure. Your task is to analyze security logs and classify them accurately.

## UniFi Device Types You May See:
- UDM/UDM-Pro/UDM-SE: UniFi Dream Machine (router/firewall/controller)
- UAP-*: UniFi Access Points (wireless)
- USW-*: UniFi Switches
- USG/USG-Pro: UniFi Security Gateway
- UXG-*: UniFi Next-Gen Gateway
- UA-Hub/UA-Reader/UA-Lite/UA-Pro: UniFi Access (door access control)
- UNVR: UniFi Network Video Recorder
- UVC-*: UniFi Protect Cameras

## UniFi Event Categories:

### Critical Severity Events:
- Firewall detecting active attacks (port scans, DDoS, intrusion attempts)
- Unauthorized access to UniFi Access doors during locked hours
- Multiple failed admin login attempts (brute force)
- Rogue AP detected
- IDS/IPS alerts for known exploits
- Configuration tampering or factory reset
- Firmware downgrade attempts

### High Severity Events:
- Failed authentication to network devices
- New admin user created
- Firewall rule changes
- VPN connection from unusual location
- Door forced open or held open alerts (UniFi Access)
- Client blocked by threat management
- Unusual outbound traffic patterns
- Guest network abuse

### Medium Severity Events:
- New device connected to network
- Client roaming between APs
- DHCP scope exhaustion warnings
- Channel changes due to interference
- Door access granted outside business hours
- Speed test or bandwidth anomalies
- Certificate warnings

### Low Severity Events:
- Normal door access granted
- Device firmware updates
- Routine AP/switch status changes
- Client connect/disconnect
- Scheduled backups completed
- Normal DHCP leases
- Routine system health checks

## Output Format:
Respond with ONLY valid JSON, no other text:
{"severity":"Critical|High|Medium|Low","event_type":"string","summary":"brief 1-2 sentence description"}"""

def analyze_with_llm(raw_log: str) -> Dict[str, Any]:
    ollama_client = Client(host=OLLAMA_URL)

    user_prompt = f"""Analyze this security log and classify it.

Log: {raw_log}

Respond with ONLY valid JSON:
{{"severity":"Critical|High|Medium|Low","event_type":"category","summary":"brief description"}}"""

    try:
        response = ollama_client.chat(
            model=OLLAMA_MODEL,
            messages=[
                {"role": "system", "content": LLM_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt}
            ],
            options={"temperature": 0.2, "num_thread": 16, "num_ctx": 2048}
        )

        response_text = response['message']['content'].strip()

        # Try to extract JSON from various formats
        if "```json" in response_text:
            response_text = response_text.split("```json")[1].split("```")[0].strip()
        elif "```" in response_text:
            response_text = response_text.split("```")[1].split("```")[0].strip()

        # Try to find JSON object in response
        json_match = re.search(r'\{[^{}]*\}', response_text, re.DOTALL)
        if json_match:
            response_text = json_match.group(0)

        analysis = json.loads(response_text)

        # Normalize field names (handle case variations)
        normalized = {}
        for key, value in analysis.items():
            normalized[key.lower()] = value

        # Map to expected fields
        result = {
            'severity': normalized.get('severity', 'Medium'),
            'event_type': normalized.get('event_type', normalized.get('eventtype', normalized.get('type', 'Unknown'))),
            'summary': normalized.get('summary', normalized.get('description', normalized.get('message', 'No summary')))
        }

        # Validate severity value
        valid_severities = ['Critical', 'High', 'Medium', 'Low', 'Info']
        if result['severity'] not in valid_severities:
            # Try to match partial
            sev_lower = result['severity'].lower()
            for vs in valid_severities:
                if vs.lower() in sev_lower or sev_lower in vs.lower():
                    result['severity'] = vs
                    break
            else:
                result['severity'] = 'Medium'

        return result

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse LLM JSON response: {e}")
        return {
            "severity": "Medium",
            "event_type": "ParseError",
            "summary": "LLM returned invalid JSON format"
        }
    except Exception as e:
        logger.error(f"LLM analysis error: {e}")
        return {
            "severity": "Unknown",
            "event_type": "Error",
            "summary": f"LLM analysis failed: {str(e)[:100]}"
        }

# ==============================================================================
# 8. Utility Functions
# ==============================================================================
def decode_bytes(data):
    if data is None:
        return ""
    if isinstance(data, bytes):
        try:
            return data.decode('utf-8', errors='replace')
        except UnicodeDecodeError:
            return data.decode('latin-1', errors='replace')
    return str(data)

def get_log_hash(message: str) -> str:
    masked = re.sub(r'\d+', 'X', message)
    return hashlib.sha256(masked.encode()).hexdigest()

def extract_host_from_log(log_message: str) -> str:
    """Extract hostname or IP address from log message."""
    import re

    # Keywords that should NOT be considered hostnames
    severity_keywords = {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'INFO', 'WARNING', 'ALERT',
                         'ERROR', 'DEBUG', 'NOTICE', 'SECURITY', 'RANSOMWARE'}

    # Try to find hostname in common patterns first (more reliable)
    # Pattern: "on hostname" or "on hostname -" or "on hostname/"
    on_host_pattern = r'\bon\s+([a-zA-Z0-9\-\.]+)(?:\s|$|/|-)'
    on_host_match = re.search(on_host_pattern, log_message)
    if on_host_match:
        hostname = on_host_match.group(1)
        if hostname.upper() not in severity_keywords:
            return hostname

    # Pattern: "from hostname" (for login/connection logs)
    from_host_pattern = r'\bfrom\s+([a-zA-Z0-9\-\.]+)(?:\s|$)'
    from_host_match = re.search(from_host_pattern, log_message)
    if from_host_match:
        hostname = from_host_match.group(1)
        if hostname.upper() not in severity_keywords and not re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname):
            return hostname

    # Pattern: "targeting hostname" or "target hostname"
    target_pattern = r'\btarget(?:ing)?\s+([a-zA-Z0-9\-\.]+)(?:\s|$|/)'
    target_match = re.search(target_pattern, log_message)
    if target_match:
        hostname = target_match.group(1)
        if hostname.upper() not in severity_keywords:
            return hostname

    # Pattern: "for hostname" (e.g., "update available for hostname")
    for_host_pattern = r'\bfor\s+([a-zA-Z0-9\-\.]+)(?:\s+-|\s|$)'
    for_host_match = re.search(for_host_pattern, log_message)
    if for_host_match:
        hostname = for_host_match.group(1)
        if hostname.upper() not in severity_keywords and len(hostname) > 2:
            return hostname

    # Try to find IP address as fallback
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ip_match = re.search(ip_pattern, log_message)
    if ip_match:
        return ip_match.group(0)

    # Try hostname (syslog format)
    # Format: <priority>timestamp hostname message
    syslog_pattern = r'^\<\d+\>\w+\s+\d+\s+\d+:\d+:\d+\s+(\S+)'
    syslog_match = re.search(syslog_pattern, log_message)
    if syslog_match:
        hostname = syslog_match.group(1)
        if hostname.upper() not in severity_keywords:
            return hostname

    # Try hostname at beginning of log (before first colon) - but exclude severity keywords
    hostname_pattern = r'^([a-zA-Z0-9\-\.]+):\s'
    hostname_match = re.search(hostname_pattern, log_message)
    if hostname_match:
        hostname = hostname_match.group(1)
        if hostname.upper() not in severity_keywords:
            return hostname

    return "Unknown"

def update_global_counts():
    global TOTAL_LOGS_COUNT, PENDING_LOGS_COUNT, PROCESSED_LOGS_COUNT

    with metrics_lock:
        with get_db() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM raw_logs")
            TOTAL_LOGS_COUNT = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM raw_logs WHERE status='PENDING'")
            PENDING_LOGS_COUNT = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM raw_logs WHERE status='PROCESSED'")
            PROCESSED_LOGS_COUNT = cursor.fetchone()[0]

# ==============================================================================
# 8b. NEW FEATURE HELPER FUNCTIONS
# ==============================================================================

def extract_ip_from_log(log_message: str) -> Optional[str]:
    """Extract source IP address from log message"""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ip_match = re.search(ip_pattern, log_message)
    return ip_match.group(0) if ip_match else None

def calculate_threat_score(severity: str, is_known_threat: bool, similar_count: int) -> int:
    """Calculate threat score (0-100) based on multiple factors"""
    base_scores = {
        "Critical": 90,
        "High": 70,
        "Medium": 40,
        "Low": 10,
        "Unknown": 20
    }

    score = base_scores.get(severity, 20)

    # Boost score if known threat
    if is_known_threat:
        score = min(100, score + 20)

    # Boost score based on similar incidents
    score = min(100, score + (similar_count * 2))

    return score

def map_to_mitre_attack(event_type: str, raw_log: str) -> tuple:
    """Map event type to MITRE ATT&CK framework"""
    mitre_mappings = {
        "Brute Force": ("Initial Access", "T1110 - Brute Force"),
        "Port Scan": ("Reconnaissance", "T1046 - Network Service Discovery"),
        "Malware": ("Execution", "T1204 - User Execution"),
        "Privilege Escalation": ("Privilege Escalation", "T1068 - Exploitation for Privilege Escalation"),
        "SQL Injection": ("Initial Access", "T1190 - Exploit Public-Facing Application"),
        "XSS": ("Initial Access", "T1190 - Exploit Public-Facing Application"),
        "Data Exfiltration": ("Exfiltration", "T1041 - Exfiltration Over C2 Channel"),
        "Backdoor": ("Persistence", "T1543 - Create or Modify System Process"),
        "DDoS": ("Impact", "T1498 - Network Denial of Service"),
        "Ransomware": ("Impact", "T1486 - Data Encrypted for Impact")
    }

    for key, (tactic, technique) in mitre_mappings.items():
        if key.lower() in event_type.lower() or key.lower() in raw_log.lower():
            return (tactic, technique)

    return ("Unknown", "Unknown")

def check_threat_intel(indicator: str, indicator_type: str = "ip") -> Dict[str, Any]:
    """
    Check threat intelligence for an indicator (IP, domain, hash)
    Returns cached result if available, otherwise returns unknown
    Note: Actual threat intel integration requires API keys
    """
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT is_malicious, threat_score, threat_type, source
            FROM threat_intel_cache
            WHERE indicator = ? AND indicator_type = ?
        """, (indicator, indicator_type))

        result = cursor.fetchone()

        if result:
            return {
                "is_malicious": bool(result[0]),
                "threat_score": result[1],
                "threat_type": result[2],
                "source": result[3]
            }

        # Return unknown if not in cache
        return {
            "is_malicious": False,
            "threat_score": 0,
            "threat_type": "Unknown",
            "source": "Not Checked"
        }

def update_host_info(hostname: str, risk_score: int = None):
    """Update or create host information"""
    with get_db() as conn:
        cursor = conn.cursor()

        # Check if host exists
        cursor.execute("SELECT id, total_alerts FROM hosts WHERE hostname = ?", (hostname,))
        host = cursor.fetchone()

        now = datetime.datetime.now().isoformat()

        if host:
            # Update existing host
            new_alert_count = host[1] + 1
            cursor.execute("""
                UPDATE hosts
                SET total_alerts = ?,
                    last_seen = ?,
                    risk_score = COALESCE(?, risk_score)
                WHERE hostname = ?
            """, (new_alert_count, now, risk_score, hostname))
        else:
            # Create new host
            cursor.execute("""
                INSERT INTO hosts (hostname, total_alerts, first_seen, last_seen, risk_score)
                VALUES (?, 1, ?, ?, ?)
            """, (hostname, now, now, risk_score or 50))

        conn.commit()

def enrich_alert(log_id: int, raw_log: str, severity: str, event_type: str, host: str):
    """Enrich alert with additional intelligence and context"""
    source_ip = extract_ip_from_log(raw_log)

    # Check threat intelligence
    threat_info = {"is_malicious": False, "threat_score": 0, "source": "None"}
    if source_ip:
        threat_info = check_threat_intel(source_ip, "ip")

    # Map to MITRE ATT&CK
    mitre_tactic, mitre_technique = map_to_mitre_attack(event_type, raw_log)

    # Count similar incidents
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) FROM raw_logs
            WHERE event_type = ? AND timestamp > datetime('now', '-24 hours')
        """, (event_type,))
        similar_count = cursor.fetchone()[0]

        # Calculate threat score
        threat_score = calculate_threat_score(
            severity,
            threat_info["is_malicious"],
            similar_count
        )

        # Insert enrichment data
        cursor.execute("""
            INSERT OR REPLACE INTO alert_enrichment
            (log_id, threat_score, mitre_attack_tactic, mitre_attack_technique,
             source_ip, is_known_threat, threat_intel_source, similar_incidents_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            log_id,
            threat_score,
            mitre_tactic,
            mitre_technique,
            source_ip,
            threat_info["is_malicious"],
            threat_info["source"],
            similar_count
        ))

        conn.commit()

    # Update host information
    update_host_info(host, threat_score)

def run_correlation_engine():
    """Run correlation engine to detect multi-stage attacks"""
    with get_db() as conn:
        cursor = conn.cursor()

        # Get enabled correlation rules
        cursor.execute("SELECT * FROM correlation_rules WHERE enabled = 1")
        rules = cursor.fetchall()

        for rule in rules:
            rule_id = rule[0]
            rule_pattern = rule[3]
            time_window = rule[4]
            threshold = rule[5]
            severity = rule[6]

            # Find matching logs within time window
            cursor.execute("""
                SELECT id, timestamp, raw_log
                FROM raw_logs
                WHERE raw_log LIKE ?
                AND timestamp > datetime('now', '-' || ? || ' seconds')
                ORDER BY timestamp DESC
            """, (f"%{rule_pattern}%", time_window))

            matching_logs = cursor.fetchall()

            # If threshold exceeded, create correlated event
            if len(matching_logs) >= threshold:
                log_ids = ",".join([str(log[0]) for log in matching_logs])
                first_event = matching_logs[-1][1]
                last_event = matching_logs[0][1]

                cursor.execute("""
                    INSERT INTO correlated_events
                    (correlation_rule_id, log_ids, event_count, first_event_time, last_event_time, severity, description)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    rule_id,
                    log_ids,
                    len(matching_logs),
                    first_event,
                    last_event,
                    severity,
                    f"Correlation rule triggered: {rule[1]} - {len(matching_logs)} events detected"
                ))

        conn.commit()

def get_ai_learning_stats() -> Dict[str, Any]:
    """Get statistics about AI learning progress"""
    with get_db() as conn:
        cursor = conn.cursor()

        # Total learned patterns
        cursor.execute("SELECT COUNT(*) FROM ai_knowledge")
        total_patterns = cursor.fetchone()[0]

        # Logs analyzed by knowledge base
        cursor.execute("SELECT COUNT(*) FROM raw_logs WHERE analyzed_by = 'knowledge_base'")
        kb_analyzed = cursor.fetchone()[0]

        # Recent corrections (last 24h)
        cursor.execute("""
            SELECT COUNT(*) FROM ai_knowledge
            WHERE updated_at > datetime('now', '-24 hours')
        """)
        recent_corrections = cursor.fetchone()[0]

        # Most corrected event types
        cursor.execute("""
            SELECT corrected_severity, COUNT(*) as count
            FROM ai_knowledge
            GROUP BY corrected_severity
            ORDER BY count DESC
            LIMIT 5
        """)
        top_corrections = cursor.fetchall()

        return {
            "total_patterns": total_patterns,
            "kb_analyzed_logs": kb_analyzed,
            "recent_corrections_24h": recent_corrections,
            "top_corrections": [{"severity": row[0], "count": row[1]} for row in top_corrections]
        }

# ==============================================================================
# 9. Log Ingestor
# ==============================================================================
def msgpack_ext_decoder(code, data):
    if code == -1:
        if len(data) == 4:
            return float(int.from_bytes(data, byteorder='big'))
        elif len(data) == 8:
            return int.from_bytes(data[:4], byteorder='big') + \
                   (int.from_bytes(data[4:], byteorder='big') / 1000000000.0)
    return msgpack.ExtType(code, data)

def handle_fluentd_connection(conn, addr):
    try:
        unpacker = msgpack.Unpacker(
            raw=True,
            ext_hook=msgpack_ext_decoder,
            max_buffer_size=5 * 1024 * 1024
        )

        while INGESTOR_RUNNING.is_set():
            data = conn.recv(65536)
            if not data:
                break

            unpacker.feed(data)

            for unpacked_message in unpacker:
                logs_to_insert = []

                # Handle different msgpack formats
                if isinstance(unpacked_message, (list, tuple)):
                    if len(unpacked_message) >= 2:
                        # FluentD Forward format: [tag, entries] or [tag, [[timestamp, record], ...]]
                        tag = unpacked_message[0]
                        entries = unpacked_message[1]

                        if isinstance(entries, bytes):
                            # Packed entries - unpack them
                            sub_unpacker = msgpack.Unpacker(
                                io.BytesIO(entries),
                                raw=True,
                                ext_hook=msgpack_ext_decoder
                            )
                            entries = list(sub_unpacker)

                        if isinstance(entries, (list, tuple)):
                            for entry in entries:
                                if isinstance(entry, (list, tuple)) and len(entry) >= 2:
                                    timestamp, record = entry[0], entry[1]
                                    if isinstance(record, dict):
                                        raw_log_data = record.get(b'message', record.get('message', str(record)))
                                        logs_to_insert.append(decode_bytes(raw_log_data))
                                    else:
                                        logs_to_insert.append(decode_bytes(record))
                                elif isinstance(entry, (bytes, str)):
                                    logs_to_insert.append(decode_bytes(entry))
                        elif isinstance(entries, dict):
                            # Single record format: [tag, record]
                            raw_log_data = entries.get(b'message', entries.get('message', str(entries)))
                            logs_to_insert.append(decode_bytes(raw_log_data))
                    elif len(unpacked_message) == 1:
                        # Just a single message
                        logs_to_insert.append(decode_bytes(unpacked_message[0]))
                elif isinstance(unpacked_message, dict):
                    # Direct record format
                    raw_log_data = unpacked_message.get(b'message', unpacked_message.get('message', str(unpacked_message)))
                    logs_to_insert.append(decode_bytes(raw_log_data))
                elif isinstance(unpacked_message, (bytes, str)):
                    # Plain string/bytes
                    logs_to_insert.append(decode_bytes(unpacked_message))

                # Insert logs into database
                if logs_to_insert:
                    with get_db() as conn_db:
                        cursor = conn_db.cursor()
                        for msg in logs_to_insert:
                            if msg and msg.strip():
                                cursor.execute(
                                    "INSERT INTO raw_logs (timestamp, raw_log, status) VALUES (?, ?, ?)",
                                    (datetime.datetime.now().isoformat(), str(msg), 'PENDING')
                                )
                        conn_db.commit()

                    update_global_counts()
                    logger.info(f"Ingested {len(logs_to_insert)} logs from {addr}")

    except Exception as e:
        logger.error(f"Ingestor connection error from {addr}: {e}")
        import traceback
        logger.debug(traceback.format_exc())
    finally:
        conn.close()

def tcp_ingestor_thread():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST_IP, LISTEN_PORT))
        s.listen(5)
        logger.info(f"TCP Ingestor listening on {HOST_IP}:{LISTEN_PORT}")

        while INGESTOR_RUNNING.is_set():
            try:
                s.settimeout(1.0)
                conn, addr = s.accept()
                threading.Thread(
                    target=handle_fluentd_connection,
                    args=(conn, addr),
                    daemon=True
                ).start()
            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"Accept connection error: {e}")

# ==============================================================================
# 9b. Syslog Ingestor (UniFi, Network Devices, etc.)
# ==============================================================================
# Syslog facility names
SYSLOG_FACILITIES = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth", 5: "syslog",
    6: "lpr", 7: "news", 8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
    12: "ntp", 13: "security", 14: "console", 15: "solaris-cron",
    16: "local0", 17: "local1", 18: "local2", 19: "local3",
    20: "local4", 21: "local5", 22: "local6", 23: "local7"
}

SYSLOG_SEVERITIES = {
    0: "Emergency", 1: "Alert", 2: "Critical", 3: "Error",
    4: "Warning", 5: "Notice", 6: "Informational", 7: "Debug"
}

# Map syslog severity to our severity levels
SYSLOG_TO_SEVERITY = {
    0: "Critical",  # Emergency
    1: "Critical",  # Alert
    2: "Critical",  # Critical
    3: "High",      # Error
    4: "Medium",    # Warning
    5: "Low",       # Notice
    6: "Low",       # Informational
    7: "Low"        # Debug
}

# UniFi device type patterns
UNIFI_DEVICE_PATTERNS = {
    r'U[A-Z]{2,3}-[A-Z0-9-]+': 'UniFi Access Point',
    r'UDM-?(?:Pro|SE|Base)?': 'UniFi Dream Machine',
    r'USW-[A-Z0-9-]+': 'UniFi Switch',
    r'USG-?(?:Pro)?': 'UniFi Security Gateway',
    r'UCK-?(?:G2)?': 'UniFi Cloud Key',
    r'UA-(?:Hub|Reader|Lite|Pro|Intercom)': 'UniFi Access',
    r'UVC-[A-Z0-9-]+': 'UniFi Protect Camera',
    r'UNVR-?(?:Pro)?': 'UniFi NVR',
    r'UBB': 'UniFi Building Bridge',
    r'UXG-?(?:Pro|Lite|Max)?': 'UniFi Next-Gen Gateway',
}

# UniFi event patterns for pre-classification (pattern, event_type, severity_hint)
# Order matters - more specific patterns should come before general ones
UNIFI_EVENT_PATTERNS = [
    # Critical events
    (r'IDS[:\s].*(?:attack|exploit|intrusion)', 'IDS Alert', 'Critical'),
    (r'IPS[:\s].*(?:blocked|dropped|attack)', 'IPS Block', 'Critical'),
    (r'(?:rogue|unauthorized)\s*(?:ap|access\s*point)', 'Rogue AP Detected', 'Critical'),
    (r'brute\s*force|multiple.*failed.*login', 'Brute Force Attack', 'Critical'),
    (r'factory\s*reset|config.*wipe', 'Factory Reset', 'Critical'),
    (r'firmware\s*downgrade', 'Firmware Downgrade', 'Critical'),
    (r'door.*forced|forced.*entry', 'Forced Entry', 'Critical'),
    (r'threat.*management.*block', 'Threat Blocked', 'Critical'),

    # High severity events
    (r'(?:admin|root).*(?:login|auth).*fail', 'Admin Auth Failure', 'High'),
    (r'new\s*admin.*created|admin.*added', 'New Admin Created', 'High'),
    (r'firewall.*rule.*(?:change|modify|add|delete)', 'Firewall Rule Change', 'High'),
    (r'vpn.*(?:connect|tunnel).*(?:unusual|foreign|unexpected)', 'Suspicious VPN', 'High'),
    (r'door.*held.*open|propped.*open', 'Door Held Open', 'High'),
    (r'client.*blocked|block.*client', 'Client Blocked', 'High'),
    (r'port\s*scan|scanning.*ports', 'Port Scan', 'High'),
    (r'dhcp.*exhausted|no.*available.*leases', 'DHCP Exhausted', 'High'),
    (r'spanning.*tree.*(?:change|topology)', 'STP Topology Change', 'High'),
    (r'poe.*(?:overload|fault|exceeded)', 'PoE Fault', 'High'),

    # Medium severity events
    (r'new\s*device.*connect|unknown.*device', 'New Device Connected', 'Medium'),
    (r'client.*roam|roaming.*to', 'Client Roaming', 'Medium'),
    (r'(?:radar|dfs).*detect', 'DFS Radar Detected', 'Medium'),
    (r'channel.*(?:change|switch)|switching.*channel', 'Channel Change', 'Medium'),
    (r'interference.*detect|detected.*interference', 'Interference Detected', 'Medium'),
    (r'access.*(?:granted|allowed).*(?:after|outside).*hours', 'After Hours Access', 'Medium'),
    (r'certificate.*(?:expir|warn|invalid)', 'Certificate Warning', 'Medium'),
    (r'high.*utilization|bandwidth.*threshold', 'High Utilization', 'Medium'),
    (r'uplink.*(?:change|failover)', 'Uplink Failover', 'Medium'),
    (r'radius.*(?:timeout|fail|reject)', 'RADIUS Issue', 'Medium'),
    (r'wpa.*(?:timeout|fail|handshake)', 'WPA Handshake Issue', 'Medium'),

    # Low severity events - WiFi/AP specific (must be before generic patterns)
    (r'failed to find.*node|node.*not found', 'Client Lookup Failed', 'Low'),
    (r'ieee80211.*deauth|deauthentication', 'Client Deauth', 'Low'),
    (r'ieee80211.*disassoc|disassociation', 'Client Disassociation', 'Low'),
    (r'sta.*(?:leave|left|timeout)', 'Station Left', 'Low'),
    (r'tag_guest|guest.*tag', 'Guest Tagging', 'Low'),
    (r'aid\s*\d+|association.*id', 'Association Event', 'Low'),
    (r'ieee80211_ioctl|ioctl.*ieee80211', 'Wireless IOCTL', 'Low'),
    (r'wlan\d*:.*sta|sta.*wlan', 'Wireless Station Event', 'Low'),
    (r'hostapd.*sta|sta.*hostapd', 'Hostapd Station Event', 'Low'),
    (r'(?:11[abnghac]{1,2}|wifi\d?).*(?:assoc|auth)', 'WiFi Association', 'Low'),
    (r'beacon.*(?:loss|miss)|missed.*beacon', 'Beacon Loss', 'Low'),
    (r'signal.*(?:low|weak)|weak.*signal', 'Weak Signal', 'Low'),
    (r'retry.*(?:limit|exceed)|excessive.*retry', 'Retry Limit', 'Low'),
    (r'kernel:.*ubnt_|ubnt_.*kernel', 'UniFi Kernel Event', 'Low'),
    (r'mcad|wevent|stamgr|cfgmtd', 'UniFi System Process', 'Low'),

    # Generic low severity events
    (r'access.*granted|door.*unlock', 'Access Granted', 'Low'),
    (r'firmware.*(?:update|upgrade).*(?:complete|success)', 'Firmware Updated', 'Low'),
    (r'client.*(?:connect|associate|join)', 'Client Connected', 'Low'),
    (r'client.*(?:disconnect|disassociate|leave)', 'Client Disconnected', 'Low'),
    (r'backup.*(?:complete|success)', 'Backup Completed', 'Low'),
    (r'dhcp.*(?:lease|assign)', 'DHCP Lease', 'Low'),
    (r'speed\s*test|speedtest', 'Speed Test', 'Low'),
    (r'system.*(?:boot|start|restart)', 'System Boot', 'Low'),
    (r'adoption.*(?:complete|success)', 'Device Adopted', 'Low'),
]

def classify_unifi_event(log_content: str) -> Optional[Dict[str, str]]:
    """Pre-classify UniFi events based on known patterns. Returns None if no match."""
    log_lower = log_content.lower()
    for pattern, event_type, severity in UNIFI_EVENT_PATTERNS:
        if re.search(pattern, log_lower):
            return {"event_type": event_type, "severity_hint": severity}
    return None

def parse_cef_message(message: str) -> Optional[Dict[str, Any]]:
    """
    Parse CEF (Common Event Format) messages.
    Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

    UniFi devices send CEF with custom extensions like:
    - UNIFIdeviceIp: The REAL source IP of the device
    - UNIFIdeviceName: The device hostname
    - UNIFIdeviceModel: Device model (UCKP, UAP, USW, etc.)
    - UNIFIdeviceMac: Device MAC address
    """
    # Find CEF header in message
    cef_match = re.search(r'CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)', message)
    if not cef_match:
        return None

    result = {
        "cef_version": cef_match.group(1),
        "vendor": cef_match.group(2),
        "product": cef_match.group(3),
        "product_version": cef_match.group(4),
        "signature_id": cef_match.group(5),
        "event_name": cef_match.group(6),
        "cef_severity": cef_match.group(7),
        "extensions": {}
    }

    # Parse extension key=value pairs
    extension_str = cef_match.group(8)

    # CEF extensions can have spaces in values, so we need careful parsing
    # Pattern: key=value where value continues until next key= or end
    ext_pattern = r'(\w+)=((?:[^=](?!\w+=))*[^=\s])'
    for match in re.finditer(ext_pattern, extension_str):
        key = match.group(1)
        value = match.group(2).strip()
        result["extensions"][key] = value

    # Also try simpler space-separated parsing for UniFi format
    # UNIFIhost=Host UNIFIdeviceName=SVD-AC-15427
    simple_pattern = r'(\w+)=(\S+)'
    for match in re.finditer(simple_pattern, extension_str):
        key = match.group(1)
        value = match.group(2)
        if key not in result["extensions"]:
            result["extensions"][key] = value

    return result

# UniFi device model to type mapping
UNIFI_MODEL_TYPES = {
    "UCKP": "UniFi Cloud Key Plus",
    "UCK": "UniFi Cloud Key",
    "UCKGEN2": "UniFi Cloud Key Gen2",
    "UCKGEN2PLUS": "UniFi Cloud Key Gen2 Plus",
    "UDM": "UniFi Dream Machine",
    "UDMPRO": "UniFi Dream Machine Pro",
    "UDMSE": "UniFi Dream Machine SE",
    "UDMPROMAX": "UniFi Dream Machine Pro Max",
    "UAP": "UniFi Access Point",
    "UAPAC": "UniFi AP AC",
    "UAPHD": "UniFi AP HD",
    "USW": "UniFi Switch",
    "USG": "UniFi Security Gateway",
    "USGPRO": "UniFi Security Gateway Pro",
    "UXG": "UniFi Next-Gen Gateway",
    "UNVR": "UniFi NVR",
    "UNVRPRO": "UniFi NVR Pro",
    "UAHUB": "UniFi Access Hub",
    "UAREADER": "UniFi Access Reader",
    "UALITE": "UniFi Access Lite",
    "UAPRO": "UniFi Access Pro",
}

def parse_syslog_message(data: bytes, source_addr: tuple) -> Dict[str, Any]:
    """Parse a syslog message (RFC 3164, RFC 5424, or CEF format)."""
    try:
        message = data.decode('utf-8', errors='replace').strip()
    except Exception:
        message = str(data)

    result = {
        "raw_message": message,
        "source_ip": source_addr[0],  # UDP source (may be NAT gateway)
        "source_port": source_addr[1],
        "real_device_ip": None,       # Actual device IP from CEF/log content
        "real_device_mac": None,      # Device MAC if available
        "facility": None,
        "facility_name": None,
        "syslog_severity": None,
        "syslog_severity_name": None,
        "severity": "Medium",
        "timestamp": None,
        "hostname": None,
        "program": None,
        "pid": None,
        "content": message,
        "device_type": "Syslog Device",
        "device_model": None,
        "cef_data": None,
    }

    # Parse priority (PRI) field: <priority>
    pri_match = re.match(r'^<(\d{1,3})>', message)
    if pri_match:
        priority = int(pri_match.group(1))
        result["facility"] = priority >> 3
        result["syslog_severity"] = priority & 0x07
        result["facility_name"] = SYSLOG_FACILITIES.get(result["facility"], f"facility{result['facility']}")
        result["syslog_severity_name"] = SYSLOG_SEVERITIES.get(result["syslog_severity"], "Unknown")
        result["severity"] = SYSLOG_TO_SEVERITY.get(result["syslog_severity"], "Medium")
        message = message[pri_match.end():]

    # Try RFC 5424 format first: VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID
    rfc5424_match = re.match(
        r'^(\d+)\s+'  # Version
        r'(\d{4}-\d{2}-\d{2}T[\d:.]+(Z|[+-]\d{2}:\d{2})?|-)\s+'  # Timestamp
        r'(\S+)\s+'  # Hostname
        r'(\S+)\s+'  # App-name
        r'(\S+)\s+'  # Procid
        r'(\S+)\s*'  # Msgid
        r'(.*)',  # Message
        message
    )

    if rfc5424_match:
        result["timestamp"] = rfc5424_match.group(2) if rfc5424_match.group(2) != '-' else None
        result["hostname"] = rfc5424_match.group(4) if rfc5424_match.group(4) != '-' else None
        result["program"] = rfc5424_match.group(5) if rfc5424_match.group(5) != '-' else None
        pid_str = rfc5424_match.group(6)
        result["pid"] = pid_str if pid_str != '-' else None
        result["content"] = rfc5424_match.group(8).strip()
    else:
        # Try RFC 3164 format: TIMESTAMP HOSTNAME TAG: MSG
        # Timestamp formats: "Mon DD HH:MM:SS" or "Mon  D HH:MM:SS"
        rfc3164_match = re.match(
            r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'  # Timestamp
            r'(\S+)\s+'  # Hostname
            r'(\S+?)(?:\[(\d+)\])?:\s*'  # Program[PID]:
            r'(.*)',  # Message
            message,
            re.IGNORECASE
        )

        if rfc3164_match:
            result["timestamp"] = rfc3164_match.group(1)
            result["hostname"] = rfc3164_match.group(2)
            result["program"] = rfc3164_match.group(3)
            result["pid"] = rfc3164_match.group(4)
            result["content"] = rfc3164_match.group(5).strip()
        else:
            # Fallback: just use the whole message as content
            result["content"] = message

    # Parse CEF (Common Event Format) if present - this gives us the REAL device info
    cef_data = parse_cef_message(message)
    if cef_data:
        result["cef_data"] = cef_data
        ext = cef_data.get("extensions", {})

        # Extract the REAL device IP (not the NAT gateway)
        real_ip = ext.get("UNIFIdeviceIp") or ext.get("deviceIp") or ext.get("src") or ext.get("sourceAddress")
        if real_ip:
            result["real_device_ip"] = real_ip

        # Extract the REAL hostname
        real_hostname = ext.get("UNIFIdeviceName") or ext.get("deviceName") or ext.get("dvchost") or ext.get("sourceHostName")
        if real_hostname:
            result["hostname"] = real_hostname

        # Extract MAC address
        real_mac = ext.get("UNIFIdeviceMac") or ext.get("deviceMac") or ext.get("sourceMacAddress")
        if real_mac:
            result["real_device_mac"] = real_mac

        # Extract device model
        model = ext.get("UNIFIdeviceModel") or ext.get("deviceModel")
        if model:
            result["device_model"] = model
            # Map model code to device type
            model_upper = model.upper().replace("-", "").replace("_", "")
            for code, dtype in UNIFI_MODEL_TYPES.items():
                if code in model_upper:
                    result["device_type"] = dtype
                    break

        # Get event name from CEF
        if cef_data.get("event_name"):
            result["cef_event_name"] = cef_data["event_name"]

        # Get the actual message content
        msg_content = ext.get("msg") or ext.get("message") or ext.get("reason")
        if msg_content:
            result["content"] = msg_content

        # Set vendor info
        if cef_data.get("vendor"):
            result["vendor"] = cef_data["vendor"]

    # Detect UniFi device type from hostname or message (if not already set from CEF)
    if result["device_type"] == "Syslog Device":
        search_text = f"{result.get('hostname', '')} {result.get('program', '')} {result.get('content', '')}"
        for pattern, device_type in UNIFI_DEVICE_PATTERNS.items():
            if re.search(pattern, search_text, re.IGNORECASE):
                result["device_type"] = device_type
                break

    # Pre-classify UniFi events
    event_class = classify_unifi_event(result.get("content", ""))
    if event_class:
        result["event_hint"] = event_class["event_type"]
        result["severity_hint"] = event_class["severity_hint"]

    return result

def format_syslog_for_storage(parsed: Dict[str, Any]) -> str:
    """Format parsed syslog data as a structured log entry for the database."""
    parts = []

    if parsed.get("timestamp"):
        parts.append(f"timestamp={parsed['timestamp']}")
    if parsed.get("hostname"):
        parts.append(f"host={parsed['hostname']}")

    # Use real device IP if available (from CEF), otherwise use UDP source
    # This is critical for SOC - we need the ACTUAL source, not NAT gateway
    if parsed.get("real_device_ip"):
        parts.append(f"device_ip={parsed['real_device_ip']}")
        # Also keep NAT source for audit trail
        if parsed.get("source_ip") and parsed["source_ip"] != parsed["real_device_ip"]:
            parts.append(f"nat_src={parsed['source_ip']}")
    elif parsed.get("source_ip"):
        parts.append(f"src_ip={parsed['source_ip']}")

    # Include MAC address if available
    if parsed.get("real_device_mac"):
        parts.append(f"mac={parsed['real_device_mac']}")

    # Include device model
    if parsed.get("device_model"):
        parts.append(f"model={parsed['device_model']}")
    if parsed.get("device_type") and parsed["device_type"] != "Syslog Device":
        parts.append(f"device_type={parsed['device_type']}")
    if parsed.get("facility_name"):
        parts.append(f"facility={parsed['facility_name']}")
    if parsed.get("syslog_severity_name"):
        parts.append(f"syslog_severity={parsed['syslog_severity_name']}")
    if parsed.get("program"):
        parts.append(f"program={parsed['program']}")
    if parsed.get("pid"):
        parts.append(f"pid={parsed['pid']}")

    # Add event classification hints for LLM
    if parsed.get("event_hint"):
        parts.append(f"event_hint={parsed['event_hint']}")
    if parsed.get("severity_hint"):
        parts.append(f"severity_hint={parsed['severity_hint']}")

    # Add the actual message content
    parts.append(f"message={parsed.get('content', parsed.get('raw_message', ''))}")

    return " | ".join(parts)

def handle_syslog_message(data: bytes, addr: tuple):
    """Process a single syslog message and store it in the database."""
    try:
        parsed = parse_syslog_message(data, addr)
        formatted_log = format_syslog_for_storage(parsed)

        if formatted_log.strip():
            # Determine if this log needs LLM analysis or should go straight to live feed
            # Info-level logs (Low severity, informational syslog) skip analysis
            severity_hint = parsed.get("severity_hint", "").lower()
            syslog_sev = parsed.get("syslog_severity", 99)  # 5=Notice, 6=Info, 7=Debug

            # Skip analysis for low-severity/informational logs
            skip_analysis = (
                severity_hint == "low" or
                syslog_sev >= 5 or  # Notice, Informational, Debug
                parsed.get("event_hint") in ["Access Granted", "Client Connected", "Client Disconnected",
                                              "Backup Completed", "DHCP Lease", "Speed Test",
                                              "System Boot", "Device Adopted", "Firmware Updated"]
            )

            if skip_analysis:
                # Mark as INFO - goes straight to live feed, no LLM analysis
                status = 'INFO'
                severity = parsed.get("severity_hint", "Info") or "Info"
                event_type = parsed.get("event_hint", "Informational")
                summary = parsed.get("content", "")[:150] if parsed.get("content") else ""
            else:
                # Mark as PENDING - will be analyzed by LLM
                status = 'PENDING'
                severity = None
                event_type = None
                summary = None

            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"INSERT INTO raw_logs (timestamp, raw_log, status, host, severity, event_type, ai_summary) "
                    f"VALUES ({sql_param()}, {sql_param()}, {sql_param()}, {sql_param()}, {sql_param()}, {sql_param()}, {sql_param()})",
                    (datetime.datetime.now().isoformat(), formatted_log, status, parsed.get('hostname'),
                     severity, event_type, summary)
                )
                conn.commit()

            update_global_counts()
            log_status = "INFO (live feed)" if skip_analysis else "PENDING (analysis)"
            logger.debug(f"Syslog [{log_status}] from {addr[0]}: {parsed.get('hostname', 'unknown')} - {parsed.get('device_type', 'unknown')}")

    except Exception as e:
        logger.error(f"Error processing syslog message from {addr}: {e}")

def syslog_udp_listener():
    """UDP syslog listener thread for receiving logs from UniFi and other devices."""
    if not SYSLOG_ENABLED:
        logger.info("Syslog listener disabled")
        return

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST_IP, SYSLOG_UDP_PORT))
        sock.settimeout(1.0)
        logger.info(f"Syslog UDP listener started on {HOST_IP}:{SYSLOG_UDP_PORT}")

        while INGESTOR_RUNNING.is_set():
            try:
                data, addr = sock.recvfrom(65535)
                if data:
                    handle_syslog_message(data, addr)
            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"Syslog UDP receive error: {e}")

    except PermissionError:
        logger.error(f"Permission denied binding to UDP port {SYSLOG_UDP_PORT}. "
                    f"Ports below 1024 require root. Try SYSLOG_UDP_PORT=1514 or run with elevated privileges.")
    except Exception as e:
        logger.error(f"Syslog UDP listener error: {e}")
    finally:
        try:
            sock.close()
        except:
            pass

def handle_syslog_tcp_connection(conn, addr):
    """Handle a TCP syslog connection (for devices that send syslog over TCP)."""
    buffer = b""
    try:
        while INGESTOR_RUNNING.is_set():
            data = conn.recv(4096)
            if not data:
                break

            buffer += data

            # Process complete messages (newline or null delimited)
            while b'\n' in buffer or b'\x00' in buffer:
                # Find the first delimiter
                newline_pos = buffer.find(b'\n')
                null_pos = buffer.find(b'\x00')

                if newline_pos >= 0 and (null_pos < 0 or newline_pos < null_pos):
                    delim_pos = newline_pos
                elif null_pos >= 0:
                    delim_pos = null_pos
                else:
                    break

                message = buffer[:delim_pos]
                buffer = buffer[delim_pos + 1:]

                if message.strip():
                    handle_syslog_message(message, addr)

    except Exception as e:
        logger.error(f"Syslog TCP connection error from {addr}: {e}")
    finally:
        conn.close()

def syslog_tcp_listener():
    """TCP syslog listener thread for devices that send syslog over TCP."""
    if not SYSLOG_ENABLED or not SYSLOG_TCP_ENABLED:
        return

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST_IP, SYSLOG_TCP_PORT))
        sock.listen(10)
        sock.settimeout(1.0)
        logger.info(f"Syslog TCP listener started on {HOST_IP}:{SYSLOG_TCP_PORT}")

        while INGESTOR_RUNNING.is_set():
            try:
                conn, addr = sock.accept()
                threading.Thread(
                    target=handle_syslog_tcp_connection,
                    args=(conn, addr),
                    daemon=True
                ).start()
            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"Syslog TCP accept error: {e}")

    except PermissionError:
        logger.error(f"Permission denied binding to TCP port {SYSLOG_TCP_PORT}. "
                    f"Ports below 1024 require root. Try SYSLOG_TCP_PORT=1514 or run with elevated privileges.")
    except Exception as e:
        logger.error(f"Syslog TCP listener error: {e}")
    finally:
        try:
            sock.close()
        except:
            pass

# ==============================================================================
# 10. Log Processor
# ==============================================================================
def check_conditional_rules(raw_log: str, log_hash: str, host: str, source_ip: str) -> Optional[Dict[str, Any]]:
    """Check if any conditional severity rules apply to this log."""
    with get_db() as conn:
        cursor = conn.cursor()

        # Get all active conditional rules for this pattern
        cursor.execute("""
            SELECT id, original_severity, corrected_severity, reason,
                   host_filter, ip_filter, expires_at, exclude_hosts, times_applied
            FROM ai_knowledge_conditions
            WHERE pattern_hash = ? AND is_active = 1
            ORDER BY created_at DESC
        """, (log_hash,))

        rules = cursor.fetchall()

        for rule in rules:
            rule_id, orig_sev, new_sev, reason, host_filter, ip_filter, expires_at, exclude_hosts, times_applied = rule

            # Check expiration
            if expires_at:
                try:
                    expiry_date = datetime.datetime.fromisoformat(expires_at)
                    if datetime.datetime.now() > expiry_date:
                        # Rule expired, deactivate it
                        cursor.execute("UPDATE ai_knowledge_conditions SET is_active = 0 WHERE id = ?", (rule_id,))
                        conn.commit()
                        logger.info(f"Conditional rule {rule_id} expired, deactivating")
                        continue
                except:
                    pass

            # Check exclude_hosts
            if exclude_hosts:
                excluded = [h.strip().lower() for h in exclude_hosts.split(',')]
                if host and host.lower() in excluded:
                    logger.info(f"Host {host} is excluded from rule {rule_id}")
                    continue

            # Check host_filter
            if host_filter:
                allowed_hosts = [h.strip().lower() for h in host_filter.split(',')]
                if host and host.lower() not in allowed_hosts:
                    continue  # Host doesn't match filter

            # Check ip_filter
            if ip_filter:
                allowed_ips = [ip.strip() for ip in ip_filter.split(',')]
                if source_ip and source_ip not in allowed_ips:
                    continue  # IP doesn't match filter

            # Rule matches! Update counter and return
            cursor.execute("""
                UPDATE ai_knowledge_conditions
                SET times_applied = times_applied + 1, updated_at = ?
                WHERE id = ?
            """, (datetime.datetime.now().isoformat(), rule_id))
            conn.commit()

            logger.info(f"Applied conditional rule {rule_id} (applied {times_applied + 1} times)")
            return {
                "severity": new_sev,
                "original_severity": orig_sev,
                "event_type": "Conditional Rule",
                "summary": f"Severity adjusted by conditional rule. Reason: {reason}",
                "analyzed_by": "conditional_rule",
                "rule_id": rule_id
            }

        return None

def analyze_logic(raw_log: str, host: str = None, source_ip: str = None) -> Dict[str, Any]:
    """Analyze a log entry using knowledge base or LLM."""
    log_hash = get_log_hash(raw_log)

    # Extract IP from log if not provided
    if not source_ip:
        source_ip = extract_ip_from_log(raw_log)

    # First check conditional rules (with host/IP/expiry conditions)
    conditional_result = check_conditional_rules(raw_log, log_hash, host, source_ip)
    if conditional_result:
        return conditional_result

    # Then check basic knowledge base
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT corrected_severity, reason FROM ai_knowledge WHERE pattern_hash=?",
            (log_hash,)
        )
        learned = cursor.fetchone()

    if learned:
        logger.info(f"Using learned pattern for log hash: {log_hash[:8]}...")
        return {
            "severity": learned[0],
            "event_type": "Learned",
            "summary": f"AI recognized pattern. Reason: {learned[1]}",
            "analyzed_by": "knowledge_base"
        }

    logger.info("Analyzing with LLM...")
    analysis = analyze_with_llm(raw_log)
    analysis["analyzed_by"] = "llm"

    return analysis

def processor_loop():
    """Main processing loop for ingesting and analyzing logs."""
    BATCH_SIZE = 5
    SLEEP_WHEN_EMPTY = 3
    MAX_RETRIES = 3

    logger.info("🚀 Processor loop started")

    while INGESTOR_RUNNING.is_set():
        try:
            # Fetch pending logs (include existing host to preserve it)
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT id, raw_log, host FROM raw_logs WHERE status='PENDING' LIMIT ?",
                    (BATCH_SIZE,)
                )
                rows = cursor.fetchall()

            if not rows:
                set_processor_active(False)
                time.sleep(SLEEP_WHEN_EMPTY)
                continue

            set_processor_active(True)
            logger.info(f"📦 Processing {len(rows)} pending logs...")

            # Process each log
            for row in rows:
                log_id = row['id']
                raw_log = row['raw_log']
                existing_host = row['host']  # Preserve host set during ingestion

                # Try processing with retries
                for attempt in range(1, MAX_RETRIES + 1):
                    try:
                        logger.info(f"🔍 Analyzing log {log_id} (attempt {attempt}/{MAX_RETRIES})...")

                        # Use existing host if set, otherwise extract from log
                        extracted_host = existing_host if existing_host else extract_host_from_log(raw_log)
                        source_ip = extract_ip_from_log(raw_log)

                        # Measure processing time
                        start_time = time.time()

                        # Check if this is an info-level log (bypasses AI)
                        if is_info_level_log(raw_log):
                            analysis = {
                                "severity": "Info",
                                "event_type": "Informational",
                                "summary": "Routine system log (auto-classified)",
                                "analyzed_by": "info_filter"
                            }
                        else:
                            # Analyze the log with host context for conditional rules
                            analysis = analyze_logic(raw_log, host=extracted_host, source_ip=source_ip)

                        # Calculate processing time in milliseconds
                        processing_time_ms = int((time.time() - start_time) * 1000)

                        # Enrich analysis with metadata
                        analysis.update({
                            "raw_log": raw_log,
                            "@timestamp": datetime.datetime.now().isoformat(),
                            "db_id": log_id,
                            "host": extracted_host,
                            "processing_time_ms": processing_time_ms
                        })

                        # Index to OpenSearch (non-blocking)
                        try:
                            index_to_opensearch(analysis)
                            logger.debug(f"✓ Indexed log {log_id} to OpenSearch")
                        except Exception as es_error:
                            logger.warning(f"⚠️ OpenSearch skip: {es_error}")

                        # Mark as processed in database with all analysis results
                        with get_db() as conn_upd:
                            cursor_upd = conn_upd.cursor()
                            cursor_upd.execute(
                                """UPDATE raw_logs
                                   SET status='PROCESSED',
                                       processed_at=?,
                                       severity=?,
                                       event_type=?,
                                       ai_summary=?,
                                       analyzed_by=?,
                                       host=?,
                                       processing_time_ms=?,
                                       original_severity=?
                                   WHERE id=?""",
                                (
                                    datetime.datetime.now().isoformat(),
                                    analysis.get('severity', 'Unknown'),
                                    analysis.get('event_type', 'Unknown'),
                                    analysis.get('summary', 'No summary'),
                                    analysis.get('analyzed_by', 'llm'),
                                    extracted_host,
                                    processing_time_ms,
                                    analysis.get('original_severity'),
                                    log_id
                                )
                            )
                            conn_upd.commit()

                        # Log processing time for visibility
                        analyzer = analysis.get('analyzed_by', 'llm')
                        logger.info(f"⏱️ Log {log_id} processed in {processing_time_ms}ms by {analyzer}")

                        # Update global counts
                        update_global_counts()

                        # NEW: Enrich alert with threat intelligence and context
                        try:
                            severity = analysis.get('severity', 'Unknown')
                            event_type = analysis.get('event_type', 'Unknown')
                            enrich_alert(log_id, raw_log, severity, event_type, extracted_host)
                            logger.debug(f"✓ Enriched log {log_id} with threat intelligence")
                        except Exception as enrich_error:
                            logger.warning(f"⚠️ Alert enrichment failed for log {log_id}: {enrich_error}")

                        # Log success
                        logger.info(f"✅ Processed log {log_id} - {severity} - {event_type} - Host: {extracted_host}")

                        break  # Success - exit retry loop

                    except Exception as e:
                        logger.error(f"❌ Error processing log {log_id} (attempt {attempt}/{MAX_RETRIES}): {e}")

                        if attempt == MAX_RETRIES:
                            # Final attempt failed - mark as error
                            try:
                                with get_db() as conn_err:
                                    cursor_err = conn_err.cursor()
                                    cursor_err.execute(
                                        "UPDATE raw_logs SET status='ERROR' WHERE id=?",
                                        (log_id,)
                                    )
                                    cursor_err.execute(
                                        "INSERT INTO processing_errors (log_id, error_message) VALUES (?, ?)",
                                        (log_id, str(e))
                                    )
                                    conn_err.commit()
                                update_global_counts()
                                logger.error(f"💀 Log {log_id} failed after {MAX_RETRIES} attempts")
                            except Exception as db_error:
                                logger.error(f"Failed to record error for log {log_id}: {db_error}")
                        else:
                            # Wait before retry (exponential backoff)
                            time.sleep(2 ** attempt)

            # NEW: Run correlation engine after each batch
            try:
                run_correlation_engine()
                logger.debug("✓ Correlation engine executed")
            except Exception as corr_error:
                logger.warning(f"⚠️ Correlation engine error: {corr_error}")

        except KeyboardInterrupt:
            logger.info("⚠️ Processor loop interrupted by user")
            break
        except Exception as e:
            logger.error(f"❌ Critical error in processor loop: {e}")
            time.sleep(5)

    logger.info("🛑 Processor loop stopped")

# ==============================================================================
# 11. Pydantic Models
# ==============================================================================
# 11.5. Authentication Pydantic Models
# ==============================================================================
class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6, max_length=100)

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: Dict[str, Any]

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class UserResponse(BaseModel):
    id: int
    username: str
    full_name: Optional[str]
    email: Optional[str]
    is_admin: bool

# ==============================================================================
class ChatRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=1000)

class FeedbackRequest(BaseModel):
    log_id: int = Field(..., gt=0)
    new_severity: str = Field(..., pattern="^(Low|Medium|High|Critical)$")
    reason: str = Field(..., min_length=5, max_length=500)

class ConditionalFeedbackRequest(BaseModel):
    log_id: int = Field(..., gt=0)
    new_severity: str = Field(..., pattern="^(Low|Medium|High|Critical)$")
    reason: str = Field(..., min_length=5, max_length=500)
    host_filter: Optional[str] = Field(None, description="Comma-separated list of hosts to apply this rule to")
    ip_filter: Optional[str] = Field(None, description="Comma-separated list of IPs to apply this rule to")
    expires_in_days: Optional[int] = Field(None, ge=1, le=365, description="Number of days until this rule expires")
    exclude_hosts: Optional[str] = Field(None, description="Comma-separated list of hosts to exclude from this rule")

class ActionChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=1000)
    context: Dict[str, Any] = Field(default_factory=dict, description="Context including current_tab, log_id, host, severity, ip")

# ==============================================================================
# 12. API Endpoints
# ==============================================================================
@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    if not os.path.exists('templates'):
        os.makedirs('templates')

    if not os.path.exists('templates/dashboard.html'):
        raise HTTPException(status_code=404, detail="Dashboard template not found")

    return FileResponse('templates/dashboard.html')

# ==============================================================================
# 12.1. Authentication Endpoints
# ==============================================================================
@app.post("/api/auth/login", response_model=TokenResponse)
@limiter.limit("5/minute")
async def login(request: Request, login_data: LoginRequest):
    """
    Authenticate user and return JWT tokens.
    Rate limited to 5 attempts per minute per IP address.
    Includes account lockout and password policy enforcement.
    """
    client_ip = get_remote_address(request)

    # Authenticate user (now returns dict with error info or user info)
    result = authenticate_user(login_data.username, login_data.password)

    # Check for authentication errors
    if "error" in result:
        # Record failed login attempt
        record_login_attempt(login_data.username, client_ip, False)

        # Add a small delay to prevent timing attacks
        await asyncio.sleep(0.5)

        error_code = result["error"]
        if error_code == "account_locked":
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail=result["message"],
                headers={"WWW-Authenticate": "Bearer"},
            )
        elif error_code == "account_disabled":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=result["message"],
                headers={"WWW-Authenticate": "Bearer"},
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

    user = result

    # Record successful login attempt
    record_login_attempt(login_data.username, client_ip, True)

    # Create tokens
    access_token = create_access_token(data={"sub": user["username"]})
    refresh_token_str = create_refresh_token(data={"sub": user["username"]})

    # Create session record
    user_agent = request.headers.get("User-Agent", "Unknown")
    session_id = create_session(user['id'], access_token, refresh_token_str, client_ip, user_agent)
    if session_id:
        logger.debug(f"Created session {session_id} for user {user['username']}")

    logger.info(f"User {user['username']} logged in from {client_ip}")
    record_audit(user['id'], user['username'], 'login', 'session', str(session_id), None, client_ip)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token_str,
        "token_type": "bearer",
        "user": user
    }

@app.post("/api/auth/refresh", response_model=TokenResponse)
async def refresh_token(request: Request, token_data: RefreshTokenRequest):
    """
    Refresh an access token using a refresh token.
    Validates the refresh token against active sessions.
    """
    try:
        payload = jwt.decode(token_data.refresh_token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        token_type: str = payload.get("type")

        if username is None or token_type != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
            )

        with get_db() as conn:
            cursor = conn.cursor()
            param = "%s" if DB_TYPE == "postgresql" else "?"
            bool_true = "TRUE" if DB_TYPE == "postgresql" else "1"
            bool_false = "FALSE" if DB_TYPE == "postgresql" else "0"

            # Verify refresh token is associated with an active session
            refresh_hash = hashlib.sha256(token_data.refresh_token.encode()).hexdigest()
            cursor.execute(f"""
                SELECT s.id, s.user_id FROM user_sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.refresh_token_hash = {param} AND s.is_active = {bool_true}
                  AND u.username = {param}
            """, (refresh_hash, username))
            session = cursor.fetchone()

            if not session:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Session expired or revoked. Please login again.",
                )

            session_id = session[0] if isinstance(session, tuple) else session['id']

            cursor.execute(f"""
                SELECT id, username, full_name, email, is_admin
                FROM users WHERE username = {param} AND is_active = {bool_true}
            """, (username,))
            user = cursor.fetchone()

            if user is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found",
                )

            user_dict = {
                "id": user[0] if isinstance(user, tuple) else user['id'],
                "username": user[1] if isinstance(user, tuple) else user['username'],
                "full_name": user[2] if isinstance(user, tuple) else user['full_name'],
                "email": user[3] if isinstance(user, tuple) else user['email'],
                "is_admin": bool(user[4] if isinstance(user, tuple) else user['is_admin'])
            }

            # Create new tokens
            access_token = create_access_token(data={"sub": username})
            new_refresh_token = create_refresh_token(data={"sub": username})

            # Update session with new token hashes
            new_access_hash = hashlib.sha256(access_token.encode()).hexdigest()
            new_refresh_hash = hashlib.sha256(new_refresh_token.encode()).hexdigest()
            cursor.execute(f"""
                UPDATE user_sessions SET session_token_hash = {param},
                       refresh_token_hash = {param},
                       last_activity = {'NOW()' if DB_TYPE == 'postgresql' else 'CURRENT_TIMESTAMP'}
                WHERE id = {param}
            """, (new_access_hash, new_refresh_hash, session_id))
            conn.commit()

            return {
                "access_token": access_token,
                "refresh_token": new_refresh_token,
                "token_type": "bearer",
                "user": user_dict
            }
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

@app.post("/api/auth/logout")
async def logout(request: Request,
                 credentials: HTTPAuthorizationCredentials = Depends(security),
                 current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Logout endpoint - revokes the current session server-side.
    """
    client_ip = get_remote_address(request)
    current_token = credentials.credentials

    # Revoke the session
    revoked = revoke_session(current_token)
    if revoked:
        logger.info(f"User {current_user['username']} logged out (session revoked) from {client_ip}")
    else:
        logger.info(f"User {current_user['username']} logged out from {client_ip}")

    record_audit(current_user['id'], current_user['username'], 'logout', 'session', None, None, client_ip)
    return {"message": "Successfully logged out"}

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

@app.post("/api/auth/change-password")
@limiter.limit("5/minute")
async def change_password(request: Request, password_data: ChangePasswordRequest,
                          current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Change the current user's password.
    Validates against password policy and updates password_changed_at.
    """
    client_ip = get_remote_address(request)

    # Validate new password against policy
    is_valid, error_msg = validate_password_policy(password_data.new_password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password does not meet requirements: {error_msg}"
        )

    # Verify current password
    with get_db() as conn:
        cursor = conn.cursor()
        param = "%s" if DB_TYPE == "postgresql" else "?"
        cursor.execute(f"SELECT password_hash FROM users WHERE id = {param}", (current_user['id'],))
        result = cursor.fetchone()

        if not result or not verify_password(password_data.current_password, result[0]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Current password is incorrect"
            )

        # Update password
        new_hash = get_password_hash(password_data.new_password)
        if DB_TYPE == "postgresql":
            cursor.execute("""
                UPDATE users SET password_hash = %s, password_changed_at = NOW(),
                       must_change_password = FALSE WHERE id = %s
            """, (new_hash, current_user['id']))
        else:
            cursor.execute("""
                UPDATE users SET password_hash = ?, password_changed_at = CURRENT_TIMESTAMP,
                       must_change_password = 0 WHERE id = ?
            """, (new_hash, current_user['id']))
        conn.commit()

    logger.info(f"User {current_user['username']} changed password from {client_ip}")
    record_audit(current_user['id'], current_user['username'], 'password_change',
                 'user', str(current_user['id']), None, client_ip)

    return {"message": "Password changed successfully"}

@app.get("/api/auth/password-policy")
async def get_password_policy():
    """Return the current password policy requirements"""
    return {
        "min_length": PASSWORD_MIN_LENGTH,
        "require_uppercase": PASSWORD_REQUIRE_UPPERCASE,
        "require_lowercase": PASSWORD_REQUIRE_LOWERCASE,
        "require_digit": PASSWORD_REQUIRE_DIGIT,
        "require_special": PASSWORD_REQUIRE_SPECIAL,
        "expiry_days": PASSWORD_EXPIRY_DAYS
    }

@app.get("/api/auth/sessions")
async def list_sessions(current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    List all active sessions for the current user.
    Returns session details including IP address, user agent, and activity times.
    """
    sessions = get_active_sessions(current_user['id'])
    return {
        "sessions": sessions,
        "max_concurrent_sessions": MAX_CONCURRENT_SESSIONS
    }

@app.delete("/api/auth/sessions/{session_id}")
async def revoke_session_by_id(session_id: int, request: Request,
                               current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Revoke a specific session by ID.
    Users can only revoke their own sessions.
    """
    client_ip = get_remote_address(request)

    with get_db() as conn:
        cursor = conn.cursor()
        param = "%s" if DB_TYPE == "postgresql" else "?"
        bool_false = "FALSE" if DB_TYPE == "postgresql" else "0"

        # Verify session belongs to current user
        cursor.execute(f"""
            SELECT id FROM user_sessions
            WHERE id = {param} AND user_id = {param} AND is_active = {'TRUE' if DB_TYPE == 'postgresql' else '1'}
        """, (session_id, current_user['id']))

        if not cursor.fetchone():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found or already revoked"
            )

        # Revoke the session
        cursor.execute(f"""
            UPDATE user_sessions SET is_active = {bool_false},
                   revoked_at = {'NOW()' if DB_TYPE == 'postgresql' else 'CURRENT_TIMESTAMP'}
            WHERE id = {param}
        """, (session_id,))
        conn.commit()

    logger.info(f"User {current_user['username']} revoked session {session_id} from {client_ip}")
    record_audit(current_user['id'], current_user['username'], 'session_revoke',
                 'session', str(session_id), None, client_ip)

    return {"message": "Session revoked successfully"}

@app.post("/api/auth/sessions/revoke-all")
async def revoke_all_sessions(request: Request,
                              credentials: HTTPAuthorizationCredentials = Depends(security),
                              current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Revoke all sessions except the current one.
    Useful for "sign out everywhere else" functionality.
    """
    client_ip = get_remote_address(request)
    current_token = credentials.credentials

    count = revoke_all_user_sessions(current_user['id'], except_current=current_token)

    logger.info(f"User {current_user['username']} revoked {count} other sessions from {client_ip}")
    record_audit(current_user['id'], current_user['username'], 'session_revoke_all',
                 'session', None, f"Revoked {count} sessions", client_ip)

    return {"message": f"Revoked {count} other session(s)", "revoked_count": count}

@app.get("/api/auth/me", response_model=UserResponse)
async def get_current_user_info(current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Get current user information from JWT token.
    """
    return current_user

@app.get("/health")
async def health_check():
    checks = {
        "database": check_db_health(),
        "opensearch": check_opensearch_health(),
        "ollama": check_ollama_health(),
        "ingestor": INGESTOR_RUNNING.is_set()
    }

    status = "healthy" if all(checks.values()) else "unhealthy"

    return {
        "status": status,
        "timestamp": datetime.datetime.now().isoformat(),
        "checks": checks,
        "version": "2.0.0"
    }

@app.get("/api/dashboard-metrics")
@limiter.limit("120/minute")
async def get_metrics(request: Request, current_user: Dict[str, Any] = Depends(get_current_user)):
    active_alerts_count = 0
    es_status = "OFFLINE"
    threats_blocked = 0

    try:
        es = get_es_client()
        if es.ping():
            es_status = "ONLINE"

            alert_query = {
                "query": {
                    "terms": {
                        "severity.keyword": ["High", "Critical"]
                    }
                }
            }
            active_alerts_count = es.count(index=ES_INDEX, body=alert_query)['count']

            threat_query = {
                "query": {
                    "bool": {
                        "should": [
                            {"match": {"raw_log": "failed"}},
                            {"match": {"raw_log": "blocked"}},
                            {"match": {"raw_log": "denied"}},
                            {"match": {"raw_log": "brute"}},
                            {"match": {"raw_log": "attack"}}
                        ],
                        "minimum_should_match": 1
                    }
                }
            }
            threats_blocked = es.count(index=ES_INDEX, body=threat_query)['count']

    except Exception as e:
        logger.debug(f"Metrics OpenSearch error: {e}")
        es_status = "OFFLINE"

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM ai_knowledge")
        relearned_count = cursor.fetchone()[0]

    return {
        "pending": PENDING_LOGS_COUNT,
        "processed": PROCESSED_LOGS_COUNT,
        "total_logs": TOTAL_LOGS_COUNT,
        "active_alerts": active_alerts_count,
        "threats_blocked": threats_blocked,
        "relearned_logs": relearned_count,
        "llm_status": "ONLINE" if check_ollama_health() else "OFFLINE",
        "api_status": "ONLINE",
        "es_status": es_status
    }

@app.get("/api/analysis-status")
@limiter.limit("60/minute")
async def get_analysis_status(request: Request, current_user: Dict[str, Any] = Depends(get_current_user)):
    total = TOTAL_LOGS_COUNT
    processed = PROCESSED_LOGS_COUNT

    progress = 0 if total == 0 else round((processed / total) * 100, 1)

    return {
        "progress": progress,
        "total": total,
        "processed": processed,
        "pending": PENDING_LOGS_COUNT
    }

@app.get("/api/log-sources")
@limiter.limit("60/minute")
async def get_log_sources(request: Request, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get statistics about log sources (hosts/devices sending logs)."""
    with get_db() as conn:
        cursor = conn.cursor()

        # Get log counts by host
        cursor.execute("""
            SELECT host, COUNT(*) as count,
                   MIN(timestamp) as first_seen,
                   MAX(timestamp) as last_seen
            FROM raw_logs
            WHERE host IS NOT NULL AND host != ''
            GROUP BY host
            ORDER BY count DESC
            LIMIT 50
        """)
        hosts = cursor.fetchall()

        # Get total counts
        cursor.execute("SELECT COUNT(*) FROM raw_logs WHERE host IS NOT NULL AND host != ''")
        total_with_host = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM raw_logs WHERE host IS NULL OR host = ''")
        total_without_host = cursor.fetchone()[0]

        # Detect device types from log content
        device_stats = {}
        cursor.execute("""
            SELECT raw_log FROM raw_logs
            WHERE raw_log LIKE '%device_type=%'
            LIMIT 1000
        """)
        for row in cursor.fetchall():
            log = row[0]
            if 'device_type=' in log:
                match = re.search(r'device_type=([^|]+)', log)
                if match:
                    dtype = match.group(1).strip()
                    device_stats[dtype] = device_stats.get(dtype, 0) + 1

    return {
        "hosts": [
            {
                "hostname": row[0],
                "log_count": row[1],
                "first_seen": row[2],
                "last_seen": row[3]
            }
            for row in hosts
        ],
        "device_types": device_stats,
        "total_with_host": total_with_host,
        "total_without_host": total_without_host,
        "syslog_config": {
            "enabled": SYSLOG_ENABLED,
            "udp_port": SYSLOG_UDP_PORT,
            "tcp_enabled": SYSLOG_TCP_ENABLED,
            "tcp_port": SYSLOG_TCP_PORT if SYSLOG_TCP_ENABLED else None
        }
    }

@app.get("/api/logs")
@limiter.limit("100/minute")
async def get_logs(request: Request, panel: str = "Total Logs", current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get logs filtered by panel type."""
    
    # Try OpenSearch first for alerts and threats
    if panel in ["Active Alerts", "Threats Blocked"]:
        try:
            es = get_es_client()
            query = {
                "sort": [{"@timestamp": "desc"}],
                "size": 50
            }

            if panel == "Active Alerts":
                query["query"] = {
                    "terms": {
                        "severity.keyword": ["High", "Critical"]
                    }
                }
            elif panel == "Threats Blocked":
                query["query"] = {
                    "bool": {
                        "should": [
                            {"match": {"raw_log": "failed"}},
                            {"match": {"raw_log": "blocked"}},
                            {"match": {"raw_log": "denied"}},
                            {"match": {"raw_log": "brute"}},
                            {"match": {"raw_log": "attack"}},
                            {"match": {"raw_log": "malware"}},
                            {"match": {"raw_log": "intrusion"}}
                        ],
                        "minimum_should_match": 1
                    }
                }

            res = es.search(index=ES_INDEX, body=query)
            
            logs = []
            for hit in res["hits"]["hits"]:
                source = hit["_source"]
                logs.append({
                    "TLID": source.get("db_id", "N/A"),
                    "Raw Log": source.get("raw_log", ""),
                    "Timestamp": source.get("@timestamp", ""),
                    "Processed At": source.get("@timestamp", ""),
                    "Severity": source.get("severity", "Unknown"),
                    "Event Type": source.get("event_type", "Unknown"),
                    "HOST": source.get("host", "Unknown"),
                    "AI Summary": source.get("summary", "Analyzed")
                })
            
            return logs

        except Exception as e:
            logger.debug(f"OpenSearch unavailable, falling back to database: {e}")
    
    # Fallback to database
    with get_db() as conn:
        cursor = conn.cursor()
        
        if panel == "Active Alerts":
            cursor.execute("""
                SELECT 
                    id, raw_log, timestamp, processed_at,
                    severity, event_type, ai_summary, host
                FROM raw_logs 
                WHERE status='PROCESSED' 
                AND (severity='High' OR severity='Critical')
                ORDER BY processed_at DESC 
                LIMIT 100
            """)
        elif panel == "Threats Blocked":
            cursor.execute("""
                SELECT 
                    id, raw_log, timestamp, processed_at,
                    severity, event_type, ai_summary, host
                FROM raw_logs 
                WHERE status='PROCESSED' 
                AND (
                    raw_log LIKE '%failed%' 
                    OR raw_log LIKE '%blocked%'
                    OR raw_log LIKE '%denied%'
                    OR raw_log LIKE '%brute%'
                    OR raw_log LIKE '%attack%'
                    OR raw_log LIKE '%malware%'
                    OR raw_log LIKE '%intrusion%'
                )
                ORDER BY processed_at DESC 
                LIMIT 100
            """)
        else:
            return []
        
        rows = cursor.fetchall()
    
    return [{
        "TLID": row['id'],
        "Raw Log": row['raw_log'],
        "Timestamp": row['timestamp'],
        "Processed At": row['processed_at'],
        "Severity": row['severity'] or 'Unknown',
        "Event Type": row['event_type'] or 'Unknown',
        "HOST": row['host'] or 'Unknown',
        "AI Summary": row['ai_summary'] or 'Analyzed'
    } for row in rows]

@app.get("/api/logs-search")
@limiter.limit("100/minute")
async def search_logs(
    request: Request,
    query: str = None,
    severity: str = None,
    host: str = None,
    event_type: str = None,
    status: str = None,
    analyzed_by: str = None,
    date_from: str = None,
    date_to: str = None,
    limit: int = 100,
    offset: int = 0,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Search and filter logs with various criteria."""
    # Input validation
    if query and len(query) > 500:
        raise HTTPException(status_code=400, detail="Query too long (max 500 characters)")

    if query and re.search(r'[;\'"\\]|--|\*\*|UNION|SELECT|DROP|INSERT|DELETE|UPDATE', query, re.IGNORECASE):
        raise HTTPException(status_code=400, detail="Invalid characters in query")

    if severity:
        valid_severities = {'Low', 'Medium', 'High', 'Critical'}
        severities_list = [s.strip() for s in severity.split(',')]
        if not all(s in valid_severities for s in severities_list):
            raise HTTPException(status_code=400, detail="Invalid severity values")

    if host and len(host) > 255:
        raise HTTPException(status_code=400, detail="Host filter too long (max 255 characters)")

    if event_type and len(event_type) > 100:
        raise HTTPException(status_code=400, detail="Event type filter too long (max 100 characters)")

    if status and status not in ['PENDING', 'PROCESSED', 'FAILED']:
        raise HTTPException(status_code=400, detail="Invalid status value")

    if limit > 1000:
        raise HTTPException(status_code=400, detail="Limit too high (max 1000)")

    if offset < 0:
        raise HTTPException(status_code=400, detail="Offset cannot be negative")

    with get_db() as conn:
        cursor = conn.cursor()

        # Build dynamic query
        conditions = []
        params = []

        # Exclude INFO status by default - INFO logs are for Live Feed only
        # Security Event Search should only show PROCESSED, PENDING, and ERROR logs
        if status:
            conditions.append("status = ?")
            params.append(status)
        else:
            # Exclude INFO status when no specific status filter is applied
            conditions.append("status != 'INFO'")

        if query:
            conditions.append("(raw_log LIKE ? OR ai_summary LIKE ?)")
            params.extend([f"%{query}%", f"%{query}%"])

        if severity:
            severities = [s.strip() for s in severity.split(',')]
            placeholders = ','.join(['?' for _ in severities])
            conditions.append(f"severity IN ({placeholders})")
            params.extend(severities)

        if host:
            conditions.append("host LIKE ?")
            params.append(f"%{host}%")

        if event_type:
            conditions.append("event_type LIKE ?")
            params.append(f"%{event_type}%")

        if analyzed_by:
            conditions.append("analyzed_by = ?")
            params.append(analyzed_by)

        if date_from:
            conditions.append("timestamp >= ?")
            params.append(date_from)

        if date_to:
            conditions.append("timestamp <= ?")
            params.append(date_to)

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        # Get total count for pagination
        count_query = f"SELECT COUNT(*) FROM raw_logs WHERE {where_clause}"
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()[0]

        # Get filtered results
        query_sql = f"""
            SELECT
                id, raw_log, timestamp, processed_at, severity,
                event_type, ai_summary, analyzed_by, host, status,
                processing_time_ms, original_severity
            FROM raw_logs
            WHERE {where_clause}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])
        cursor.execute(query_sql, params)
        rows = cursor.fetchall()

        # Get filter options (distinct values)
        cursor.execute("SELECT DISTINCT severity FROM raw_logs WHERE severity IS NOT NULL ORDER BY severity")
        severities = [r[0] for r in cursor.fetchall()]

        cursor.execute("SELECT DISTINCT host FROM raw_logs WHERE host IS NOT NULL AND host != 'Unknown' ORDER BY host LIMIT 50")
        hosts = [r[0] for r in cursor.fetchall()]

        cursor.execute("SELECT DISTINCT event_type FROM raw_logs WHERE event_type IS NOT NULL ORDER BY event_type")
        event_types = [r[0] for r in cursor.fetchall()]

        cursor.execute("SELECT DISTINCT analyzed_by FROM raw_logs WHERE analyzed_by IS NOT NULL ORDER BY analyzed_by")
        analyzers = [r[0] for r in cursor.fetchall()]

    return {
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "filters": {
            "severities": severities,
            "hosts": hosts,
            "event_types": event_types,
            "analyzers": analyzers
        },
        "logs": [{
            "TLID": row[0],
            "Raw Log": row[1],
            "Timestamp": row[2],
            "Processed At": row[3],
            "Severity": row[4] or 'Unknown',
            "Event Type": row[5] or 'Unknown',
            "AI Summary": row[6] or ('Pending...' if row[9] == 'PENDING' else 'Processed'),
            "Analyzed By": row[7] or 'N/A',
            "HOST": row[8] or 'Unknown',
            "Status": row[9],
            "Processing Time (ms)": row[10],
            "Original Severity": row[11]
        } for row in rows]
    }

@app.get("/api/logs-all")
@limiter.limit("100/minute")
async def get_logs_all(request: Request):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                id,
                raw_log,
                timestamp,
                processed_at,
                severity,
                event_type,
                ai_summary,
                analyzed_by,
                host,
                status
            FROM raw_logs
            ORDER BY timestamp DESC
            LIMIT 200
        """)
        rows = cursor.fetchall()
    
    return [{
        "TLID": row['id'],
        "Raw Log": row['raw_log'],
        "Timestamp": row['timestamp'],
        "Processed At": row['processed_at'],
        "Severity": row['severity'] or 'Unknown',
        "Event Type": row['event_type'] or 'Unknown',
        "HOST": row['host'] or 'Unknown',
        "AI Summary": row['ai_summary'] or ('Pending analysis...' if row['status'] == 'PENDING' else 'Processed'),
        "Status": row['status']
    } for row in rows]

@app.get("/api/logs-pending")
@limiter.limit("100/minute")
async def get_logs_pending(request: Request):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                id,
                raw_log,
                timestamp,
                created_at,
                status
            FROM raw_logs 
            WHERE status='PENDING'
            ORDER BY timestamp DESC 
            LIMIT 100
        """)
        rows = cursor.fetchall()
    
    return [{
        "TLID": row['id'],
        "Raw Log": row['raw_log'],
        "Timestamp": row['timestamp'],
        "Processed At": None,
        "Severity": 'N/A',
        "Event Type": 'N/A',
        "HOST": 'N/A',
        "AI Summary": 'Pending analysis...',
        "Status": row['status']
    } for row in rows]

@app.get("/api/logs-queue")
@limiter.limit("100/minute")
async def get_logs_queue(request: Request):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, raw_log, timestamp FROM raw_logs WHERE status='PENDING' ORDER BY timestamp DESC LIMIT 50"
        )
        rows = cursor.fetchall()

    return [{
        "TLID": row['id'],
        "Raw Log": row['raw_log'],
        "Timestamp": row['timestamp'],
        "Severity": "N/A",
        "Event Type": "N/A",
        "HOST": "N/A",
        "AI Summary": "Pending analysis..."
    } for row in rows]

@app.post("/api/learn")
@limiter.limit("10/minute")
async def learn(request: Request, req: FeedbackRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    with get_db() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT raw_log FROM raw_logs WHERE id=?", (req.log_id,))
        row = cursor.fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Log not found")

        log_hash = get_log_hash(row['raw_log'])
        cursor.execute(
            """INSERT OR REPLACE INTO ai_knowledge
               (pattern_hash, corrected_severity, reason, updated_at)
               VALUES (?, ?, ?, ?)""",
            (log_hash, req.new_severity, req.reason, datetime.datetime.now().isoformat())
        )
        conn.commit()

    update_global_counts()
    logger.info(f"AI learned from log {req.log_id}: {req.new_severity}")
    record_audit(current_user.get('id'), current_user.get('username', 'unknown'), 'severity_change',
                 'log', str(req.log_id), json.dumps({"new_severity": req.new_severity, "reason": req.reason}))

    return {
        "status": "success",
        "message": "AI knowledge base updated",
        "pattern_hash": log_hash
    }

@app.post("/api/learn-conditional")
@limiter.limit("10/minute")
async def learn_conditional(request: Request, req: ConditionalFeedbackRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Learn from feedback with conditional rules (host-specific, time-limited, etc.)"""
    with get_db() as conn:
        cursor = conn.cursor()

        # Get log details
        cursor.execute("SELECT raw_log, severity, host FROM raw_logs WHERE id=?", (req.log_id,))
        row = cursor.fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Log not found")

        raw_log = row['raw_log']
        original_severity = row['severity']
        host = row['host']
        log_hash = get_log_hash(raw_log)

        # Calculate expiry date if specified
        expires_at = None
        if req.expires_in_days:
            expires_at = (datetime.datetime.now() + datetime.timedelta(days=req.expires_in_days)).isoformat()

        # Insert conditional rule
        cursor.execute("""
            INSERT INTO ai_knowledge_conditions
            (pattern_hash, original_severity, corrected_severity, reason,
             host_filter, ip_filter, expires_at, exclude_hosts, is_active, times_applied)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 0)
        """, (
            log_hash,
            original_severity,
            req.new_severity,
            req.reason,
            req.host_filter,
            req.ip_filter,
            expires_at,
            req.exclude_hosts
        ))

        rule_id = cursor.lastrowid

        # Record the severity adjustment
        cursor.execute("""
            INSERT INTO severity_adjustments
            (log_id, pattern_hash, original_severity, new_severity, reason,
             host_filter, ip_filter, expires_at, exclude_hosts, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        """, (
            req.log_id,
            log_hash,
            original_severity,
            req.new_severity,
            req.reason,
            req.host_filter,
            req.ip_filter,
            expires_at,
            req.exclude_hosts
        ))

        conn.commit()

    logger.info(f"Conditional rule created for log {req.log_id}: {original_severity} -> {req.new_severity}")

    return {
        "status": "success",
        "message": "Conditional severity rule created",
        "rule_id": rule_id,
        "pattern_hash": log_hash,
        "original_severity": original_severity,
        "new_severity": req.new_severity,
        "expires_at": expires_at,
        "conditions": {
            "host_filter": req.host_filter,
            "ip_filter": req.ip_filter,
            "exclude_hosts": req.exclude_hosts
        }
    }

@app.get("/api/severity-adjustments")
@limiter.limit("60/minute")
async def get_severity_adjustments(request: Request, host: str = None, ip: str = None):
    """Get all severity adjustments with before/after view, filterable by host and IP."""
    with get_db() as conn:
        cursor = conn.cursor()

        query = """
            SELECT
                sa.id,
                sa.log_id,
                sa.pattern_hash,
                sa.original_severity,
                sa.new_severity,
                sa.reason,
                sa.host_filter,
                sa.ip_filter,
                sa.expires_at,
                sa.exclude_hosts,
                sa.is_active,
                sa.times_applied,
                sa.created_at,
                rl.raw_log,
                rl.host,
                ae.source_ip
            FROM severity_adjustments sa
            LEFT JOIN raw_logs rl ON sa.log_id = rl.id
            LEFT JOIN alert_enrichment ae ON sa.log_id = ae.log_id
            WHERE 1=1
        """
        params = []

        if host:
            query += " AND (rl.host = ? OR sa.host_filter LIKE ?)"
            params.extend([host, f"%{host}%"])

        if ip:
            query += " AND (ae.source_ip = ? OR sa.ip_filter LIKE ?)"
            params.extend([ip, f"%{ip}%"])

        query += " ORDER BY sa.created_at DESC LIMIT 100"

        cursor.execute(query, params)
        rows = cursor.fetchall()

        # Get total count of adjustments
        cursor.execute("SELECT COUNT(*) FROM severity_adjustments")
        total_count = cursor.fetchone()[0]

        # Get count by severity change type
        cursor.execute("""
            SELECT original_severity, new_severity, COUNT(*) as count
            FROM severity_adjustments
            GROUP BY original_severity, new_severity
            ORDER BY count DESC
        """)
        change_stats = [{"from": r[0], "to": r[1], "count": r[2]} for r in cursor.fetchall()]

    return {
        "total_adjustments": total_count,
        "change_statistics": change_stats,
        "adjustments": [{
            "id": row[0],
            "log_id": row[1],
            "pattern_hash": row[2][:16] + "..." if row[2] else None,
            "original_severity": row[3],
            "new_severity": row[4],
            "reason": row[5],
            "host_filter": row[6],
            "ip_filter": row[7],
            "expires_at": row[8],
            "exclude_hosts": row[9],
            "is_active": bool(row[10]),
            "times_applied": row[11],
            "created_at": row[12],
            "raw_log": row[13][:100] + "..." if row[13] and len(row[13]) > 100 else row[13],
            "host": row[14],
            "source_ip": row[15]
        } for row in rows]
    }

@app.get("/api/conditional-rules")
@limiter.limit("60/minute")
async def get_conditional_rules(request: Request, active_only: bool = True):
    """Get all conditional severity rules."""
    with get_db() as conn:
        cursor = conn.cursor()

        query = """
            SELECT
                id, pattern_hash, original_severity, corrected_severity, reason,
                host_filter, ip_filter, expires_at, exclude_hosts,
                is_active, times_applied, created_at, updated_at
            FROM ai_knowledge_conditions
        """
        if active_only:
            query += " WHERE is_active = 1"
        query += " ORDER BY created_at DESC"

        cursor.execute(query)
        rows = cursor.fetchall()

        # Get total times rules have been applied
        cursor.execute("SELECT SUM(times_applied) FROM ai_knowledge_conditions WHERE is_active = 1")
        total_applied = cursor.fetchone()[0] or 0

    return {
        "total_rules": len(rows),
        "total_times_applied": total_applied,
        "rules": [{
            "id": row[0],
            "pattern_hash": row[1][:16] + "..." if row[1] else None,
            "original_severity": row[2],
            "corrected_severity": row[3],
            "reason": row[4],
            "host_filter": row[5],
            "ip_filter": row[6],
            "expires_at": row[7],
            "exclude_hosts": row[8],
            "is_active": bool(row[9]),
            "times_applied": row[10],
            "created_at": row[11],
            "updated_at": row[12]
        } for row in rows]
    }

@app.get("/api/processing-time-stats")
@limiter.limit("60/minute")
async def get_processing_time_stats(request: Request):
    """Get processing time statistics comparing LLM vs Knowledge Base analysis."""
    with get_db() as conn:
        cursor = conn.cursor()

        # Average processing time by analyzer type
        cursor.execute("""
            SELECT
                analyzed_by,
                COUNT(*) as count,
                AVG(processing_time_ms) as avg_ms,
                MIN(processing_time_ms) as min_ms,
                MAX(processing_time_ms) as max_ms
            FROM raw_logs
            WHERE status = 'PROCESSED'
            AND processing_time_ms IS NOT NULL
            GROUP BY analyzed_by
        """)
        by_analyzer = [{
            "analyzer": row[0] or "unknown",
            "count": row[1],
            "avg_ms": round(row[2], 2) if row[2] else 0,
            "min_ms": row[3] or 0,
            "max_ms": row[4] or 0
        } for row in cursor.fetchall()]

        # Recent processing times for chart
        cursor.execute("""
            SELECT id, analyzed_by, processing_time_ms, processed_at
            FROM raw_logs
            WHERE status = 'PROCESSED'
            AND processing_time_ms IS NOT NULL
            ORDER BY processed_at DESC
            LIMIT 50
        """)
        recent = [{
            "id": row[0],
            "analyzer": row[1],
            "processing_time_ms": row[2],
            "processed_at": row[3]
        } for row in cursor.fetchall()]

        # Time savings calculation
        llm_stats = next((s for s in by_analyzer if s["analyzer"] == "llm"), {"avg_ms": 0, "count": 0})
        kb_stats = next((s for s in by_analyzer if s["analyzer"] == "knowledge_base"), {"avg_ms": 0, "count": 0})
        conditional_stats = next((s for s in by_analyzer if s["analyzer"] == "conditional_rule"), {"avg_ms": 0, "count": 0})

        time_saved_ms = 0
        if llm_stats["avg_ms"] > 0:
            kb_time_saved = (llm_stats["avg_ms"] - kb_stats["avg_ms"]) * kb_stats["count"]
            cond_time_saved = (llm_stats["avg_ms"] - conditional_stats["avg_ms"]) * conditional_stats["count"]
            time_saved_ms = kb_time_saved + cond_time_saved

        # Count knowledge base entries
        cursor.execute("SELECT COUNT(*) FROM ai_knowledge")
        kb_entries_count = cursor.fetchone()[0]

        # Count conditional rules
        cursor.execute("SELECT COUNT(*) FROM ai_knowledge_conditions WHERE is_active = 1")
        active_rules_count = cursor.fetchone()[0]

    return {
        "by_analyzer": by_analyzer,
        "recent_processing": recent,
        "time_savings": {
            "total_time_saved_ms": round(time_saved_ms, 0),
            "total_time_saved_formatted": format_duration(int(time_saved_ms / 1000)),
            "llm_avg_ms": llm_stats["avg_ms"],
            "llm_count": llm_stats["count"],
            "knowledge_base_avg_ms": kb_stats["avg_ms"],
            "knowledge_base_count": kb_stats["count"],
            "conditional_rule_avg_ms": conditional_stats["avg_ms"],
            "conditional_rule_count": conditional_stats["count"],
            "speedup_factor": round(llm_stats["avg_ms"] / kb_stats["avg_ms"], 1) if kb_stats["avg_ms"] > 0 else 0,
            "kb_entries_count": kb_entries_count,
            "active_rules_count": active_rules_count
        }
    }

@app.delete("/api/conditional-rules/{rule_id}")
@limiter.limit("10/minute")
async def deactivate_conditional_rule(request: Request, rule_id: int, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Deactivate a conditional severity rule."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE ai_knowledge_conditions SET is_active = 0 WHERE id = ?", (rule_id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Rule not found")
        conn.commit()

    return {"status": "success", "message": f"Rule {rule_id} deactivated"}

@app.get("/api/logs-processed")
@limiter.limit("100/minute")
async def get_logs_processed(request: Request):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                id,
                raw_log,
                timestamp,
                processed_at,
                severity,
                event_type,
                ai_summary,
                analyzed_by,
                host
            FROM raw_logs
            WHERE status='PROCESSED'
            ORDER BY processed_at DESC
            LIMIT 100
        """)
        rows = cursor.fetchall()

    return [{
        "TLID": row['id'],
        "Raw Log": row['raw_log'],
        "Timestamp": row['timestamp'],
        "Processed At": row['processed_at'],
        "Severity": row['severity'] or 'Unknown',
        "Event Type": row['event_type'] or 'Unknown',
        "HOST": row['host'] or 'Unknown',
        "AI Summary": row['ai_summary'] or 'Analyzed'
    } for row in rows]

@app.get("/api/relearned-logs")
@limiter.limit("30/minute")
async def get_relearned_logs(request: Request):
    """Get logs that were learned from user feedback."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                r.id,
                r.raw_log,
                r.timestamp,
                r.processed_at,
                r.severity,
                r.event_type,
                r.ai_summary,
                r.analyzed_by,
                r.host
            FROM raw_logs r
            WHERE r.analyzed_by = 'knowledge_base'
            ORDER BY r.processed_at DESC
            LIMIT 100
        """)
        rows = cursor.fetchall()
    
    return [{
        "TLID": row['id'],
        "Raw Log": row['raw_log'],
        "Timestamp": row['timestamp'],
        "Processed At": row['processed_at'],
        "Severity": row['severity'] or 'Unknown',
        "Event Type": row['event_type'] or 'Learned',
        "HOST": row['host'] or 'Unknown',
        "AI Summary": row['ai_summary'] or 'AI learned pattern from user feedback'
    } for row in rows]

@app.get("/api/knowledge-base")
@limiter.limit("30/minute")
async def get_knowledge_base(request: Request):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT pattern_hash, corrected_severity, reason, created_at, updated_at FROM ai_knowledge ORDER BY updated_at DESC"
        )
        rows = cursor.fetchall()

    return [{
        "pattern_hash": row['pattern_hash'][:16] + "...",
        "severity": row['corrected_severity'],
        "reason": row['reason'],
        "created_at": row['created_at'],
        "updated_at": row['updated_at']
    } for row in rows]

@app.post("/api/chat")
@limiter.limit("20/minute")
async def chat_with_ai(request: Request, req: ChatRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    try:
        ollama_client = Client(host=OLLAMA_URL)

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT raw_log, status FROM raw_logs ORDER BY timestamp DESC LIMIT 10"
            )
            recent_logs = cursor.fetchall()

        log_context = "\n".join([f"- {log['raw_log'][:100]}" for log in recent_logs[:5]])

        system_prompt = f"""SOC analyst assistant. Recent logs:
{log_context}
Stats: {TOTAL_LOGS_COUNT} total, {PENDING_LOGS_COUNT} pending, {PROCESSED_LOGS_COUNT} processed.
Be concise and actionable."""

        response = ollama_client.chat(
            model=OLLAMA_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": req.query}
            ],
            options={"temperature": 0.7, "num_thread": 16, "num_ctx": 1024}
        )

        ai_response = response['message']['content']
        logger.info(f"Chat query processed: {req.query[:50]}...")

        return {"response": ai_response}

    except Exception as e:
        logger.error(f"Chat error: {e}")
        return {"response": f"Sorry, I encountered an error: {str(e)[:100]}"}

@app.post("/api/action-chat")
@limiter.limit("30/minute")
async def action_chat(request: Request, req: ActionChatRequest, current_user: dict = Depends(get_current_user)):
    """
    Action chatbot that can execute actions like changing severity via natural language.
    """
    try:
        ollama_client = Client(host=OLLAMA_URL)

        # Extract context
        context = req.context
        current_tab = context.get('current_tab', 'unknown')
        log_id = context.get('log_id')
        host = context.get('host', '')
        severity = context.get('severity', '')
        ip = context.get('ip', '')

        # Intent detection using Ollama
        intent_prompt = f"""Classify this message into ONE category: change_severity, create_incident, search_logs, question

Message: "{req.message}"
Log ID: {log_id}

Reply with ONLY the category name."""

        intent_response = ollama_client.chat(
            model=OLLAMA_MODEL,
            messages=[
                {"role": "system", "content": "You are a precise intent classifier. Respond with only the category name."},
                {"role": "user", "content": intent_prompt}
            ],
            options={"temperature": 0.1, "num_thread": 16, "num_ctx": 512}
        )

        intent = intent_response['message']['content'].strip().lower()
        logger.info(f"Action chat intent detected: {intent} for message: {req.message}")

        action_executed = False
        action_type = None
        action_result = {}
        response_text = ""

        # Handle change_severity intent
        if "change_severity" in intent or "severity" in intent.lower():
            if not log_id:
                response_text = "Please select a log first to change its severity. Open a log detail view and try again."
            else:
                # Extract the new severity from the message
                severity_prompt = f"""What severity level? Reply with ONLY one of: Low, Medium, High, Critical

Message: "{req.message}" """

                severity_response = ollama_client.chat(
                    model=OLLAMA_MODEL,
                    messages=[
                        {"role": "system", "content": "Extract severity level. Respond with only: Low, Medium, High, or Critical"},
                        {"role": "user", "content": severity_prompt}
                    ],
                    options={"temperature": 0.1, "num_thread": 16, "num_ctx": 512}
                )

                new_severity = severity_response['message']['content'].strip()

                if new_severity in ["Low", "Medium", "High", "Critical"]:
                    # Create conditional rule
                    with get_db() as conn:
                        cursor = conn.cursor()

                        # Get log hash
                        cursor.execute("SELECT pattern_hash FROM raw_logs WHERE id = ?", (log_id,))
                        log_row = cursor.fetchone()

                        if log_row:
                            log_hash = log_row['pattern_hash']

                            # Generate reason from user message
                            reason = f"User adjusted via Action Chat: {req.message[:200]}"

                            # Insert conditional rule
                            cursor.execute("""
                                INSERT INTO ai_knowledge_conditions
                                (pattern_hash, original_severity, corrected_severity, reason,
                                 host_filter, ip_filter, expires_at, exclude_hosts, is_active, times_applied)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 0)
                            """, (
                                log_hash,
                                severity,
                                new_severity,
                                reason,
                                host if host else None,
                                ip if ip else None,
                                None,  # No expiration
                                None,  # No exclusions
                            ))

                            rule_id = cursor.lastrowid
                            conn.commit()

                            action_executed = True
                            action_type = "change_severity"
                            action_result = {
                                "rule_id": rule_id,
                                "new_severity": new_severity,
                                "log_id": log_id,
                                "host": host
                            }

                            response_text = f"✅ Severity changed to {new_severity} for log #{log_id}."
                            if host:
                                response_text += f" This rule applies to host: {host}."
                            response_text += " The AI will learn from this adjustment."
                        else:
                            response_text = f"Could not find log #{log_id} in the database."
                else:
                    response_text = f"I couldn't determine a valid severity level from your message. Please specify Low, Medium, High, or Critical."

        # Handle create_incident intent
        elif "create_incident" in intent or "incident" in intent.lower():
            if not log_id:
                response_text = "Please select a log first to create an incident. Open a log detail view and try again."
            else:
                with get_db() as conn:
                    cursor = conn.cursor()

                    # Get log details
                    cursor.execute("""
                        SELECT id, host, event_type, severity, raw_log
                        FROM raw_logs WHERE id = ?
                    """, (log_id,))

                    log_row = cursor.fetchone()

                    if log_row:
                        # Create incident
                        title = f"Security Incident - {log_row['event_type']} on {log_row['host']}"
                        description = f"Created from log #{log_id} via Action Chat\n\n{log_row['raw_log'][:500]}"

                        cursor.execute("""
                            INSERT INTO incidents (title, description, severity, status, log_id, assigned_to, created_at)
                            VALUES (?, ?, ?, 'Open', ?, ?, ?)
                        """, (
                            title,
                            description,
                            log_row['severity'],
                            log_id,
                            current_user.get('username', 'SOC Analyst'),
                            datetime.datetime.now().isoformat()
                        ))

                        incident_id = cursor.lastrowid
                        conn.commit()

                        action_executed = True
                        action_type = "create_incident"
                        action_result = {
                            "incident_id": incident_id,
                            "log_id": log_id
                        }

                        response_text = f"✅ Incident #{incident_id} created successfully from log #{log_id}. Title: {title}"
                    else:
                        response_text = f"Could not find log #{log_id} in the database."

        # Handle search_logs intent
        elif "search" in intent:
            response_text = "To search logs, use the search filters in the Logs tab. You can filter by severity, host, event type, and more."

        # Handle general questions
        else:
            # Use regular chat response
            chat_prompt = f"""User: "{req.message}"
Tab: {current_tab}, Log: #{log_id if log_id else 'None'}
Answer briefly."""

            general_response = ollama_client.chat(
                model=OLLAMA_MODEL,
                messages=[
                    {"role": "system", "content": "You are a helpful SOC assistant."},
                    {"role": "user", "content": chat_prompt}
                ],
                options={"temperature": 0.7, "num_thread": 16, "num_ctx": 1024}
            )

            response_text = general_response['message']['content']

        logger.info(f"Action chat completed - User: {current_user['username']}, Intent: {intent}, Action executed: {action_executed}")

        return {
            "response_text": response_text,
            "action_executed": action_executed,
            "action_type": action_type,
            "action_result": action_result
        }

    except Exception as e:
        logger.error(f"Action chat error: {e}")
        return {
            "response_text": f"Sorry, I encountered an error: {str(e)[:100]}",
            "action_executed": False,
            "action_type": None,
            "action_result": {}
        }

# ==============================================================================
# 12b. NEW FEATURE API ENDPOINTS
# ==============================================================================

@app.get("/api/alert-enrichment/{log_id}")
@limiter.limit("60/minute")
async def get_alert_enrichment(request: Request, log_id: int):
    """Get enrichment data for a specific alert"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ae.*, rl.raw_log, rl.severity, rl.event_type, rl.host
            FROM alert_enrichment ae
            JOIN raw_logs rl ON ae.log_id = rl.id
            WHERE ae.log_id = ?
        """, (log_id,))

        row = cursor.fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Alert enrichment not found")

        return {
            "log_id": row[1],
            "threat_score": row[2],
            "mitre_tactic": row[3],
            "mitre_technique": row[4],
            "geo_country": row[5],
            "geo_city": row[6],
            "source_ip": row[7],
            "is_known_threat": bool(row[8]),
            "threat_intel_source": row[9],
            "similar_incidents_count": row[10],
            "raw_log": row[13],
            "severity": row[14],
            "event_type": row[15],
            "host": row[16]
        }

@app.get("/api/remediation/{log_id}")
@limiter.limit("20/minute")
async def get_remediation(request: Request, log_id: int):
    """Generate AI-powered remediation steps for a security event"""
    with get_db() as conn:
        cursor = conn.cursor()

        # Get log details
        cursor.execute("""
            SELECT rl.*, ae.mitre_attack_tactic, ae.mitre_attack_technique, ae.threat_score
            FROM raw_logs rl
            LEFT JOIN alert_enrichment ae ON rl.id = ae.log_id
            WHERE rl.id = ?
        """, (log_id,))

        row = cursor.fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Log not found")

        raw_log = row[2]
        severity = row[5]
        event_type = row[6]
        ai_summary = row[7]
        mitre_tactic = row[12] if len(row) > 12 else None
        mitre_technique = row[13] if len(row) > 13 else None

        # Build remediation prompt
        prompt = f"""You are a SOC analyst assistant. Based on this security event, provide specific remediation steps.

Security Event Details:
- Severity: {severity}
- Event Type: {event_type}
- MITRE Tactic: {mitre_tactic or 'Unknown'}
- MITRE Technique: {mitre_technique or 'Unknown'}
- AI Summary: {ai_summary or 'N/A'}
- Raw Log: {raw_log[:500]}

Provide remediation steps in this format:
## Immediate Actions
(List 2-3 immediate steps to contain the threat)

## Investigation Steps
(List 2-3 steps to investigate the root cause)

## Long-term Remediation
(List 2-3 steps to prevent recurrence)

## Commands/Tools
(Provide specific commands or tools that can be used)

Be specific and actionable. Focus on practical steps a SOC analyst can execute immediately."""

        try:
            ollama_client = Client(host=OLLAMA_URL)
            response = ollama_client.generate(
                model=OLLAMA_MODEL,
                prompt=prompt,
                options={"temperature": 0.3}
            )

            remediation_steps = response['response']

            return {
                "log_id": log_id,
                "severity": severity,
                "event_type": event_type,
                "remediation_steps": remediation_steps
            }

        except Exception as e:
            logger.error(f"Error generating remediation: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to generate remediation: {str(e)}")

@app.get("/api/ai-learning-stats")
@limiter.limit("60/minute")
async def get_ai_stats(request: Request):
    """Get AI learning progress statistics"""
    stats = get_ai_learning_stats()
    return stats

@app.get("/api/hosts")
@limiter.limit("100/minute")
async def get_hosts(request: Request):
    """Get all monitored hosts"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM hosts
            ORDER BY risk_score DESC, total_alerts DESC
            LIMIT 100
        """)
        rows = cursor.fetchall()

    return [{
        "id": row[0],
        "hostname": row[1],
        "ip_address": row[2],
        "asset_classification": row[3],
        "criticality": row[4],
        "risk_score": row[5],
        "total_alerts": row[6],
        "last_seen": row[7],
        "first_seen": row[8]
    } for row in rows]

@app.get("/api/hosts/{hostname}")
@limiter.limit("60/minute")
async def get_host_details(request: Request, hostname: str):
    """Get detailed information about a specific host"""
    with get_db() as conn:
        cursor = conn.cursor()

        # Host info
        cursor.execute("SELECT * FROM hosts WHERE hostname = ?", (hostname,))
        host = cursor.fetchone()

        if not host:
            raise HTTPException(status_code=404, detail="Host not found")

        # Recent alerts for this host
        cursor.execute("""
            SELECT id, timestamp, severity, event_type, ai_summary
            FROM raw_logs
            WHERE host = ? AND status = 'PROCESSED'
            ORDER BY timestamp DESC
            LIMIT 50
        """, (hostname,))
        alerts = cursor.fetchall()

        return {
            "host_info": {
                "hostname": host[1],
                "ip_address": host[2],
                "asset_classification": host[3],
                "criticality": host[4],
                "risk_score": host[5],
                "total_alerts": host[6],
                "last_seen": host[7],
                "first_seen": host[8]
            },
            "recent_alerts": [{
                "id": alert[0],
                "timestamp": alert[1],
                "severity": alert[2],
                "event_type": alert[3],
                "summary": alert[4]
            } for alert in alerts]
        }

@app.get("/api/incidents")
@limiter.limit("100/minute")
async def get_incidents(request: Request, status: str = None):
    """Get all incidents, optionally filtered by status"""
    with get_db() as conn:
        cursor = conn.cursor()

        if status:
            cursor.execute("""
                SELECT * FROM incidents
                WHERE status = ?
                ORDER BY created_at DESC
                LIMIT 100
            """, (status,))
        else:
            cursor.execute("""
                SELECT * FROM incidents
                ORDER BY created_at DESC
                LIMIT 100
            """)

        rows = cursor.fetchall()

    return [{
        "id": row[0],
        "title": row[1],
        "severity": row[2],
        "status": row[3],
        "assigned_to": row[4],
        "primary_log_id": row[5],
        "related_log_ids": row[6],
        "mitre_tactics": row[7],
        "created_at": row[8],
        "updated_at": row[9],
        "resolved_at": row[10]
    } for row in rows]

@app.get("/api/correlated-events")
@limiter.limit("60/minute")
async def get_correlated_events(request: Request):
    """Get correlated security events"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ce.*, cr.rule_name, cr.rule_description
            FROM correlated_events ce
            JOIN correlation_rules cr ON ce.correlation_rule_id = cr.id
            ORDER BY ce.created_at DESC
            LIMIT 100
        """)
        rows = cursor.fetchall()

    return [{
        "id": row[0],
        "rule_name": row[9],
        "rule_description": row[10],
        "event_count": row[3],
        "first_event_time": row[4],
        "last_event_time": row[5],
        "severity": row[6],
        "description": row[7],
        "log_ids": row[2].split(",") if row[2] else [],
        "created_at": row[8]
    } for row in rows]

@app.get("/api/threat-statistics")
@limiter.limit("60/minute")
async def get_threat_statistics(request: Request):
    """Get threat statistics for charts and visualizations"""
    with get_db() as conn:
        cursor = conn.cursor()

        # Last 24 hours by severity
        cursor.execute("""
            SELECT severity, COUNT(*) as count
            FROM raw_logs
            WHERE timestamp > datetime('now', '-24 hours')
            AND status = 'PROCESSED'
            GROUP BY severity
        """)
        severity_counts = {row[0]: row[1] for row in cursor.fetchall()}

        # Top event types
        cursor.execute("""
            SELECT event_type, COUNT(*) as count
            FROM raw_logs
            WHERE timestamp > datetime('now', '-24 hours')
            AND status = 'PROCESSED'
            GROUP BY event_type
            ORDER BY count DESC
            LIMIT 10
        """)
        top_events = [{"event_type": row[0], "count": row[1]} for row in cursor.fetchall()]

        # Most targeted hosts
        cursor.execute("""
            SELECT host, COUNT(*) as count, MAX(risk_score) as risk
            FROM raw_logs rl
            LEFT JOIN hosts h ON rl.host = h.hostname
            WHERE rl.timestamp > datetime('now', '-24 hours')
            AND rl.status = 'PROCESSED'
            GROUP BY host
            ORDER BY count DESC
            LIMIT 10
        """)
        top_hosts = [{"host": row[0], "count": row[1], "risk_score": row[2] or 50} for row in cursor.fetchall()]

        # Hourly trend (last 24 hours)
        cursor.execute("""
            SELECT strftime('%H', timestamp) as hour, severity, COUNT(*) as count
            FROM raw_logs
            WHERE timestamp > datetime('now', '-24 hours')
            AND status = 'PROCESSED'
            GROUP BY hour, severity
            ORDER BY hour
        """)
        hourly_data = {}
        for row in cursor.fetchall():
            hour = row[0]
            severity = row[1]
            count = row[2]
            if hour not in hourly_data:
                hourly_data[hour] = {}
            hourly_data[hour][severity] = count

        return {
            "severity_distribution": severity_counts,
            "top_event_types": top_events,
            "most_targeted_hosts": top_hosts,
            "hourly_trend": hourly_data
        }

@app.get("/api/compliance-dashboard")
@limiter.limit("30/minute")
async def get_compliance_dashboard(request: Request):
    """Get compliance metrics"""
    with get_db() as conn:
        cursor = conn.cursor()

        # Last 30 days stats
        cursor.execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN severity = 'Medium' THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN severity = 'Low' THEN 1 ELSE 0 END) as low
            FROM raw_logs
            WHERE timestamp > datetime('now', '-30 days')
            AND status = 'PROCESSED'
        """)
        row = cursor.fetchone()

        # Calculate compliance score (simplified)
        total = row[0] or 1
        critical = row[1] or 0
        high = row[2] or 0

        # Score decreases with more critical/high events
        compliance_score = max(0, 100 - ((critical * 10) + (high * 5)))

        return {
            "period": "Last 30 Days",
            "total_events": total,
            "critical_events": critical,
            "high_events": high,
            "medium_events": row[3],
            "low_events": row[4],
            "compliance_score": compliance_score,
            "status": "Compliant" if compliance_score >= 70 else "Non-Compliant"
        }

@app.post("/api/export-logs")
@limiter.limit("10/minute")
async def export_logs(request: Request):
    """Export logs to CSV format"""
    import csv
    import io

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, timestamp, severity, event_type, host, raw_log, ai_summary
            FROM raw_logs
            WHERE status = 'PROCESSED'
            ORDER BY timestamp DESC
            LIMIT 1000
        """)
        rows = cursor.fetchall()

    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Timestamp', 'Severity', 'Event Type', 'Host', 'Raw Log', 'AI Summary'])

    for row in rows:
        writer.writerow(row)

    output.seek(0)

    from fastapi.responses import StreamingResponse
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=security_logs_export.csv"}
    )

@app.post("/api/create-incident")
@limiter.limit("20/minute")
async def create_incident(request: Request, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Create a new incident from an alert"""
    data = await request.json()

    log_id = data.get('log_id')
    title = data.get('title', 'Security Incident')
    assigned_to = data.get('assigned_to', 'Unassigned')

    if not log_id:
        raise HTTPException(status_code=400, detail="log_id is required")

    with get_db() as conn:
        cursor = conn.cursor()

        # Get log details
        cursor.execute("SELECT severity, event_type FROM raw_logs WHERE id = ?", (log_id,))
        log = cursor.fetchone()

        if not log:
            raise HTTPException(status_code=404, detail="Log not found")

        # Get MITRE tactics
        cursor.execute("SELECT mitre_attack_tactic FROM alert_enrichment WHERE log_id = ?", (log_id,))
        enrichment = cursor.fetchone()
        mitre_tactics = enrichment[0] if enrichment else "Unknown"

        # Create incident
        cursor.execute("""
            INSERT INTO incidents (title, severity, status, assigned_to, primary_log_id, mitre_tactics)
            VALUES (?, ?, 'Open', ?, ?, ?)
        """, (title, log[0], assigned_to, log_id, mitre_tactics))

        incident_id = cursor.lastrowid
        conn.commit()

    logger.info(f"Created incident {incident_id} for log {log_id}")
    record_audit(current_user.get('id'), current_user.get('username', 'unknown'), 'create_incident',
                 'incident', str(incident_id), json.dumps({"log_id": log_id, "title": title}))

    return {
        "status": "success",
        "incident_id": incident_id,
        "message": f"Incident created successfully"
    }

@app.get("/api/playbooks")
@limiter.limit("30/minute")
async def get_playbooks(request: Request):
    """Get available incident response playbooks"""
    playbooks = [
        {
            "id": 1,
            "name": "Brute Force Response",
            "description": "Block IP, notify admin, investigate source",
            "severity": "High",
            "steps": [
                "Block source IP at firewall",
                "Notify security team",
                "Check for successful logins",
                "Investigate user accounts",
                "Document incident"
            ]
        },
        {
            "id": 2,
            "name": "Malware Detection Response",
            "description": "Isolate host, scan system, remediate",
            "severity": "Critical",
            "steps": [
                "Isolate infected host from network",
                "Run full system scan",
                "Identify malware type",
                "Remove malware",
                "Check for lateral movement",
                "Document and report"
            ]
        },
        {
            "id": 3,
            "name": "Data Exfiltration Response",
            "description": "Block connection, investigate data, contain breach",
            "severity": "Critical",
            "steps": [
                "Block outbound connection",
                "Identify exfiltrated data",
                "Investigate compromised accounts",
                "Check for additional backdoors",
                "Notify stakeholders",
                "Document incident"
            ]
        }
    ]

    return playbooks

# ==============================================================================
# 12b. Dashboard v4.0 - New Feature Endpoints
# ==============================================================================

@app.get("/api/system-metrics")
@limiter.limit("120/minute")
async def get_system_metrics(request: Request):
    """Get system CPU, memory, disk, and network status"""
    global PROCESSOR_ACTIVE

    cpu_percent = psutil.cpu_percent(interval=0.1)
    cpu_count = psutil.cpu_count()
    cpu_freq = psutil.cpu_freq()

    memory = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_usage('/')

    # Network I/O
    net_io = psutil.net_io_counters()

    # System uptime
    boot_time = psutil.boot_time()
    uptime_seconds = time.time() - boot_time
    uptime_days = int(uptime_seconds // 86400)
    uptime_hours = int((uptime_seconds % 86400) // 3600)
    uptime_mins = int((uptime_seconds % 3600) // 60)

    return {
        "cpu_percent": cpu_percent,
        "cpu_count": cpu_count,
        "cpu_freq_mhz": round(cpu_freq.current, 0) if cpu_freq else 0,
        "memory_percent": memory.percent,
        "memory_used_gb": round(memory.used / (1024**3), 2),
        "memory_total_gb": round(memory.total / (1024**3), 2),
        "memory_available_gb": round(memory.available / (1024**3), 2),
        "swap_percent": swap.percent,
        "swap_used_gb": round(swap.used / (1024**3), 2),
        "swap_total_gb": round(swap.total / (1024**3), 2),
        "disk_percent": disk.percent,
        "disk_used_gb": round(disk.used / (1024**3), 2),
        "disk_total_gb": round(disk.total / (1024**3), 2),
        "disk_free_gb": round(disk.free / (1024**3), 2),
        "net_bytes_sent_mb": round(net_io.bytes_sent / (1024**2), 2),
        "net_bytes_recv_mb": round(net_io.bytes_recv / (1024**2), 2),
        "net_packets_sent": net_io.packets_sent,
        "net_packets_recv": net_io.packets_recv,
        "uptime": f"{uptime_days}d {uptime_hours}h {uptime_mins}m",
        "processor_active": PROCESSOR_ACTIVE,
        "timestamp": datetime.datetime.now().isoformat()
    }

@app.get("/api/soc-metrics")
@limiter.limit("60/minute")
async def get_soc_metrics(request: Request):
    """Get SOC performance metrics: MTTD, MTTR, MTTA"""
    with get_db() as conn:
        cursor = conn.cursor()

        # MTTD: Mean Time to Detect (time between log timestamp and processed_at)
        cursor.execute("""
            SELECT AVG(
                CAST((julianday(processed_at) - julianday(timestamp)) * 86400 AS INTEGER)
            ) as avg_mttd
            FROM raw_logs
            WHERE status = 'PROCESSED'
            AND processed_at IS NOT NULL
            AND timestamp IS NOT NULL
            AND datetime(timestamp) > datetime('now', '-7 days')
        """)
        mttd_result = cursor.fetchone()
        mttd_seconds = int(mttd_result[0]) if mttd_result and mttd_result[0] else 0

        # MTTR: Mean Time to Respond (incident created to resolved)
        cursor.execute("""
            SELECT AVG(
                CAST((julianday(resolved_at) - julianday(created_at)) * 86400 AS INTEGER)
            ) as avg_mttr
            FROM incidents
            WHERE resolved_at IS NOT NULL
            AND datetime(created_at) > datetime('now', '-30 days')
        """)
        mttr_result = cursor.fetchone()
        mttr_seconds = int(mttr_result[0]) if mttr_result and mttr_result[0] else 0

        # MTTA: Mean Time to Acknowledge (created to status change)
        cursor.execute("""
            SELECT AVG(
                CAST((julianday(updated_at) - julianday(created_at)) * 86400 AS INTEGER)
            ) as avg_mtta
            FROM incidents
            WHERE status != 'Open'
            AND datetime(created_at) > datetime('now', '-30 days')
        """)
        mtta_result = cursor.fetchone()
        mtta_seconds = int(mtta_result[0]) if mtta_result and mtta_result[0] else 0

        # Get counts for context
        cursor.execute("SELECT COUNT(*) FROM raw_logs WHERE status = 'PROCESSED' AND datetime(timestamp) > datetime('now', '-24 hours')")
        logs_24h = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM incidents WHERE datetime(created_at) > datetime('now', '-7 days')")
        incidents_7d = cursor.fetchone()[0]

    return {
        "mttd_seconds": mttd_seconds,
        "mttd_formatted": format_duration(mttd_seconds),
        "mttr_seconds": mttr_seconds,
        "mttr_formatted": format_duration(mttr_seconds),
        "mtta_seconds": mtta_seconds,
        "mtta_formatted": format_duration(mtta_seconds),
        "logs_analyzed_24h": logs_24h,
        "incidents_7d": incidents_7d
    }

def format_duration(seconds):
    """Format seconds into human-readable duration"""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    elif seconds < 86400:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours}h {minutes}m"
    else:
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        return f"{days}d {hours}h"

@app.get("/api/mitre-matrix")
@limiter.limit("60/minute")
async def get_mitre_matrix(request: Request):
    """Get MITRE ATT&CK matrix data from alert enrichment"""
    with get_db() as conn:
        cursor = conn.cursor()

        # Get tactic counts
        cursor.execute("""
            SELECT mitre_attack_tactic, COUNT(*) as count
            FROM alert_enrichment
            WHERE mitre_attack_tactic IS NOT NULL AND mitre_attack_tactic != ''
            GROUP BY mitre_attack_tactic
            ORDER BY count DESC
        """)
        tactics = [{"tactic": row[0], "count": row[1]} for row in cursor.fetchall()]

        # Get technique counts
        cursor.execute("""
            SELECT mitre_attack_technique, mitre_attack_tactic, COUNT(*) as count
            FROM alert_enrichment
            WHERE mitre_attack_technique IS NOT NULL AND mitre_attack_technique != ''
            GROUP BY mitre_attack_technique, mitre_attack_tactic
            ORDER BY count DESC
            LIMIT 20
        """)
        techniques = [{"technique": row[0], "tactic": row[1], "count": row[2]} for row in cursor.fetchall()]

        # Get total coverage
        cursor.execute("SELECT COUNT(DISTINCT mitre_attack_tactic) FROM alert_enrichment WHERE mitre_attack_tactic IS NOT NULL")
        total_tactics = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(DISTINCT mitre_attack_technique) FROM alert_enrichment WHERE mitre_attack_technique IS NOT NULL")
        total_techniques = cursor.fetchone()[0]

    # MITRE ATT&CK Framework Tactics (for matrix display)
    mitre_tactics = [
        "Reconnaissance", "Resource Development", "Initial Access", "Execution",
        "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
        "Discovery", "Lateral Movement", "Collection", "Command and Control",
        "Exfiltration", "Impact"
    ]

    # Build matrix data
    matrix = []
    for tactic in mitre_tactics:
        tactic_data = next((t for t in tactics if t["tactic"] == tactic), None)
        matrix.append({
            "tactic": tactic,
            "count": tactic_data["count"] if tactic_data else 0,
            "detected": tactic_data is not None
        })

    return {
        "matrix": matrix,
        "tactics": tactics,
        "techniques": techniques,
        "total_tactics_detected": total_tactics,
        "total_techniques_detected": total_techniques,
        "coverage_percent": round((total_tactics / len(mitre_tactics)) * 100, 1) if total_tactics else 0
    }

@app.get("/api/timeline")
@limiter.limit("60/minute")
async def get_timeline(request: Request, hours: int = 24, host: str = None, severity: str = None):
    """Get chronological timeline of security events"""
    with get_db() as conn:
        cursor = conn.cursor()

        query = """
            SELECT id, timestamp, raw_log, severity, event_type, ai_summary, host, processed_at
            FROM raw_logs
            WHERE status = 'PROCESSED'
            AND datetime(timestamp) > datetime('now', ? || ' hours')
        """
        params = [f"-{hours}"]

        if host:
            query += " AND host = ?"
            params.append(host)

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        query += " ORDER BY timestamp DESC LIMIT 100"

        cursor.execute(query, params)
        events = []
        for row in cursor.fetchall():
            events.append({
                "id": row[0],
                "timestamp": row[1],
                "raw_log": row[2][:200] if row[2] else "",
                "severity": row[3],
                "event_type": row[4],
                "summary": row[5],
                "host": row[6],
                "processed_at": row[7]
            })

        # Get available hosts for filtering
        cursor.execute("SELECT DISTINCT host FROM raw_logs WHERE host IS NOT NULL ORDER BY host")
        available_hosts = [row[0] for row in cursor.fetchall()]

    return {
        "events": events,
        "total": len(events),
        "timeframe_hours": hours,
        "available_hosts": available_hosts,
        "filters": {
            "host": host,
            "severity": severity
        }
    }

@app.get("/api/threat-briefing")
@limiter.limit("10/minute")
async def get_threat_briefing(request: Request):
    """Generate AI-powered threat briefing summary"""
    with get_db() as conn:
        cursor = conn.cursor()

        # Gather statistics for the briefing
        cursor.execute("""
            SELECT severity, COUNT(*) as count
            FROM raw_logs
            WHERE datetime(timestamp) > datetime('now', '-24 hours')
            GROUP BY severity
        """)
        severity_stats = {row[0]: row[1] for row in cursor.fetchall()}

        cursor.execute("""
            SELECT event_type, COUNT(*) as count
            FROM raw_logs
            WHERE datetime(timestamp) > datetime('now', '-24 hours')
            GROUP BY event_type
            ORDER BY count DESC
            LIMIT 5
        """)
        top_events = [{"type": row[0], "count": row[1]} for row in cursor.fetchall()]

        cursor.execute("""
            SELECT host, COUNT(*) as count
            FROM raw_logs
            WHERE severity IN ('High', 'Critical')
            AND datetime(timestamp) > datetime('now', '-24 hours')
            GROUP BY host
            ORDER BY count DESC
            LIMIT 5
        """)
        targeted_hosts = [{"host": row[0], "alerts": row[1]} for row in cursor.fetchall()]

        cursor.execute("SELECT COUNT(*) FROM incidents WHERE status = 'Open'")
        open_incidents = cursor.fetchone()[0]

        cursor.execute("""
            SELECT mitre_attack_tactic, COUNT(*) as count
            FROM alert_enrichment
            WHERE datetime(created_at) > datetime('now', '-24 hours')
            GROUP BY mitre_attack_tactic
            ORDER BY count DESC
            LIMIT 3
        """)
        top_tactics = [{"tactic": row[0], "count": row[1]} for row in cursor.fetchall()]

    # Generate briefing with AI
    try:
        client = Client(host=OLLAMA_URL)

        briefing_prompt = f"""Generate a concise security threat briefing based on the following 24-hour statistics:

Severity Distribution:
- Critical: {severity_stats.get('Critical', 0)}
- High: {severity_stats.get('High', 0)}
- Medium: {severity_stats.get('Medium', 0)}
- Low: {severity_stats.get('Low', 0)}

Top Event Types: {', '.join([f"{e['type']} ({e['count']})" for e in top_events])}

Most Targeted Hosts: {', '.join([f"{h['host']} ({h['alerts']} alerts)" for h in targeted_hosts])}

Open Incidents: {open_incidents}

Top MITRE ATT&CK Tactics: {', '.join([f"{t['tactic']} ({t['count']})" for t in top_tactics])}

Provide a brief executive summary (3-4 sentences), key findings, and recommended actions. Be concise and actionable."""

        response = client.chat(
            model=OLLAMA_MODEL,
            messages=[{"role": "user", "content": briefing_prompt}]
        )
        ai_summary = response['message']['content']
    except Exception as e:
        logger.error(f"Failed to generate AI briefing: {e}")
        ai_summary = "AI briefing generation unavailable. Please check Ollama connection."

    return {
        "generated_at": datetime.datetime.now().isoformat(),
        "period": "Last 24 hours",
        "statistics": {
            "severity_distribution": severity_stats,
            "top_event_types": top_events,
            "targeted_hosts": targeted_hosts,
            "open_incidents": open_incidents,
            "top_mitre_tactics": top_tactics
        },
        "ai_summary": ai_summary
    }

@app.get("/api/notifications")
@limiter.limit("120/minute")
async def get_notifications(request: Request, unread_only: bool = True):
    """Get recent notifications/alerts for the dashboard"""
    with get_db() as conn:
        cursor = conn.cursor()

        # Get recent critical/high severity events as notifications
        cursor.execute("""
            SELECT id, timestamp, severity, event_type, ai_summary, host
            FROM raw_logs
            WHERE severity IN ('Critical', 'High')
            AND datetime(timestamp) > datetime('now', '-1 hour')
            ORDER BY timestamp DESC
            LIMIT 10
        """)

        notifications = []
        for row in cursor.fetchall():
            severity = row[2]
            notifications.append({
                "id": row[0],
                "timestamp": row[1],
                "type": "alert",
                "severity": severity,
                "title": f"{severity} Alert: {row[3] or 'Security Event'}",
                "message": row[4][:100] if row[4] else "New security event detected",
                "host": row[5],
                "read": False
            })

        # Also check for any new incidents
        cursor.execute("""
            SELECT id, title, severity, created_at
            FROM incidents
            WHERE datetime(created_at) > datetime('now', '-1 hour')
            ORDER BY created_at DESC
            LIMIT 5
        """)

        for row in cursor.fetchall():
            notifications.append({
                "id": f"incident-{row[0]}",
                "timestamp": row[3],
                "type": "incident",
                "severity": row[2],
                "title": f"New Incident: {row[1]}",
                "message": f"Incident #{row[0]} has been created",
                "read": False
            })

        # Sort by timestamp
        notifications.sort(key=lambda x: x['timestamp'], reverse=True)

    return {
        "notifications": notifications[:15],
        "total_unread": len(notifications),
        "has_critical": any(n['severity'] == 'Critical' for n in notifications)
    }

@app.post("/api/incidents/{incident_id}/update-status")
@limiter.limit("30/minute")
async def update_incident_status(request: Request, incident_id: int, status: str):
    """Update incident status for Kanban board"""
    valid_statuses = ['Open', 'In Progress', 'Resolved', 'Closed']
    if status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")

    with get_db() as conn:
        cursor = conn.cursor()

        # Update status and timestamps
        if status == 'Resolved':
            cursor.execute("""
                UPDATE incidents
                SET status = ?, updated_at = datetime('now'), resolved_at = datetime('now')
                WHERE id = ?
            """, (status, incident_id))
        else:
            cursor.execute("""
                UPDATE incidents
                SET status = ?, updated_at = datetime('now')
                WHERE id = ?
            """, (status, incident_id))

        conn.commit()

        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Incident not found")

    return {"status": "success", "incident_id": incident_id, "new_status": status}

# ==============================================================================
# 12c. Professional Feature Endpoints
# ==============================================================================

# --- Audit Log ---
@app.get("/api/audit-log")
@limiter.limit("60/minute")
async def get_audit_log(request: Request, action: str = None, username: str = None,
                        date_from: str = None, date_to: str = None, limit: int = 100,
                        current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get audit trail with optional filters"""
    with get_db() as conn:
        cursor = conn.cursor()
        conditions = []
        params = []
        if action:
            conditions.append("action = ?")
            params.append(action)
        if username:
            conditions.append("username = ?")
            params.append(username)
        if date_from:
            conditions.append("created_at >= ?")
            params.append(date_from)
        if date_to:
            conditions.append("created_at <= ?")
            params.append(date_to)
        where = " AND ".join(conditions) if conditions else "1=1"
        cursor.execute(f"""
            SELECT id, user_id, username, action, entity_type, entity_id, details, ip_address, created_at
            FROM audit_log WHERE {where} ORDER BY created_at DESC LIMIT ?
        """, params + [limit])
        rows = cursor.fetchall()
    return {"logs": [{
        "id": r[0], "user_id": r[1], "username": r[2], "action": r[3],
        "entity_type": r[4], "entity_id": r[5], "details": r[6],
        "ip_address": r[7], "created_at": r[8]
    } for r in rows]}

# --- Role Management ---
@app.put("/api/users/{user_id}/role")
@limiter.limit("10/minute")
async def update_user_role(request: Request, user_id: int, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Update user role (admin only)"""
    if current_user.get('role') != 'admin' and not current_user.get('is_admin'):
        raise HTTPException(status_code=403, detail="Admin access required")
    data = await request.json()
    new_role = data.get('role')
    if new_role not in ('admin', 'analyst', 'manager'):
        raise HTTPException(status_code=400, detail="Invalid role. Must be admin, analyst, or manager")
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="User not found")
        conn.commit()
    record_audit(current_user.get('id'), current_user.get('username'), 'role_change',
                 'user', str(user_id), json.dumps({"new_role": new_role}), get_remote_address(request))
    return {"status": "success", "user_id": user_id, "new_role": new_role}

# --- Alert Triage ---
@app.get("/api/triage/queue")
@limiter.limit("60/minute")
async def get_triage_queue(request: Request, triage_status: str = None,
                           current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get triage queue"""
    with get_db() as conn:
        cursor = conn.cursor()
        if triage_status:
            cursor.execute("""
                SELECT rl.id, rl.timestamp, rl.severity, rl.event_type, rl.host, rl.ai_summary,
                       at.triage_status, at.assigned_to, at.notes, at.triaged_by, at.triaged_at
                FROM raw_logs rl
                LEFT JOIN alert_triage at ON rl.id = at.log_id
                WHERE rl.status = 'PROCESSED' AND at.triage_status = ?
                ORDER BY rl.timestamp DESC LIMIT 200
            """, (triage_status,))
        else:
            cursor.execute("""
                SELECT rl.id, rl.timestamp, rl.severity, rl.event_type, rl.host, rl.ai_summary,
                       at.triage_status, at.assigned_to, at.notes, at.triaged_by, at.triaged_at
                FROM raw_logs rl
                LEFT JOIN alert_triage at ON rl.id = at.log_id
                WHERE rl.status = 'PROCESSED'
                AND (rl.severity IN ('High', 'Critical') OR at.triage_status IS NOT NULL)
                ORDER BY CASE rl.severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END,
                         rl.timestamp DESC
                LIMIT 200
            """)
        rows = cursor.fetchall()
    return [{"log_id": r[0], "timestamp": r[1], "severity": r[2], "event_type": r[3],
             "host": r[4], "summary": r[5], "triage_status": r[6] or "new",
             "assigned_to": r[7], "notes": r[8], "triaged_by": r[9], "triaged_at": r[10]} for r in rows]

@app.put("/api/triage/{log_id}")
@limiter.limit("30/minute")
async def update_triage(request: Request, log_id: int, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Update triage status for a single alert"""
    data = await request.json()
    triage_status = data.get('triage_status', 'acknowledged')
    assigned_to = data.get('assigned_to')
    notes = data.get('notes')
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO alert_triage (log_id, triage_status, assigned_to, notes, triaged_by, triaged_at)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(log_id) DO UPDATE SET
                triage_status = excluded.triage_status,
                assigned_to = COALESCE(excluded.assigned_to, alert_triage.assigned_to),
                notes = COALESCE(excluded.notes, alert_triage.notes),
                triaged_by = excluded.triaged_by,
                triaged_at = excluded.triaged_at
        """, (log_id, triage_status, assigned_to, notes, current_user.get('username')))
        conn.commit()
    record_audit(current_user.get('id'), current_user.get('username'), 'triage_update',
                 'alert', str(log_id), json.dumps({"status": triage_status}), get_remote_address(request))
    return {"status": "success", "log_id": log_id, "triage_status": triage_status}

@app.post("/api/triage/bulk-action")
@limiter.limit("20/minute")
async def bulk_triage(request: Request, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Bulk triage action on multiple alerts"""
    data = await request.json()
    log_ids = data.get('log_ids', [])
    action = data.get('action', 'acknowledged')
    assigned_to = data.get('assigned_to')
    notes = data.get('notes')
    if not log_ids:
        raise HTTPException(status_code=400, detail="No log IDs provided")
    if len(log_ids) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 logs per bulk action")
    with get_db() as conn:
        cursor = conn.cursor()
        for lid in log_ids:
            cursor.execute("""
                INSERT INTO alert_triage (log_id, triage_status, assigned_to, notes, triaged_by, triaged_at)
                VALUES (?, ?, ?, ?, ?, datetime('now'))
                ON CONFLICT(log_id) DO UPDATE SET
                    triage_status = excluded.triage_status,
                    assigned_to = COALESCE(excluded.assigned_to, alert_triage.assigned_to),
                    notes = COALESCE(excluded.notes, alert_triage.notes),
                    triaged_by = excluded.triaged_by,
                    triaged_at = excluded.triaged_at
            """, (lid, action, assigned_to, notes, current_user.get('username')))
        conn.commit()
    record_audit(current_user.get('id'), current_user.get('username'), 'bulk_triage',
                 'alert', ','.join(str(i) for i in log_ids[:10]), json.dumps({"action": action, "count": len(log_ids)}),
                 get_remote_address(request))
    return {"status": "success", "affected": len(log_ids), "action": action}

@app.get("/api/triage/stats")
@limiter.limit("60/minute")
async def get_triage_stats(request: Request, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get triage statistics"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT triage_status, COUNT(*) FROM alert_triage GROUP BY triage_status
        """)
        stats = {r[0]: r[1] for r in cursor.fetchall()}
        cursor.execute("SELECT COUNT(*) FROM raw_logs WHERE status='PROCESSED' AND severity IN ('High','Critical')")
        total_high = cursor.fetchone()[0]
    return {"stats": stats, "total_high_critical": total_high,
            "triaged": sum(stats.values()), "untriaged": max(0, total_high - sum(stats.values()))}

# --- Info Logs / Live Feed ---
@app.get("/api/info-logs")
@limiter.limit("120/minute")
async def get_info_logs(request: Request, since_id: int = 0):
    """Get recent logs for live feed - includes both processed and info (no-analysis) logs"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, timestamp, raw_log, host, ai_summary, severity, status
            FROM raw_logs
            WHERE id > ? AND status IN ('PROCESSED', 'INFO')
            ORDER BY id DESC LIMIT 50
        """, (since_id,))
        rows = cursor.fetchall()
    return [{"id": r[0], "timestamp": r[1], "raw_log": r[2][:200] if r[2] else "",
             "host": r[3] or "Unknown", "summary": r[4] or r[2][:100] if r[2] else "",
             "severity": r[5] or "Info", "status": r[6]} for r in rows]

@app.get("/api/log/{log_id}")
@limiter.limit("120/minute")
async def get_log_detail(log_id: int, request: Request, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get full details of a specific log entry including raw log"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, timestamp, raw_log, host, ai_summary, severity, event_type,
                   status, analyzed_by, processed_at, created_at
            FROM raw_logs WHERE id = ?
        """, (log_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Log not found")

        return {
            "id": row[0],
            "timestamp": row[1],
            "raw_log": row[2],  # Full raw log
            "host": row[3],
            "ai_summary": row[4],
            "severity": row[5],
            "event_type": row[6],
            "status": row[7],
            "analyzed_by": row[8],
            "processed_at": row[9],
            "created_at": row[10]
        }

@app.post("/api/clear-pending")
@limiter.limit("10/minute")
async def clear_pending_analysis(request: Request, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Clear all pending logs - mark them as INFO (skipped analysis)"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM raw_logs WHERE status = 'PENDING'")
        pending_count = cursor.fetchone()[0]

        if pending_count > 0:
            cursor.execute("""
                UPDATE raw_logs
                SET status = 'INFO',
                    ai_summary = 'Analysis skipped - cleared by user',
                    severity = COALESCE(
                        (SELECT CASE
                            WHEN raw_log LIKE '%severity_hint=Critical%' THEN 'Critical'
                            WHEN raw_log LIKE '%severity_hint=High%' THEN 'High'
                            WHEN raw_log LIKE '%severity_hint=Medium%' THEN 'Medium'
                            ELSE 'Low'
                        END),
                        'Info'
                    )
                WHERE status = 'PENDING'
            """)
            conn.commit()

        update_global_counts()
        record_audit(current_user.get('id'), current_user.get('username'), 'clear_pending',
                     'system', None, json.dumps({"cleared_count": pending_count}),
                     get_remote_address(request))

        return {"status": "success", "cleared": pending_count}

@app.get("/api/pending-count")
@limiter.limit("120/minute")
async def get_pending_count(request: Request):
    """Get count of logs pending analysis"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM raw_logs WHERE status = 'PENDING'")
        count = cursor.fetchone()[0]
    return {"pending": count}

# --- Shift Notes ---
@app.get("/api/shift-notes")
@limiter.limit("60/minute")
async def get_shift_notes(request: Request, date: str = None, shift: str = None,
                          current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get shift handoff notes"""
    with get_db() as conn:
        cursor = conn.cursor()
        conditions = []
        params = []
        if date:
            conditions.append("shift_date = ?")
            params.append(date)
        if shift:
            conditions.append("shift_period = ?")
            params.append(shift)
        where = " AND ".join(conditions) if conditions else "1=1"
        cursor.execute(f"""
            SELECT id, author, shift_date, shift_period, title, content, priority,
                   acknowledged_by, created_at, updated_at
            FROM shift_notes WHERE {where} ORDER BY created_at DESC LIMIT 50
        """, params)
        rows = cursor.fetchall()
    return [{"id": r[0], "author": r[1], "shift_date": r[2], "shift_period": r[3],
             "title": r[4], "content": r[5], "priority": r[6], "acknowledged_by": r[7],
             "created_at": r[8], "updated_at": r[9]} for r in rows]

@app.post("/api/shift-notes")
@limiter.limit("20/minute")
async def create_shift_note(request: Request, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Create a new shift note"""
    data = await request.json()
    title = data.get('title', '').strip()
    content = data.get('content', '').strip()
    priority = data.get('priority', 'normal')
    shift_period = data.get('shift_period', 'day')
    shift_date = data.get('shift_date', datetime.date.today().isoformat())
    if not title or not content:
        raise HTTPException(status_code=400, detail="Title and content are required")
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO shift_notes (author, shift_date, shift_period, title, content, priority)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (current_user.get('username'), shift_date, shift_period, title, content, priority))
        note_id = cursor.lastrowid
        conn.commit()
    record_audit(current_user.get('id'), current_user.get('username'), 'create_shift_note',
                 'shift_note', str(note_id), None, get_remote_address(request))
    return {"status": "success", "id": note_id}

@app.put("/api/shift-notes/{note_id}")
@limiter.limit("20/minute")
async def update_shift_note(request: Request, note_id: int, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Update a shift note"""
    data = await request.json()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT author FROM shift_notes WHERE id = ?", (note_id,))
        note = cursor.fetchone()
        if not note:
            raise HTTPException(status_code=404, detail="Note not found")
        updates = []
        params = []
        for field in ('title', 'content', 'priority', 'shift_period'):
            if field in data:
                updates.append(f"{field} = ?")
                params.append(data[field])
        if updates:
            updates.append("updated_at = datetime('now')")
            params.append(note_id)
            cursor.execute(f"UPDATE shift_notes SET {', '.join(updates)} WHERE id = ?", params)
            conn.commit()
    return {"status": "success", "id": note_id}

@app.delete("/api/shift-notes/{note_id}")
@limiter.limit("20/minute")
async def delete_shift_note(request: Request, note_id: int, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Delete a shift note"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM shift_notes WHERE id = ?", (note_id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Note not found")
        conn.commit()
    return {"status": "success"}

@app.post("/api/shift-notes/{note_id}/acknowledge")
@limiter.limit("30/minute")
async def acknowledge_shift_note(request: Request, note_id: int, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Acknowledge a shift note"""
    username = current_user.get('username')
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT acknowledged_by FROM shift_notes WHERE id = ?", (note_id,))
        note = cursor.fetchone()
        if not note:
            raise HTTPException(status_code=404, detail="Note not found")
        existing = note[0] or ""
        if username not in existing:
            new_ack = f"{existing},{username}" if existing else username
            cursor.execute("UPDATE shift_notes SET acknowledged_by = ? WHERE id = ?", (new_ack, note_id))
            conn.commit()
    return {"status": "success", "acknowledged_by": username}

# --- Export Report ---
@app.post("/api/export/report")
@limiter.limit("5/minute")
async def export_report(request: Request, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Generate HTML report for threats, compliance, or incidents"""
    from fastapi.responses import HTMLResponse as HTMLResp
    data = await request.json()
    report_type = data.get('type', 'threat')
    with get_db() as conn:
        cursor = conn.cursor()
        # Gather data based on report type
        cursor.execute("""
            SELECT severity, COUNT(*) FROM raw_logs
            WHERE status='PROCESSED' AND datetime(timestamp) > datetime('now', '-30 days')
            GROUP BY severity
        """)
        sev_counts = {r[0]: r[1] for r in cursor.fetchall()}
        cursor.execute("""
            SELECT COUNT(*) FROM raw_logs WHERE status='PROCESSED'
            AND datetime(timestamp) > datetime('now', '-30 days')
        """)
        total = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM incidents WHERE status = 'Open'")
        open_incidents = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM incidents")
        total_incidents = cursor.fetchone()[0]
        cursor.execute("""
            SELECT event_type, COUNT(*) FROM raw_logs
            WHERE status='PROCESSED' AND datetime(timestamp) > datetime('now', '-30 days')
            GROUP BY event_type ORDER BY COUNT(*) DESC LIMIT 10
        """)
        top_events = [(r[0], r[1]) for r in cursor.fetchall()]

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    crit = sev_counts.get('Critical', 0)
    high = sev_counts.get('High', 0)
    med = sev_counts.get('Medium', 0)
    low = sev_counts.get('Low', 0)
    score = max(0, 100 - (crit * 10 + high * 5))

    events_html = "".join(f"<tr><td>{e[0]}</td><td>{e[1]}</td></tr>" for e in top_events)
    title_map = {"threat": "Threat Summary Report", "compliance": "Compliance Report", "incident": "Incident Report"}
    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>{title_map.get(report_type, 'SOC Report')}</title>
    <style>body{{font-family:Arial,sans-serif;margin:40px;color:#1e293b}}h1{{color:#1e40af}}
    table{{border-collapse:collapse;width:100%;margin:20px 0}}th,td{{border:1px solid #cbd5e1;padding:8px;text-align:left}}
    th{{background:#1e40af;color:white}}.metric{{display:inline-block;margin:10px 20px 10px 0;padding:15px;
    background:#f1f5f9;border-radius:8px;min-width:120px;text-align:center}}.metric .val{{font-size:2em;font-weight:bold;
    color:#1e40af}}.metric .lbl{{font-size:0.85em;color:#64748b}}
    @media print{{body{{margin:20px}}}}</style></head><body>
    <h1>{title_map.get(report_type, 'SOC Report')}</h1>
    <p>Generated: {now} | By: {current_user.get('username')} | Period: Last 30 Days</p>
    <div class="metric"><div class="val">{total}</div><div class="lbl">Total Events</div></div>
    <div class="metric"><div class="val" style="color:#dc2626">{crit}</div><div class="lbl">Critical</div></div>
    <div class="metric"><div class="val" style="color:#ef4444">{high}</div><div class="lbl">High</div></div>
    <div class="metric"><div class="val" style="color:#f59e0b">{med}</div><div class="lbl">Medium</div></div>
    <div class="metric"><div class="val" style="color:#22c55e">{low}</div><div class="lbl">Low</div></div>
    <div class="metric"><div class="val">{score}%</div><div class="lbl">Compliance Score</div></div>
    <div class="metric"><div class="val">{open_incidents}</div><div class="lbl">Open Incidents</div></div>
    <div class="metric"><div class="val">{total_incidents}</div><div class="lbl">Total Incidents</div></div>
    <h2>Top Event Types</h2><table><tr><th>Event Type</th><th>Count</th></tr>{events_html}</table>
    <script>window.onload=function(){{if(window.location.search.includes('print=1'))window.print()}}</script>
    </body></html>"""
    record_audit(current_user.get('id'), current_user.get('username'), 'export_report',
                 'report', report_type, None, get_remote_address(request))
    return HTMLResp(content=html)

# --- SLA Config ---
@app.get("/api/sla-config")
@limiter.limit("60/minute")
async def get_sla_config(request: Request, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get SLA configuration"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT severity, response_minutes FROM sla_config ORDER BY response_minutes")
        rows = cursor.fetchall()
    return {r[0]: r[1] for r in rows}

@app.put("/api/sla-config/{severity}")
@limiter.limit("10/minute")
async def update_sla_config(request: Request, severity: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Update SLA threshold (admin only)"""
    if current_user.get('role') != 'admin' and not current_user.get('is_admin'):
        raise HTTPException(status_code=403, detail="Admin access required")
    data = await request.json()
    minutes = data.get('response_minutes')
    if not isinstance(minutes, int) or minutes < 1:
        raise HTTPException(status_code=400, detail="response_minutes must be a positive integer")
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE sla_config SET response_minutes = ?, updated_at = datetime('now') WHERE severity = ?",
                       (minutes, severity))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Severity not found")
        conn.commit()
    record_audit(current_user.get('id'), current_user.get('username'), 'update_sla',
                 'sla', severity, json.dumps({"minutes": minutes}), get_remote_address(request))
    return {"status": "success", "severity": severity, "response_minutes": minutes}

# --- Correlation Timeline ---
@app.get("/api/correlation-timeline/{host}")
@limiter.limit("30/minute")
async def get_correlation_timeline(request: Request, host: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get attack progression timeline for a host with MITRE kill-chain mapping"""
    mitre_order = ["Reconnaissance", "Resource Development", "Initial Access", "Execution",
                   "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
                   "Discovery", "Lateral Movement", "Collection", "Command and Control",
                   "Exfiltration", "Impact", "Unknown"]
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT rl.id, rl.timestamp, rl.severity, rl.event_type, rl.ai_summary,
                   ae.mitre_attack_tactic, ae.mitre_attack_technique, ae.threat_score
            FROM raw_logs rl
            LEFT JOIN alert_enrichment ae ON rl.id = ae.log_id
            WHERE rl.host = ? AND rl.status = 'PROCESSED'
            ORDER BY rl.timestamp ASC LIMIT 100
        """, (host,))
        rows = cursor.fetchall()
    events = []
    for r in rows:
        tactic = r[5] or "Unknown"
        events.append({
            "id": r[0], "timestamp": r[1], "severity": r[2], "event_type": r[3],
            "summary": r[4], "mitre_tactic": tactic, "mitre_technique": r[6] or "Unknown",
            "threat_score": r[7] or 0,
            "stage_index": mitre_order.index(tactic) if tactic in mitre_order else len(mitre_order) - 1
        })
    return {"host": host, "events": events, "stages": mitre_order}

# --- Geo IP Data ---
@app.get("/api/geo-data")
@limiter.limit("30/minute")
async def get_geo_data(request: Request, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get geo-IP data aggregated from alert enrichment"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT geo_country, geo_city, COUNT(*) as cnt, AVG(threat_score) as avg_score
            FROM alert_enrichment
            WHERE geo_country IS NOT NULL AND geo_country != ''
            GROUP BY geo_country, geo_city
            ORDER BY cnt DESC LIMIT 100
        """)
        geo_rows = cursor.fetchall()
        cursor.execute("""
            SELECT source_ip, geo_country, geo_city, COUNT(*) as cnt
            FROM alert_enrichment
            WHERE source_ip IS NOT NULL AND source_ip != ''
            GROUP BY source_ip
            ORDER BY cnt DESC LIMIT 50
        """)
        ip_rows = cursor.fetchall()
    # Country coordinate approximations for map markers
    country_coords = {
        "United States": [39.8, -98.5], "China": [35.8, 104.1], "Russia": [61.5, 105.3],
        "Germany": [51.1, 10.4], "United Kingdom": [55.3, -3.4], "France": [46.2, 2.2],
        "Japan": [36.2, 138.2], "India": [20.5, 78.9], "Brazil": [-14.2, -51.9],
        "Australia": [-25.2, 133.7], "Canada": [56.1, -106.3], "Netherlands": [52.1, 5.2],
        "South Korea": [35.9, 127.7], "Iran": [32.4, 53.6], "North Korea": [40.3, 127.5],
        "Ukraine": [48.3, 31.1], "Romania": [45.9, 24.9], "Vietnam": [14.0, 108.2],
        "Indonesia": [-0.7, 113.9], "Turkey": [38.9, 35.2], "Unknown": [0, 0]
    }
    countries = []
    for r in geo_rows:
        country = r[0] or "Unknown"
        coords = country_coords.get(country, [0, 0])
        countries.append({"country": country, "city": r[1], "count": r[2],
                         "avg_score": round(r[3] or 0), "lat": coords[0], "lon": coords[1]})
    ips = [{"ip": r[0], "country": r[1], "city": r[2], "count": r[3]} for r in ip_rows]
    return {"countries": countries, "ips": ips}

# --- Datasource Health ---
@app.get("/api/datasource-health")
@limiter.limit("60/minute")
async def get_datasource_health(request: Request, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get health status of all data sources"""
    sources = []
    # Elasticsearch
    es_start = time.time()
    es_ok = check_opensearch_health()
    es_latency = int((time.time() - es_start) * 1000)
    sources.append({"name": "Elasticsearch", "status": "online" if es_ok else "offline",
                    "latency_ms": es_latency, "icon": "ES"})
    # Ollama
    ol_start = time.time()
    ol_ok = check_ollama_health()
    ol_latency = int((time.time() - ol_start) * 1000)
    sources.append({"name": "Ollama LLM", "status": "online" if ol_ok else "offline",
                    "latency_ms": ol_latency, "icon": "AI"})
    # Syslog Listener
    sources.append({"name": "Syslog Listener", "status": "online" if INGESTOR_RUNNING.is_set() else "offline",
                    "latency_ms": 0, "icon": "SL"})
    # SQLite
    db_start = time.time()
    db_ok = check_db_health()
    db_latency = int((time.time() - db_start) * 1000)
    sources.append({"name": "SQLite Database", "status": "online" if db_ok else "offline",
                    "latency_ms": db_latency, "icon": "DB"})
    return {"sources": sources}

# --- Saved Searches ---
@app.get("/api/saved-searches")
@limiter.limit("60/minute")
async def get_saved_searches(request: Request, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get saved searches for current user"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, user_id, name, filters, is_shared, created_at
            FROM saved_searches
            WHERE user_id = ? OR is_shared = 1
            ORDER BY created_at DESC
        """, (current_user.get('id'),))
        rows = cursor.fetchall()
    return [{"id": r[0], "user_id": r[1], "name": r[2], "filters": json.loads(r[3]) if r[3] else {},
             "is_shared": bool(r[4]), "created_at": r[5]} for r in rows]

@app.post("/api/saved-searches")
@limiter.limit("20/minute")
async def create_saved_search(request: Request, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Save a search preset"""
    data = await request.json()
    name = data.get('name', '').strip()
    filters = data.get('filters', {})
    is_shared = data.get('is_shared', False)
    if not name:
        raise HTTPException(status_code=400, detail="Name is required")
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO saved_searches (user_id, name, filters, is_shared)
            VALUES (?, ?, ?, ?)
        """, (current_user.get('id'), name, json.dumps(filters), 1 if is_shared else 0))
        search_id = cursor.lastrowid
        conn.commit()
    return {"status": "success", "id": search_id}

@app.delete("/api/saved-searches/{search_id}")
@limiter.limit("20/minute")
async def delete_saved_search(request: Request, search_id: int, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Delete a saved search"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM saved_searches WHERE id = ? AND user_id = ?",
                       (search_id, current_user.get('id')))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Saved search not found or access denied")
        conn.commit()
    return {"status": "success"}

# ==============================================================================
# 13. Graceful Shutdown
# ==============================================================================
def signal_handler(sig, frame):
    logger.info("Shutdown signal received, stopping services...")
    INGESTOR_RUNNING.clear()
    time.sleep(2)
    logger.info("Shutdown complete")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# ==============================================================================
# 14. Main Entry Point
# ==============================================================================
if __name__ == "__main__":
    try:
        logger.info("Starting AXS ICT Hybrid SOC Agent v2.0.0")

        validate_config()
        init_db()

        try:
            ensure_index_exists()
        except Exception as e:
            logger.warning(f"OpenSearch unavailable, continuing without it: {e}")

        if not os.path.exists('templates'):
            os.makedirs('templates')
            logger.info("Created templates directory")

        # Start background threads
        threading.Thread(target=tcp_ingestor_thread, daemon=True, name="FluentD-Ingestor").start()
        threading.Thread(target=processor_loop, daemon=True, name="Processor").start()

        # Start syslog listeners (for UniFi and other network devices)
        if SYSLOG_ENABLED:
            threading.Thread(target=syslog_udp_listener, daemon=True, name="Syslog-UDP").start()
            if SYSLOG_TCP_ENABLED:
                threading.Thread(target=syslog_tcp_listener, daemon=True, name="Syslog-TCP").start()

        # Wait a moment for threads to start
        time.sleep(1)
        logger.info("Background threads started successfully")

        update_global_counts()

        logger.info(f"Starting API server on {HOST_IP}:{API_PORT}")

        uvicorn.run(
            app,
            host=HOST_IP,
            port=API_PORT,
            log_level="info"
        )

    except Exception as e:
        logger.critical(f"Fatal error during startup: {e}")
        sys.exit(1)
