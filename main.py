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
from contextlib import contextmanager
from typing import Optional, Dict, Any
from dotenv import load_dotenv
from ollama import Client
from elasticsearch import Elasticsearch
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# ==============================================================================
# 1. Logging Configuration
# ==============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('soc_agent.log'),
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
DB_NAME = os.getenv("DB_NAME", 'ai_agent_logs.db')
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "5046"))
HOST_IP = os.getenv("HOST_IP", '0.0.0.0')
API_PORT = int(os.getenv("API_PORT", "8000"))
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))

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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
@contextmanager
def get_db():
    conn = sqlite3.connect(DB_NAME, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    with get_db() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS raw_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                raw_log TEXT NOT NULL,
                status TEXT DEFAULT 'PENDING',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                processed_at TEXT,
                severity TEXT,
                event_type TEXT,
                ai_summary TEXT,
                analyzed_by TEXT,
                host TEXT
            )
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_status ON raw_logs(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON raw_logs(timestamp)")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ai_knowledge (
                pattern_hash TEXT PRIMARY KEY,
                corrected_severity TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Severity Adjustments - Track all severity changes with conditions
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS severity_adjustments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
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

def analyze_with_llm(raw_log: str) -> Dict[str, Any]:
    ollama_client = Client(host=OLLAMA_URL)

    prompt = f"""Analyze this security log and respond ONLY with valid JSON in this exact format:
{{
    "severity": "Low|Medium|High|Critical",
    "event_type": "string",
    "summary": "brief description"
}}

Log to analyze: {raw_log}

Provide a concise security analysis. Focus on: potential threats, anomalies, or routine events."""

    try:
        response = ollama_client.chat(
            model=OLLAMA_MODEL,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.3}
        )

        response_text = response['message']['content'].strip()

        if "```json" in response_text:
            response_text = response_text.split("```json")[1].split("```")[0].strip()
        elif "```" in response_text:
            response_text = response_text.split("```")[1].split("```")[0].strip()

        analysis = json.loads(response_text)

        required_fields = ['severity', 'event_type', 'summary']
        if not all(field in analysis for field in required_fields):
            raise ValueError("Missing required fields in LLM response")

        return analysis

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
            # Fetch pending logs
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT id, raw_log FROM raw_logs WHERE status='PENDING' LIMIT ?",
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

                # Try processing with retries
                for attempt in range(1, MAX_RETRIES + 1):
                    try:
                        logger.info(f"🔍 Analyzing log {log_id} (attempt {attempt}/{MAX_RETRIES})...")

                        # Extract host from log first (needed for conditional rules)
                        extracted_host = extract_host_from_log(raw_log)
                        source_ip = extract_ip_from_log(raw_log)

                        # Measure processing time
                        start_time = time.time()

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
async def get_metrics(request: Request):
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
async def get_analysis_status(request: Request):
    total = TOTAL_LOGS_COUNT
    processed = PROCESSED_LOGS_COUNT

    progress = 0 if total == 0 else round((processed / total) * 100, 1)

    return {
        "progress": progress,
        "total": total,
        "processed": processed,
        "pending": PENDING_LOGS_COUNT
    }

@app.get("/api/logs")
@limiter.limit("100/minute")
async def get_logs(request: Request, panel: str = "Total Logs"):
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
    offset: int = 0
):
    """Search and filter logs with various criteria."""
    with get_db() as conn:
        cursor = conn.cursor()

        # Build dynamic query
        conditions = []
        params = []

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

        if status:
            conditions.append("status = ?")
            params.append(status)

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
async def learn(request: Request, req: FeedbackRequest):
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

    return {
        "status": "success",
        "message": "AI knowledge base updated",
        "pattern_hash": log_hash
    }

@app.post("/api/learn-conditional")
@limiter.limit("10/minute")
async def learn_conditional(request: Request, req: ConditionalFeedbackRequest):
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

    return {
        "by_analyzer": by_analyzer,
        "recent_processing": recent,
        "time_savings": {
            "total_time_saved_ms": round(time_saved_ms, 0),
            "total_time_saved_formatted": format_duration(int(time_saved_ms / 1000)),
            "llm_avg_ms": llm_stats["avg_ms"],
            "knowledge_base_avg_ms": kb_stats["avg_ms"],
            "conditional_rule_avg_ms": conditional_stats["avg_ms"],
            "speedup_factor": round(llm_stats["avg_ms"] / kb_stats["avg_ms"], 1) if kb_stats["avg_ms"] > 0 else 0
        }
    }

@app.delete("/api/conditional-rules/{rule_id}")
@limiter.limit("10/minute")
async def deactivate_conditional_rule(request: Request, rule_id: int):
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
async def chat_with_ai(request: Request, req: ChatRequest):
    try:
        ollama_client = Client(host=OLLAMA_URL)

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT raw_log, status FROM raw_logs ORDER BY timestamp DESC LIMIT 10"
            )
            recent_logs = cursor.fetchall()

        log_context = "\n".join([f"- {log['raw_log'][:100]}" for log in recent_logs[:5]])

        system_prompt = f"""You are an AI Security Operations Center (SOC) analyst assistant.
You help analyze security logs, explain threats, and provide actionable recommendations.

Recent logs context:
{log_context}

Current system stats:
- Total logs: {TOTAL_LOGS_COUNT}
- Pending: {PENDING_LOGS_COUNT}
- Processed: {PROCESSED_LOGS_COUNT}

Provide concise, actionable security advice. Be professional and helpful."""

        response = ollama_client.chat(
            model=OLLAMA_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": req.query}
            ],
            options={"temperature": 0.7}
        )

        ai_response = response['message']['content']
        logger.info(f"Chat query processed: {req.query[:50]}...")

        return {"response": ai_response}

    except Exception as e:
        logger.error(f"Chat error: {e}")
        return {"response": f"Sorry, I encountered an error: {str(e)[:100]}"}

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
async def create_incident(request: Request):
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
    """Get system CPU, memory, and processor status"""
    global PROCESSOR_ACTIVE

    cpu_percent = psutil.cpu_percent(interval=0.1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')

    return {
        "cpu_percent": cpu_percent,
        "memory_percent": memory.percent,
        "memory_used_gb": round(memory.used / (1024**3), 2),
        "memory_total_gb": round(memory.total / (1024**3), 2),
        "disk_percent": disk.percent,
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
        threading.Thread(target=tcp_ingestor_thread, daemon=True, name="Ingestor").start()
        threading.Thread(target=processor_loop, daemon=True, name="Processor").start()

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
