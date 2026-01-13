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
metrics_lock = threading.Lock()

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

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS processing_errors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_id INTEGER,
                error_message TEXT,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (log_id) REFERENCES raw_logs(id)
            )
        """)

        conn.commit()
        logger.info("Database initialized successfully")

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

    # Try to find IP address
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ip_match = re.search(ip_pattern, log_message)
    if ip_match:
        return ip_match.group(0)

    # Try hostname (syslog format)
    # Format: <priority>timestamp hostname message
    syslog_pattern = r'^\<\d+\>\w+\s+\d+\s+\d+:\d+:\d+\s+(\S+)'
    syslog_match = re.search(syslog_pattern, log_message)
    if syslog_match:
        return syslog_match.group(1)

    # Try hostname at beginning of log (before first colon)
    hostname_pattern = r'^([a-zA-Z0-9\-\.]+):\s'
    hostname_match = re.search(hostname_pattern, log_message)
    if hostname_match:
        return hostname_match.group(1)

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
                if len(unpacked_message) < 2:
                    continue

                entries = unpacked_message[1]

                if isinstance(entries, bytes):
                    sub_unpacker = msgpack.Unpacker(
                        io.BytesIO(entries),
                        raw=True,
                        ext_hook=msgpack_ext_decoder
                    )
                    entries = list(sub_unpacker)

                with get_db() as conn_db:
                    cursor = conn_db.cursor()
                    for timestamp, record in entries:
                        raw_log_data = record.get(b'message', record)
                        msg = decode_bytes(raw_log_data)

                        cursor.execute(
                            "INSERT INTO raw_logs (timestamp, raw_log, status) VALUES (?, ?, ?)",
                            (datetime.datetime.now().isoformat(), str(msg), 'PENDING')
                        )

                    conn_db.commit()

                update_global_counts()
                logger.info(f"Ingested {len(entries)} logs from {addr}")

    except Exception as e:
        logger.error(f"Ingestor connection error from {addr}: {e}")
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
def analyze_logic(raw_log: str) -> Dict[str, Any]:
    log_hash = get_log_hash(raw_log)

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
                time.sleep(SLEEP_WHEN_EMPTY)
                continue

            logger.info(f"📦 Processing {len(rows)} pending logs...")

            # Process each log
            for row in rows:
                log_id = row['id']
                raw_log = row['raw_log']

                # Try processing with retries
                for attempt in range(1, MAX_RETRIES + 1):
                    try:
                        logger.info(f"🔍 Analyzing log {log_id} (attempt {attempt}/{MAX_RETRIES})...")

                        # Analyze the log
                        analysis = analyze_logic(raw_log)

                        # Extract host from log
                        extracted_host = extract_host_from_log(raw_log)

                        # Enrich analysis with metadata
                        analysis.update({
                            "raw_log": raw_log,
                            "@timestamp": datetime.datetime.now().isoformat(),
                            "db_id": log_id,
                            "host": extracted_host
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
                                       host=?
                                   WHERE id=?""",
                                (
                                    datetime.datetime.now().isoformat(),
                                    analysis.get('severity', 'Unknown'),
                                    analysis.get('event_type', 'Unknown'),
                                    analysis.get('summary', 'No summary'),
                                    analysis.get('analyzed_by', 'llm'),
                                    extracted_host,
                                    log_id
                                )
                            )
                            conn_upd.commit()

                        # Update global counts
                        update_global_counts()

                        # Log success
                        severity = analysis.get('severity', 'Unknown')
                        event_type = analysis.get('event_type', 'Unknown')
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