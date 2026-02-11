# Log analysis Celery tasks
# Handles LLM-based log analysis in background workers

import os
import re
import json
import time
import hashlib
import logging
import datetime
from typing import Dict, Any, Optional

from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded

# Setup logging
logger = logging.getLogger(__name__)

# Import from core modules
from core.config import Config
from core.database import get_db
from core.shared_state import get_shared_state

# Ollama client
try:
    from ollama import Client as OllamaClient
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False
    logger.warning("Ollama client not available")

# Elasticsearch client
try:
    from elasticsearch import Elasticsearch
    ES_AVAILABLE = True
except ImportError:
    ES_AVAILABLE = False


# LLM System Prompt (copied from main.py for standalone worker operation)
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


def get_log_hash(message: str) -> str:
    """Generate hash for log pattern matching."""
    masked = re.sub(r'\d+', 'X', message)
    return hashlib.sha256(masked.encode()).hexdigest()


def extract_ip_from_log(log_message: str) -> Optional[str]:
    """Extract source IP address from log message."""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ip_match = re.search(ip_pattern, log_message)
    return ip_match.group(0) if ip_match else None


def extract_host_from_log(log_message: str) -> Optional[str]:
    """Extract hostname from log message."""
    # Keywords that should NOT be considered hostnames
    severity_keywords = {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'INFO', 'WARNING', 'ALERT',
                         'ERROR', 'DEBUG', 'NOTICE', 'SECURITY', 'RANSOMWARE'}

    # Pattern: "on hostname"
    on_host_pattern = r'\bon\s+([a-zA-Z0-9\-\.]+)(?:\s|$|/|-)'
    on_host_match = re.search(on_host_pattern, log_message)
    if on_host_match:
        hostname = on_host_match.group(1)
        if hostname.upper() not in severity_keywords:
            return hostname

    # Pattern: "from hostname"
    from_host_pattern = r'\bfrom\s+([a-zA-Z0-9\-\.]+)(?:\s|$)'
    from_host_match = re.search(from_host_pattern, log_message)
    if from_host_match:
        hostname = from_host_match.group(1)
        if hostname.upper() not in severity_keywords and not re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname):
            return hostname

    return None


def is_info_level_log(raw_log: str) -> bool:
    """Detect routine/informational logs that bypass AI analysis."""
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


def get_es_client() -> Optional['Elasticsearch']:
    """Get Elasticsearch client."""
    if not ES_AVAILABLE:
        return None
    try:
        return Elasticsearch(
            hosts=[Config.ES_HOSTS],
            sniff_on_start=False,
            request_timeout=30
        )
    except Exception as e:
        logger.debug(f"ES client creation failed: {e}")
        return None


def index_to_opensearch(analysis: Dict[str, Any]) -> bool:
    """Index analysis result to OpenSearch/Elasticsearch."""
    es = get_es_client()
    if not es:
        return False
    try:
        es.index(index=Config.ES_INDEX, document=analysis)
        return True
    except Exception as e:
        logger.debug(f"OpenSearch indexing skipped: {str(e)[:100]}")
        return False


def check_conditional_rules(raw_log: str, log_hash: str, host: str, source_ip: str) -> Optional[Dict[str, Any]]:
    """Check if any conditional severity rules apply to this log."""
    with get_db() as conn:
        cursor = conn.cursor()
        param = "%s" if conn.db_type == "postgresql" else "?"

        cursor.execute(f"""
            SELECT id, original_severity, corrected_severity, reason,
                   host_filter, ip_filter, expires_at, exclude_hosts, times_applied
            FROM ai_knowledge_conditions
            WHERE pattern_hash = {param} AND is_active = 1
            ORDER BY created_at DESC
        """, (log_hash,))

        rules = cursor.fetchall()

        for rule in rules:
            rule_id = rule[0] if isinstance(rule, tuple) else rule['id']
            orig_sev = rule[1] if isinstance(rule, tuple) else rule['original_severity']
            new_sev = rule[2] if isinstance(rule, tuple) else rule['corrected_severity']
            reason = rule[3] if isinstance(rule, tuple) else rule['reason']
            host_filter = rule[4] if isinstance(rule, tuple) else rule['host_filter']
            ip_filter = rule[5] if isinstance(rule, tuple) else rule['ip_filter']
            expires_at = rule[6] if isinstance(rule, tuple) else rule['expires_at']
            exclude_hosts = rule[7] if isinstance(rule, tuple) else rule['exclude_hosts']
            times_applied = rule[8] if isinstance(rule, tuple) else rule['times_applied']

            # Check expiration
            if expires_at:
                try:
                    expiry_date = datetime.datetime.fromisoformat(expires_at)
                    if datetime.datetime.now() > expiry_date:
                        cursor.execute(f"UPDATE ai_knowledge_conditions SET is_active = 0 WHERE id = {param}", (rule_id,))
                        conn.commit()
                        continue
                except Exception:
                    pass

            # Check exclude_hosts
            if exclude_hosts:
                excluded = [h.strip().lower() for h in exclude_hosts.split(',')]
                if host and host.lower() in excluded:
                    continue

            # Check host_filter
            if host_filter:
                allowed_hosts = [h.strip().lower() for h in host_filter.split(',')]
                if host and host.lower() not in allowed_hosts:
                    continue

            # Check ip_filter
            if ip_filter:
                allowed_ips = [ip.strip() for ip in ip_filter.split(',')]
                if source_ip and source_ip not in allowed_ips:
                    continue

            # Rule matches - update counter and return
            cursor.execute(f"""
                UPDATE ai_knowledge_conditions
                SET times_applied = times_applied + 1, updated_at = {param}
                WHERE id = {param}
            """, (datetime.datetime.now().isoformat(), rule_id))
            conn.commit()

            return {
                "severity": new_sev,
                "original_severity": orig_sev,
                "event_type": "Conditional Rule",
                "summary": f"Severity adjusted by conditional rule. Reason: {reason}",
                "analyzed_by": "conditional_rule",
                "rule_id": rule_id
            }

    return None


def analyze_with_llm(raw_log: str) -> Dict[str, Any]:
    """Analyze log using Ollama LLM."""
    if not OLLAMA_AVAILABLE:
        return {
            "severity": "Unknown",
            "event_type": "Error",
            "summary": "Ollama client not available"
        }

    ollama_client = OllamaClient(host=Config.OLLAMA_URL)

    user_prompt = f"""Analyze this security log and classify it.

Log: {raw_log}

Respond with ONLY valid JSON:
{{"severity":"Critical|High|Medium|Low","event_type":"category","summary":"brief description"}}"""

    try:
        response = ollama_client.chat(
            model=Config.OLLAMA_MODEL,
            messages=[
                {"role": "system", "content": LLM_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt}
            ],
            options={"temperature": 0.2, "num_thread": 16, "num_ctx": 2048}
        )

        response_text = response['message']['content'].strip()

        # Extract JSON from various formats
        if "```json" in response_text:
            response_text = response_text.split("```json")[1].split("```")[0].strip()
        elif "```" in response_text:
            response_text = response_text.split("```")[1].split("```")[0].strip()

        json_match = re.search(r'\{[^{}]*\}', response_text, re.DOTALL)
        if json_match:
            response_text = json_match.group(0)

        analysis = json.loads(response_text)

        # Normalize field names
        normalized = {k.lower(): v for k, v in analysis.items()}

        result = {
            'severity': normalized.get('severity', 'Medium'),
            'event_type': normalized.get('event_type', normalized.get('eventtype', normalized.get('type', 'Unknown'))),
            'summary': normalized.get('summary', normalized.get('description', normalized.get('message', 'No summary')))
        }

        # Validate severity value
        valid_severities = ['Critical', 'High', 'Medium', 'Low', 'Info']
        if result['severity'] not in valid_severities:
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


def analyze_logic(raw_log: str, host: str = None, source_ip: str = None) -> Dict[str, Any]:
    """Analyze a log entry using knowledge base or LLM."""
    log_hash = get_log_hash(raw_log)

    # Extract IP from log if not provided
    if not source_ip:
        source_ip = extract_ip_from_log(raw_log)

    # First check conditional rules
    conditional_result = check_conditional_rules(raw_log, log_hash, host, source_ip)
    if conditional_result:
        return conditional_result

    # Then check basic knowledge base
    with get_db() as conn:
        cursor = conn.cursor()
        param = "%s" if conn.db_type == "postgresql" else "?"
        cursor.execute(
            f"SELECT corrected_severity, reason FROM ai_knowledge WHERE pattern_hash={param}",
            (log_hash,)
        )
        learned = cursor.fetchone()

    if learned:
        logger.info(f"Using learned pattern for log hash: {log_hash[:8]}...")
        return {
            "severity": learned[0] if isinstance(learned, tuple) else learned['corrected_severity'],
            "event_type": "Learned",
            "summary": f"AI recognized pattern. Reason: {learned[1] if isinstance(learned, tuple) else learned['reason']}",
            "analyzed_by": "knowledge_base"
        }

    logger.info("Analyzing with LLM...")
    analysis = analyze_with_llm(raw_log)
    analysis["analyzed_by"] = "llm"

    return analysis


@shared_task(bind=True, max_retries=3, default_retry_delay=5)
def analyze_log_task(self, log_id: int, raw_log: str, existing_host: str = None):
    """
    Celery task to analyze a single log entry.

    This is the main task dispatched when logs are ingested.
    """
    try:
        start_time = time.time()
        shared_state = get_shared_state()

        # Extract host if not provided
        host = existing_host if existing_host else extract_host_from_log(raw_log)
        source_ip = extract_ip_from_log(raw_log)

        # Check if this is an info-level log
        if is_info_level_log(raw_log):
            analysis = {
                "severity": "Info",
                "event_type": "Informational",
                "summary": "Routine system log (auto-classified)",
                "analyzed_by": "info_filter"
            }
        else:
            # Analyze the log
            analysis = analyze_logic(raw_log, host=host, source_ip=source_ip)

        processing_time_ms = int((time.time() - start_time) * 1000)

        # Enrich analysis with metadata
        analysis.update({
            "raw_log": raw_log,
            "@timestamp": datetime.datetime.now().isoformat(),
            "db_id": log_id,
            "host": host,
            "processing_time_ms": processing_time_ms
        })

        # Index to OpenSearch
        try:
            index_to_opensearch(analysis)
        except Exception as es_error:
            logger.debug(f"OpenSearch indexing skipped: {es_error}")

        # Update database
        with get_db() as conn:
            cursor = conn.cursor()
            param = "%s" if conn.db_type == "postgresql" else "?"

            cursor.execute(
                f"""UPDATE raw_logs
                   SET status='PROCESSED',
                       processed_at={param},
                       severity={param},
                       event_type={param},
                       ai_summary={param},
                       analyzed_by={param},
                       host={param}
                   WHERE id={param}""",
                (
                    datetime.datetime.now().isoformat(),
                    analysis.get('severity', 'Unknown'),
                    analysis.get('event_type', 'Unknown'),
                    analysis.get('summary', 'No summary'),
                    analysis.get('analyzed_by', 'llm'),
                    host,
                    log_id
                )
            )
            conn.commit()

        # Update metrics
        shared_state.increment_metric("processed_logs")
        shared_state.decrement_metric("pending_logs")

        logger.info(f"Processed log {log_id} in {processing_time_ms}ms - {analysis.get('severity')} - {analysis.get('event_type')}")

        return {
            "log_id": log_id,
            "severity": analysis.get('severity'),
            "event_type": analysis.get('event_type'),
            "processing_time_ms": processing_time_ms,
            "analyzed_by": analysis.get('analyzed_by')
        }

    except SoftTimeLimitExceeded:
        logger.error(f"Log {log_id} analysis timed out")
        # Mark as error
        with get_db() as conn:
            cursor = conn.cursor()
            param = "%s" if conn.db_type == "postgresql" else "?"
            cursor.execute(f"UPDATE raw_logs SET status='ERROR' WHERE id={param}", (log_id,))
            cursor.execute(
                f"INSERT INTO processing_errors (log_id, error_message) VALUES ({param}, {param})",
                (log_id, "Analysis timed out")
            )
            conn.commit()
        raise

    except Exception as e:
        logger.error(f"Error processing log {log_id}: {e}")
        # Retry with exponential backoff
        try:
            self.retry(exc=e, countdown=2 ** self.request.retries)
        except self.MaxRetriesExceededError:
            # Mark as error after all retries exhausted
            with get_db() as conn:
                cursor = conn.cursor()
                param = "%s" if conn.db_type == "postgresql" else "?"
                cursor.execute(f"UPDATE raw_logs SET status='ERROR' WHERE id={param}", (log_id,))
                cursor.execute(
                    f"INSERT INTO processing_errors (log_id, error_message) VALUES ({param}, {param})",
                    (log_id, str(e))
                )
                conn.commit()
            raise


@shared_task(bind=True, max_retries=2)
def analyze_log_batch_task(self, log_ids: list):
    """
    Celery task to analyze a batch of logs.

    More efficient than individual tasks for high-volume ingestion.
    """
    results = []
    for log_id in log_ids:
        try:
            with get_db() as conn:
                cursor = conn.cursor()
                param = "%s" if conn.db_type == "postgresql" else "?"
                cursor.execute(
                    f"SELECT raw_log, host FROM raw_logs WHERE id={param}",
                    (log_id,)
                )
                row = cursor.fetchone()

            if row:
                raw_log = row[0] if isinstance(row, tuple) else row['raw_log']
                host = row[1] if isinstance(row, tuple) else row['host']
                result = analyze_log_task.apply(args=[log_id, raw_log, host])
                results.append(result.get())
        except Exception as e:
            logger.error(f"Batch processing error for log {log_id}: {e}")
            results.append({"log_id": log_id, "error": str(e)})

    return results


@shared_task(bind=True, max_retries=3, default_retry_delay=2)
def analyze_log_priority_task(self, log_id: int, raw_log: str, existing_host: str = None):
    """
    High-priority log analysis task.

    Used for logs that need immediate attention (e.g., critical security events).
    Routes to the priority queue for faster processing.
    """
    return analyze_log_task(log_id, raw_log, existing_host)
