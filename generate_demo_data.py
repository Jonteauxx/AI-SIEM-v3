"""
Demo Data Generator for AI-SIEM v3
Generates realistic security log samples for testing and demonstration
"""

import sqlite3
import random
import datetime
from typing import List, Dict
import sys

# Sample data pools
HOSTNAMES = [
    "web-server-01", "web-server-02", "db-primary", "db-replica",
    "app-server-01", "app-server-02", "firewall-01", "vpn-gateway",
    "mail-server", "file-server", "backup-server", "load-balancer"
]

SOURCE_IPS = [
    "192.168.1.100", "192.168.1.105", "10.0.0.50", "10.0.0.51",
    "45.142.212.61", "185.220.101.45", "103.253.145.28", "91.241.19.84",  # Known malicious IPs
    "172.16.0.10", "172.16.0.15", "192.168.100.25"
]

USERNAMES = [
    "admin", "root", "user", "developer", "operator", "backup", "service",
    "test", "guest", "postgres", "mysql", "nginx", "apache"
]

ATTACK_IPS = [
    "45.142.212.61", "185.220.101.45", "103.253.145.28", "91.241.19.84",
    "198.51.100.42", "203.0.113.99", "89.248.165.22", "176.123.45.67"
]

# Log templates by severity
LOG_TEMPLATES = {
    "Critical": [
        "CRITICAL: Multiple failed root login attempts from {ip} on {host} - Possible brute force attack detected",
        "ALERT: Unauthorized access attempt to /etc/shadow on {host} from user {user}",
        "CRITICAL: Malware detected on {host} - Trojan.Generic.KD.46325841 in /tmp/malicious.exe",
        "SECURITY BREACH: Privilege escalation detected on {host} - User {user} gained root access",
        "CRITICAL: SQL Injection attempt detected from {ip} targeting {host}/api/users",
        "RANSOMWARE ALERT: File encryption activity detected on {host} - 1247 files affected",
        "CRITICAL: Backdoor detected on {host} - Listening on port 4444",
        "ALERT: Data exfiltration detected from {host} to {ip} - 2.3GB transferred"
    ],
    "High": [
        "WARNING: Failed SSH login for {user} from {ip} on {host} (Attempt 15/20)",
        "ALERT: Port scan detected from {ip} targeting {host} - 1024 ports scanned in 30 seconds",
        "HIGH: Suspicious process detected on {host} - /tmp/.hidden running with SUID",
        "WARNING: Unusual outbound connection from {host} to {ip}:6667 (IRC)",
        "HIGH: Authentication failure for {user}@{host} - Invalid certificate",
        "ALERT: Cross-site scripting (XSS) attempt blocked on {host}/login",
        "HIGH: DDoS attack detected - {host} receiving 50000 requests/sec from {ip}",
        "WARNING: Kernel exploit attempt detected on {host} - CVE-2023-12345"
    ],
    "Medium": [
        "INFO: Failed login attempt for {user} from {ip} on {host}",
        "WARNING: Firewall rule violation - {ip} attempted connection to blocked port 23 on {host}",
        "MEDIUM: Unusual API access pattern from {ip} - 500 requests in 1 minute",
        "INFO: User {user} logged in from unusual location on {host} - {ip}",
        "MEDIUM: TLS certificate expired on {host} - Renew immediately",
        "WARNING: Failed database authentication from {ip} on {host}",
        "MEDIUM: Suspicious file upload detected on {host} - .exe file in /uploads/",
        "INFO: Rate limit exceeded for {ip} accessing {host}/api"
    ],
    "Low": [
        "INFO: Successful SSH login for {user} from {ip} on {host}",
        "INFO: Service restart on {host} - nginx reloaded successfully",
        "LOW: Disk usage warning on {host} - 75% capacity reached",
        "INFO: Backup completed successfully on {host}",
        "LOW: SSL certificate will expire in 30 days on {host}",
        "INFO: User {user} logged out from {host}",
        "LOW: System update available for {host} - 12 packages",
        "INFO: Cron job executed successfully on {host} - /opt/scripts/cleanup.sh"
    ]
}

# Event types by severity
EVENT_TYPES = {
    "Critical": [
        "Brute Force Attack", "Malware Detection", "Privilege Escalation",
        "SQL Injection", "Ransomware", "Backdoor", "Data Exfiltration",
        "Security Breach"
    ],
    "High": [
        "Authentication Failure", "Port Scan", "Suspicious Process",
        "Unusual Network Activity", "XSS Attempt", "DDoS Attack",
        "Exploit Attempt", "Invalid Certificate"
    ],
    "Medium": [
        "Failed Login", "Firewall Violation", "API Abuse",
        "Unusual Location", "Certificate Expiration", "DB Auth Failure",
        "Suspicious Upload", "Rate Limit Exceeded"
    ],
    "Low": [
        "Successful Login", "Service Restart", "Disk Warning",
        "Backup Completed", "Certificate Expiry Warning", "User Logout",
        "Update Available", "Scheduled Task"
    ]
}

def generate_timestamp(days_ago: int = 7) -> str:
    """Generate a random timestamp within the last N days"""
    now = datetime.datetime.now()
    random_seconds = random.randint(0, days_ago * 24 * 60 * 60)
    timestamp = now - datetime.timedelta(seconds=random_seconds)
    return timestamp.isoformat()

def generate_log_entry(severity: str) -> Dict[str, str]:
    """Generate a single log entry with the given severity"""
    template = random.choice(LOG_TEMPLATES[severity])
    event_type = random.choice(EVENT_TYPES[severity])

    # Choose appropriate IP based on severity
    if severity in ["Critical", "High"]:
        ip = random.choice(ATTACK_IPS)
    else:
        ip = random.choice(SOURCE_IPS)

    host = random.choice(HOSTNAMES)
    user = random.choice(USERNAMES)

    log_message = template.format(ip=ip, host=host, user=user)

    return {
        "raw_log": log_message,
        "severity": severity,
        "event_type": event_type,
        "host": host,
        "timestamp": generate_timestamp()
    }

def generate_demo_data(
    db_path: str = "ai_agent_logs.db",
    total_logs: int = 100,
    distribution: Dict[str, float] = None
) -> None:
    """
    Generate demo data and insert into database

    Args:
        db_path: Path to SQLite database
        total_logs: Total number of logs to generate
        distribution: Dictionary with severity distribution (e.g., {"Low": 0.5, "Medium": 0.3, "High": 0.15, "Critical": 0.05})
    """
    if distribution is None:
        # Default distribution (realistic for a SOC)
        distribution = {
            "Low": 0.50,      # 50% low severity
            "Medium": 0.30,   # 30% medium severity
            "High": 0.15,     # 15% high severity
            "Critical": 0.05  # 5% critical severity
        }

    # Calculate number of logs per severity
    logs_by_severity = {
        severity: int(total_logs * percentage)
        for severity, percentage in distribution.items()
    }

    # Adjust for rounding errors
    total_generated = sum(logs_by_severity.values())
    if total_generated < total_logs:
        logs_by_severity["Medium"] += (total_logs - total_generated)

    print(f"Generating {total_logs} demo logs:")
    for severity, count in logs_by_severity.items():
        print(f"  - {severity}: {count} logs")

    # Connect to database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Generate and insert logs
    inserted_count = 0
    processed_count = 0

    for severity, count in logs_by_severity.items():
        for i in range(count):
            log_entry = generate_log_entry(severity)

            # Randomly mark some as processed (80% processed, 20% pending)
            status = "PROCESSED" if random.random() < 0.8 else "PENDING"

            if status == "PROCESSED":
                # Generate AI summary
                summaries = {
                    "Critical": f"Critical security incident detected. Immediate action required. {log_entry['event_type']} from {log_entry['host']}.",
                    "High": f"High-priority security event requiring investigation. {log_entry['event_type']} detected.",
                    "Medium": f"Moderate security event logged. {log_entry['event_type']} - monitor for escalation.",
                    "Low": f"Routine security log. {log_entry['event_type']} - no immediate action needed."
                }

                cursor.execute("""
                    INSERT INTO raw_logs
                    (timestamp, raw_log, status, severity, event_type, host, ai_summary, analyzed_by, created_at, processed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    log_entry["timestamp"],
                    log_entry["raw_log"],
                    status,
                    log_entry["severity"],
                    log_entry["event_type"],
                    log_entry["host"],
                    summaries[severity],
                    "demo_generator",
                    datetime.datetime.now().isoformat(),
                    datetime.datetime.now().isoformat()
                ))
                processed_count += 1
            else:
                cursor.execute("""
                    INSERT INTO raw_logs
                    (timestamp, raw_log, status, created_at)
                    VALUES (?, ?, ?, ?)
                """, (
                    log_entry["timestamp"],
                    log_entry["raw_log"],
                    status,
                    datetime.datetime.now().isoformat()
                ))

            inserted_count += 1

    conn.commit()
    conn.close()

    print(f"\n✅ Successfully generated {inserted_count} demo logs!")
    print(f"   - {processed_count} processed logs")
    print(f"   - {inserted_count - processed_count} pending logs")
    print(f"\n📊 Dashboard should now display:")
    print(f"   - Active Alerts: {logs_by_severity.get('Critical', 0) + logs_by_severity.get('High', 0)} logs")
    print(f"   - Threats Blocked: Logs with attack patterns")
    print(f"   - Total Logs: {inserted_count}")

def generate_learned_patterns(db_path: str = "ai_agent_logs.db", count: int = 10) -> None:
    """Generate some learned patterns in the knowledge base"""
    import hashlib
    import re

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Get some processed logs
    cursor.execute("SELECT raw_log, severity FROM raw_logs WHERE status='PROCESSED' LIMIT ?", (count,))
    logs = cursor.fetchall()

    learned_count = 0
    for raw_log, severity in logs:
        # Create pattern hash (simplified version of get_log_hash)
        masked = re.sub(r'\d+', 'X', raw_log)
        pattern_hash = hashlib.sha256(masked.encode()).hexdigest()

        # Randomly change severity to simulate learning
        new_severities = ["Low", "Medium", "High", "Critical"]
        corrected_severity = random.choice(new_severities)

        cursor.execute("""
            INSERT OR IGNORE INTO ai_knowledge
            (pattern_hash, corrected_severity, reason, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            pattern_hash,
            corrected_severity,
            f"User corrected classification from {severity} to {corrected_severity}",
            datetime.datetime.now().isoformat(),
            datetime.datetime.now().isoformat()
        ))
        learned_count += 1

    conn.commit()
    conn.close()

    print(f"\n✅ Generated {learned_count} learned patterns in AI knowledge base")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generate demo data for AI-SIEM")
    parser.add_argument("--logs", type=int, default=100, help="Number of logs to generate (default: 100)")
    parser.add_argument("--db", type=str, default="ai_agent_logs.db", help="Database path (default: ai_agent_logs.db)")
    parser.add_argument("--learned", type=int, default=10, help="Number of learned patterns to generate (default: 10)")

    args = parser.parse_args()

    print("=" * 60)
    print("AI-SIEM v3 - Demo Data Generator")
    print("=" * 60)
    print()

    generate_demo_data(db_path=args.db, total_logs=args.logs)
    generate_learned_patterns(db_path=args.db, count=args.learned)

    print("\n" + "=" * 60)
    print("🚀 Demo data generation complete!")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Start the application: python main.py")
    print("2. Open dashboard: http://localhost:8000")
    print("3. Click on different metric cards to filter logs")
    print("\n")
