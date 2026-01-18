#!/usr/bin/env python3
"""
AI Learning & Severity Adjustment Test Script

This script demonstrates:
1. How the AI learns from logs (LLM vs KB processing time)
2. How severity adjustments work
3. How conditional rules are applied

Usage:
    python test_ai_learning.py [--api-url http://localhost:5001]
"""

import requests
import time
import argparse
import sys
from datetime import datetime

# ANSI colors for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_header(text):
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"{Colors.HEADER}{Colors.BOLD}  {text}{Colors.END}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*60}{Colors.END}\n")

def print_step(step_num, text):
    print(f"{Colors.CYAN}{Colors.BOLD}[Step {step_num}]{Colors.END} {text}")

def print_success(text):
    print(f"{Colors.GREEN}  ✓ {text}{Colors.END}")

def print_warning(text):
    print(f"{Colors.YELLOW}  ⚠ {text}{Colors.END}")

def print_error(text):
    print(f"{Colors.RED}  ✗ {text}{Colors.END}")

def print_info(text):
    print(f"{Colors.BLUE}  ℹ {text}{Colors.END}")

def print_metric(label, value, unit=""):
    print(f"    {Colors.BOLD}{label}:{Colors.END} {Colors.GREEN}{value}{unit}{Colors.END}")


def check_api_health(api_url):
    """Check if the API is running"""
    try:
        resp = requests.get(f"{api_url}/api/metrics", timeout=5)
        return resp.status_code == 200
    except:
        return False


def send_log_batch(api_url, logs, batch_name):
    """Send a batch of logs and measure processing time"""
    print(f"\n{Colors.YELLOW}  Sending {len(logs)} logs ({batch_name})...{Colors.END}")

    results = []
    for i, log in enumerate(logs):
        start_time = time.time()

        try:
            resp = requests.post(
                f"{api_url}/api/log",
                json={"log": log},
                timeout=120  # LLM can be slow
            )
            elapsed = (time.time() - start_time) * 1000  # ms

            if resp.status_code == 200:
                data = resp.json()
                results.append({
                    "log": log[:50] + "...",
                    "time_ms": elapsed,
                    "severity": data.get("severity", "Unknown"),
                    "analyzed_by": data.get("analyzed_by", "unknown"),
                    "processing_time_ms": data.get("processing_time_ms", elapsed)
                })

                analyzer = data.get("analyzed_by", "unknown")
                color = Colors.RED if analyzer == "llm" else Colors.GREEN
                print(f"    [{i+1}/{len(logs)}] {color}{analyzer.upper()}{Colors.END} - {data.get('severity', '?')} - {elapsed:.0f}ms")
            else:
                print_error(f"Failed to send log {i+1}: {resp.status_code}")

        except Exception as e:
            print_error(f"Error sending log {i+1}: {e}")

    return results


def get_processing_stats(api_url):
    """Get processing time statistics"""
    try:
        resp = requests.get(f"{api_url}/api/processing-time-stats", timeout=10)
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return None


def adjust_severity(api_url, log_id, new_severity, reason="Test adjustment"):
    """Adjust severity of a log"""
    try:
        resp = requests.post(
            f"{api_url}/api/learn",
            json={
                "log_id": log_id,
                "new_severity": new_severity,
                "reason": reason
            },
            timeout=10
        )
        return resp.status_code == 200
    except:
        return False


def create_conditional_rule(api_url, log_id, new_severity, conditions):
    """Create a conditional severity rule"""
    try:
        resp = requests.post(
            f"{api_url}/api/learn-conditional",
            json={
                "log_id": log_id,
                "new_severity": new_severity,
                **conditions
            },
            timeout=10
        )
        return resp.status_code == 200, resp.json() if resp.status_code == 200 else {}
    except Exception as e:
        return False, {"error": str(e)}


def get_recent_logs(api_url, limit=10):
    """Get recent processed logs"""
    try:
        resp = requests.get(f"{api_url}/api/search-logs?limit={limit}", timeout=10)
        if resp.status_code == 200:
            return resp.json().get("logs", [])
    except:
        pass
    return []


def clear_knowledge_base(api_url):
    """Clear the AI knowledge base for fresh testing"""
    try:
        # This would need a new endpoint - for now we'll skip
        print_warning("Knowledge base clearing not implemented - results may vary")
        return True
    except:
        return False


def main():
    parser = argparse.ArgumentParser(description="Test AI Learning Features")
    parser.add_argument("--api-url", default="http://localhost:5001", help="API base URL")
    parser.add_argument("--skip-learning-demo", action="store_true", help="Skip the learning demonstration")
    args = parser.parse_args()

    api_url = args.api_url.rstrip("/")

    print_header("AI-SIEM Learning & Severity Test")
    print(f"API URL: {api_url}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Check API health
    print_step(1, "Checking API health...")
    if not check_api_health(api_url):
        print_error("API is not responding! Make sure the server is running.")
        print_info(f"Start it with: python main.py")
        sys.exit(1)
    print_success("API is healthy")

    if not args.skip_learning_demo:
        # ===========================================
        # PART 1: AI Learning Demonstration
        # ===========================================
        print_header("Part 1: AI Learning Demonstration")
        print_info("This shows how the AI learns from logs and speeds up over time")
        print_info("First batch: NEW log types -> LLM analysis (slow)")
        print_info("Second batch: SIMILAR logs -> Knowledge Base lookup (fast)")

        # Batch 1: Unique log types (will use LLM)
        print_step(2, "Sending FIRST batch - unique log types (expect LLM analysis)...")
        batch1_logs = [
            "CRITICAL: Ransomware encryption detected on file-server - 500 files encrypted in /data/documents",
            "HIGH: Cryptocurrency mining process detected on web-server-01 - xmrig using 95% CPU",
            "MEDIUM: Unusual DNS query pattern from app-server-02 - 1000 queries to suspicious domain",
            "HIGH: Reverse shell connection detected from db-primary to 185.220.101.45:4444",
            "CRITICAL: Database dump detected - 50GB exported from db-primary to external IP",
        ]

        batch1_results = send_log_batch(api_url, batch1_logs, "Batch 1 - New Logs")

        if batch1_results:
            llm_times = [r["processing_time_ms"] for r in batch1_results if r["analyzed_by"] == "llm"]
            if llm_times:
                avg_llm = sum(llm_times) / len(llm_times)
                print_metric("LLM Average Time", f"{avg_llm:.0f}", "ms")
                print_metric("LLM Logs Count", len(llm_times))

        print_info("Waiting 2 seconds for knowledge base to sync...")
        time.sleep(2)

        # Batch 2: Similar logs (should use Knowledge Base)
        print_step(3, "Sending SECOND batch - similar log types (expect KB lookup)...")
        batch2_logs = [
            "CRITICAL: Ransomware encryption detected on backup-server - 800 files encrypted in /data/backups",
            "HIGH: Cryptocurrency mining process detected on web-server-02 - cryptominer using 90% CPU",
            "MEDIUM: Unusual DNS query pattern from app-server-01 - 2000 queries to malicious domain",
            "HIGH: Reverse shell connection detected from app-server-02 to 91.241.19.84:5555",
            "CRITICAL: Database dump detected - 30GB exported from db-replica to suspicious IP",
        ]

        batch2_results = send_log_batch(api_url, batch2_logs, "Batch 2 - Similar Logs")

        if batch2_results:
            kb_times = [r["processing_time_ms"] for r in batch2_results if r["analyzed_by"] == "knowledge_base"]
            llm_times_b2 = [r["processing_time_ms"] for r in batch2_results if r["analyzed_by"] == "llm"]

            if kb_times:
                avg_kb = sum(kb_times) / len(kb_times)
                print_metric("KB Average Time", f"{avg_kb:.0f}", "ms")
                print_metric("KB Logs Count", len(kb_times))

            if llm_times_b2:
                print_warning(f"{len(llm_times_b2)} logs still went to LLM (patterns not matched)")

        # Show comparison
        print_step(4, "Fetching overall statistics...")
        stats = get_processing_stats(api_url)
        if stats:
            savings = stats.get("time_savings", {})
            print(f"\n{Colors.BOLD}  Processing Time Comparison:{Colors.END}")
            print_metric("LLM Average", f"{savings.get('llm_avg_ms', 0):.0f}", "ms (first-time analysis)")
            print_metric("KB Average", f"{savings.get('knowledge_base_avg_ms', 0):.0f}", "ms (learned patterns)")
            print_metric("Speedup Factor", f"{savings.get('speedup_factor', 0):.1f}", "x faster")
            print_metric("Total Time Saved", savings.get('total_time_saved_formatted', '-'))
            print_metric("Patterns Learned", savings.get('kb_entries_count', 0))

    # ===========================================
    # PART 2: Severity Adjustment Test
    # ===========================================
    print_header("Part 2: Severity Adjustment Test")
    print_info("This shows how to adjust log severity and create conditional rules")

    # Send a test log
    print_step(5, "Sending a test log for severity adjustment...")
    test_log = "WARNING: SSL certificate will expire in 25 days on web-server-01 - CN=*.example.com"

    resp = requests.post(f"{api_url}/api/log", json={"log": test_log}, timeout=120)
    if resp.status_code == 200:
        log_data = resp.json()
        log_id = log_data.get("log_id")
        original_severity = log_data.get("severity")
        print_success(f"Log created with ID: {log_id}")
        print_metric("Original Severity", original_severity)

        # Adjust severity
        print_step(6, "Adjusting severity from High -> Low...")
        if adjust_severity(api_url, log_id, "Low", "SSL renewal is scheduled, not urgent"):
            print_success("Severity adjusted successfully!")
            print_info("Check the Severity tab to see this adjustment")
        else:
            print_error("Failed to adjust severity")
    else:
        print_error("Failed to create test log")
        log_id = None

    # ===========================================
    # PART 3: Conditional Rule Test
    # ===========================================
    print_header("Part 3: Conditional Rule Test")
    print_info("Creating a conditional rule that only applies to specific hosts")

    # Send another log for conditional rule
    print_step(7, "Sending a log for conditional rule testing...")
    conditional_log = "HIGH: Failed SSH login for admin from 192.168.1.100 on dev-server-01 (Attempt 5/10)"

    resp = requests.post(f"{api_url}/api/log", json={"log": conditional_log}, timeout=120)
    if resp.status_code == 200:
        log_data = resp.json()
        log_id = log_data.get("log_id")
        print_success(f"Log created with ID: {log_id}")
        print_metric("Original Severity", log_data.get("severity"))

        # Create conditional rule
        print_step(8, "Creating conditional rule...")
        print_info("Rule: Lower severity to 'Low' ONLY for host 'dev-server-01'")
        print_info("Other hosts will keep the original severity")

        success, result = create_conditional_rule(api_url, log_id, "Low", {
            "reason": "Dev server - failed logins are expected during testing",
            "host_filter": "dev-server-01",
            "exclude_hosts": "prod-server-01,prod-server-02"
        })

        if success:
            print_success("Conditional rule created!")
            print_info("Check 'Active Conditional Rules' table in Severity tab")
        else:
            print_error(f"Failed to create rule: {result}")

    # ===========================================
    # PART 4: Test Conditional Rule Application
    # ===========================================
    print_header("Part 4: Testing Conditional Rule")
    print_info("Sending similar logs to test if the rule is applied correctly")

    print_step(9, "Sending log from dev-server-01 (should be Low)...")
    test_log1 = "HIGH: Failed SSH login for admin from 192.168.1.105 on dev-server-01 (Attempt 3/10)"
    resp = requests.post(f"{api_url}/api/log", json={"log": test_log1}, timeout=120)
    if resp.status_code == 200:
        data = resp.json()
        severity = data.get("severity")
        analyzer = data.get("analyzed_by")
        color = Colors.GREEN if severity == "Low" else Colors.YELLOW
        print(f"    Result: {color}{severity}{Colors.END} (analyzed by: {analyzer})")

    print_step(10, "Sending log from prod-server-01 (should stay High - excluded)...")
    test_log2 = "HIGH: Failed SSH login for admin from 192.168.1.105 on prod-server-01 (Attempt 3/10)"
    resp = requests.post(f"{api_url}/api/log", json={"log": test_log2}, timeout=120)
    if resp.status_code == 200:
        data = resp.json()
        severity = data.get("severity")
        analyzer = data.get("analyzed_by")
        color = Colors.GREEN if severity in ["High", "Critical"] else Colors.YELLOW
        print(f"    Result: {color}{severity}{Colors.END} (analyzed by: {analyzer})")

    # ===========================================
    # Summary
    # ===========================================
    print_header("Test Complete!")
    print(f"""
{Colors.BOLD}What to check in the dashboard:{Colors.END}

1. {Colors.CYAN}Severity Tab{Colors.END} -> See all sections properly displayed:
   - Stats cards with info tooltips (hover over ℹ icons)
   - AI Learning Demonstration panel
   - Processing Time charts
   - Severity Change Statistics
   - Severity Adjustments table (Before -> After)
   - Active Conditional Rules table

2. {Colors.CYAN}Overview Tab{Colors.END} -> Click on a log to:
   - View log details
   - Change severity
   - Enable "Show advanced conditions"
   - Set host filters, time limits, exclusions

3. {Colors.CYAN}Processing Time Stats{Colors.END}:
   - LLM Avg Time: Time for new/unknown logs (~seconds)
   - KB Avg Time: Time for learned logs (~milliseconds)
   - Speedup Factor: How much faster KB is vs LLM

{Colors.GREEN}Dashboard URL: http://localhost:5001{Colors.END}
""")


if __name__ == "__main__":
    main()
