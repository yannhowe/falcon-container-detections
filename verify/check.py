#!/usr/bin/env python3
"""
Falcon Detection Scorecard — verify detection scenarios fired in Falcon console.

Uses FalconPy Alerts service class (v2) — the Detects API was decommissioned Sep 2025.

Usage:
    python verify/check.py              # Check last 4 hours
    python verify/check.py --hours 8    # Check last 8 hours
    python verify/check.py --verbose    # Show detection details
"""

import argparse
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import Counter

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

try:
    from falconpy import Alerts, Hosts
except ImportError:
    print("ERROR: falconpy not installed. Run: pip install -r verify/requirements.txt")
    sys.exit(1)


# Detection rules we expect to trigger (required)
REQUIRED_DETECTIONS = [
    {"name": "ContainerEscape", "description": "Privilege Escalation via Escape to Host"},
    {"name": "BashReverseShell", "description": "C2 via Remote Access Tools",
     "aliases": ["GenReverseShell", "GenCommandAndControlLin"]},
    {"name": "GenPersistenceLin", "description": "Persistence via External Remote Services"},
    {"name": "LinWebshell", "description": "Persistence via Web Shell"},
    {"name": "CredentialTheftLin", "description": "Credential Access via Unsecured Credentials"},
    {"name": "JynxRootkitInstall", "description": "Defense Evasion via Rootkit"},
    {"name": "GenExecutionLin", "description": "Execution via CLI"},
    {"name": "GenCollectionLin", "description": "Collection via Automated Collection"},
    {"name": "ExfilViaDNSRequest", "description": "Exfiltration via DNS",
     "aliases": ["LinExfiltrationOverAlternativeProtocol"]},
    {"name": "LinProcRansomware", "description": "Impact via Data Encrypted for Impact"},
    {"name": "ContainerDrift", "description": "File Creation and Execution",
     "aliases": ["RecentlyModifiedFileExecutedInContainer"]},
    {"name": "LapsangSensorDetect", "description": "ML on Trojan Binary"},
    {"name": "OnWrite-MLSensor", "description": "EICAR Malware",
     "aliases": ["EICARTestFileWrittenLin", "TestingActivity"]},
]

BEST_EFFORT = [
    {"name": "ElfExecutedFromMemory", "description": "requires IOA policy with fileless exec enabled"},
    {"name": "IMDS exfil", "description": "no reliable detection"},
    {"name": "Lateral movement", "description": "port scan alone insufficient"},
    {"name": "Crypto-miner", "description": "needs known miner binary/hash"},
]


def get_credentials():
    """Load Falcon API credentials from .env or environment."""
    env_path = Path(__file__).parent.parent / ".env"
    if load_dotenv and env_path.exists():
        load_dotenv(env_path)

    client_id = os.environ.get("FALCON_CLIENT_ID")
    client_secret = os.environ.get("FALCON_CLIENT_SECRET")
    cloud = os.environ.get("FALCON_CLOUD", "us-1")

    if not client_id or not client_secret:
        print("ERROR: FALCON_CLIENT_ID and FALCON_CLIENT_SECRET required.")
        print("Set in .env file or environment variables.")
        sys.exit(1)

    return client_id, client_secret, cloud


def query_alerts(client_id, client_secret, cloud, hours, hostname=None, verbose=False):
    """Query Falcon Alerts API v2 for detections in the time window."""
    alerts = Alerts(client_id=client_id, client_secret=client_secret, base_url=cloud)

    start_time = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Query all alerts in time window
    # Note: hostname is not directly filterable, so we query broadly and filter in Python
    response = alerts.query_alerts_v2(
        filter=f"timestamp:>'{start_time}'",
        limit=200,
        sort="timestamp|desc",
    )

    if response["status_code"] != 200:
        print(f"  WARNING: Alerts query failed (HTTP {response['status_code']})")
        if verbose:
            print(f"  Response: {response['body']}")
        return []

    alert_ids = response["body"].get("resources", [])
    if not alert_ids:
        return []

    # Get full alert details in batches of 50
    all_alerts = []
    for i in range(0, len(alert_ids), 50):
        batch = alert_ids[i : i + 50]
        detail_resp = alerts.get_alerts_v2(composite_ids=batch)
        if detail_resp["status_code"] == 200:
            all_alerts.extend(detail_resp["body"].get("resources", []))

    # Filter to specific hostname if provided
    if hostname:
        all_alerts = [
            a for a in all_alerts
            if hostname in str(a.get("device", {}).get("hostname", ""))
        ]

    return all_alerts


def match_detections(alerts, verbose=False):
    """Match alerts against expected detection patterns. Returns dict of name→count."""
    results = {}

    for det in REQUIRED_DETECTIONS:
        names_to_match = [det["name"]] + det.get("aliases", [])
        count = 0
        matched_alerts = []

        for alert in alerts:
            alert_name = alert.get("name", "")
            for pattern in names_to_match:
                if pattern.lower() in alert_name.lower():
                    count += 1
                    matched_alerts.append(alert)
                    break

        results[det["name"]] = {
            "found": count > 0,
            "count": count,
            "description": det["description"],
            "alerts": matched_alerts if verbose else [],
        }

    return results


def check_host_health(client_id, client_secret, cloud, hours):
    """Check if the detection host is online and reporting."""
    hosts = Hosts(client_id=client_id, client_secret=client_secret, base_url=cloud)

    start_time = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Find hosts with our sensor grouping tag
    response = hosts.query_devices_by_filter(
        filter=f"tags:'SensorGroupingTags/falcon-detections'+last_seen:>'{start_time}'",
        limit=5,
    )

    if response["status_code"] != 200 or not response["body"].get("resources"):
        # Fallback: try without tag filter
        response = hosts.query_devices_by_filter(
            filter=f"last_seen:>'{start_time}'",
            limit=5,
        )

    if response["status_code"] == 200 and response["body"].get("resources"):
        host_ids = response["body"]["resources"]
        detail = hosts.get_device_details(ids=host_ids[:3])
        if detail["status_code"] == 200:
            for host in detail["body"].get("resources", []):
                tags = host.get("tags", [])
                if any("falcon-detections" in t for t in tags):
                    return {
                        "online": True,
                        "hostname": host.get("hostname", "unknown"),
                        "last_seen": host.get("last_seen", "unknown"),
                        "platform": host.get("platform_name", ""),
                        "agent_version": host.get("agent_version", ""),
                    }

    return {"online": False, "hostname": "unknown", "last_seen": "unknown"}


def print_scorecard(results, host_health, hours):
    """Print formatted scorecard."""
    print("")
    print("=== Falcon Detection Scorecard ===")
    print(f"    Time window: last {hours} hours")
    if host_health["online"]:
        print(f"    Host: {host_health['hostname']}")
        print(f"    Sensor: v{host_health.get('agent_version', '?')}")
    print("")

    # Runtime Detections
    print("Runtime Detections:")
    passed = 0
    failed = 0

    for det in REQUIRED_DETECTIONS:
        result = results.get(det["name"], {})
        if result.get("found"):
            count = result.get("count", 1)
            suffix = f" (x{count})" if count > 1 else ""
            print(f"  [PASS] {det['name']} — {det['description']}{suffix}")
            passed += 1
        else:
            print(f"  [FAIL] {det['name']} — {det['description']}")
            failed += 1

    # Best effort
    for det in BEST_EFFORT:
        print(f"  [SKIP] {det['name']} ({det['description']})")

    print("")

    # Sensor Health
    print("Sensor Health:")
    if host_health["online"]:
        print(f"  [PASS] Host online — {host_health['hostname']}, last seen {host_health['last_seen']}")
    else:
        print("  [FAIL] No host found with 'falcon-detections' tag in time window")

    print("")

    # Summary
    total_required = len(REQUIRED_DETECTIONS)
    print(f"Score: {passed}/{total_required} required detections confirmed")
    if failed > 0:
        print(f"       {failed} not yet visible in Alerts API")
    print("")

    return failed == 0


def main():
    parser = argparse.ArgumentParser(description="Falcon Detection Scorecard")
    parser.add_argument("--hours", type=int, default=4, help="Look back N hours (default: 4)")
    parser.add_argument("--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--hostname", type=str, default=None, help="Filter to specific hostname")
    args = parser.parse_args()

    client_id, client_secret, cloud = get_credentials()

    print(f"Querying Falcon Alerts API ({cloud}) for last {args.hours}h...")

    # Get alerts
    alerts = query_alerts(client_id, client_secret, cloud, args.hours, args.hostname, args.verbose)
    print(f"  Found {len(alerts)} alerts" + (f" for {args.hostname}" if args.hostname else ""))

    # Match against expected detections
    results = match_detections(alerts, args.verbose)

    # Check host health
    host_health = check_host_health(client_id, client_secret, cloud, args.hours)

    # Print scorecard
    success = print_scorecard(results, host_health, args.hours)

    if args.verbose and alerts:
        print("All alert names from host:")
        names = Counter(a.get("name", "unknown") for a in alerts)
        for name, count in names.most_common():
            print(f"    {name} (x{count})")

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
