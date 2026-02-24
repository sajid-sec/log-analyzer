import sys
import re
import json
import logging
from datetime import datetime, timedelta
from collections import defaultdict, deque

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# ---------------- CONFIGURATION ---------------- #
BRUTE_FORCE_LIMIT = 4
TIME_WINDOW_MINUTES = 5
MAX_TRACKED_IPS = 10000  # Prevent unbounded memory growth
FAILED_CODES = {"401", "403"}
SUCCESS_CODES = {"200", "302"}

TIME_WINDOW = timedelta(minutes=TIME_WINDOW_MINUTES)

LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+).*?\[(?P<timestamp>[^\]]+)\].*?"\s*(?P<status>\d{3})'
)

# ---------------- PARSING ---------------- #

def parse_line(line):
    match = LOG_PATTERN.search(line)
    if not match:
        return None

    try:
        timestamp = datetime.strptime(
            match.group("timestamp"),
            "%d/%b/%Y:%H:%M:%S %z"
        )
    except ValueError:
        return None

    return {
        "ip": match.group("ip"),
        "time": timestamp,
        "status": match.group("status"),
    }

# ---------------- DETECTION ENGINE ---------------- #

def detect_bruteforce(events):
    """
    Batch detection with timestamp ordering.
    Handles out-of-order logs safely.
    """
    # Sort events by time to prevent logic corruption
    events.sort(key=lambda x: x["time"])

    active_memory = defaultdict(deque)
    confirmed_threats = {}
    last_seen = {}

    for event in events:
        ip = event["ip"]
        log_time = event["time"]
        status = event["status"]

        last_seen[ip] = log_time

        # Global IP cap protection
        if len(active_memory) > MAX_TRACKED_IPS:
            oldest_ip = min(last_seen, key=last_seen.get)
            active_memory.pop(oldest_ip, None)
            last_seen.pop(oldest_ip, None)

        # Success correlation
        if status in SUCCESS_CODES:
            if ip in confirmed_threats:
                confirmed_threats[ip]["breached"] = True
            active_memory.pop(ip, None)
            continue

        # Failed attempt tracking
        if status in FAILED_CODES:
            window = active_memory[ip]
            window.append(log_time)

            # Sliding window eviction
            cutoff = log_time - TIME_WINDOW
            while window and window[0] < cutoff:
                window.popleft()

            # Detection trigger
            if len(window) >= BRUTE_FORCE_LIMIT:
                threat = confirmed_threats.setdefault(
                    ip,
                    {
                        "first_detected": log_time.isoformat(),
                        "peak_count": 0,
                        "breached": False,
                    },
                )
                threat["peak_count"] = max(threat["peak_count"], len(window))

    return confirmed_threats

# ---------------- OUTPUT ---------------- #

def output_console(threats):
    print("\n" + "=" * 55)
    print("CONFIRMED BRUTE FORCE THREATS (ROBUST ENGINE)")
    print("=" * 55)

    if not threats:
        print("No suspicious activity detected.")
        return

    sorted_threats = sorted(
        threats.items(),
        key=lambda x: x[1]["peak_count"],
        reverse=True,
    )[:10]

    for ip, data in sorted_threats:
        status = "[COMPROMISED]" if data["breached"] else "[BLOCKED]"
        print(f"{status} {ip:15} | Peak Failures: {data['peak_count']}")

def export_json(threats, filename="threat_report.json"):
    with open(filename, "w") as f:
        json.dump(threats, f, indent=4)
    logging.info(f"Threat report exported to {filename}")

# ---------------- MAIN ---------------- #

def main(file_path):
    events = []

    try:
        with open(file_path, "r") as file:
            for line in file:
                parsed = parse_line(line.strip())
                if parsed:
                    events.append(parsed)

        if not events:
            logging.warning("No valid log entries found.")
            return

        threats = detect_bruteforce(events)
        output_console(threats)
        export_json(threats)

    except FileNotFoundError:
        logging.error(f"File '{file_path}' not found.")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 analyzer.py <log_file>")
        sys.exit(1)

    main(sys.argv[1])
