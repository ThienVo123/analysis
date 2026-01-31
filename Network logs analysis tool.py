from collections import defaultdict
from datetime import datetime

LOG_FILE = "network_logs.txt"

# Thresholds
FAILED_LOGIN_THRESHOLD = 3
SENSITIVE_PORTS = {22, 23, 3389, 445}

failed_logins = defaultdict(int)
connections = defaultdict(int)

suspicious_events = []

with open(LOG_FILE, "r") as f:
    next(f)  # skip header
    for line in f:
        line = line.strip()
        if not line:
            continue

        timestamp, src_ip, dst_ip, dst_port, protocol, action = line.split(",")

        dst_port = int(dst_port)
        time_obj = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")

        # Count connections per IP
        connections[src_ip] += 1

        # Detect failed logins
        if action == "FAIL":
            failed_logins[src_ip] += 1
            if failed_logins[src_ip] >= FAILED_LOGIN_THRESHOLD:
                suspicious_events.append(
                    f"[BRUTE FORCE] {src_ip} has {failed_logins[src_ip]} failed attempts"
                )

        # Detect sensitive ports access
        if dst_port in SENSITIVE_PORTS:
            suspicious_events.append(
                f"[SENSITIVE PORT] {src_ip} accessed port {dst_port} on {dst_ip}"
            )

        # Detect after-hours access (outside 8AM–6PM)
        if time_obj.hour < 8 or time_obj.hour > 18:
            suspicious_events.append(
                f"[AFTER HOURS] {src_ip} accessed {dst_ip}:{dst_port} at {timestamp}"
            )

print("=== Suspicious Activities Detected ===")
if not suspicious_events:
    print("No suspicious activity found.")
else:
    for event in suspicious_events:
        print(event)
