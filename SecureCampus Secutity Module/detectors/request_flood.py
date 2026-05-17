from collections import defaultdict
import time
from threat_detector import create_alert
from ip_blocker import block_ip

requests = defaultdict(list)

# configurable settings
TIME_WINDOW = 5      # seconds
THRESHOLD = 8        # requests allowed in window


def detect_flood(ip):

    current_time = time.time()

    # add request timestamp
    requests[ip].append(current_time)

    # keep only last TIME_WINDOW seconds
    requests[ip] = [
        t for t in requests[ip]
        if current_time - t <= TIME_WINDOW
    ]

    request_count = len(requests[ip])

    # ---------------- DETECTION ----------------
    if request_count >= THRESHOLD:

        block_ip(ip)

        # reset after detection (IMPORTANT FIX)
        requests[ip] = []

        return create_alert(
            "REQUEST_FLOOD",
            "HIGH",
            f"Flood detected from {ip} ({request_count} requests/{TIME_WINDOW}s)"
        )

    return None