from collections import defaultdict
import time

request_times = defaultdict(list)

# thresholds (tune these)
NORMAL_LIMIT = 5
SUSPICIOUS_LIMIT = 10
ATTACK_LIMIT = 15


def track_request(ip):

    now = time.time()

    # store request time
    request_times[ip].append(now)

    # keep only last 60 seconds
    request_times[ip] = [
        t for t in request_times[ip]
        if now - t < 60
    ]

    count = len(request_times[ip])

    # ---------------- BEHAVIOR CLASSIFICATION ----------------

    if count >= ATTACK_LIMIT:
        return {
            "level": "ATTACK",
            "count": count
        }

    elif count >= SUSPICIOUS_LIMIT:
        return {
            "level": "SUSPICIOUS",
            "count": count
        }

    elif count >= NORMAL_LIMIT:
        return {
            "level": "HEAVY",
            "count": count
        }

    else:
        return {
            "level": "NORMAL",
            "count": count
        }