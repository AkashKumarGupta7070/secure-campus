from collections import defaultdict
from threat_detector import create_alert
from ip_blocker import block_ip
from user_blocker import block_user

attempts = defaultdict(int)

THRESHOLD = 5

def detect_bruteforce(user, ip, status):

    # Count failed attempts
    if status == 401:
        attempts[ip] += 1
    else:
        attempts[ip] = 0  # reset on success (important)

    # Check threshold
    if attempts[ip] >= THRESHOLD:

        block_ip(ip)

        if user:
            block_user(user)

        return create_alert(
            "BRUTE_FORCE",
            "CRITICAL",
            f"Multiple failed logins from {ip}"
        )

    return None


def reset_attempts(ip):
    attempts[ip] = 0