attack_counts = {
    "BRUTE_FORCE": 0,
    "SQL_INJECTION": 0,
    "REQUEST_FLOOD": 0,
    "UNAUTHORIZED_ACCESS": 0,
    "SUSPICIOUS_LINK": 0
}


def normalize(threat):

    if not threat:
        return "UNKNOWN"

    return threat.strip().upper().replace(" ", "_")


def increment_attack(threat):

    threat = normalize(threat)

    if threat not in attack_counts:
        attack_counts[threat] = 0

    attack_counts[threat] += 1


def get_attack_stats():
    return attack_counts


def reset_attack_stats():

    for attack in attack_counts:
        attack_counts[attack] = 0