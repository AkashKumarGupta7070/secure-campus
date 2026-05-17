blocked_ips = set()

def block_ip(ip):
    blocked_ips.add(ip)

def unblock_ip(ip):
    blocked_ips.discard(ip)

def is_blocked(ip):
    return ip in blocked_ips

def get_blocked_ips():
    return list(blocked_ips)
