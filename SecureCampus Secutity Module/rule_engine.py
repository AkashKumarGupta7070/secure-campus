from detectors.brute_force import detect_bruteforce
from detectors.request_flood import detect_flood
from detectors.suspicious_access import detect_unauthorized
from detectors.link_detector import detect_link
from detectors.sql_injection_detector import detect_sql_injection


def safe_result(result):

    if not result:
        return None

    return {
        "threat": result.get("threat", "UNKNOWN"),
        "severity": result.get("severity", "LOW"),
        "description": result.get("description", ""),
        "confidence": result.get("confidence", 0.7)
    }


def analyze_request(user, role, ip, endpoint, status, url):

    # ==========================================
    # INPUT NORMALIZATION
    # ==========================================

    user = str(user or "unknown").strip()
    role = str(role or "unknown").strip().upper()
    endpoint = str(endpoint or "/").strip().lower()
    url = str(url or "").strip()

    # ==========================================
    # IGNORE SAFE SYSTEM ROUTES
    # ==========================================

    ignored_routes = [
        "/",
        "/dashboard",
        "/attack-stats",
        "/api/logs",
        "/api/blocked-ips",
        "/clear-logs",
        "/reset-system",
        "/logout",
        "/favicon.ico"
    ]

    if endpoint in ignored_routes:
        return {
            "threat": "NONE",
            "severity": "INFO",
            "description": "Safe system route",
            "attack_class": "NONE",
            "confidence": 1.0
        }

    # ==========================================
    # 1. SQL INJECTION
    # ==========================================

    result = safe_result(
        detect_sql_injection(url, endpoint, ip)
    )

    if result:
        result["attack_class"] = "INJECTION"
        return result

    # ==========================================
    # 2. MALICIOUS / PHISHING LINKS
    # ==========================================
    if "http://" in url or "https://" in url:
     result = safe_result(
        detect_link(url)
    )

    if result:
        result["attack_class"] = "PHISHING"
        return result

    # ==========================================
    # 3. UNAUTHORIZED ACCESS
    # ==========================================

    result = safe_result(
        detect_unauthorized(role, endpoint)
    )

    if result:
        result["attack_class"] = "AUTH"
        return result

    
        # ==========================================
    # 4. REQUEST FLOOD / DOS
    # ==========================================

    # Don't flood-detect dashboard auto refresh APIs
    ignored_flood_routes = [
        "/attack-stats",
        "/api/logs",
        "/api/blocked-ips"
    ]

    if endpoint not in ignored_flood_routes:

        result = safe_result(
            detect_flood(ip)
        )

        if result:
            result["attack_class"] = "DOS"
            return result
    
    # ==========================================
    # 5. BRUTE FORCE
    # ONLY CHECK LOGIN ROUTE
    # ==========================================

    if endpoint == "/login":

        result = safe_result(
            detect_bruteforce(user, ip, status)
        )

        if result:
            result["attack_class"] = "BRUTE_FORCE"
            return result

    # ==========================================
    # SAFE REQUEST
    # ==========================================

    return {
        "threat": "NONE",
        "severity": "INFO",
        "description": "No suspicious activity detected",
        "attack_class": "NONE",
        "confidence": 1.0
    }