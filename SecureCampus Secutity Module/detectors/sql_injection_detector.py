import re

def detect_sql_injection(url, endpoint, ip):

    if not url:
        return None

    patterns = [
        r"or\s+1=1",
        r"union\s+select",
        r"--",
        r"drop\s+table",
        r"' or '1'='1"
    ]

    for p in patterns:
        if re.search(p, url, re.I):
            return {
                "threat": "SQL_INJECTION",
                "severity": "HIGH",
                "description": f"SQL Injection from {ip}"
            }

    return None