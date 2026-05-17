import re
from urllib.parse import urlparse
from threat_detector import create_alert


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "update",
    "secure",
    "bank",
    "password",
    "account"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".tk", ".ml", ".cf", ".ru"
]


def detect_link(url):

    if not url:
        return None

    url = url.lower()

    parsed = urlparse(url)
    domain = parsed.netloc + parsed.path

    # ---------------- KEYWORD CHECK ----------------
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url:
            return create_alert(
                "SUSPICIOUS_LINK",
                "MEDIUM",
                f"Suspicious keyword '{keyword}' found in URL: {url}"
            )

    # ---------------- TLD CHECK ----------------
    for tld in SUSPICIOUS_TLDS:
        if tld in url:
            return create_alert(
                "SUSPICIOUS_LINK",
                "HIGH",
                f"Suspicious domain extension detected: {url}"
            )

    # ---------------- IP BASED URL CHECK ----------------
    ip_pattern = r"\b\d{1,3}(\.\d{1,3}){3}\b"
    if re.search(ip_pattern, url):
        return create_alert(
            "SUSPICIOUS_LINK",
            "HIGH",
            f"IP-based URL detected: {url}"
        )

    return None