from datetime import datetime


def create_alert(threat, severity, description, ip=None, user=None, source=None, confidence=1.0):

    return {
        "threat": threat.strip().upper() if threat else "UNKNOWN",
        "severity": severity.strip().upper() if severity else "LOW",
        "description": description,

        #  NEW FIELDS (IMPORTANT FOR IDS)
        "ip": ip,
        "user": user,
        "source": source,
        "confidence": confidence,

        # timestamp for SOC dashboard
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }