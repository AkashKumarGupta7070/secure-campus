# ids_engine.py

from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime

from rule_engine import analyze_request

from attack_counter import (
    increment_attack,
    get_attack_stats,
    reset_attack_stats
)

from ip_blocker import (
    block_ip,
    is_blocked,
    get_blocked_ips,
    unblock_ip,
    reset_blocked_ips
)

from database import (
    init_db,
    log_attack,
    get_logs,
    clear_logs
)

from detectors.brute_force import attempts


# =========================================================
# FLASK APP
# =========================================================

app = Flask(__name__)

# Request size limit (1 MB)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024

# Disable pretty JSON formatting
app.config["JSONIFY_PRETTYPRINT_REGULAR"] = False


# =========================================================
# ENABLE CORS
# =========================================================

CORS(
    app,
    origins=[
        "http://localhost:8080",
        "http://127.0.0.1:8080"
    ]
)


# =========================================================
# INITIALIZE DATABASE
# =========================================================

init_db()


# =========================================================
# HEALTH CHECK
# =========================================================

@app.route("/health", methods=["GET"])
def health():

    return jsonify({
        "status": "IDS ONLINE",
        "service": "SecureCampus IDS",
        "time": datetime.utcnow().isoformat() + "Z"
    })


# =========================================================
# MAIN IDS ANALYSIS
# =========================================================

@app.route("/analyze", methods=["POST"])
def analyze():

    # =====================================================
    # SAFE JSON PARSING
    # =====================================================

    data = request.get_json(silent=True) or {}

    if not data:

        return jsonify({
            "threat": "ERROR",
            "severity": "LOW",
            "description": "Invalid JSON request"
        }), 400

    # =====================================================
    # REQUEST DATA
    # =====================================================

    user = str(data.get("user", "unknown"))
    role = str(data.get("role", "UNKNOWN"))
    endpoint = str(data.get("endpoint", "/"))
    url = str(data.get("url", ""))

    # Safe status conversion
    try:
        status = int(data.get("status", 200))
    except:
        status = 200

    # =====================================================
    # CLIENT IP
    # =====================================================

    ip = request.headers.get(
        "X-Forwarded-For",
        request.remote_addr
    )

    # Handle proxy chain
    if ip and "," in ip:
        ip = ip.split(",")[0].strip()

    if not ip:

        return jsonify({
            "threat": "ERROR",
            "severity": "LOW",
            "description": "Unable to determine IP"
        }), 400

    # =====================================================
    # BLOCKED IP CHECK
    # =====================================================

    if is_blocked(ip):

        return jsonify({
            "threat": "BLOCKED",
            "severity": "CRITICAL",
            "description": "Access denied"
        }), 403

    # =====================================================
    # IDS ANALYSIS
    # =====================================================

    try:

        result = analyze_request(
            user=user,
            role=role,
            ip=ip,
            endpoint=endpoint,
            status=status,
            url=url
        )

    except Exception as e:

        print("IDS ERROR:", e)

        return jsonify({
            "threat": "ERROR",
            "severity": "LOW",
            "description": "IDS processing failed"
        }), 500

    # =====================================================
    # SAFETY FALLBACK
    # =====================================================

    if not result:

        return jsonify({
            "threat": "NONE",
            "severity": "INFO",
            "description": "No threat detected"
        })

    # =====================================================
    # ATTACK DETECTED
    # =====================================================

    if result.get("threat") != "NONE":

        # Update statistics
        increment_attack(
            result.get("threat")
        )

        # Save attack log
        log_attack(
            user=user,
            ip=ip,
            threat=result.get("threat"),
            severity=result.get("severity"),
            endpoint=endpoint
        )

        # Auto-block dangerous attackers
        if result.get("severity") in ["HIGH", "CRITICAL"]:

            block_ip(ip)

    return jsonify(result)


# =========================================================
# GET ATTACK STATISTICS
# =========================================================

@app.route("/attack-stats", methods=["GET"])
def attack_stats():

    return jsonify(
        get_attack_stats()
    )


# =========================================================
# GET IDS LOGS
# =========================================================

@app.route("/api/logs", methods=["GET"])
def logs():

    logs = get_logs()

    return jsonify([

        {
            "time": l[0],
            "user": l[1],
            "ip": l[2],
            "threat": l[3],
            "severity": l[4],
            "endpoint": l[5]
        }

        for l in logs
    ])


# =========================================================
# GET BLOCKED IPS
# =========================================================

@app.route("/api/blocked-ips", methods=["GET"])
def blocked_ips():

    return jsonify(
        list(get_blocked_ips())
    )


# =========================================================
# UNBLOCK IP
# =========================================================

@app.route("/unblock-ip", methods=["POST"])
def unblock():

    data = request.get_json(silent=True) or {}

    ip = data.get("ip")

    if not ip:

        return jsonify({
            "success": False,
            "message": "IP address missing"
        }), 400

    # Remove blocked IP
    unblock_ip(ip)

    # Remove brute-force tracking
    if ip in attempts:
        del attempts[ip]

    return jsonify({
        "success": True,
        "message": f"{ip} unblocked successfully"
    })


# =========================================================
# CLEAR LOGS
# =========================================================

@app.route("/clear-logs", methods=["POST"])
def clear_logs_route():

    clear_logs()

    return jsonify({
        "success": True,
        "message": "Logs cleared successfully"
    })


# =========================================================
# RESET IDS SYSTEM
# =========================================================

@app.route("/reset-system", methods=["POST"])
def reset_system():

    # Clear blocked IPs
    reset_blocked_ips()

    # Clear brute-force attempts
    attempts.clear()

    # Clear database logs
    clear_logs()

    # Reset attack counters
    reset_attack_stats()

    return jsonify({
        "success": True,
        "message": "IDS reset complete"
    })


# =========================================================
# 404 ERROR HANDLER
# =========================================================

@app.errorhandler(404)
def not_found(e):

    return jsonify({
        "error": "Endpoint not found"
    }), 404


# =========================================================
# 413 ERROR HANDLER
# =========================================================

@app.errorhandler(413)
def payload_too_large(e):

    return jsonify({
        "error": "Payload too large"
    }), 413


# =========================================================
# 500 ERROR HANDLER
# =========================================================

@app.errorhandler(500)
def server_error(e):

    return jsonify({
        "error": "Internal server error"
    }), 500


# =========================================================
# RUN SERVER
# =========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
