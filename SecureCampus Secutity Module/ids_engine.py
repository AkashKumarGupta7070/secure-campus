from flask import Flask, request, jsonify, session, redirect, render_template
import os

from rule_engine import analyze_request
from ip_blocker import (
    is_blocked,
    unblock_ip,
    get_blocked_ips,
    block_ip
)

from detectors.brute_force import (
    detect_bruteforce,
    reset_attempts,
    attempts
)

from attack_counter import (
    get_attack_stats,
    increment_attack,
    reset_attack_stats
)

from user_blocker import is_user_blocked
from database import init_db, log_attack, get_logs, clear_logs

app = Flask(__name__)
app.secret_key = os.urandom(24)

# ================= CONFIG =================

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"

STUDENT_USERNAME = "student"
STUDENT_PASSWORD = "1234"

init_db()

# ================= HOME =================

@app.route("/")
def home():
    return render_template("index.html")

# ================= DASHBOARD =================

@app.route("/dashboard")
def dashboard():

    if not session.get("admin"):
        return redirect("/")

    return render_template("dashboard.html")


# ---------------- LOGIN API ----------------
@app.route("/login", methods=["POST"])
def login():

    data = request.get_json(silent=True) or {}

    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    role = data.get("role", "").upper()

    ip = request.remote_addr

    # ================= BLOCKED IP =================

    if is_blocked(ip):

        log_attack(
            user=username,
            ip=ip,
            threat="BLOCKED_IP",
            severity="CRITICAL",
            endpoint="/login"
        )

        increment_attack("BLOCKED_IP")

        return jsonify({
            "success": False,
            "error": "IP blocked by IDS"
        }), 403

    # ================= LOGIN VALIDATION =================

    success = False

    # ADMIN LOGIN
    if role == "ADMIN":

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            success = True
            session.clear()
            session["admin"] = True
            session["user"] = username

    # STUDENT LOGIN
    elif role == "STUDENT":

        if username == STUDENT_USERNAME and password == STUDENT_PASSWORD:
            success = True
            session.clear()
            session["student"] = True
            session["user"] = username

    # ================= IDS ANALYSIS =================

    status = 200 if success else 401

    # VERY IMPORTANT:
    # pass username as payload
    # so SQL injection can detect it
    result = analyze_request(
        username,
        role,
        ip,
        "/login",
        status,
        username
    )

    # ================= ATTACK DETECTED =================

    if result and result["threat"] != "NONE":

        log_attack(
            user=username,
            ip=ip,
            threat=result["threat"],
            severity=result["severity"],
            endpoint="/login"
        )

        increment_attack(result["threat"])

        # block dangerous attackers
        if result["severity"] in ["HIGH", "CRITICAL"]:
            block_ip(ip)

        # login failed
        if not success:

            return jsonify({
                "success": False,
                "error": result["description"],
                "threat": result["threat"]
            }), 403

    # ================= LOGIN SUCCESS =================

    if success:

        if role == "ADMIN":

            return jsonify({
                "success": True,
                "redirect": "/dashboard"
            })

        return jsonify({
            "success": True,
            "redirect": "/"
        })

    # ================= INVALID LOGIN =================

    return jsonify({
        "success": False,
        "error": "Invalid credentials"
    }), 401


# ================= LOGOUT =================

@app.route("/logout")
def logout():

    session.clear()

    return jsonify({
        "success": True
    })

# ================= ANALYZE =================

@app.route("/analyze", methods=["POST"])
def analyze():

    data = request.get_json()

    if not data:
        return jsonify({
            "threat": "ERROR",
            "severity": "LOW",
            "description": "Invalid request"
        })

    user = data.get("user")
    role = data.get("role")
    endpoint = data.get("endpoint")
    status = data.get("status")
    url = data.get("url")

    ip = request.remote_addr

    if is_blocked(ip):
        return jsonify({
            "threat": "BLOCKED",
            "severity": "CRITICAL",
            "description": "Your IP is blocked"
        })

    result = analyze_request(
        user,
        role,
        ip,
        endpoint,
        status,
        url
    )

    if not result:
        return jsonify({
            "threat": "NONE"
        })

    # ATTACK
    if result["threat"] != "NONE":

        log_attack(
            user=user,
            ip=ip,
            threat=result["threat"],
            severity=result["severity"],
            endpoint=endpoint
        )

        increment_attack(result["threat"])

        if result["severity"] in ["HIGH", "CRITICAL"]:
            block_ip(ip)

    return jsonify(result)

# ================= LOGS =================

@app.route("/api/logs")
def api_logs():

    if not session.get("admin"):
        return jsonify([])

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

# ================= STATS =================

@app.route("/attack-stats")
def attack_stats():

    if not session.get("admin"):
        return jsonify({})

    return jsonify(get_attack_stats())

# ================= BLOCKED IPS =================

@app.route("/api/blocked-ips")
def blocked_ips():

    if not session.get("admin"):
        return jsonify([])

    return jsonify(list(get_blocked_ips()))

# ================= UNBLOCK =================

@app.route("/unblock-ip", methods=["POST"])
def unblock():

    if not session.get("admin"):
        return jsonify({"success": False})

    ip = request.form.get("ip")

    unblock_ip(ip)
    reset_attempts(ip)

    return jsonify({
        "success": True
    })

# ================= CLEAR LOGS =================

@app.route("/clear-logs", methods=["POST"])
def clear_logs_route():

    if not session.get("admin"):
        return jsonify({"success": False})

    clear_logs()

    return jsonify({
        "success": True
    })

# ================= RESET =================

@app.route("/reset-system", methods=["POST"])
def reset_system():

    if not session.get("admin"):
        return jsonify({"success": False})

    clear_logs()
    attempts.clear()
    reset_attack_stats()

    return jsonify({
        "success": True
    })

@app.before_request
def global_ids_monitor():

    endpoint = request.path

    # ✅ Ignore safe routes
    ignored_routes = [
    "/login",
    "/logout",
    "/attack-stats",
    "/api/logs",
    "/api/blocked-ips",
    "/unblock-ip",
    "/clear-logs",
    "/reset-system",
    "/favicon.ico"
]

    # ✅ Ignore static/templates files
    if endpoint.startswith("/static"):
        return

    # ✅ Skip ignored routes
    if endpoint in ignored_routes:
        return

    ip = request.remote_addr

    if session.get("admin"):
     role = "ADMIN"

    elif session.get("student"):
     role = "STUDENT"

    else:
     role = "UNKNOWN"

    user = session.get("user", "guest")

    result = analyze_request(
        user=user,
        role=role,
        ip=ip,
        endpoint=endpoint,
        status=200,
        url=endpoint
    )

    # ✅ Only block REAL dangerous attacks
    if result and result.get("severity") in ["HIGH", "CRITICAL"]:

     if endpoint != "/":

        # LOG ATTACK
        log_attack(
            user=user,
            ip=ip,
            threat=result["threat"],
            severity=result["severity"],
            endpoint=endpoint
        )

        # UPDATE STATS
        increment_attack(result["threat"])

        # BLOCK IP
        block_ip(ip)

        return jsonify({
            "blocked": True,
            "reason": result
        }), 403
# ================= RUN =================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )