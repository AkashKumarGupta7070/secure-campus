# database.py

import sqlite3
from datetime import datetime

DB_NAME = "ids_logs.db"


# -------------------------
# INIT DATABASE
# -------------------------
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS attack_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        user TEXT,
        ip TEXT,
        threat TEXT,
        severity TEXT,
        endpoint TEXT
    )
    """)

    conn.commit()
    conn.close()


# -------------------------
# LOG ATTACK
# -------------------------
def log_attack(user, ip, threat, severity, endpoint):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
    INSERT INTO attack_logs (timestamp, user, ip, threat, severity, endpoint)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (timestamp, user, ip, threat, severity, endpoint))

    conn.commit()
    conn.close()


# -------------------------
# GET ALL LOGS
# -------------------------
def get_logs(limit=50):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT timestamp, user, ip, threat, severity, endpoint
    FROM attack_logs
    ORDER BY id DESC
    LIMIT ?
    """, (limit,))

    logs = cursor.fetchall()
    conn.close()

    return logs


# -------------------------
# CLEAR LOGS (OPTIONAL)
# -------------------------
def clear_logs():
    import sqlite3

    conn = sqlite3.connect("ids_logs.db")
    cursor = conn.cursor()

    cursor.execute("DELETE FROM attack_logs")

    conn.commit()
    conn.close()
                  