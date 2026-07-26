from flask import Flask, render_template
from database import init_db, insert_threat
import sqlite3
import os
import threading
import time
import random
from datetime import datetime

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'threats.db')

# ── Simulator ──────────────────────────────────────────────────────────────────
THREAT_TYPES = ["Port Scan", "Brute Force", "DDoS", "Suspicious Port", "Anomaly", "Rapid Traffic"]

def random_ip():
    return f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"

def threat_simulator():
    while True:
        threat = random.choice(THREAT_TYPES)
        ip = random_ip()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        insert_threat(threat, ip, timestamp)
        time.sleep(random.randint(4, 10))  # new threat every 4-10 seconds

# ── DB helpers ─────────────────────────────────────────────────────────────────
def get_threats():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM threats ORDER BY id DESC')
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_threat_stats():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT threat_type, COUNT(*) FROM threats GROUP BY threat_type")
    data = cursor.fetchall()
    conn.close()
    labels = [row[0] for row in data]
    values = [row[1] for row in data]
    return labels, values

# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    threats = get_threats()
    labels, values = get_threat_stats()
    return render_template("index.html", threats=threats, labels=labels, values=values)

# ── Start ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    init_db()
    t = threading.Thread(target=threat_simulator, daemon=True)
    t.start()
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
