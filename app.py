from flask import Flask, render_template
from database import init_db, insert_threat, get_threats, get_threat_stats
import os
import threading
import time
import random
from datetime import datetime

app = Flask(__name__)

init_db()

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
        time.sleep(random.randint(4, 10))

# Start simulator when gunicorn loads the app
t = threading.Thread(target=threat_simulator, daemon=True)
t.start()

# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    threats = get_threats()
    labels, values = get_threat_stats()
    return render_template("index.html", threats=threats, labels=labels, values=values)

# ── Local run ──────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
