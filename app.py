from flask import Flask, render_template, redirect, url_for
from database import init_db, insert_threat, get_threats, get_threat_stats, clear_threats
import os
import threading
import time
import random
from datetime import datetime

app = Flask(__name__)

init_db()

# ── Simulator State ────────────────────────────────────────────────────────────
THREAT_TYPES = ["Port Scan", "Brute Force", "DDoS", "Suspicious Port", "Anomaly", "Rapid Traffic"]
simulator_running = False
simulator_thread = None

def random_ip():
    return f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"

def threat_simulator():
    global simulator_running
    while simulator_running:
        threat = random.choice(THREAT_TYPES)
        ip = random_ip()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        insert_threat(threat, ip, timestamp)
        time.sleep(random.randint(4, 10))

def start_simulator():
    global simulator_running, simulator_thread
    if not simulator_running:
        simulator_running = True
        simulator_thread = threading.Thread(target=threat_simulator, daemon=True)
        simulator_thread.start()

def stop_simulator():
    global simulator_running
    simulator_running = False

# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    threats = get_threats()
    labels, values = get_threat_stats()
    return render_template("index.html", threats=threats, labels=labels, values=values, running=simulator_running)

@app.route("/start", methods=["POST"])
def start():
    start_simulator()
    return redirect(url_for("index"))

@app.route("/stop", methods=["POST"])
def stop():
    stop_simulator()
    return redirect(url_for("index"))

@app.route("/clear", methods=["POST"])
def clear():
    clear_threats()
    return redirect(url_for("index"))

# ── Secret toggle (only you know this URL) ─────────────────────────────────────
@app.route("/ng-admin-toggle-7x", methods=["POST"])
def secret_toggle():
    if simulator_running:
        stop_simulator()
    else:
        start_simulator()
    return redirect(url_for("index"))

# ── Local run ──────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
