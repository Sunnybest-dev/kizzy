from flask import Flask, render_template, redirect, url_for
from database import init_db, get_threats, get_threat_stats, clear_threats
import os

app = Flask(__name__)

init_db()

# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    threats = get_threats()
    labels, values = get_threat_stats()
    return render_template("index.html", threats=threats, labels=labels, values=values)

@app.route("/clear", methods=["POST"])
def clear():
    clear_threats()
    return redirect(url_for("index"))

# ── Local run ──────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
