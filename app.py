from flask import Flask, render_template
import sqlite3
import os

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'threats.db')

def get_threats():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM threats ORDER BY id DESC')
    rows = cursor.fetchall()

    conn.close()
    return rows

print("DEBUG DATA:", get_threats())  # Debugging line to check the data being fetched    

def get_threat_stats():
    conn = sqlite3.connect("threats.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT threat_type, COUNT(*) 
        FROM threats 
        GROUP BY threat_type
    """)

    data = cursor.fetchall()
    conn.close()

    labels = [row[0] for row in data]
    values = [row[1] for row in data]

    return labels, values

@app.route("/")
def index():
    threats = get_threats()
    labels, values = get_threat_stats()
    return render_template("index.html", threats=threats, labels=labels, values=values)

if __name__ == '__main__':
    app.run(debug=True)