import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'threats.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            threat_type TEXT NOT NULL,
            source_ip TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
    print("✅ Database initialized successfully!")


def insert_threat(threat_type, source_ip, timestamp):
    conn = sqlite3.connect("threats.db")
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO threats (threat_type, source_ip, timestamp)
        VALUES (?, ?, ?)
    """, (threat_type, source_ip, timestamp))

    conn.commit()
    conn.close()