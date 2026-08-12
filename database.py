import psycopg
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.environ.get("DATABASE_URL")

def get_conn():
    return psycopg.connect(DATABASE_URL)

def init_db():
    conn = get_conn()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS threats (
            id SERIAL PRIMARY KEY,
            timestamp TEXT,
            threat_type TEXT NOT NULL,
            source_ip TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
    print("✅ Database initialized successfully!")

def insert_threat(threat_type, source_ip, timestamp):
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO threats (threat_type, source_ip, timestamp)
        VALUES (%s, %s, %s)
    """, (threat_type, source_ip, timestamp))
    conn.commit()
    conn.close()

def get_threats():
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM threats ORDER BY id DESC')
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_threat_stats():
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT threat_type, COUNT(*) FROM threats GROUP BY threat_type")
    data = cursor.fetchall()
    conn.close()
    labels = [row[0] for row in data]
    values = [row[1] for row in data]
    return labels, values

def clear_threats():
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM threats")
    conn.commit()
    conn.close()

