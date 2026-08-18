import sqlite3
from datetime import datetime

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "alerts.db")


def get_connection():
    return sqlite3.connect(DB_PATH)


def create_tables():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        time TEXT,
        attack_type TEXT,
        risk_level TEXT,
        risk_score INTEGER,
        source TEXT,
        details TEXT
    )
    """)

    conn.commit()
    conn.close()


def insert_alert(attack_type, risk_level, risk_score, source, details):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO alerts (
        time,
        attack_type,
        risk_level,
        risk_score,
        source,
        details
    )
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        attack_type,
        risk_level,
        risk_score,
        source,
        details
    ))

    conn.commit()
    conn.close()


def fetch_alerts():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT time, attack_type, risk_level, risk_score, source, details
    FROM alerts
    ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    return rows


if __name__ == "__main__":
    create_tables()
    print("Database and alerts table created successfully.")