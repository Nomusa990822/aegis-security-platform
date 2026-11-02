import sqlite3
from pathlib import Path

DATABASE_PATH = Path(__file__).resolve().parent.parent / "aegis.db"


def get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                source_ip TEXT,
                username TEXT,
                outcome TEXT,
                description TEXT,
                occurred_at TEXT NOT NULL,
                received_at TEXT NOT NULL
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                source_ip TEXT,
                detection_rule TEXT NOT NULL,
                created_at TEXT NOT NULL,
                status TEXT DEFAULT 'open'
            )
        """)

        connection.commit()
