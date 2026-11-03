"""SQLite storage for alerts.

All queries are parameterized (the ? placeholders) rather than built with
string formatting. That avoids SQL injection, which matters here because
log data (usernames, IPs) is attacker-controlled input.
"""
import sqlite3
from typing import Iterable, List, Optional

from src.detections.brute_force import Alert

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule        TEXT    NOT NULL,
    severity    TEXT    NOT NULL,
    ip          TEXT    NOT NULL,
    first_seen  TEXT    NOT NULL,
    last_seen   TEXT    NOT NULL,
    count       INTEGER NOT NULL,
    users       TEXT    NOT NULL,
    description TEXT    NOT NULL,
    UNIQUE (rule, ip, first_seen)
)
"""


def connect(path: str = ":memory:") -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute(SCHEMA)
    conn.commit()
    return conn


def save_alerts(conn: sqlite3.Connection, alerts: Iterable[Alert]) -> int:
    """Insert alerts, skipping duplicates. Returns how many were new."""
    inserted = 0
    for a in alerts:
        cur = conn.execute(
            "INSERT OR IGNORE INTO alerts "
            "(rule, severity, ip, first_seen, last_seen, count, users, description) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                a.rule,
                a.severity,
                a.ip,
                a.first_seen.isoformat(),
                a.last_seen.isoformat(),
                a.count,
                ",".join(a.users),
                a.description,
            ),
        )
        inserted += cur.rowcount
    conn.commit()
    return inserted


def list_alerts(conn: sqlite3.Connection, severity: Optional[str] = None) -> List[dict]:
    if severity:
        rows = conn.execute(
            "SELECT * FROM alerts WHERE severity = ? ORDER BY first_seen", (severity,)
        )
    else:
        rows = conn.execute("SELECT * FROM alerts ORDER BY first_seen")
    return [dict(r) for r in rows]
