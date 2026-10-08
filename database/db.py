"""
ARGUS database: stores every scan and its findings permanently in SQLite.
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path("argus.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT NOT NULL,
    scanned_at  TEXT NOT NULL,
    tools       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id           INTEGER NOT NULL REFERENCES scans(id),
    tool              TEXT NOT NULL,
    category          TEXT NOT NULL,
    rule_id           TEXT,
    title             TEXT,
    severity          TEXT NOT NULL,
    original_severity TEXT,
    file              TEXT,
    line              INTEGER,
    package           TEXT,
    installed_version TEXT,
    fixed_version     TEXT,
    cwe_json          TEXT,
    description       TEXT,
    fix               TEXT,
    references_json   TEXT,
    raw_json          TEXT
);
"""


def get_connection(db_path=DB_PATH):
    """Open a connection to the database."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row          # lets us read columns by name
    conn.execute("PRAGMA foreign_keys = ON")  # enforce the scans <-> findings link
    return conn


def init_db(db_path=DB_PATH):
    """Create the tables if they don't exist yet."""
    conn = get_connection(db_path)
    try:
        conn.executescript(SCHEMA)
    finally:
        conn.close()


def save_scan(target, tools, findings, db_path=DB_PATH):
    """Save one scan and all its findings. Returns the new scan's id."""
    conn = get_connection(db_path)
    try:
        # 'with conn' = a transaction: either EVERYTHING is saved, or NOTHING is.
        with conn:
            cursor = conn.execute(
                "INSERT INTO scans (target, scanned_at, tools) VALUES (?, ?, ?)",
                (target, datetime.now(timezone.utc).isoformat(), ",".join(tools)),
            )
            scan_id = cursor.lastrowid

            for f in findings:
                conn.execute(
                    """INSERT INTO findings (
                        scan_id, tool, category, rule_id, title, severity,
                        original_severity, file, line, package, installed_version,
                        fixed_version, cwe_json, description, fix,
                        references_json, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        scan_id, f["tool"], f["category"], f["rule_id"], f["title"],
                        f["severity"], f["original_severity"], f["file"], f["line"],
                        f["package"], f["installed_version"], f["fixed_version"],
                        json.dumps(f["cwe"]), f["description"], f["fix"],
                        json.dumps(f["references"]), json.dumps(f["raw"]),
                    ),
                )
        return scan_id
    finally:
        conn.close()


def list_scans(db_path=DB_PATH):
    """Return every scan, newest first, with its number of findings."""
    conn = get_connection(db_path)
    try:
        return conn.execute(
            """SELECT s.id, s.target, s.scanned_at, COUNT(f.id) AS finding_count
               FROM scans s
               LEFT JOIN findings f ON f.scan_id = s.id
               GROUP BY s.id
               ORDER BY s.id DESC"""
        ).fetchall()
    finally:
        conn.close()


def get_findings(scan_id, db_path=DB_PATH):
    """Return all findings for one scan."""
    conn = get_connection(db_path)
    try:
        return conn.execute(
            "SELECT * FROM findings WHERE scan_id = ?", (scan_id,)
        ).fetchall()
    finally:
        conn.close()


# Test:  python -m database.db   -> lists all saved scans
if __name__ == "__main__":
    init_db()
    scans = list_scans()
    if not scans:
        print("No scans saved yet.")
    for scan in scans:
        print(f"Scan #{scan['id']}  {scan['scanned_at'][:19]}  "
              f"{scan['finding_count']} findings  ({scan['target']})")