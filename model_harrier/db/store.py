"""Database operations for scan history, telemetry, and watch targets."""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from model_harrier.utils.config import DB_PATH
from model_harrier.db.schema import SCHEMA_SQL


def init_db(db_path: Path = DB_PATH):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    conn.close()


def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def record_scan(
    model_id: str,
    risk_score: float,
    severity: str,
    file_count: int,
    risky_file_count: int,
    summary: str,
    db_path: Path = DB_PATH,
) -> int:
    conn = get_connection(db_path)
    cursor = conn.execute(
        """INSERT INTO scans (model_id, timestamp, risk_score, severity, file_count, risky_file_count, summary)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (model_id, datetime.utcnow().isoformat(), risk_score, severity, file_count, risky_file_count, summary),
    )
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def get_scan_history(limit: int = 50, db_path: Path = DB_PATH) -> list[dict]:
    conn = get_connection(db_path)
    rows = conn.execute(
        "SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_scan_by_id(scan_id: int, db_path: Path = DB_PATH) -> Optional[dict]:
    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def add_scan_file(scan_id: int, file_path: str, fmt: str, verdict: str, risk_score: float, details: str, db_path: Path = DB_PATH):
    conn = get_connection(db_path)
    conn.execute(
        """INSERT INTO scan_files (scan_id, file_path, format, verdict, risk_score, details)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (scan_id, file_path, fmt, verdict, risk_score, details),
    )
    conn.commit()
    conn.close()


def add_alert(scan_id: int, alert_type: str, severity: str, description: str, cve: Optional[str] = None, source: Optional[str] = None, db_path: Path = DB_PATH):
    conn = get_connection(db_path)
    conn.execute(
        """INSERT INTO scan_alerts (scan_id, alert_type, severity, description, cve, source)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (scan_id, alert_type, severity, description, cve, source),
    )
    conn.commit()
    conn.close()


def add_telemetry_record(
    file_hash: str,
    label: str,
    file_size: int,
    aieye_score: int,
    consensus_score: Optional[int],
    is_false_positive: bool,
    is_false_negative: bool,
    has_reduce: bool,
    has_global: bool,
    dangerous_globals: int,
    opcode_counts: Optional[dict],
    model_type: Optional[str],
    confidence: float,
    db_path: Path = DB_PATH,
):
    opcode_vector = json.dumps(opcode_counts) if opcode_counts else None
    conn = get_connection(db_path)
    conn.execute(
        """INSERT INTO telemetry (file_hash, timestamp, label, file_size, aieye_score, consensus_score,
           is_false_positive, is_false_negative, has_reduce, has_global, dangerous_globals,
           opcode_vector, model_type, confidence)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (file_hash, datetime.utcnow().isoformat(), label, file_size, aieye_score, consensus_score,
         is_false_positive, is_false_negative, has_reduce, has_global, dangerous_globals,
         opcode_vector, model_type, confidence),
    )
    conn.commit()
    conn.close()


def get_telemetry_stats(db_path: Path = DB_PATH) -> dict:
    conn = get_connection(db_path)
    stats = {"total_scans": 0, "by_label": {}, "fp_count": 0, "fn_count": 0, "fp_rate": 0.0, "fn_rate": 0.0, "avg_confidence": 0.0, "by_model_type": {}}

    row = conn.execute("SELECT COUNT(*) FROM telemetry").fetchone()
    stats["total_scans"] = row[0]

    if stats["total_scans"] == 0:
        conn.close()
        return stats

    for row in conn.execute("SELECT label, COUNT(*) FROM telemetry GROUP BY label").fetchall():
        stats["by_label"][row[0]] = row[1]

    stats["fp_count"] = conn.execute("SELECT COUNT(*) FROM telemetry WHERE is_false_positive = 1").fetchone()[0]
    stats["fn_count"] = conn.execute("SELECT COUNT(*) FROM telemetry WHERE is_false_negative = 1").fetchone()[0]

    risky = sum(v for k, v in stats["by_label"].items() if k in ("HIGH", "CRITICAL"))
    safe = sum(v for k, v in stats["by_label"].items() if k in ("SAFE", "LOW"))
    if risky > 0:
        stats["fp_rate"] = stats["fp_count"] / risky
    if safe > 0:
        stats["fn_rate"] = stats["fn_count"] / safe

    result = conn.execute("SELECT AVG(confidence) FROM telemetry WHERE confidence IS NOT NULL").fetchone()[0]
    stats["avg_confidence"] = result if result else 0.0

    for row in conn.execute("SELECT model_type, COUNT(*) FROM telemetry WHERE model_type IS NOT NULL GROUP BY model_type").fetchall():
        stats["by_model_type"][row[0]] = row[1]

    conn.close()
    return stats


def add_watch_target(model_id: str, interval_hours: int = 24, db_path: Path = DB_PATH):
    conn = get_connection(db_path)
    conn.execute(
        "INSERT OR REPLACE INTO watch_targets (model_id, check_interval_hours, last_checked) VALUES (?, ?, ?)",
        (model_id, interval_hours, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()


def get_watch_targets(db_path: Path = DB_PATH) -> list[dict]:
    conn = get_connection(db_path)
    rows = conn.execute("SELECT * FROM watch_targets").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def remove_watch_target(model_id: str, db_path: Path = DB_PATH):
    conn = get_connection(db_path)
    conn.execute("DELETE FROM watch_targets WHERE model_id = ?", (model_id,))
    conn.commit()
    conn.close()
